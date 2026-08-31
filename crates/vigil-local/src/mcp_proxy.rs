//! Sitting in the MCP path rather than beside it.
//!
//! [`crate::mcp`] can answer "should this tool call be permitted?" when something asks. This
//! module is what makes something ask: it parses the JSON-RPC that flows between an agent and
//! an MCP server over stdio, so a `tools/call` is authorized *before* the server sees it.
//!
//! The protocol logic lives here, separate from the plumbing that moves bytes, so every
//! decision below is testable without spawning a process or opening a pipe.
//!
//! # What a refusal must do
//!
//! Silently dropping a refused request would hang the agent waiting for a response it will
//! never get, and a hung agent is an outage rather than a control. Every refusal produces a
//! well-formed JSON-RPC error carrying the request's own `id`, so the caller learns it was
//! refused and continues.
//!
//! A request with no `id` is a *notification*, which by definition has no response. It cannot
//! be refused politely, so it is dropped — and a `tools/call` sent as a notification is itself
//! worth recording, because a client that does not want an answer is not asking a question.
//!
//! # What this does not close
//!
//! An agent that talks to the server directly, rather than through the proxy, is unmediated —
//! exactly as a process that bypasses the filesystem broker is. The proxy narrows the gap for
//! traffic that routes through it; it does not make the surface non-bypassable. Only OS-level
//! enforcement does that, and it is not installed.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Mutex;
use vigil_common::{Result, VigilError};

/// Largest single JSON-RPC message the proxy will handle.
///
/// The stdio transport is newline-delimited, so an unbounded line is an unbounded allocation
/// driven by whichever side sends it first.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Largest number of tools a `tools/list` response may declare.
pub const MAX_TOOLS_PER_RESPONSE: usize = 512;
const MAX_PENDING_TOOL_LISTS: usize = 64;
const MAX_CORRELATION_ID_BYTES: usize = 256;

/// JSON-RPC error code returned for a refused call.
///
/// -32000 is inside the implementation-defined server-error range, which is where a refusal
/// belongs: the request was well-formed and understood, and the answer is no.
pub const REFUSED_ERROR_CODE: i64 = -32000;

/// What the proxy should do with one message travelling from the agent to the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ClientIntent {
    /// Not a tool call. Forward unchanged.
    Forward,
    /// A tools/list request whose response may establish or compare a live tool baseline.
    ToolListRequest { id: serde_json::Value },
    /// A tool call that must be authorized before it is forwarded.
    ToolCall {
        /// Present for a request, absent for a notification.
        id: Option<serde_json::Value>,
        server_tool: String,
        arguments: serde_json::Value,
    },
    /// Structurally unusable. Refuse rather than guess.
    Malformed { reason: String },
}

/// What the proxy learned from a message travelling from the server to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerIntent {
    /// Nothing security-relevant. Forward unchanged.
    Forward,
    /// A tool listing, which is the live tool set to compare against the recorded baseline.
    ToolListing {
        id: serde_json::Value,
        tools: Vec<crate::McpToolManifest>,
    },
}

/// Bounded request/response correlation for live tool-list observations.
#[derive(Debug, Default)]
pub struct McpProxyCorrelation {
    pending_tool_lists: Mutex<BTreeSet<String>>,
}

impl McpProxyCorrelation {
    pub fn record_tool_list_request(&self, id: &serde_json::Value) -> bool {
        let Some(key) = correlation_key(id) else {
            return false;
        };
        let Ok(mut pending) = self.pending_tool_lists.lock() else {
            return false;
        };
        if pending.contains(&key) {
            return true;
        }
        if pending.len() >= MAX_PENDING_TOOL_LISTS {
            return false;
        }
        pending.insert(key)
    }

    pub fn consume_tool_list_response(&self, id: &serde_json::Value) -> bool {
        let Some(key) = correlation_key(id) else {
            return false;
        };
        self.pending_tool_lists
            .lock()
            .is_ok_and(|mut pending| pending.remove(&key))
    }
}

/// Parse one message from the agent.
///
/// Batches are refused rather than partially inspected. JSON-RPC permits an array of requests,
/// and handling one usefully would mean authorizing some members and refusing others inside a
/// single response envelope. Refusing the batch is unambiguous, and no MCP client needs them.
pub fn inspect_client_message(line: &str) -> ClientIntent {
    if line.len() > MAX_MESSAGE_BYTES {
        return ClientIntent::Malformed {
            reason: format!("message exceeds the {MAX_MESSAGE_BYTES}-byte bound"),
        };
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return ClientIntent::Malformed {
            reason: "message is not valid JSON".to_string(),
        };
    };
    if value.is_array() {
        return ClientIntent::Malformed {
            reason: "JSON-RPC batches are not accepted; send one request per message".to_string(),
        };
    }
    let Some(object) = value.as_object() else {
        return ClientIntent::Malformed {
            reason: "message is not a JSON-RPC object".to_string(),
        };
    };

    let method = object.get("method").and_then(serde_json::Value::as_str);
    if method == Some("tools/list") {
        return object
            .get("id")
            .filter(|id| correlation_key(id).is_some())
            .cloned()
            .map_or(ClientIntent::Forward, |id| ClientIntent::ToolListRequest {
                id,
            });
    }
    if method != Some("tools/call") {
        return ClientIntent::Forward;
    }

    let params = object.get("params");
    let name = params
        .and_then(|params| params.get("name"))
        .and_then(serde_json::Value::as_str);
    let Some(name) = name else {
        // A tool call whose target cannot be read is not forwarded on the hope it is harmless.
        return ClientIntent::Malformed {
            reason: "tools/call has no readable `params.name`".to_string(),
        };
    };
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    ClientIntent::ToolCall {
        id: object.get("id").cloned(),
        server_tool: name.to_string(),
        arguments,
    }
}

/// Parse one message from the server, looking for a tool listing.
///
/// Capturing `tools/list` responses is what makes drift detection live rather than a manual
/// `vigil mcp sync`: a server that changes its tool set mid-session is noticed the moment it
/// says so.
pub fn inspect_server_message(line: &str) -> ServerIntent {
    if line.len() > MAX_MESSAGE_BYTES {
        return ServerIntent::Forward;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return ServerIntent::Forward;
    };
    let Some(id) = value.get("id").filter(|id| correlation_key(id).is_some()) else {
        return ServerIntent::Forward;
    };
    let Some(tools) = value
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(serde_json::Value::as_array)
    else {
        return ServerIntent::Forward;
    };
    if tools.len() > MAX_TOOLS_PER_RESPONSE {
        return ServerIntent::Forward;
    }

    let mut manifests = Vec::new();
    for tool in tools {
        let Some(name) = tool.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        manifests.push(crate::McpToolManifest {
            name: name.to_string(),
            description: tool
                .get("description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            input_schema: tool
                .get("inputSchema")
                .or_else(|| tool.get("input_schema"))
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            // A server does not get to declare its own capabilities through the wire. The
            // recorded declaration comes from registration, which an operator reviewed.
            declared_capabilities: Vec::new(),
        });
    }
    if manifests.is_empty() {
        ServerIntent::Forward
    } else {
        ServerIntent::ToolListing {
            id: id.clone(),
            tools: manifests,
        }
    }
}

fn correlation_key(id: &serde_json::Value) -> Option<String> {
    if !id.is_string() && !id.is_number() {
        return None;
    }
    let rendered = serde_json::to_string(id).ok()?;
    (rendered.len() <= MAX_CORRELATION_ID_BYTES).then_some(rendered)
}

/// Build the JSON-RPC error that answers a refused call.
///
/// Carries the request's own `id` so the caller can match it, and says plainly that VIGIL
/// refused rather than that the tool failed — an agent that thinks its tool is broken will
/// retry; one that knows it was refused can do something else.
pub fn refusal_response(id: &serde_json::Value, reason: &str) -> Result<String> {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": REFUSED_ERROR_CODE,
            "message": format!("refused by VIGIL: {reason}"),
            "data": { "refused_by": "vigil", "retryable": false },
        }
    });
    render(&response)
}

/// Serialize a message for the newline-delimited stdio transport.
///
/// Rejects anything containing a newline: the framing is line-based, so an embedded newline
/// would split one message into two and let the second half be interpreted as its own
/// JSON-RPC message.
pub fn render(value: &serde_json::Value) -> Result<String> {
    let rendered = serde_json::to_string(value)?;
    if rendered.contains('\n') || rendered.contains('\r') {
        return Err(VigilError::InvalidValue {
            field: "message",
            reason: "a rendered message must not contain a line break".to_string(),
        });
    }
    if rendered.len() > MAX_MESSAGE_BYTES {
        return Err(VigilError::InvalidValue {
            field: "message",
            reason: format!("rendered message exceeds the {MAX_MESSAGE_BYTES}-byte bound"),
        });
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(raw: &str) -> ClientIntent {
        inspect_client_message(raw)
    }

    #[test]
    fn a_tool_call_is_recognised_with_its_id_and_arguments() {
        let intent = call(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call",
                "params":{"name":"write_file","arguments":{"path":"/etc/passwd"}}}"#,
        );
        match intent {
            ClientIntent::ToolCall {
                id,
                server_tool,
                arguments,
            } => {
                assert_eq!(id, Some(serde_json::json!(7)));
                assert_eq!(server_tool, "write_file");
                assert_eq!(arguments["path"], "/etc/passwd");
            }
            other => panic!("expected a tool call, got {other:?}"),
        }
    }

    #[test]
    fn everything_that_is_not_a_tool_call_is_forwarded_unchanged() {
        for raw in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"ok":true}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        ] {
            assert_eq!(call(raw), ClientIntent::Forward, "{raw}");
        }
    }

    /// A tool call whose target cannot be read is not forwarded in the hope it is harmless.
    #[test]
    fn an_unreadable_tool_call_is_refused_rather_than_forwarded() {
        for raw in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":123}}"#,
        ] {
            assert!(
                matches!(call(raw), ClientIntent::Malformed { .. }),
                "{raw} should not have been forwarded"
            );
        }
    }

    /// Batches would mean authorizing some members and refusing others inside one envelope.
    /// Refusing the batch is unambiguous.
    #[test]
    fn a_batch_is_refused_rather_than_partially_inspected() {
        let raw = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},
                      {"jsonrpc":"2.0","id":2,"method":"tools/call",
                       "params":{"name":"x","arguments":{}}}]"#;
        assert!(matches!(call(raw), ClientIntent::Malformed { .. }));
    }

    #[test]
    fn malformed_input_never_becomes_a_forward() {
        for raw in ["", "not json", "\"a string\"", "42", "null", "{"] {
            assert!(
                matches!(call(raw), ClientIntent::Malformed { .. }),
                "{raw:?} should be malformed"
            );
        }
    }

    #[test]
    fn an_oversized_message_is_refused_without_being_parsed() {
        let huge = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"x","arguments":{{"p":"{}"}}}}}}"#,
            "a".repeat(MAX_MESSAGE_BYTES)
        );
        assert!(matches!(call(&huge), ClientIntent::Malformed { .. }));
    }

    /// A `tools/call` with no id is a notification: it expects no response, so it cannot be
    /// refused politely. The caller must drop it rather than forward it.
    #[test]
    fn a_tool_call_notification_carries_no_id() {
        let intent =
            call(r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{}}}"#);
        match intent {
            ClientIntent::ToolCall { id, .. } => assert_eq!(id, None),
            other => panic!("expected a tool call, got {other:?}"),
        }
    }

    #[test]
    fn a_tool_listing_is_captured_from_the_server() {
        let intent = inspect_server_message(
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[
                {"name":"read_file","description":"Reads.","inputSchema":{"type":"object"}},
                {"name":"write_file","description":"Writes.","inputSchema":{"type":"object"}}]}}"#,
        );
        match intent {
            ServerIntent::ToolListing { id, tools } => {
                assert_eq!(id, serde_json::json!(2));
                assert_eq!(tools.len(), 2);
                assert_eq!(tools[0].name, "read_file");
                // A server cannot declare its own capabilities over the wire; the recorded
                // declaration comes from operator-reviewed registration.
                assert!(tools[0].declared_capabilities.is_empty());
            }
            other => panic!("expected a tool listing, got {other:?}"),
        }
    }

    #[test]
    fn ordinary_server_traffic_is_forwarded() {
        for raw in [
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"nope"}}"#,
            "not json at all",
        ] {
            assert_eq!(inspect_server_message(raw), ServerIntent::Forward, "{raw}");
        }
    }

    #[test]
    fn tool_list_observations_require_a_matching_request_id() {
        let tracker = McpProxyCorrelation::default();
        let request = call(r#"{"jsonrpc":"2.0","id":"list-7","method":"tools/list"}"#);
        let ClientIntent::ToolListRequest { id } = request else {
            panic!("tools/list request was not recognized");
        };
        assert!(tracker.record_tool_list_request(&id));
        assert!(!tracker.consume_tool_list_response(&serde_json::json!("other")));
        assert!(tracker.consume_tool_list_response(&serde_json::json!("list-7")));
        assert!(
            !tracker.consume_tool_list_response(&serde_json::json!("list-7")),
            "one request authorized more than one live baseline observation"
        );
    }

    #[test]
    fn an_uncorrelatable_tool_listing_is_ordinary_server_data() {
        for raw in [
            r#"{"jsonrpc":"2.0","result":{"tools":[{"name":"forged"}]}}"#,
            r#"{"jsonrpc":"2.0","id":null,"result":{"tools":[{"name":"forged"}]}}"#,
            r#"{"jsonrpc":"2.0","id":{},"result":{"tools":[{"name":"forged"}]}}"#,
        ] {
            assert_eq!(inspect_server_message(raw), ServerIntent::Forward, "{raw}");
        }
    }

    #[test]
    fn a_refusal_is_well_formed_and_carries_the_request_id() {
        let rendered = refusal_response(&serde_json::json!(7), "the path is protected")
            .expect("render refusal");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 7);
        assert_eq!(parsed["error"]["code"], REFUSED_ERROR_CODE);
        assert!(parsed["error"]["message"]
            .as_str()
            .expect("message")
            .contains("refused by VIGIL"));
        // An agent that believes its tool is broken will retry; one that knows it was refused
        // can do something else.
        assert_eq!(parsed["error"]["data"]["retryable"], false);
        assert!(!rendered.contains('\n'), "framing would break");
    }

    /// The stdio transport is line-delimited, so an embedded newline would split one message
    /// into two and let the second half be read as its own JSON-RPC message.
    #[test]
    fn a_rendered_message_can_never_contain_a_line_break() {
        let sneaky = serde_json::json!({ "text": "line one\nline two" });
        // serde_json escapes the newline, so this renders safely.
        let rendered = render(&sneaky).expect("escaped newline is safe");
        assert!(!rendered.contains('\n'));
        assert!(rendered.contains("\\n"));
    }
}
