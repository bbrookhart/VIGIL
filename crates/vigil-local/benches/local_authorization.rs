//! Latency of the local authorization path.
//!
//! Every brokered request goes through this path, and it has grown: a decision now consults
//! session risk, may consume a lease, may record a detection and a risk signal, may open an
//! incident, and may raise an approval — each of those touching SQLite. That is a lot to have
//! accumulated without measuring, and §68 requires the measurement.
//!
//! The shapes below are chosen to separate the cheap common case from the expensive rare one,
//! because an average over both tells you nothing useful about either.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::hint::black_box;
use std::path::PathBuf;
use vigil_local::{LocalAction, LocalProfile, LocalStore, NewSession};

struct Fixture {
    root: PathBuf,
    store: LocalStore,
    session: String,
    workspace: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("vigil-bench-{label}-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let workspace = std::fs::canonicalize(&workspace).expect("canonical");
        std::fs::write(workspace.join("main.rs"), b"fn main() {}").expect("seed");
        let store = LocalStore::open(&root.join("state/vigil.db")).expect("open store");
        let session = store
            .create_session(&NewSession {
                profile: "developer-standard".to_string(),
                workspace: workspace.clone(),
                executable: "vigil-bench".to_string(),
                argv: vec!["vigil-bench".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session")
            .id;
        store
            .mark_running(&session, std::process::id())
            .expect("activate");
        Self {
            root,
            store,
            session,
            workspace,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn local_authorization(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("local_authorization");

    // The common case: a permitted workspace read. This is what a working agent does all day,
    // so it is the number that matters most.
    let allow = Fixture::new("allow");
    group.bench_function("allow_workspace_read", |bencher| {
        bencher.iter(|| {
            black_box(
                allow
                    .store
                    .authorize_local(
                        &allow.session,
                        LocalProfile::DeveloperStandard,
                        &allow.workspace,
                        LocalAction::FsRead,
                        "main.rs",
                    )
                    .expect("authorize"),
            )
        })
    });

    // A routine refusal that names no detection: no risk signal, no detection row, no
    // approval. The cheapest deny.
    let deny = Fixture::new("deny");
    let outside = deny.root.join("outside.txt").display().to_string();
    group.bench_function("deny_outside_workspace", |bencher| {
        bencher.iter(|| {
            black_box(
                deny.store
                    .authorize_local(
                        &deny.session,
                        LocalProfile::DeveloperStandard,
                        &deny.workspace,
                        LocalAction::FsRead,
                        &outside,
                    )
                    .expect("authorize"),
            )
        })
    });

    // The expensive path: a denial that fires a detection, which records a detection row, a
    // risk signal, re-derives the aggregate state, and may open an incident. A fresh fixture
    // per iteration so the accumulating detection history does not skew later samples.
    group.bench_function("deny_with_detection", |bencher| {
        bencher.iter_batched(
            || Fixture::new("detect"),
            // The fixture is *returned*, not consumed: its `Drop` removes a directory tree,
            // and moving it into the routine put that filesystem work inside the timer. The
            // first version of this benchmark reported 832 µs for a decision that costs 63.
            |fixture| {
                black_box(
                    fixture
                        .store
                        .authorize_local(
                            &fixture.session,
                            LocalProfile::DeveloperStandard,
                            &fixture.workspace,
                            LocalAction::FsRead,
                            "~/.ssh/vigil-bench-synthetic",
                        )
                        .expect("authorize"),
                );
                fixture
            },
            BatchSize::SmallInput,
        )
    });

    // Raising an approval: the most work a single decision can do short of an incident.
    group.bench_function("require_approval_raises_request", |bencher| {
        bencher.iter_batched(
            || Fixture::new("approval"),
            |fixture| {
                black_box(
                    fixture
                        .store
                        .authorize_local(
                            &fixture.session,
                            LocalProfile::DeveloperStandard,
                            &fixture.workspace,
                            LocalAction::ProcessExec,
                            "/usr/bin/uname",
                        )
                        .expect("authorize"),
                );
                fixture
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// An MCP call authorizes every resource in its arguments independently, so its cost scales
/// with the argument document rather than with the call. Measured separately because that is a
/// different performance shape from a single decision.
fn mcp_authorization(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("mcp_authorization");
    let fixture = Fixture::new("mcp");
    let executable = fixture.root.join("bench-server");
    std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("write server");
    let digest =
        vigil_common::ContentHash::sha256(&std::fs::read(&executable).expect("read")).to_string();
    fixture
        .store
        .register_mcp_server(
            "bench",
            vigil_local::McpTransport::Stdio,
            Some(executable.to_str().expect("path")),
            Some(&digest),
            None,
        )
        .expect("register");
    fixture
        .store
        .sync_mcp_tools(
            "bench",
            None,
            &[vigil_local::McpToolManifest {
                name: "edit".to_string(),
                description: "Edits files.".to_string(),
                input_schema: serde_json::json!({ "type": "object" }),
                declared_capabilities: vec![LocalAction::FsRead],
            }],
        )
        .expect("sync");

    for count in [1usize, 8, 32] {
        let arguments = serde_json::json!({
            "edits": (0..count)
                .map(|index| serde_json::json!({ "path": format!("./file{index}.rs") }))
                .collect::<Vec<_>>()
        });
        group.bench_function(format!("call_with_{count}_resources"), |bencher| {
            bencher.iter(|| {
                black_box(
                    fixture
                        .store
                        .authorize_mcp_call(
                            &fixture.session,
                            &vigil_local::McpToolCall {
                                server_name: "bench",
                                tool_name: "edit",
                                arguments: &arguments,
                            },
                        )
                        .expect("authorize"),
                )
            })
        });
    }
    group.finish();
}

criterion_group!(benches, local_authorization, mcp_authorization);
criterion_main!(benches);
