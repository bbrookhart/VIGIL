//! Per-session state: provenance, budgets and behavioural history.
//!
//! # Why
//!
//! Almost every interesting agent attack is a *sequence*, not a single call. Reading a secret
//! is fine. Fetching a page is fine. Sending an email is fine. The three together, in that
//! order, driven by content from the page, is an exfiltration. Only session state makes that
//! visible, which is why VIGIL is stateful where a conventional authorization service is not.
//!
//! # Failure mode
//!
//! State is held in memory and scoped to a session. A Core restart loses it, which means a
//! session in flight loses its accumulated provenance — and therefore becomes *more*
//! restrictive, since actions with no provenance are treated as maximally influenced. The
//! failure direction is deliberate; see `docs/architecture/failure-modes.md` for the
//! shared-state option for multi-replica deployments.

use std::collections::HashMap;
use std::sync::Mutex;
use vigil_common::ids::{AgentId, AgentInstanceId, PrincipalId, SessionId, TenantId};
use vigil_common::{ContentHash, Result, Timestamp, VigilError};
use vigil_protocol::decision::Decision;
use vigil_remit::BudgetLedger;
use vigil_trace::SessionTrace;

/// What one session has done so far.
#[derive(Debug)]
pub struct SessionState {
    pub session_id: SessionId,
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub agent_instance_id: AgentInstanceId,
    pub principal_id: PrincipalId,
    pub started_at: Timestamp,

    /// The provenance graph for this session.
    pub trace: SessionTrace,
    /// Budget consumption.
    pub budget: BudgetLedger,

    /// The remit version pinned at session start.
    ///
    /// Pinned rather than looked up per action so that editing a remit mid-session cannot
    /// retroactively legitimize what the agent already did, nor silently widen it mid-task.
    pub remit_version: Option<String>,

    /// How many actions have been denied. Drives the escalating-probe rule.
    pub denial_count: u32,
    /// Distinct actions that were denied, so a *variant* retry is distinguishable from a
    /// straight repeat.
    denied_action_hashes: Vec<String>,
    /// Recent decisions, newest last, bounded.
    recent: Vec<(String, Decision)>,

    /// Set once a decision terminates the session. Every later action is refused.
    pub terminated: bool,
}

/// How many recent decisions to retain per session.
const RECENT_CAPACITY: usize = 64;

impl SessionState {
    pub fn new(
        session_id: SessionId,
        tenant_id: TenantId,
        agent_id: AgentId,
        agent_instance_id: AgentInstanceId,
        principal_id: PrincipalId,
        started_at: Timestamp,
    ) -> Self {
        Self {
            session_id,
            tenant_id,
            agent_id,
            agent_instance_id,
            principal_id,
            started_at,
            trace: SessionTrace::new(),
            budget: BudgetLedger::new(started_at),
            remit_version: None,
            denial_count: 0,
            denied_action_hashes: Vec::new(),
            recent: Vec::new(),
            terminated: false,
        }
    }

    /// Record the outcome of an action.
    pub fn record(&mut self, action_hash: &ContentHash, decision: Decision) {
        if !decision.permits_execution() {
            self.denial_count += 1;
            let hex = action_hash.hex().to_string();
            if !self.denied_action_hashes.contains(&hex) {
                self.denied_action_hashes.push(hex);
            }
        }
        if decision.terminates_session() {
            self.terminated = true;
        }
        self.recent.push((action_hash.hex().to_string(), decision));
        if self.recent.len() > RECENT_CAPACITY {
            self.recent.remove(0);
        }
    }

    /// Whether this exact action was denied before.
    pub fn was_denied_before(&self, action_hash: &ContentHash) -> bool {
        self.denied_action_hashes
            .iter()
            .any(|h| h == action_hash.hex())
    }

    /// How many *distinct* actions have been denied.
    ///
    /// A separate signal from [`Self::denial_count`]: five denials of the same action is a
    /// confused agent, while five denials of five different actions is an agent probing for
    /// a gap, which is the behaviour the escalating-probe rule targets.
    pub fn distinct_denials(&self) -> u32 {
        self.denied_action_hashes.len() as u32
    }

    pub fn action_count(&self) -> usize {
        self.recent.len()
    }
}

/// Every live session.
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, SessionState>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Run `f` against a session, creating it if this is its first action.
    ///
    /// Access goes through a closure so a caller cannot hold session state across an await
    /// point — that would either deadlock the store or, worse, let two actions in the same
    /// session evaluate against stale budget counts.
    pub fn with_session<T>(
        &self,
        key: &SessionKey,
        now: Timestamp,
        f: impl FnOnce(&mut SessionState) -> T,
    ) -> Result<T> {
        let mut sessions = self.sessions.lock().map_err(|_| VigilError::Unavailable {
            component: "session_store",
            reason: "lock poisoned; session state is unreliable".to_string(),
        })?;
        let state = sessions.entry(key.composite()).or_insert_with(|| {
            SessionState::new(
                key.session_id.clone(),
                key.tenant_id.clone(),
                key.agent_id.clone(),
                key.agent_instance_id.clone(),
                key.principal_id.clone(),
                now,
            )
        });
        Ok(f(state))
    }

    /// Read a session without creating one.
    pub fn inspect<T>(
        &self,
        key: &SessionKey,
        f: impl FnOnce(&SessionState) -> T,
    ) -> Result<Option<T>> {
        let sessions = self.sessions.lock().map_err(|_| VigilError::Unavailable {
            component: "session_store",
            reason: "lock poisoned".to_string(),
        })?;
        Ok(sessions.get(&key.composite()).map(f))
    }

    /// End a session and release its state, including any tracked secret values.
    pub fn end(&self, key: &SessionKey) -> Result<bool> {
        let mut sessions = self.sessions.lock().map_err(|_| VigilError::Unavailable {
            component: "session_store",
            reason: "lock poisoned".to_string(),
        })?;
        Ok(sessions.remove(&key.composite()).is_some())
    }

    /// Drop sessions that have exceeded a maximum lifetime, so a client that never calls
    /// `end` cannot grow the store without bound.
    pub fn evict_older_than(&self, cutoff: Timestamp) -> Result<usize> {
        let mut sessions = self.sessions.lock().map_err(|_| VigilError::Unavailable {
            component: "session_store",
            reason: "lock poisoned".to_string(),
        })?;
        let before = sessions.len();
        sessions.retain(|_, s| s.started_at > cutoff);
        Ok(before - sessions.len())
    }
}

/// The composite key identifying a session.
///
/// Tenant is part of the key, not merely a field on the value. Two tenants using the same
/// session id string must never collide into one state object — that would be a cross-tenant
/// provenance leak, and keying by session id alone makes it a one-line mistake away.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub agent_instance_id: AgentInstanceId,
    pub principal_id: PrincipalId,
}

impl SessionKey {
    fn composite(&self) -> String {
        // Identifier charset excludes `/`, so this delimiter cannot be forged from within
        // a component to make one tenant's key collide with another's.
        format!(
            "{}/{}/{}/{}",
            self.tenant_id, self.session_id, self.agent_id, self.agent_instance_id
        )
    }
}

impl From<&vigil_protocol::ActionRequest> for SessionKey {
    fn from(req: &vigil_protocol::ActionRequest) -> Self {
        Self {
            tenant_id: req.tenant_id.clone(),
            session_id: req.session_id.clone(),
            agent_id: req.agent_id.clone(),
            agent_instance_id: req.agent_instance_id.clone(),
            principal_id: req.principal.id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_common::{Clock, FixedClock};

    fn key(tenant: &str, session: &str) -> SessionKey {
        SessionKey {
            tenant_id: tenant.parse().unwrap(),
            session_id: session.parse().unwrap(),
            agent_id: "agent-a".parse().unwrap(),
            agent_instance_id: "inst-1".parse().unwrap(),
            principal_id: "user-1".parse().unwrap(),
        }
    }

    #[test]
    fn two_tenants_with_the_same_session_id_get_separate_state() {
        let store = SessionStore::new();
        let now = FixedClock::at_epoch().now();
        store
            .with_session(&key("acme", "s-1"), now, |s| {
                s.record(&ContentHash::sha256(b"a"), Decision::Deny);
            })
            .unwrap();
        let other = store
            .inspect(&key("other-corp", "s-1"), |s| s.denial_count)
            .unwrap();
        assert_eq!(other, None, "cross-tenant session state leaked");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn denials_are_counted_and_distinct_denials_tracked_separately() {
        let store = SessionStore::new();
        let now = FixedClock::at_epoch().now();
        let k = key("acme", "s-1");
        store
            .with_session(&k, now, |s| {
                s.record(&ContentHash::sha256(b"same"), Decision::Deny);
                s.record(&ContentHash::sha256(b"same"), Decision::Deny);
                s.record(&ContentHash::sha256(b"other"), Decision::Deny);
            })
            .unwrap();
        let (total, distinct) = store
            .inspect(&k, |s| (s.denial_count, s.distinct_denials()))
            .unwrap()
            .unwrap();
        assert_eq!(total, 3);
        assert_eq!(distinct, 2);
    }

    #[test]
    fn a_terminating_decision_marks_the_session() {
        let store = SessionStore::new();
        let now = FixedClock::at_epoch().now();
        let k = key("acme", "s-1");
        store
            .with_session(&k, now, |s| {
                s.record(&ContentHash::sha256(b"x"), Decision::TerminateSession);
            })
            .unwrap();
        assert!(store.inspect(&k, |s| s.terminated).unwrap().unwrap());
    }

    #[test]
    fn recent_history_is_bounded() {
        let store = SessionStore::new();
        let now = FixedClock::at_epoch().now();
        let k = key("acme", "s-1");
        store
            .with_session(&k, now, |s| {
                for i in 0..1000 {
                    s.record(
                        &ContentHash::sha256(format!("{i}").as_bytes()),
                        Decision::Allow,
                    );
                }
            })
            .unwrap();
        assert_eq!(
            store.inspect(&k, |s| s.action_count()).unwrap().unwrap(),
            RECENT_CAPACITY
        );
    }

    #[test]
    fn ending_a_session_releases_its_state() {
        let store = SessionStore::new();
        let now = FixedClock::at_epoch().now();
        let k = key("acme", "s-1");
        store.with_session(&k, now, |_| {}).unwrap();
        assert!(store.end(&k).unwrap());
        assert!(!store.end(&k).unwrap());
        assert!(store.is_empty());
    }

    #[test]
    fn abandoned_sessions_are_evicted() {
        let clock = FixedClock::at_epoch();
        let store = SessionStore::new();
        store
            .with_session(&key("acme", "s-1"), clock.now(), |_| {})
            .unwrap();
        clock.advance(chrono::Duration::hours(2));
        store
            .with_session(&key("acme", "s-2"), clock.now(), |_| {})
            .unwrap();
        let evicted = store
            .evict_older_than(clock.now() - chrono::Duration::hours(1))
            .unwrap();
        assert_eq!(evicted, 1);
        assert_eq!(store.len(), 1);
    }
}
