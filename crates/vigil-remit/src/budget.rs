//! Execution budgets: denial-of-wallet, runaway loops and resource exhaustion.
//!
//! # Why
//!
//! An agent stuck in a retry loop is an availability and cost incident; an agent driven into
//! one deliberately is an attack (spec §36). Budgets are also the backstop for goal hijack:
//! an injection that redirects an agent usually costs *more* actions than the legitimate
//! task, so a tight budget bounds the blast radius even when detection misses.
//!
//! # What
//!
//! A per-session ledger charged before each action. Charges are checked against the remit's
//! limits and return an explicit verdict; there is no "warn and continue" path.
//!
//! # Failure mode
//!
//! Exhaustion produces [`BudgetVerdict::Exhausted`], which the pipeline turns into a denial
//! carrying the specific budget's reason code. A ledger that cannot be read is treated as
//! exhausted, because an uncounted action is an unbounded one.

use std::collections::{HashMap, HashSet};
use vigil_common::{ContentHash, Timestamp};
use vigil_protocol::reason::ReasonCode;

use crate::schema::Limits;

/// The outcome of charging a budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetVerdict {
    /// Within budget.
    Within,
    /// A budget is exhausted; the reason code names which.
    Exhausted(ReasonCode),
}

impl BudgetVerdict {
    pub fn permits(&self) -> bool {
        matches!(self, Self::Within)
    }
}

/// A point-in-time view of a session's consumption, for the console and for alerts.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetSnapshot {
    pub tool_calls: u32,
    pub model_calls: u32,
    pub elapsed_minutes: i64,
    pub external_domains: u32,
    pub cost_usd: f64,
    pub max_repeat_count: u32,
}

/// Per-session consumption.
#[derive(Debug)]
pub struct BudgetLedger {
    started_at: Timestamp,
    tool_calls: u32,
    model_calls: u32,
    cost_usd: f64,
    external_domains: HashSet<String>,
    /// How many times each distinct action has been attempted, keyed by action hash.
    ///
    /// Keyed by the *material* hash, so an agent that retries the same call with a
    /// reordered argument map still counts as a repeat.
    action_counts: HashMap<String, u32>,
}

impl BudgetLedger {
    pub fn new(started_at: Timestamp) -> Self {
        Self {
            started_at,
            tool_calls: 0,
            model_calls: 0,
            cost_usd: 0.0,
            external_domains: HashSet::new(),
            action_counts: HashMap::new(),
        }
    }

    pub fn snapshot(&self, now: Timestamp) -> BudgetSnapshot {
        BudgetSnapshot {
            tool_calls: self.tool_calls,
            model_calls: self.model_calls,
            elapsed_minutes: (now - self.started_at).num_minutes().max(0),
            external_domains: self.external_domains.len() as u32,
            cost_usd: self.cost_usd,
            max_repeat_count: self.action_counts.values().copied().max().unwrap_or(0),
        }
    }

    /// Check every budget without charging.
    ///
    /// Separating check from charge matters: an action that is going to be denied for another
    /// reason should not consume budget, or a blocked agent would exhaust its own session and
    /// mask the original denial reason.
    pub fn check(&self, limits: &Limits, now: Timestamp) -> BudgetVerdict {
        if self.tool_calls >= limits.max_tool_calls {
            return BudgetVerdict::Exhausted(ReasonCode::ToolCallBudgetExceeded);
        }
        if self.model_calls >= limits.max_model_calls {
            return BudgetVerdict::Exhausted(ReasonCode::ModelCallBudgetExceeded);
        }
        if (now - self.started_at).num_minutes() >= limits.max_session_minutes as i64 {
            return BudgetVerdict::Exhausted(ReasonCode::WallClockBudgetExceeded);
        }
        if self.cost_usd >= limits.max_cost_usd {
            return BudgetVerdict::Exhausted(ReasonCode::CostBudgetExceeded);
        }
        BudgetVerdict::Within
    }

    /// Check the loop and domain budgets for a specific action.
    pub fn check_action(
        &self,
        limits: &Limits,
        action_hash: &ContentHash,
        destination: Option<&str>,
    ) -> BudgetVerdict {
        let repeats = self
            .action_counts
            .get(action_hash.hex())
            .copied()
            .unwrap_or(0);
        if repeats >= limits.max_repeated_actions {
            return BudgetVerdict::Exhausted(ReasonCode::LoopDetected);
        }
        if let Some(host) = destination {
            let host = host.to_ascii_lowercase();
            if !self.external_domains.contains(&host)
                && self.external_domains.len() as u32 >= limits.max_external_domains
            {
                return BudgetVerdict::Exhausted(ReasonCode::RateLimitExceeded);
            }
        }
        BudgetVerdict::Within
    }

    /// Record consumption for an action that is going ahead.
    pub fn charge(
        &mut self,
        action_kind: &str,
        action_hash: &ContentHash,
        destination: Option<&str>,
        estimated_cost_usd: f64,
    ) {
        match action_kind {
            "model_call" => self.model_calls += 1,
            _ => self.tool_calls += 1,
        }
        if estimated_cost_usd.is_finite() && estimated_cost_usd > 0.0 {
            self.cost_usd += estimated_cost_usd;
        }
        if let Some(host) = destination {
            self.external_domains.insert(host.to_ascii_lowercase());
        }
        *self
            .action_counts
            .entry(action_hash.hex().to_string())
            .or_insert(0) += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_common::{Clock, FixedClock};

    fn hash(s: &str) -> ContentHash {
        ContentHash::sha256(s.as_bytes())
    }

    fn limits() -> Limits {
        Limits {
            max_tool_calls: 3,
            max_model_calls: 2,
            max_session_minutes: 10,
            max_external_domains: 2,
            max_cost_usd: 1.0,
            max_delegation_depth: 2,
            max_repeated_actions: 2,
        }
    }

    #[test]
    fn tool_and_model_budgets_are_counted_separately() {
        let clock = FixedClock::at_epoch();
        let mut ledger = BudgetLedger::new(clock.now());
        for _ in 0..3 {
            assert!(ledger.check(&limits(), clock.now()).permits());
            ledger.charge("tool_call", &hash("a"), None, 0.0);
        }
        assert_eq!(
            ledger.check(&limits(), clock.now()),
            BudgetVerdict::Exhausted(ReasonCode::ToolCallBudgetExceeded)
        );
        // Model calls have their own counter and are unaffected.
        assert_eq!(ledger.snapshot(clock.now()).model_calls, 0);
    }

    #[test]
    fn the_wall_clock_budget_ends_a_long_session() {
        let clock = FixedClock::at_epoch();
        let ledger = BudgetLedger::new(clock.now());
        assert!(ledger.check(&limits(), clock.now()).permits());
        clock.advance(chrono::Duration::minutes(11));
        assert_eq!(
            ledger.check(&limits(), clock.now()),
            BudgetVerdict::Exhausted(ReasonCode::WallClockBudgetExceeded)
        );
    }

    #[test]
    fn repeating_one_action_is_detected_as_a_loop() {
        let clock = FixedClock::at_epoch();
        let mut ledger = BudgetLedger::new(clock.now());
        let h = hash("same-action");
        for _ in 0..2 {
            assert!(ledger.check_action(&limits(), &h, None).permits());
            ledger.charge("tool_call", &h, None, 0.0);
        }
        assert_eq!(
            ledger.check_action(&limits(), &h, None),
            BudgetVerdict::Exhausted(ReasonCode::LoopDetected)
        );
        // A *different* action is unaffected by the repeated one.
        assert!(ledger
            .check_action(&limits(), &hash("other"), None)
            .permits());
    }

    #[test]
    fn the_external_domain_budget_caps_fan_out_but_not_repeat_visits() {
        let clock = FixedClock::at_epoch();
        let mut ledger = BudgetLedger::new(clock.now());
        for host in ["a.example", "b.example"] {
            assert!(ledger
                .check_action(&limits(), &hash(host), Some(host))
                .permits());
            ledger.charge("tool_call", &hash(host), Some(host), 0.0);
        }
        // A third distinct domain exceeds the budget.
        assert!(!ledger
            .check_action(&limits(), &hash("c"), Some("c.example"))
            .permits());
        // Returning to an already-visited domain does not.
        assert!(ledger
            .check_action(&limits(), &hash("a2"), Some("a.example"))
            .permits());
    }

    #[test]
    fn cost_accumulates_and_stops_the_session() {
        // Call-count limits are raised so cost is the binding constraint; `check` reports
        // the first exhausted budget in a fixed order, and this test is about cost.
        let limits = Limits {
            max_model_calls: 100,
            ..limits()
        };
        let clock = FixedClock::at_epoch();
        let mut ledger = BudgetLedger::new(clock.now());
        ledger.charge("model_call", &hash("m"), None, 0.6);
        assert!(ledger.check(&limits, clock.now()).permits());
        ledger.charge("model_call", &hash("m2"), None, 0.6);
        assert_eq!(
            ledger.check(&limits, clock.now()),
            BudgetVerdict::Exhausted(ReasonCode::CostBudgetExceeded)
        );
    }

    #[test]
    fn budget_check_order_is_fixed_so_reason_codes_are_reproducible() {
        // When several budgets are exhausted at once, the reported one must not depend on
        // hash iteration order — an audit record that varies between replicas is not evidence.
        let clock = FixedClock::at_epoch();
        let mut ledger = BudgetLedger::new(clock.now());
        for i in 0..10 {
            ledger.charge("tool_call", &hash(&format!("a{i}")), None, 5.0);
            ledger.charge("model_call", &hash(&format!("m{i}")), None, 5.0);
        }
        clock.advance(chrono::Duration::minutes(60));
        let first = ledger.check(&limits(), clock.now());
        for _ in 0..50 {
            assert_eq!(ledger.check(&limits(), clock.now()), first);
        }
    }

    #[test]
    fn a_nonsense_cost_estimate_cannot_corrupt_the_ledger() {
        let clock = FixedClock::at_epoch();
        let mut ledger = BudgetLedger::new(clock.now());
        ledger.charge("model_call", &hash("m"), None, f64::NAN);
        ledger.charge("model_call", &hash("m"), None, f64::INFINITY);
        ledger.charge("model_call", &hash("m"), None, -100.0);
        assert_eq!(ledger.snapshot(clock.now()).cost_usd, 0.0);
    }

    #[test]
    fn checking_does_not_consume_budget() {
        let clock = FixedClock::at_epoch();
        let ledger = BudgetLedger::new(clock.now());
        for _ in 0..100 {
            assert!(ledger.check(&limits(), clock.now()).permits());
        }
        assert_eq!(ledger.snapshot(clock.now()).tool_calls, 0);
    }
}
