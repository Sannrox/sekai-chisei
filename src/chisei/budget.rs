use std::sync::Arc;

use crate::db::chisei_budget::{METRIC_TOKENS, scope_chain};
use crate::db::sekai::SekaiDb;

#[derive(Debug, Clone, PartialEq)]
pub enum PeriodType {
    Daily,
    Weekly,
    Monthly,
}

impl PeriodType {
    /// Parse untrusted period type inputs. Unknown values return `Err` so callers
    /// can surface a clear invalid-argument rejection.
    pub fn parse_strict(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "day" | "days" | "daily" => Ok(Self::Daily),
            "week" | "weeks" | "weekly" => Ok(Self::Weekly),
            "month" | "months" | "monthly" => Ok(Self::Monthly),
            value => Err(format!("unsupported period type '{value}'")),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "week" | "weeks" | "weekly" => Self::Weekly,
            "month" | "months" | "monthly" => Self::Monthly,
            "day" | "days" | "daily" => Self::Daily,
            _ => Self::Daily,
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Usage {
    pub user_id: String,
    pub tokens_used: i32,
    pub max_tokens: i32,
    pub period_type: PeriodType,
    pub period_start: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PressureLevel {
    None,
    Moderate,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetRouteBias {
    Capable,
    Cheap,
}

impl BudgetRouteBias {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capable => "capable",
            Self::Cheap => "cheap",
        }
    }
}

const CHEAP_BIAS_THRESHOLD_PERCENT: i64 = 70;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Token-budget enforcement over the hierarchical scope chain persisted in
/// `chisei_budget_limits`/`chisei_budget_usage` (see `db::chisei_budget`).
///
/// `user_id`/`subject` arguments here are scope ids: either a flat legacy
/// subject (e.g. an explicit `subject` field, chaining only through the
/// unset `global` root) or a `/`-joined hierarchical id such as
/// `project:p/agent:a/work_unit:w`, whose ancestors (`global`, `project:p`,
/// `project:p/agent:a`) are all checked and deducted together atomically.
pub struct BudgetTracker {
    db: Arc<SekaiDb>,
}

impl BudgetTracker {
    pub fn new(db: Arc<SekaiDb>) -> Self {
        Self { db }
    }

    pub fn set_limit(
        &self,
        scope_id: &str,
        max_tokens: i32,
        period: PeriodType,
    ) -> Result<(), String> {
        self.set_limit_with_metric(scope_id, METRIC_TOKENS, max_tokens, period)
    }

    pub fn set_limit_with_metric(
        &self,
        scope_id: &str,
        metric: &str,
        max_tokens: i32,
        period: PeriodType,
    ) -> Result<(), String> {
        self.db
            .budget_set_limit(scope_id, metric, max_tokens as i64, period.as_str())
            .inspect_err(
                |err| tracing::error!(error = %err, scope_id, "failed to persist budget limit"),
            )
    }

    pub fn check(&self, scope_id: &str, estimated: i32) -> Result<(), String> {
        self.check_with_metric(scope_id, estimated, METRIC_TOKENS)
    }

    pub fn check_with_metric(
        &self,
        scope_id: &str,
        estimated: i32,
        metric: &str,
    ) -> Result<(), String> {
        self.db
            .budget_check_chain(scope_id, metric, estimated as i64, now_ms())
    }

    /// Atomically checks budget headroom across the whole ancestor chain and
    /// reserves `estimated` at every level.
    pub fn check_and_reserve(&self, scope_id: &str, estimated: i32) -> Result<(), String> {
        self.check_and_reserve_with_metric(scope_id, estimated, METRIC_TOKENS)
    }

    pub fn check_and_reserve_with_metric(
        &self,
        scope_id: &str,
        estimated: i32,
        metric: &str,
    ) -> Result<(), String> {
        self.db
            .budget_check_and_reserve_chain(scope_id, metric, estimated as i64, now_ms())
    }

    /// Adjust reservation to actual usage after the call completes.
    pub fn adjust(&self, scope_id: &str, reserved: i32, actual: i32) {
        self.adjust_with_metric(scope_id, reserved, actual, METRIC_TOKENS)
    }

    pub fn adjust_with_metric(&self, scope_id: &str, reserved: i32, actual: i32, metric: &str) {
        let delta = actual as i64 - reserved as i64;
        if let Err(err) = self
            .db
            .budget_adjust_chain(scope_id, metric, delta, now_ms())
        {
            tracing::error!(error = %err, scope_id, "failed to adjust budget usage");
        }
    }

    pub fn record(&self, scope_id: &str, tokens: i32) {
        self.record_with_metric(scope_id, tokens, METRIC_TOKENS)
    }

    pub fn record_with_metric(&self, scope_id: &str, amount: i32, metric: &str) {
        if let Err(err) = self
            .db
            .budget_adjust_chain(scope_id, metric, amount as i64, now_ms())
        {
            tracing::error!(error = %err, scope_id, "failed to record budget usage");
        }
    }

    pub fn get_usage(&self, scope_id: &str) -> Usage {
        self.get_usage_with_metric(scope_id, METRIC_TOKENS)
    }

    pub fn get_usage_with_metric(&self, scope_id: &str, metric: &str) -> Usage {
        let (used, max, period_type) = self
            .db
            .budget_usage(scope_id, metric, now_ms())
            .unwrap_or((0, 0, "daily".to_string()));
        Usage {
            user_id: scope_id.into(),
            tokens_used: used as i32,
            max_tokens: max as i32,
            period_type: PeriodType::parse(&period_type),
            period_start: 0,
        }
    }

    /// Maps projected token-budget pressure to an advisory routing bias. The
    /// most constrained bounded scope in the hierarchy wins. Unknown, primary,
    /// and reasoning work stay capable by default; request-count quotas never
    /// influence model selection.
    pub fn route_bias(
        &self,
        scope_id: &str,
        estimated: i32,
        metric: &str,
        task_class: &str,
    ) -> BudgetRouteBias {
        if metric != METRIC_TOKENS
            || !crate::chisei::model_routing::is_cheap_eligible_task_class(task_class)
        {
            return BudgetRouteBias::Capable;
        }

        let projected = i64::from(estimated.max(0));
        let pressured = scope_chain(scope_id).into_iter().any(|scope| {
            let usage = self.get_usage_with_metric(&scope, metric);
            let limit = i64::from(usage.max_tokens);
            limit > 0
                && (i64::from(usage.tokens_used).max(0) + projected) * 100
                    >= limit * CHEAP_BIAS_THRESHOLD_PERCENT
        });
        if pressured {
            BudgetRouteBias::Cheap
        } else {
            BudgetRouteBias::Capable
        }
    }

    pub fn namespace_pressure(&self, namespace: &str) -> PressureLevel {
        let level = self
            .db
            .budget_namespace_pressure(namespace, METRIC_TOKENS, now_ms())
            .unwrap_or(0);
        match level {
            2 => PressureLevel::Critical,
            1 => PressureLevel::Moderate,
            _ => PressureLevel::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> BudgetTracker {
        BudgetTracker::new(Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    #[test]
    fn test_budget_check_and_record() {
        let t = tracker();
        t.set_limit("alice", 1000, PeriodType::Daily).unwrap();
        assert!(t.check("alice", 500).is_ok());
        t.record("alice", 800);
        assert!(t.check("alice", 300).is_err());
        assert!(t.check("alice", 100).is_ok()); // 800+100 < 1000... wait no 800+100=900 <= 1000
    }

    #[test]
    fn test_no_limit_allows_all() {
        let t = tracker();
        assert!(t.check("bob", 999999).is_ok());
    }

    #[test]
    fn test_pressure() {
        let t = tracker();
        t.set_limit("ns1:alice", 100, PeriodType::Daily).unwrap();
        t.record("ns1:alice", 75);
        assert_eq!(t.namespace_pressure("ns1"), PressureLevel::Moderate);
        t.record("ns1:alice", 20);
        assert_eq!(t.namespace_pressure("ns1"), PressureLevel::Critical);
    }

    #[test]
    fn budget_bias_downgrades_only_eligible_work_under_chain_pressure() {
        let t = tracker();
        t.set_limit("project:p", 100, PeriodType::Daily).unwrap();
        t.record("project:p/agent:a", 65);

        assert_eq!(
            t.route_bias("project:p/agent:a", 5, METRIC_TOKENS, "background"),
            BudgetRouteBias::Cheap
        );
        assert_eq!(
            t.route_bias("project:p/agent:a", 5, METRIC_TOKENS, "primary"),
            BudgetRouteBias::Capable
        );
        assert_eq!(
            t.route_bias("project:p/agent:a", 5, METRIC_TOKENS, "reasoning"),
            BudgetRouteBias::Capable
        );
        assert_eq!(
            t.route_bias("project:p/agent:a", 5, METRIC_TOKENS, "unknown"),
            BudgetRouteBias::Capable
        );
    }

    #[test]
    fn budget_bias_stays_capable_without_pressure_or_for_non_token_quotas() {
        let t = tracker();
        t.set_limit("project:p", 100, PeriodType::Daily).unwrap();
        t.record("project:p", 10);
        assert_eq!(
            t.route_bias("project:p", 5, METRIC_TOKENS, "bulk"),
            BudgetRouteBias::Capable
        );
        assert_eq!(
            t.route_bias("project:p", 100, "requests", "bulk"),
            BudgetRouteBias::Capable
        );
    }

    #[test]
    fn parent_cap_rejects_child_within_its_own_limit() {
        let t = tracker();
        // Project-level pool of 100 shared across agents; agent's own cap is
        // generous (500) but the project ancestor is nearly exhausted.
        t.set_limit("project:p", 100, PeriodType::Daily).unwrap();
        t.set_limit("project:p/agent:a", 500, PeriodType::Daily)
            .unwrap();
        t.record("project:p/agent:a", 90);
        // Agent-level check alone would allow (90+20=110 <= 500) but the
        // project ancestor (90+20=110 > 100) must reject it.
        assert!(t.check_and_reserve("project:p/agent:a", 20).is_err());
        // A smaller request that fits under both levels succeeds.
        assert!(t.check_and_reserve("project:p/agent:a", 5).is_ok());
    }

    #[test]
    fn checks_and_records_against_flat_agent_scope() {
        let t = tracker();
        t.set_limit("agent:codex-app", 100, PeriodType::Daily)
            .unwrap();
        t.set_limit("project:p", 500, PeriodType::Daily).unwrap();
        t.record("project:p/agent:codex-app", 90);
        assert_eq!(t.get_usage("agent:codex-app").tokens_used, 90);
        assert_eq!(t.get_usage("project:p").tokens_used, 90);
        assert!(t.check("project:p/agent:codex-app", 5).is_ok());
        assert!(
            t.check_and_reserve("project:p/agent:codex-app", 11)
                .is_err()
        );
    }

    #[test]
    fn chain_deducts_at_every_level() {
        let t = tracker();
        t.set_limit("project:p", 1000, PeriodType::Daily).unwrap();
        t.set_limit("project:p/agent:a", 1000, PeriodType::Daily)
            .unwrap();
        t.check_and_reserve("project:p/agent:a/work_unit:w", 40)
            .unwrap();
        assert_eq!(t.get_usage("project:p").tokens_used, 40);
        assert_eq!(t.get_usage("project:p/agent:a").tokens_used, 40);
        assert_eq!(t.get_usage("project:p/agent:a/work_unit:w").tokens_used, 40);
    }

    #[test]
    fn parse_strict_period_type_accepts_aliases_and_rejects_unknown() {
        assert!(PeriodType::parse_strict("day").is_ok());
        assert!(PeriodType::parse_strict("Week").is_ok());
        assert!(PeriodType::parse_strict("monthly").is_ok());
        assert!(PeriodType::parse_strict("months").is_ok());
        assert!(PeriodType::parse_strict("").is_ok());
        assert!(PeriodType::parse_strict("fiscal").is_err());
    }

    #[test]
    fn parse_period_type_defaults_untrusted_to_daily() {
        assert!(matches!(PeriodType::parse("fiscal"), PeriodType::Daily));
        assert!(matches!(PeriodType::parse("yearly"), PeriodType::Daily));
    }

    #[test]
    fn later_ancestor_limit_sees_prior_unbounded_usage() {
        let t = tracker();
        // No limit anywhere yet: usage still accrues at every level.
        t.record("project:p/agent:a", 30);
        // Now cap the project after the fact — it should already see the 30
        // recorded while unbounded, and reject a request that would exceed it.
        t.set_limit("project:p", 40, PeriodType::Daily).unwrap();
        assert!(t.check_and_reserve("project:p/agent:a", 20).is_err());
        assert!(t.check_and_reserve("project:p/agent:a", 5).is_ok());
    }

    #[test]
    fn concurrent_reservations_never_over_admit_shared_parent() {
        use std::thread;
        let t = Arc::new(tracker());
        t.set_limit("project:p", 100, PeriodType::Daily).unwrap();
        let mut handles = Vec::new();
        for i in 0..20 {
            let t = t.clone();
            handles.push(thread::spawn(move || {
                t.check_and_reserve(&format!("project:p/agent:a{i}"), 10)
                    .is_ok()
            }));
        }
        let admitted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(admitted, 10);
        assert_eq!(t.get_usage("project:p").tokens_used, 100);
    }
}
