use chrono::Datelike;

/// Default metric for token-based budgets. Request-rate quotas reuse this
/// table with `METRIC_REQUESTS`.
pub const METRIC_TOKENS: &str = "tokens";
pub const METRIC_REQUESTS: &str = "requests";

/// Durable result of an audited budget capacity transfer (#294).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetTransferRecord {
    pub transfer_id: String,
    pub metric: String,
    pub pool_id: String,
    pub from_scope_id: String,
    pub to_scope_id: String,
    pub amount: i64,
    pub actor: String,
    pub status: String,
    pub reason: String,
    pub created_at: i64,
}

/// Metrics a budget usage read reports for each scope level.
pub const BUDGET_METRICS: [&str; 2] = [METRIC_TOKENS, METRIC_REQUESTS];

/// Period a scope without a limit charges its usage to. Enforcement uses the
/// same default when it records usage at an unbounded level.
pub const UNLIMITED_PERIOD_TYPE: &str = "daily";

/// One scope level's usage for one metric in the current period of its limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetScopeUsage {
    pub scope_id: String,
    pub metric: String,
    pub period_type: String,
    /// Start of the current period, Unix milliseconds UTC.
    pub period_start: i64,
    pub used: i64,
    /// `None` when the scope has no limit for the metric. A stored limit of
    /// zero is a hard stop, not unlimited.
    pub limit: Option<i64>,
    /// True when `limit` is the parent scope's work-unit default.
    pub from_work_unit_default: bool,
}

impl BudgetScopeUsage {
    /// Headroom left in the period, floored at zero. `None` when unlimited.
    pub fn remaining(&self) -> Option<i64> {
        self.limit.map(|limit| (limit - self.used).max(0))
    }
}

/// Root of every budget scope chain. A bare `global` limit applies to every
/// scope in the system; leaving it unset preserves today's "no limit = allow"
/// behavior at that level.
pub const GLOBAL_SCOPE: &str = "global";

/// Builds the root-to-leaf chain of ancestor scope ids for `scope_id`.
///
/// Scope ids are constructed (not stored) as `/`-joined segments, e.g.
/// `project:p/agent:a/work_unit:w`. The chain for that id is
/// `["global", "project:p", "project:p/agent:a", "agent:a", "project:p/agent:a/work_unit:w"]`.
/// A flat, single-segment scope id (e.g. a legacy explicit `subject`) chains
/// through `global` only. For `agent` segments we additionally append a flat
/// `agent:<id>` scope so both scoped and flat `agent:` limits apply.
pub fn scope_chain(scope_id: &str) -> Vec<String> {
    if scope_id.is_empty() || scope_id == GLOBAL_SCOPE {
        return vec![GLOBAL_SCOPE.to_string()];
    }
    let mut chain = vec![GLOBAL_SCOPE.to_string()];
    let mut acc = String::new();
    for segment in scope_id.split('/') {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(segment);
        if !chain.contains(&acc) {
            chain.push(acc.clone());
        }
        if let Some((kind, _)) = segment.split_once(':')
            && kind == "agent"
        {
            let flat_scope = segment.to_string();
            if !chain.contains(&flat_scope) {
                chain.push(flat_scope);
            }
        }
    }
    chain
}

/// The parent of `scope_id` in the chain built by [`scope_chain`].
pub fn parent_scope_id(scope_id: &str) -> String {
    if scope_id.is_empty() || scope_id == GLOBAL_SCOPE {
        return String::new();
    }
    match scope_id.rsplit_once('/') {
        Some((parent, _)) => parent.to_string(),
        None => GLOBAL_SCOPE.to_string(),
    }
}

/// The scope whose work-unit default governs `scope_id` when `scope_id` has
/// no limit of its own (#1862): its parent, when its leaf is a `work_unit:`
/// segment. Each work unit counts its own usage against the default.
pub fn work_unit_default_scope(scope_id: &str) -> Option<&str> {
    let (parent, leaf) = scope_id.rsplit_once('/')?;
    leaf.starts_with("work_unit:").then_some(parent)
}

pub fn period_start_ms(period_type: &str, now_ms: i64) -> i64 {
    let now = chrono::DateTime::from_timestamp_millis(now_ms).unwrap_or_default();
    let date = now.date_naive();
    let start_date = match period_type {
        "weekly" => {
            let days_from_monday = date.weekday().num_days_from_monday() as i64;
            date - chrono::Duration::days(days_from_monday)
        }
        "monthly" => date.with_day(1).unwrap_or(date),
        _ => date,
    };
    start_date
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc()
        .timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn scope_chain_includes_flat_agent_scope() {
        let chain = scope_chain("project:sekai/agent:codex-app/work_unit:wu-1");
        assert_eq!(
            chain,
            vec![
                "global".to_string(),
                "project:sekai".to_string(),
                "project:sekai/agent:codex-app".to_string(),
                "agent:codex-app".to_string(),
                "project:sekai/agent:codex-app/work_unit:wu-1".to_string(),
            ]
        );
    }

    #[test]
    fn monthly_period_starts_at_first_of_month() {
        let now_ms = chrono::Utc
            .with_ymd_and_hms(2026, 6, 30, 12, 30, 0)
            .unwrap()
            .timestamp_millis();
        let actual = period_start_ms("monthly", now_ms);
        let expected = chrono::Utc
            .with_ymd_and_hms(2026, 6, 1, 0, 0, 0)
            .unwrap()
            .timestamp_millis();
        assert_eq!(actual, expected);
    }
}
