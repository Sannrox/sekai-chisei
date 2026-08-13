//! Shared budget identity helpers for Gateway decide and receipt admission.
//!
//! These are private implementation used by already-deep modules. They are not a
//! new ordered lifecycle.

use super::*;

pub(super) fn budget_metric(metric: &str) -> Result<&'static str, Status> {
    if metric.trim().eq_ignore_ascii_case(METRIC_REQUESTS) {
        Ok(METRIC_REQUESTS)
    } else if metric.trim().is_empty() || metric.trim().eq_ignore_ascii_case(METRIC_TOKENS) {
        Ok(METRIC_TOKENS)
    } else {
        Err(Status::invalid_argument(
            "unsupported budget metric; use tokens or requests",
        ))
    }
}

/// Builds the budget scope id for a request. An explicit `subject` bypasses
/// hierarchy construction entirely (kept for legacy/direct callers and any
/// caller that wants a flat, non-nested scope) and chains only through the
/// unset `global` root. Otherwise the scope is built from whichever of
/// project/agent/work_unit are present, in that nesting order, so that
/// Canonical gateway decisions and `RecordUsage` walk and deduct the whole ancestor chain
/// (project -> agent -> work_unit) atomically — see `db::chisei_budget`.
pub(super) fn budget_subject(
    subject: &str,
    project: &str,
    agent: &str,
    key_id: &str,
    work_unit: &str,
    legacy_user_id: &str,
) -> Result<String, Status> {
    if !subject.trim().is_empty() {
        return Ok(subject.trim().to_string());
    }
    let mut segments = Vec::new();
    if !project.trim().is_empty() {
        segments.push(format!("project:{}", project.trim()));
    }
    if !agent.trim().is_empty() {
        segments.push(format!("agent:{}", agent.trim()));
    }
    if !work_unit.trim().is_empty() {
        segments.push(format!("work_unit:{}", work_unit.trim()));
    }
    if !segments.is_empty() {
        return Ok(segments.join("/"));
    }
    if !key_id.trim().is_empty() {
        return Ok(format!("gateway_key:{}", key_id.trim()));
    }
    if !legacy_user_id.trim().is_empty() {
        return Ok(legacy_user_id.trim().to_string());
    }
    Err(Status::invalid_argument("budget subject required"))
}
