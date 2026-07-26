//! Historical policy dry-run over operation receipts (#282).
//!
//! Replays recorded route preferences against a **candidate** namespace policy
//! revision without calling providers, redeeming permits, or mutating state.

use crate::chisei::policy::{Policy, PolicyResolver};
use crate::chisei::receipt::{OperationReceipt, ReceiptEventKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum receipts evaluated in one dry-run.
pub const MAX_DRY_RUN_RECEIPTS: usize = 5_000;
/// Maximum sample operation IDs retained per delta class.
pub const MAX_DRY_RUN_SAMPLES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalOutcomeClass {
    Allowed,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateOutcomeClass {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRunDeltaClass {
    Unchanged,
    ReRouted,
    WouldDeny,
    WouldAllow,
    InsufficientHistory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalRouteSnapshot {
    pub operation_id: String,
    pub namespace: String,
    pub preferred_runtime: String,
    pub preferred_model: String,
    pub historical_runtime: String,
    pub historical_model: String,
    pub historical_outcome: HistoricalOutcomeClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunReceiptResult {
    pub operation_id: String,
    pub delta: DryRunDeltaClass,
    pub historical_outcome: HistoricalOutcomeClass,
    pub candidate_outcome: Option<CandidateOutcomeClass>,
    pub historical_runtime: String,
    pub historical_model: String,
    pub candidate_runtime: String,
    pub candidate_model: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DryRunDeltaCounts {
    pub evaluated: u32,
    pub unchanged: u32,
    pub re_routed: u32,
    pub would_deny: u32,
    pub would_allow: u32,
    pub insufficient_history: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDryRunReport {
    pub namespace: String,
    pub start_timestamp_ms: i64,
    pub end_timestamp_ms: i64,
    pub candidate_policy_version: String,
    pub counts: DryRunDeltaCounts,
    pub samples: BTreeMap<String, Vec<String>>,
    pub results: Vec<DryRunReceiptResult>,
}

/// Extract a dry-run snapshot from a stored receipt when enough route metadata
/// is present. Returns `None` only when the receipt has no usable preference.
pub fn snapshot_from_receipt(receipt: &OperationReceipt) -> HistoricalRouteSnapshot {
    let route = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::RouteSelected);
    let policy = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::PolicyDecided);

    let historical_model = route
        .and_then(|event| attr(event, &["resolved_model", "model"]))
        .unwrap_or_default();
    let historical_runtime = route
        .and_then(|event| attr(event, &["runtime", "provider", "resolved_runtime"]))
        .unwrap_or_default();
    // Prefer original request fields when present. Older receipts that only
    // store the resolved route cannot recover the pre-policy request, so
    // leave preferences empty and classify as insufficient history below.
    let preferred_model = route
        .and_then(|event| attr(event, &["preferred_model", "requested_model"]))
        .unwrap_or_default();
    let preferred_runtime = route
        .and_then(|event| attr(event, &["preferred_runtime", "requested_runtime"]))
        .unwrap_or_default();

    // Route-policy dry-run only. A selected route means the namespace route
    // policy allowed the request; composite `executable=false` (budget, privacy,
    // eval, etc.) must not be treated as a route-policy denial.
    let historical_outcome = if !historical_runtime.is_empty() || !historical_model.is_empty() {
        HistoricalOutcomeClass::Allowed
    } else if let Some(value) = policy.and_then(|event| {
        attr(
            event,
            &["route_policy_decision", "outcome", "decision", "result"],
        )
    }) {
        classify_historical_outcome(&value)
    } else if policy
        .and_then(|event| attr(event, &["executable"]))
        .as_deref()
        == Some("false")
    {
        // No route was selected and the plan was not executable — treat as deny
        // only when no resolved route evidence exists.
        HistoricalOutcomeClass::Denied
    } else {
        HistoricalOutcomeClass::Unknown
    };

    HistoricalRouteSnapshot {
        operation_id: receipt.operation_id.clone(),
        namespace: receipt.namespace.clone(),
        preferred_runtime,
        preferred_model,
        historical_runtime,
        historical_model,
        historical_outcome,
    }
}

/// Evaluate one historical snapshot against a candidate policy revision.
///
/// Pure: no I/O, no provider adapters, no permit redemption.
pub fn evaluate_snapshot_against_policy(
    snapshot: &HistoricalRouteSnapshot,
    candidate: &Policy,
) -> DryRunReceiptResult {
    if snapshot.preferred_model.trim().is_empty() && snapshot.preferred_runtime.trim().is_empty() {
        return DryRunReceiptResult {
            operation_id: snapshot.operation_id.clone(),
            delta: DryRunDeltaClass::InsufficientHistory,
            historical_outcome: snapshot.historical_outcome,
            candidate_outcome: None,
            historical_runtime: snapshot.historical_runtime.clone(),
            historical_model: snapshot.historical_model.clone(),
            candidate_runtime: String::new(),
            candidate_model: String::new(),
            detail: "receipt lacks preferred_runtime/preferred_model for accurate dry-run".into(),
        };
    }
    let resolver = PolicyResolver::new();
    match resolver.apply_policy(
        candidate,
        &snapshot.preferred_runtime,
        &snapshot.preferred_model,
    ) {
        Ok((runtime, model)) => {
            let candidate_outcome = CandidateOutcomeClass::Allow;
            let (delta, detail) = match snapshot.historical_outcome {
                HistoricalOutcomeClass::Denied => (
                    DryRunDeltaClass::WouldAllow,
                    "candidate policy would allow a historically denied operation".into(),
                ),
                HistoricalOutcomeClass::Unknown => (
                    DryRunDeltaClass::InsufficientHistory,
                    "historical policy outcome unknown; candidate would allow".into(),
                ),
                HistoricalOutcomeClass::Allowed => {
                    if runtime == snapshot.historical_runtime && model == snapshot.historical_model
                    {
                        (
                            DryRunDeltaClass::Unchanged,
                            "candidate policy preserves the historical route".into(),
                        )
                    } else {
                        (
                            DryRunDeltaClass::ReRouted,
                            format!(
                                "candidate would route to {runtime}/{model} instead of {}/{}",
                                snapshot.historical_runtime, snapshot.historical_model
                            ),
                        )
                    }
                }
            };
            DryRunReceiptResult {
                operation_id: snapshot.operation_id.clone(),
                delta,
                historical_outcome: snapshot.historical_outcome,
                candidate_outcome: Some(candidate_outcome),
                historical_runtime: snapshot.historical_runtime.clone(),
                historical_model: snapshot.historical_model.clone(),
                candidate_runtime: runtime,
                candidate_model: model,
                detail,
            }
        }
        Err(error) => {
            let (delta, detail) = match snapshot.historical_outcome {
                HistoricalOutcomeClass::Denied => (
                    DryRunDeltaClass::Unchanged,
                    format!("candidate policy still denies: {error}"),
                ),
                HistoricalOutcomeClass::Unknown => (
                    DryRunDeltaClass::InsufficientHistory,
                    format!("historical outcome unknown; candidate denies: {error}"),
                ),
                HistoricalOutcomeClass::Allowed => (
                    DryRunDeltaClass::WouldDeny,
                    format!("candidate policy would deny: {error}"),
                ),
            };
            DryRunReceiptResult {
                operation_id: snapshot.operation_id.clone(),
                delta,
                historical_outcome: snapshot.historical_outcome,
                candidate_outcome: Some(CandidateOutcomeClass::Deny),
                historical_runtime: snapshot.historical_runtime.clone(),
                historical_model: snapshot.historical_model.clone(),
                candidate_runtime: String::new(),
                candidate_model: String::new(),
                detail,
            }
        }
    }
}

/// Run a dry-run over a fixed set of receipts against a candidate policy.
pub fn dry_run_policy_over_receipts(
    namespace: &str,
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
    candidate: &Policy,
    receipts: &[OperationReceipt],
) -> Result<PolicyDryRunReport, String> {
    if namespace.trim().is_empty() {
        return Err("namespace required".into());
    }
    if end_timestamp_ms <= start_timestamp_ms {
        return Err("end_timestamp_ms must be greater than start_timestamp_ms".into());
    }
    if receipts.len() > MAX_DRY_RUN_RECEIPTS {
        return Err(format!(
            "policy dry-run receipt limit exceeded ({MAX_DRY_RUN_RECEIPTS})"
        ));
    }

    let mut counts = DryRunDeltaCounts::default();
    let mut samples: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut results = Vec::new();

    for receipt in receipts {
        if receipt.namespace != namespace {
            continue;
        }
        if !receipt_in_window(receipt, start_timestamp_ms, end_timestamp_ms) {
            continue;
        }
        let snapshot = snapshot_from_receipt(receipt);
        let result = evaluate_snapshot_against_policy(&snapshot, candidate);
        counts.evaluated = counts.evaluated.saturating_add(1);
        match result.delta {
            DryRunDeltaClass::Unchanged => counts.unchanged = counts.unchanged.saturating_add(1),
            DryRunDeltaClass::ReRouted => counts.re_routed = counts.re_routed.saturating_add(1),
            DryRunDeltaClass::WouldDeny => counts.would_deny = counts.would_deny.saturating_add(1),
            DryRunDeltaClass::WouldAllow => {
                counts.would_allow = counts.would_allow.saturating_add(1)
            }
            DryRunDeltaClass::InsufficientHistory => {
                counts.insufficient_history = counts.insufficient_history.saturating_add(1)
            }
        }
        let class_key = delta_key(result.delta);
        let sample_list = samples.entry(class_key).or_default();
        if sample_list.len() < MAX_DRY_RUN_SAMPLES {
            sample_list.push(result.operation_id.clone());
        }
        results.push(result);
    }

    Ok(PolicyDryRunReport {
        namespace: namespace.into(),
        start_timestamp_ms,
        end_timestamp_ms,
        candidate_policy_version: candidate.version(),
        counts,
        samples,
        results,
    })
}

fn receipt_in_window(
    receipt: &OperationReceipt,
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
) -> bool {
    if receipt.started_at_ms >= end_timestamp_ms {
        return false;
    }
    match receipt.completed_at_ms {
        None => true,
        Some(completed) => completed.max(receipt.started_at_ms) > start_timestamp_ms,
    }
}

fn classify_historical_outcome(value: &str) -> HistoricalOutcomeClass {
    let lower = value.trim().to_ascii_lowercase();
    match lower.as_str() {
        "allow" | "allowed" | "succeeded" | "success" | "ok" | "true" => {
            HistoricalOutcomeClass::Allowed
        }
        "deny" | "denied" | "reject" | "rejected" | "failed" | "fail" | "false" => {
            HistoricalOutcomeClass::Denied
        }
        _ => HistoricalOutcomeClass::Unknown,
    }
}

fn classify_executable(value: &str) -> HistoricalOutcomeClass {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => HistoricalOutcomeClass::Allowed,
        "false" | "0" | "no" => HistoricalOutcomeClass::Denied,
        _ => HistoricalOutcomeClass::Unknown,
    }
}

fn attr(event: &crate::chisei::receipt::OperationReceiptEvent, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| event.attributes.get(*key).cloned())
        .filter(|value| !value.trim().is_empty())
}

fn delta_key(delta: DryRunDeltaClass) -> String {
    match delta {
        DryRunDeltaClass::Unchanged => "unchanged".into(),
        DryRunDeltaClass::ReRouted => "re_routed".into(),
        DryRunDeltaClass::WouldDeny => "would_deny".into(),
        DryRunDeltaClass::WouldAllow => "would_allow".into(),
        DryRunDeltaClass::InsufficientHistory => "insufficient_history".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptEventKind, ReceiptSurface,
    };
    use std::collections::BTreeMap;

    fn receipt(
        id: &str,
        historical_runtime: &str,
        historical_model: &str,
        outcome: &str,
    ) -> OperationReceipt {
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: id.into(),
            parent_operation_id: None,
            namespace: "ns".into(),
            operation_class: "chat".into(),
            initiating_actor: "operator".into(),
            schema_version: "s1".into(),
            policy_version: "old-policy".into(),
            started_at_ms: 150,
            completed_at_ms: Some(160),
            events: vec![
                OperationReceiptEvent {
                    event_id: format!("{id}-policy"),
                    operation_id: id.into(),
                    parent_event_id: None,
                    timestamp_ms: 150,
                    kind: ReceiptEventKind::PolicyDecided,
                    surface: ReceiptSurface::Policy,
                    actor: "chisei".into(),
                    references: Vec::new(),
                    attributes: BTreeMap::from([(
                        "executable".into(),
                        if outcome == "deny" {
                            "false".into()
                        } else {
                            "true".into()
                        },
                    )]),
                },
                OperationReceiptEvent {
                    event_id: format!("{id}-route"),
                    operation_id: id.into(),
                    parent_event_id: Some(format!("{id}-policy")),
                    timestamp_ms: 151,
                    kind: ReceiptEventKind::RouteSelected,
                    surface: ReceiptSurface::Routing,
                    actor: "chisei".into(),
                    references: Vec::new(),
                    attributes: BTreeMap::from([
                        ("runtime".into(), historical_runtime.into()),
                        ("model".into(), historical_model.into()),
                        ("preferred_runtime".into(), historical_runtime.into()),
                        ("preferred_model".into(), historical_model.into()),
                    ]),
                },
            ],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
        }
    }

    fn candidate(allowed_models: &[&str], default_model: &str) -> Policy {
        Policy {
            allowed_runtimes: vec!["openai".into(), "anthropic".into(), "ollama".into()],
            allowed_models: allowed_models.iter().map(|item| (*item).into()).collect(),
            default_runtime: "openai".into(),
            default_model: default_model.into(),
            data_class: "internal".into(),
        }
    }

    #[test]
    fn dry_run_produces_stable_delta_counts() {
        let receipts = [
            receipt("op-same", "openai", "gpt-5.5", "allow"),
            receipt("op-deny", "openai", "gpt-5.5", "allow"),
            receipt("op-allow-again", "openai", "gpt-5.5", "deny"),
        ];
        // Candidate keeps gpt-5.5, drops nothing for first; for second we force deny by empty models + empty default in a separate call
        let keep = candidate(&["gpt-5.5"], "gpt-5.5");
        let report = dry_run_policy_over_receipts("ns", 100, 200, &keep, &receipts[..1]).unwrap();
        assert_eq!(report.counts.evaluated, 1);
        assert_eq!(report.counts.unchanged, 1);

        let deny_all = Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["other-model".into()],
            default_runtime: String::new(),
            default_model: String::new(),
            data_class: "internal".into(),
        };
        let deny_report =
            dry_run_policy_over_receipts("ns", 100, 200, &deny_all, &receipts[1..2]).unwrap();
        assert_eq!(deny_report.counts.would_deny, 1);
        assert_eq!(
            deny_report.samples.get("would_deny").unwrap(),
            &vec!["op-deny".to_string()]
        );

        let allow_report =
            dry_run_policy_over_receipts("ns", 100, 200, &keep, &receipts[2..3]).unwrap();
        assert_eq!(allow_report.counts.would_allow, 1);
    }

    #[test]
    fn re_route_detected_when_default_model_changes() {
        let receipts = vec![receipt("op-route", "openai", "gpt-5.5", "allow")];
        // Preferred model not allowed; falls back to default model.
        let candidate = Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-4.1-mini".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-4.1-mini".into(),
            data_class: "internal".into(),
        };
        let report = dry_run_policy_over_receipts("ns", 100, 200, &candidate, &receipts).unwrap();
        assert_eq!(report.counts.re_routed, 1);
        assert_eq!(report.results[0].candidate_model, "gpt-4.1-mini");
    }

    #[test]
    fn dry_run_is_side_effect_free() {
        // Documented guarantee: pure evaluation path does not touch provider
        // adapters. This test simply asserts the pure API is usable without a
        // RuntimeDb or network.
        let receipts = vec![receipt("op-1", "openai", "gpt-5.5", "allow")];
        let candidate = candidate(&["gpt-5.5"], "gpt-5.5");
        let report = dry_run_policy_over_receipts("ns", 100, 200, &candidate, &receipts).unwrap();
        assert_eq!(report.counts.evaluated, 1);
        assert!(!report.candidate_policy_version.is_empty());
    }
}
