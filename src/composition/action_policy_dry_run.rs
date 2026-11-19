//! Historical dry-run of a candidate Action policy (#2121, #3059), shared by
//! the operator console form and `SekaiService.DryRunActionPolicy`.
//!
//! Reads the namespace's operation receipts from the Sekai store and replays
//! them through the Chisei engine. Requires a namespace grant, writes nothing
//! but one `action_policy.dry_run` decision, and fails when that audit write
//! fails.

use crate::chisei::action_policy_dry_run::{self, ActionPolicyDryRunReport};
use crate::chisei::policy_dry_run::MAX_DRY_RUN_RECEIPTS;
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_policy::ActionPolicy;
use crate::sekai::audit::Decision;
use crate::sekai::namespace_access::principal_can_access_namespace;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Why a dry-run produced no report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionPolicyDryRunError {
    /// The principal holds no grant on the namespace.
    AccessDenied,
    /// The window or candidate is invalid, or the window holds more receipts
    /// than one run replays.
    Invalid(String),
    /// Reading receipts or recording the audit decision failed.
    Store(String),
}

impl std::fmt::Display for ActionPolicyDryRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessDenied => f.write_str("namespace access denied"),
            Self::Invalid(message) | Self::Store(message) => f.write_str(message),
        }
    }
}

/// Dry-run `candidate` over the namespace's past governed action submits in
/// `[start_timestamp_ms, end_timestamp_ms)`. `surface` names the caller in the
/// audit decision (`console`, `grpc`).
pub fn run_action_policy_dry_run(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
    candidate: &ActionPolicy,
    surface: &str,
) -> Result<ActionPolicyDryRunReport, ActionPolicyDryRunError> {
    if !principal_can_access_namespace(db, principal, namespace).unwrap_or(false) {
        return Err(ActionPolicyDryRunError::AccessDenied);
    }
    if end_timestamp_ms <= start_timestamp_ms {
        return Err(ActionPolicyDryRunError::Invalid(
            "end_timestamp_ms must be greater than start_timestamp_ms".into(),
        ));
    }
    let receipts = db
        .list_operation_receipts_in_window(
            namespace,
            start_timestamp_ms,
            end_timestamp_ms,
            MAX_DRY_RUN_RECEIPTS.saturating_add(1),
        )
        .map_err(ActionPolicyDryRunError::Store)?;
    let report = action_policy_dry_run::dry_run_action_policy_over_receipts(
        namespace,
        start_timestamp_ms,
        end_timestamp_ms,
        candidate,
        &receipts,
    )
    .map_err(ActionPolicyDryRunError::Invalid)?;
    // The millisecond alone repeats when two identical runs land together, so
    // a random suffix keeps their decision ids, which hash the request id,
    // distinct.
    let request_id = format!(
        "{surface}-action-policy-dry-run-{}-{}",
        chrono::Utc::now().timestamp_millis(),
        uuid::Uuid::new_v4().simple()
    );
    let decision_id = format!(
        "action-policy-dry-run:{:x}",
        Sha256::digest(format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}",
            report.namespace,
            principal,
            request_id,
            report.candidate_scope,
            report.candidate_policy_version,
            report.start_timestamp_ms,
            report.end_timestamp_ms
        ))
    );
    let counts = &report.counts;
    db.record_decision(&Decision {
        id: decision_id,
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: principal.into(),
        action: "action_policy.dry_run".into(),
        reason: format!("{surface} historical action policy dry-run"),
        evidence: HashMap::from([
            ("namespace".into(), report.namespace.clone()),
            ("candidate_scope".into(), report.candidate_scope.clone()),
            (
                "candidate_policy_version".into(),
                report.candidate_policy_version.clone(),
            ),
            ("evaluated".into(), counts.evaluated.to_string()),
            ("unchanged".into(), counts.unchanged.to_string()),
            ("would_deny".into(), counts.would_deny.to_string()),
            ("would_allow".into(), counts.would_allow.to_string()),
            (
                "would_require_approval".into(),
                counts.would_require_approval.to_string(),
            ),
            (
                "would_skip_approval".into(),
                counts.would_skip_approval.to_string(),
            ),
            (
                "insufficient_history".into(),
                counts.insufficient_history.to_string(),
            ),
            ("request_id".into(), request_id),
            ("surface".into(), surface.into()),
        ]),
        target_id: report.namespace.clone(),
        outcome: "completed".into(),
    })
    .map_err(ActionPolicyDryRunError::Store)?;
    Ok(report)
}
