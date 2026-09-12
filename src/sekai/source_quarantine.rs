//! Bounded inspect/preview of the latest quarantined source batch (#820).
//!
//! Inspection and preview are observational projections. They never write, never
//! open a batch transaction, and never become apply authority. Re-admission is
//! existing [`RuntimeDb::apply_source_batch`].

use std::collections::HashMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::obs::console::principal_can_access_namespace;
use crate::obs::console_pressure::principal_can_write_namespace;
use crate::sekai::audit::{Decision, DecisionFilter};
use crate::sekai::object_sync::{
    OperationOutcome, SourceBatch, SourceBatchResult, SourceBatchStatus, SourceRecordResult,
    SourceSyncState, SyncDecision, contains_secret_like_text,
};

pub const INSPECT_CONTRACT: &str = "sekai.source-quarantine-inspect/v1";
pub const PREVIEW_CONTRACT: &str = "sekai.source-batch-preview/v1";
pub const APPLY_CONTRACT: &str = "sekai.source-batch-apply/v1";

pub const STATUS_QUARANTINED: &str = "quarantined";
pub const STATUS_UNAVAILABLE: &str = "unavailable";

pub const DISPOSITION_READY: &str = "ready";
pub const DISPOSITION_STALE: &str = "stale";
pub const DISPOSITION_INVALID: &str = "invalid";
pub const DISPOSITION_UNAVAILABLE: &str = "unavailable";

pub const REASON_NONE: &str = "none";
pub const REASON_ABSENT: &str = "absent";
pub const REASON_NOT_QUARANTINED: &str = "not_quarantined";
pub const REASON_STALE_CHECKPOINT: &str = "stale_checkpoint";
pub const REASON_STALE_TYPE_REVISION: &str = "stale_type_revision";
pub const REASON_INVALID_BATCH: &str = "invalid_batch";
pub const REASON_PRODUCER_MISMATCH: &str = "producer_identity_mismatch";
pub const REASON_FOREIGN_IDENTITY: &str = "foreign_identity";
pub const REASON_WRITE_DENIED: &str = "write_denied";

const OUTCOME_SUCCESS: &str = "success";
const OUTCOME_DENIAL: &str = "denial";
const OUTCOME_UNAVAILABLE: &str = "unavailable";
const OUTCOME_PARTIAL: &str = "partial";
const OUTCOME_UNKNOWN: &str = "unknown";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceQuarantineQuery {
    pub namespace: String,
    pub source_instance: String,
    pub type_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuarantineRecordView {
    pub source_id: String,
    pub decision: String,
    pub outcome: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceQuarantineInspect {
    pub contract_version: String,
    pub namespace: String,
    pub source_instance: String,
    pub type_digest: String,
    pub status: String,
    pub reason_code: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_batch_digest: Option<String>,
    pub records: Vec<QuarantineRecordView>,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceBatchPreview {
    pub contract_version: String,
    pub namespace: String,
    pub source_instance: String,
    pub type_digest: String,
    pub disposition: String,
    pub reason_code: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_batch_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_batch_digest: Option<String>,
    pub write_authority: bool,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceBatchApplyReport {
    pub contract_version: String,
    pub namespace: String,
    pub source_instance: String,
    pub type_digest: String,
    pub status: String,
    pub outcome: String,
    pub reason_code: String,
    pub checkpoint_advanced: bool,
    pub observed_at_ms: i64,
}

pub fn parse_source_quarantine_query(
    namespace: &str,
    source_instance: &str,
    type_digest: &str,
) -> Result<SourceQuarantineQuery, String> {
    required("namespace", namespace)?;
    required("source_instance", source_instance)?;
    required("type_digest", type_digest)?;
    if !crate::obs::console::is_safe_namespace(namespace) {
        return Err("source_quarantine_invalid: namespace is invalid".into());
    }
    if identity_looks_secret(namespace)
        || identity_looks_secret(source_instance)
        || identity_looks_secret(type_digest)
    {
        return Err("source_quarantine_invalid: identity must not contain secret-like text".into());
    }
    if !is_digest(type_digest) {
        return Err("source_quarantine_invalid: type digest is invalid".into());
    }
    Ok(SourceQuarantineQuery {
        namespace: namespace.to_string(),
        source_instance: source_instance.to_string(),
        type_digest: type_digest.to_string(),
    })
}

pub fn inspect_latest_quarantine(
    db: &RuntimeDb,
    actor: &str,
    query: &SourceQuarantineQuery,
    now_ms: i64,
) -> Result<SourceQuarantineInspect, String> {
    if actor.trim().is_empty() {
        return Err("source_quarantine_invalid: actor is required".into());
    }
    if now_ms < 0 {
        return Err("source_quarantine_invalid: observation time must be non-negative".into());
    }
    if !principal_can_access_namespace(db, actor, &query.namespace)? {
        let report = undisclosed_inspect(query, now_ms);
        audit_inspect(db, actor, &report)?;
        return Ok(report);
    }
    let state = db
        .get_source_sync_state(&query.namespace, &query.source_instance, &query.type_digest)
        .map_err(|_| "source quarantine identity is unavailable".to_string())?;
    let report = match state {
        Some(state) => project_quarantine_inspect(&state, query, now_ms),
        None => undisclosed_inspect(query, now_ms),
    };
    audit_inspect(db, actor, &report)?;
    Ok(report)
}

pub fn project_quarantine_inspect(
    state: &SourceSyncState,
    query: &SourceQuarantineQuery,
    now_ms: i64,
) -> SourceQuarantineInspect {
    if !identities_match(state, query) {
        return fail_closed_inspect(query, now_ms, REASON_FOREIGN_IDENTITY, OUTCOME_DENIAL);
    }
    let Some(result) = latest_quarantined_result(state) else {
        return fail_closed_inspect(query, now_ms, REASON_NOT_QUARANTINED, OUTCOME_UNAVAILABLE);
    };
    SourceQuarantineInspect {
        contract_version: INSPECT_CONTRACT.into(),
        namespace: query.namespace.clone(),
        source_instance: query.source_instance.clone(),
        type_digest: query.type_digest.clone(),
        status: STATUS_QUARANTINED.into(),
        reason_code: reason_code(&result.transaction.reason),
        outcome: outcome_str(result.transaction.outcome).into(),
        committed_batch_digest: state
            .checkpoint
            .as_ref()
            .and_then(|checkpoint| digest_or_none(&checkpoint.committed_batch_digest)),
        records: result.records.iter().filter_map(sanitize_record).collect(),
        observed_at_ms: now_ms,
    }
}

pub fn preview_source_batch(
    db: &RuntimeDb,
    actor: &str,
    batch: &SourceBatch,
    now_ms: i64,
) -> Result<SourceBatchPreview, String> {
    if actor.trim().is_empty() {
        return Err("source_quarantine_invalid: actor is required".into());
    }
    if now_ms < 0 {
        return Err("source_quarantine_invalid: observation time must be non-negative".into());
    }
    let query = parse_source_quarantine_query(
        &batch.namespace,
        &batch.source_instance,
        &batch.type_digest,
    )?;
    if !principal_can_access_namespace(db, actor, &query.namespace)? {
        let report = undisclosed_preview(&query, now_ms);
        audit_preview(db, actor, &report)?;
        return Ok(report);
    }
    if let Err(error) = batch.validate_for_producer(&batch.producer_identity) {
        let reason = if error.code == REASON_PRODUCER_MISMATCH {
            REASON_PRODUCER_MISMATCH
        } else {
            REASON_INVALID_BATCH
        };
        let report = SourceBatchPreview {
            contract_version: PREVIEW_CONTRACT.into(),
            namespace: query.namespace.clone(),
            source_instance: query.source_instance.clone(),
            type_digest: query.type_digest.clone(),
            disposition: DISPOSITION_INVALID.into(),
            reason_code: reason.into(),
            outcome: OUTCOME_DENIAL.into(),
            committed_batch_digest: None,
            proposed_batch_digest: digest_or_none(&batch.batch_digest),
            write_authority: false,
            observed_at_ms: now_ms,
        };
        audit_preview(db, actor, &report)?;
        return Ok(report);
    }
    let state = db
        .get_source_sync_state(&query.namespace, &query.source_instance, &query.type_digest)
        .map_err(|_| "source quarantine identity is unavailable".to_string())?;
    let report = match state {
        Some(state) => project_source_batch_preview(&state, batch, &query, now_ms),
        None => undisclosed_preview(&query, now_ms),
    };
    audit_preview(db, actor, &report)?;
    Ok(report)
}

pub fn project_source_batch_preview(
    state: &SourceSyncState,
    batch: &SourceBatch,
    query: &SourceQuarantineQuery,
    now_ms: i64,
) -> SourceBatchPreview {
    if !identities_match(state, query)
        || batch.namespace != state.binding.namespace
        || batch.source != state.binding.source
        || batch.source_instance != state.binding.source_instance
    {
        return fail_closed_preview(query, now_ms, REASON_FOREIGN_IDENTITY);
    }
    if latest_quarantined_result(state).is_none() {
        return fail_closed_preview(query, now_ms, REASON_NOT_QUARANTINED);
    }
    if batch.type_digest != state.binding.type_digest {
        return stale_preview(query, state, batch, now_ms, REASON_STALE_TYPE_REVISION);
    }
    match &state.checkpoint {
        Some(checkpoint) if checkpoint.cursor != batch.current_cursor => {
            return stale_preview(query, state, batch, now_ms, REASON_STALE_CHECKPOINT);
        }
        None if !batch.current_cursor.is_empty() => {
            return stale_preview(query, state, batch, now_ms, REASON_STALE_CHECKPOINT);
        }
        Some(_) | None => {}
    }
    SourceBatchPreview {
        contract_version: PREVIEW_CONTRACT.into(),
        namespace: query.namespace.clone(),
        source_instance: query.source_instance.clone(),
        type_digest: query.type_digest.clone(),
        disposition: DISPOSITION_READY.into(),
        reason_code: REASON_NONE.into(),
        outcome: OUTCOME_SUCCESS.into(),
        committed_batch_digest: state
            .checkpoint
            .as_ref()
            .and_then(|checkpoint| digest_or_none(&checkpoint.committed_batch_digest)),
        proposed_batch_digest: digest_or_none(&batch.batch_digest),
        write_authority: false,
        observed_at_ms: now_ms,
    }
}

pub fn apply_corrected_source_batch(
    db: &RuntimeDb,
    actor: &str,
    batch: &SourceBatch,
    now_ms: i64,
) -> Result<SourceBatchApplyReport, String> {
    if actor.trim().is_empty() {
        return Err("source_quarantine_invalid: actor is required".into());
    }
    if now_ms <= 0 {
        return Err("source_quarantine_invalid: apply time must be positive".into());
    }
    let query = parse_source_quarantine_query(
        &batch.namespace,
        &batch.source_instance,
        &batch.type_digest,
    )?;
    if !principal_can_write_namespace(db, actor, &query.namespace)? {
        let report = SourceBatchApplyReport {
            contract_version: APPLY_CONTRACT.into(),
            namespace: query.namespace.clone(),
            source_instance: query.source_instance.clone(),
            type_digest: query.type_digest.clone(),
            status: STATUS_UNAVAILABLE.into(),
            outcome: OUTCOME_DENIAL.into(),
            reason_code: REASON_WRITE_DENIED.into(),
            checkpoint_advanced: false,
            observed_at_ms: now_ms,
        };
        audit_apply(db, actor, &report)?;
        return Ok(report);
    }
    match db.apply_source_batch(batch, &batch.producer_identity, now_ms) {
        Ok(result) => {
            let report = SourceBatchApplyReport {
                contract_version: APPLY_CONTRACT.into(),
                namespace: query.namespace.clone(),
                source_instance: query.source_instance.clone(),
                type_digest: query.type_digest.clone(),
                status: result.transaction.status.as_str().to_ascii_lowercase(),
                outcome: outcome_str(result.transaction.outcome).into(),
                reason_code: reason_code(&result.transaction.reason),
                checkpoint_advanced: result.checkpoint_advanced,
                observed_at_ms: now_ms,
            };
            audit_apply(db, actor, &report)?;
            Ok(report)
        }
        Err(error) => {
            let report = SourceBatchApplyReport {
                contract_version: APPLY_CONTRACT.into(),
                namespace: query.namespace.clone(),
                source_instance: query.source_instance.clone(),
                type_digest: query.type_digest.clone(),
                status: STATUS_UNAVAILABLE.into(),
                outcome: OUTCOME_DENIAL.into(),
                reason_code: reason_code(&error),
                checkpoint_advanced: false,
                observed_at_ms: now_ms,
            };
            audit_apply(db, actor, &report)?;
            Ok(report)
        }
    }
}

pub fn latest_quarantine_inspect_audit(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<Option<Decision>, String> {
    latest_audit(db, "source.quarantine.inspect", namespace)
}

pub fn latest_quarantine_preview_audit(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<Option<Decision>, String> {
    latest_audit(db, "source.quarantine.preview", namespace)
}

fn latest_audit(db: &RuntimeDb, action: &str, namespace: &str) -> Result<Option<Decision>, String> {
    let decisions = db.list_decisions(&DecisionFilter {
        action: Some(action.into()),
        target_id: Some(namespace.into()),
        limit: 8,
        ..Default::default()
    })?;
    Ok(decisions.into_iter().next())
}

fn identities_match(state: &SourceSyncState, query: &SourceQuarantineQuery) -> bool {
    state.binding.namespace == query.namespace
        && state.binding.source_instance == query.source_instance
        && state.binding.type_digest == query.type_digest
}

fn latest_quarantined_result(state: &SourceSyncState) -> Option<&SourceBatchResult> {
    let result = state.last_result.as_ref()?;
    (result.transaction.status == SourceBatchStatus::Quarantined).then_some(result)
}

fn sanitize_record(record: &SourceRecordResult) -> Option<QuarantineRecordView> {
    if identity_looks_secret(&record.source_id) {
        return None;
    }
    Some(QuarantineRecordView {
        source_id: record.source_id.clone(),
        decision: decision_name(&record.decision).into(),
        outcome: outcome_str(record.outcome).into(),
        reason_code: reason_code(&record.reason),
    })
}

fn decision_name(decision: &SyncDecision) -> &'static str {
    match decision {
        SyncDecision::Upsert(_) => "upsert",
        SyncDecision::Tombstone(_) => "tombstone",
        SyncDecision::Conflict { .. } => "conflict",
        SyncDecision::Reject { .. } => "reject",
    }
}

fn outcome_str(outcome: OperationOutcome) -> &'static str {
    match outcome {
        OperationOutcome::Success => OUTCOME_SUCCESS,
        OperationOutcome::Denial => OUTCOME_DENIAL,
        OperationOutcome::Unavailable => OUTCOME_UNAVAILABLE,
        OperationOutcome::Partial => OUTCOME_PARTIAL,
        OperationOutcome::Unknown => OUTCOME_UNKNOWN,
    }
}

fn reason_code(reason: &str) -> String {
    let code = reason
        .split_once(':')
        .map(|(code, _)| code)
        .unwrap_or(reason)
        .trim();
    if code.is_empty() || identity_looks_secret(code) {
        REASON_NONE.into()
    } else {
        code.to_string()
    }
}

fn digest_or_none(value: &str) -> Option<String> {
    is_digest(value).then(|| value.to_string())
}

fn undisclosed_inspect(query: &SourceQuarantineQuery, now_ms: i64) -> SourceQuarantineInspect {
    fail_closed_inspect(query, now_ms, REASON_ABSENT, OUTCOME_UNAVAILABLE)
}

fn fail_closed_inspect(
    query: &SourceQuarantineQuery,
    now_ms: i64,
    reason_code: &str,
    outcome: &str,
) -> SourceQuarantineInspect {
    SourceQuarantineInspect {
        contract_version: INSPECT_CONTRACT.into(),
        namespace: query.namespace.clone(),
        source_instance: query.source_instance.clone(),
        type_digest: query.type_digest.clone(),
        status: STATUS_UNAVAILABLE.into(),
        reason_code: reason_code.into(),
        outcome: outcome.into(),
        committed_batch_digest: None,
        records: Vec::new(),
        observed_at_ms: now_ms,
    }
}

fn undisclosed_preview(query: &SourceQuarantineQuery, now_ms: i64) -> SourceBatchPreview {
    fail_closed_preview(query, now_ms, REASON_ABSENT)
}

fn fail_closed_preview(
    query: &SourceQuarantineQuery,
    now_ms: i64,
    reason_code: &str,
) -> SourceBatchPreview {
    SourceBatchPreview {
        contract_version: PREVIEW_CONTRACT.into(),
        namespace: query.namespace.clone(),
        source_instance: query.source_instance.clone(),
        type_digest: query.type_digest.clone(),
        disposition: DISPOSITION_UNAVAILABLE.into(),
        reason_code: reason_code.into(),
        outcome: OUTCOME_UNAVAILABLE.into(),
        committed_batch_digest: None,
        proposed_batch_digest: None,
        write_authority: false,
        observed_at_ms: now_ms,
    }
}

fn stale_preview(
    query: &SourceQuarantineQuery,
    state: &SourceSyncState,
    batch: &SourceBatch,
    now_ms: i64,
    reason_code: &str,
) -> SourceBatchPreview {
    SourceBatchPreview {
        contract_version: PREVIEW_CONTRACT.into(),
        namespace: query.namespace.clone(),
        source_instance: query.source_instance.clone(),
        type_digest: query.type_digest.clone(),
        disposition: DISPOSITION_STALE.into(),
        reason_code: reason_code.into(),
        outcome: OUTCOME_DENIAL.into(),
        committed_batch_digest: state
            .checkpoint
            .as_ref()
            .and_then(|checkpoint| digest_or_none(&checkpoint.committed_batch_digest)),
        proposed_batch_digest: digest_or_none(&batch.batch_digest),
        write_authority: false,
        observed_at_ms: now_ms,
    }
}

fn audit_inspect(
    db: &RuntimeDb,
    actor: &str,
    report: &SourceQuarantineInspect,
) -> Result<(), String> {
    record_quarantine_audit(
        db,
        actor,
        QuarantineAudit {
            action: "source.quarantine.inspect",
            contract: INSPECT_CONTRACT,
            namespace: &report.namespace,
            source_instance: &report.source_instance,
            type_digest: &report.type_digest,
            class: &report.status,
            reason_code: &report.reason_code,
            outcome: &report.outcome,
            observed_at_ms: report.observed_at_ms,
        },
    )
}

fn audit_preview(db: &RuntimeDb, actor: &str, report: &SourceBatchPreview) -> Result<(), String> {
    record_quarantine_audit(
        db,
        actor,
        QuarantineAudit {
            action: "source.quarantine.preview",
            contract: PREVIEW_CONTRACT,
            namespace: &report.namespace,
            source_instance: &report.source_instance,
            type_digest: &report.type_digest,
            class: &report.disposition,
            reason_code: &report.reason_code,
            outcome: &report.outcome,
            observed_at_ms: report.observed_at_ms,
        },
    )
}

fn audit_apply(db: &RuntimeDb, actor: &str, report: &SourceBatchApplyReport) -> Result<(), String> {
    record_quarantine_audit(
        db,
        actor,
        QuarantineAudit {
            action: "source.quarantine.apply",
            contract: APPLY_CONTRACT,
            namespace: &report.namespace,
            source_instance: &report.source_instance,
            type_digest: &report.type_digest,
            class: &report.status,
            reason_code: &report.reason_code,
            outcome: &report.outcome,
            observed_at_ms: report.observed_at_ms,
        },
    )
}

struct QuarantineAudit<'a> {
    action: &'a str,
    contract: &'a str,
    namespace: &'a str,
    source_instance: &'a str,
    type_digest: &'a str,
    class: &'a str,
    reason_code: &'a str,
    outcome: &'a str,
    observed_at_ms: i64,
}

fn record_quarantine_audit(
    db: &RuntimeDb,
    actor: &str,
    audit: QuarantineAudit<'_>,
) -> Result<(), String> {
    let identity = identity_digest(audit.namespace, audit.source_instance, audit.type_digest);
    db.record_decisions_idempotently(&[Decision {
        id: format!(
            "{}:{}:{}:{actor}:{}",
            audit.action, audit.namespace, identity, audit.observed_at_ms
        ),
        timestamp: audit.observed_at_ms,
        actor: actor.to_string(),
        action: audit.action.into(),
        reason: format!(
            "recorded {} authorized source quarantine observation",
            audit.contract
        ),
        evidence: HashMap::from([
            ("contract_version".into(), audit.contract.into()),
            ("namespace".into(), audit.namespace.into()),
            ("class".into(), audit.class.into()),
            ("reason_code".into(), audit.reason_code.into()),
            ("outcome".into(), audit.outcome.into()),
            ("write_authority".into(), "false".into()),
        ]),
        target_id: audit.namespace.into(),
        outcome: audit.outcome.into(),
    }])
}

fn identity_digest(namespace: &str, source_instance: &str, type_digest: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update(b"\n");
    hasher.update(source_instance.as_bytes());
    hasher.update(b"\n");
    hasher.update(type_digest.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn identity_looks_secret(value: &str) -> bool {
    if contains_secret_like_text(value) {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    ["sk-", "glpat-", "xoxb-", "xoxp-", "bearer ", "akia", "asia"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
        || (lower.starts_with("eyj") && lower.matches('.').count() == 2)
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("source_quarantine_invalid: {label} is required"));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::object_sync::{
        ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
        GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_VERSION, SOURCE_GITHUB, SourceBinding,
        SourceRecord,
    };
    use std::collections::BTreeMap;

    const PRODUCER: &str = "connector/github-primary";
    const PAYLOAD_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CONFLICT_DIGEST: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const REPAIR_DIGEST: &str =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn query() -> SourceQuarantineQuery {
        parse_source_quarantine_query("acme", "acme/ops", GITHUB_OBJECT_SYNC_TYPE_DIGEST).unwrap()
    }

    fn record() -> SourceRecord {
        SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            external_id: "12".into(),
            source_version: "node-v1".into(),
            type_name: "Issue".into(),
            display_name: "Bounded sync".into(),
            payload_digest: PAYLOAD_DIGEST.into(),
            properties: BTreeMap::from([
                ("state".into(), "open".into()),
                ("title".into(), "Bounded sync".into()),
            ]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        }
    }

    fn batch(current_cursor: &str, next_cursor: &str, key: &str) -> SourceBatch {
        let mut batch = SourceBatch {
            contract_version: SOURCE_BATCH_VERSION.into(),
            namespace: "acme".into(),
            producer_identity: PRODUCER.into(),
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            family: FAMILY_OBJECT_SYNC.into(),
            adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
            adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
            type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
            current_cursor: current_cursor.into(),
            proposed_next_cursor: next_cursor.into(),
            idempotency_key: key.into(),
            batch_digest: String::new(),
            collected_at_ms: 20,
            records: vec![record()],
            delivery: None,
        };
        batch.batch_digest = batch.canonical_digest().unwrap();
        batch
    }

    fn quarantine_db() -> (RuntimeDb, SourceBatchResult) {
        let db = RuntimeDb::memory();
        db.apply_source_batch(&batch("", "cursor:1", "batch-1"), PRODUCER, 100)
            .unwrap();
        let mut conflict = batch("cursor:1", "cursor:blocked", "batch-revision-conflict");
        conflict.records[0].payload_digest = CONFLICT_DIGEST.into();
        conflict.batch_digest = conflict.canonical_digest().unwrap();
        let quarantined = db.apply_source_batch(&conflict, PRODUCER, 200).unwrap();
        assert_eq!(
            quarantined.transaction.status,
            SourceBatchStatus::Quarantined
        );
        (db, quarantined)
    }

    fn repair_batch() -> SourceBatch {
        let mut repair = batch("cursor:1", "cursor:2", "batch-repair");
        repair.records[0].source_version = "node-v2".into();
        repair.records[0].payload_digest = REPAIR_DIGEST.into();
        repair.records[0].display_name = "Bounded sync repaired".into();
        repair.records[0]
            .properties
            .insert("title".into(), "Bounded sync repaired".into());
        repair.batch_digest = repair.canonical_digest().unwrap();
        repair
    }

    #[test]
    fn inspect_exposes_reason_codes_without_cursors_or_payloads() {
        let (db, quarantined) = quarantine_db();
        let report = inspect_latest_quarantine(&db, "root", &query(), 300).unwrap();
        assert_eq!(report.status, STATUS_QUARANTINED);
        assert_eq!(report.reason_code, "source_revision_conflict");
        assert_eq!(report.outcome, OUTCOME_DENIAL);
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].reason_code, "source_revision_conflict");
        assert!(!report.records[0].source_id.contains(CONFLICT_DIGEST));
        assert!(!serde_json::to_string(&report).unwrap().contains("cursor:"));
        assert!(!serde_json::to_string(&report).unwrap().contains("cccc"));
        assert_eq!(
            report.committed_batch_digest.as_deref(),
            Some(
                db.get_source_sync_state("acme", "acme/ops", GITHUB_OBJECT_SYNC_TYPE_DIGEST)
                    .unwrap()
                    .unwrap()
                    .checkpoint
                    .unwrap()
                    .committed_batch_digest
                    .as_str()
            )
        );
        assert_eq!(
            quarantined.records[0].reason.split_once(':').unwrap().0,
            "source_revision_conflict"
        );
    }

    #[test]
    fn hidden_and_unknown_inspections_share_one_unavailable_shape() {
        let (db, _) = quarantine_db();
        let hidden = inspect_latest_quarantine(&db, "stranger", &query(), 300).unwrap();
        let unknown = inspect_latest_quarantine(
            &db,
            "root",
            &parse_source_quarantine_query("acme", "missing/repo", GITHUB_OBJECT_SYNC_TYPE_DIGEST)
                .unwrap(),
            300,
        )
        .unwrap();
        assert_eq!(hidden.status, STATUS_UNAVAILABLE);
        assert_eq!(hidden.reason_code, REASON_ABSENT);
        assert_eq!(hidden.records, unknown.records);
        assert_eq!(hidden.committed_batch_digest, None);
        assert_eq!(hidden.outcome, unknown.outcome);
    }

    #[test]
    fn stale_preview_cannot_overwrite_a_newer_checkpoint() {
        let (db, _) = quarantine_db();
        let repair = repair_batch();
        let ready = preview_source_batch(&db, "root", &repair, 300).unwrap();
        assert_eq!(ready.disposition, DISPOSITION_READY);
        assert!(!ready.write_authority);

        let mut stale = repair_batch();
        stale.idempotency_key = "batch-stale-repair".into();
        stale.current_cursor = "cursor:foreign".into();
        stale.proposed_next_cursor = "cursor:stale".into();
        stale.batch_digest = stale.canonical_digest().unwrap();
        let preview = preview_source_batch(&db, "root", &stale, 500).unwrap();
        assert_eq!(preview.disposition, DISPOSITION_STALE);
        assert_eq!(preview.reason_code, REASON_STALE_CHECKPOINT);
        assert!(!preview.write_authority);

        let applied = apply_corrected_source_batch(&db, "root", &stale, 600).unwrap();
        assert!(!applied.checkpoint_advanced);
        assert_eq!(applied.reason_code, "stale_cursor");
        let state = db
            .get_source_sync_state("acme", "acme/ops", GITHUB_OBJECT_SYNC_TYPE_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(state.checkpoint.as_ref().unwrap().cursor, "cursor:1");
        assert_eq!(
            state.last_result.as_ref().unwrap().transaction.status,
            SourceBatchStatus::Quarantined
        );
    }

    #[test]
    fn preview_of_a_mismatched_type_revision_is_stale() {
        let (db, _) = quarantine_db();
        let state = db
            .get_source_sync_state("acme", "acme/ops", GITHUB_OBJECT_SYNC_TYPE_DIGEST)
            .unwrap()
            .unwrap();
        let mut repair = repair_batch();
        repair.type_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        let preview = project_source_batch_preview(&state, &repair, &query(), 300);
        assert_eq!(preview.disposition, DISPOSITION_STALE);
        assert_eq!(preview.reason_code, REASON_STALE_TYPE_REVISION);
    }

    #[test]
    fn re_admission_preserves_identity_and_records_a_new_outcome() {
        let (db, quarantined) = quarantine_db();
        let repair = repair_batch();
        let applied = apply_corrected_source_batch(&db, "root", &repair, 400).unwrap();
        assert_eq!(applied.status, "committed");
        assert_eq!(applied.outcome, OUTCOME_SUCCESS);
        assert!(applied.checkpoint_advanced);
        let state = db
            .get_source_sync_state("acme", "acme/ops", GITHUB_OBJECT_SYNC_TYPE_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(state.binding.source_instance, "acme/ops");
        assert_eq!(state.binding.source, SOURCE_GITHUB);
        assert_eq!(state.checkpoint.as_ref().unwrap().cursor, "cursor:2");
        assert_ne!(
            state
                .last_result
                .as_ref()
                .unwrap()
                .transaction
                .transaction_id,
            quarantined.transaction.transaction_id
        );
        let replay = db
            .apply_source_batch(
                &{
                    let mut original =
                        batch("cursor:1", "cursor:blocked", "batch-revision-conflict");
                    original.records[0].payload_digest = CONFLICT_DIGEST.into();
                    original.batch_digest = original.canonical_digest().unwrap();
                    original
                },
                PRODUCER,
                500,
            )
            .unwrap();
        assert_eq!(replay.transaction.status, SourceBatchStatus::Quarantined);
        assert!(!replay.checkpoint_advanced);
    }

    #[test]
    fn invalid_preview_does_not_echo_secret_like_text() {
        let (db, _) = quarantine_db();
        let mut secret = repair_batch();
        secret.records[0]
            .properties
            .insert("access_token".into(), "redacted".into());
        secret.batch_digest = secret.canonical_digest().unwrap();
        let preview = preview_source_batch(&db, "root", &secret, 300).unwrap();
        assert_eq!(preview.disposition, DISPOSITION_INVALID);
        assert_eq!(preview.reason_code, REASON_INVALID_BATCH);
        let encoded = serde_json::to_string(&preview).unwrap();
        assert!(!encoded.contains("access_token"));
        assert!(!encoded.contains("redacted"));
    }

    #[test]
    fn write_denied_apply_does_not_advance_the_checkpoint() {
        let (db, _) = quarantine_db();
        let applied = apply_corrected_source_batch(&db, "stranger", &repair_batch(), 400).unwrap();
        assert_eq!(applied.reason_code, REASON_WRITE_DENIED);
        assert!(!applied.checkpoint_advanced);
        let state = db
            .get_source_sync_state("acme", "acme/ops", GITHUB_OBJECT_SYNC_TYPE_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(state.checkpoint.as_ref().unwrap().cursor, "cursor:1");
    }

    #[test]
    fn inspect_audit_omits_cursors_and_source_instance() {
        let (db, _) = quarantine_db();
        inspect_latest_quarantine(&db, "root", &query(), 300).unwrap();
        let audit = latest_quarantine_inspect_audit(&db, "acme")
            .unwrap()
            .unwrap();
        assert_eq!(audit.action, "source.quarantine.inspect");
        assert!(
            !audit
                .evidence
                .values()
                .any(|value| value.contains("cursor:") || value.contains("acme/ops"))
        );
    }

    #[test]
    fn projection_rejects_foreign_binding_identity() {
        let (db, _) = quarantine_db();
        let mut state = db
            .get_source_sync_state("acme", "acme/ops", GITHUB_OBJECT_SYNC_TYPE_DIGEST)
            .unwrap()
            .unwrap();
        state.binding = SourceBinding {
            namespace: "other".into(),
            ..state.binding
        };
        let inspect = project_quarantine_inspect(&state, &query(), 300);
        assert_eq!(inspect.status, STATUS_UNAVAILABLE);
        assert_eq!(inspect.reason_code, REASON_FOREIGN_IDENTITY);
    }
}
