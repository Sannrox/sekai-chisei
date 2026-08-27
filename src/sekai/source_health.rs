//! Authorized source-health projection over durable object-sync state (#685).
//!
//! Health is a computed `sekai.source-health/v1` observation. It never writes
//! a second checkpoint, probes a remote connector, or stores credentials.

use std::collections::HashMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::obs::console::principal_can_access_namespace;
use crate::sekai::audit::{Decision, DecisionFilter};
use crate::sekai::object_sync::{
    OperationOutcome, SOURCE_BATCH_V2_VERSION, SOURCE_BATCH_VERSION, SourceBatchStatus,
    SourceBinding, SourceCheckpoint, SourceSyncGenerationStatus, SourceSyncState,
    contains_secret_like_text,
};

pub const HEALTH_CONTRACT: &str = "sekai.source-health/v1";
pub const DEFAULT_DELAYED_AFTER_MS: i64 = 15 * 60 * 1000;

pub const CLASS_HEALTHY: &str = "healthy";
pub const CLASS_DELAYED: &str = "delayed";
pub const CLASS_BLOCKED: &str = "blocked";
pub const CLASS_UNAVAILABLE: &str = "unavailable";

pub const FAILURE_NONE: &str = "none";
pub const FAILURE_OPEN_TRANSACTION: &str = "open_transaction";
pub const FAILURE_ABORTED: &str = "aborted";
pub const FAILURE_QUARANTINED: &str = "quarantined";
pub const FAILURE_RECOVERY_REQUIRED: &str = "recovery_required";
pub const FAILURE_INVALID_CHECKPOINT: &str = "invalid_checkpoint";
pub const FAILURE_UNKNOWN_VERSION: &str = "unknown_version";
pub const FAILURE_FOREIGN_IDENTITY: &str = "foreign_identity";
pub const FAILURE_AMBIGUOUS: &str = "ambiguous_lifecycle";
pub const FAILURE_ABSENT: &str = "absent";

pub const OUTCOME_SUCCESS: &str = "success";
pub const OUTCOME_DENIAL: &str = "denial";
pub const OUTCOME_UNAVAILABLE: &str = "unavailable";
pub const OUTCOME_PARTIAL: &str = "partial";
pub const OUTCOME_UNKNOWN: &str = "unknown";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHealthQuery {
    pub namespace: String,
    pub source_instance: String,
    pub type_digest: String,
    pub delayed_after_ms: i64,
    pub contract_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceHealth {
    pub contract_version: String,
    pub namespace: String,
    pub source_instance: String,
    pub type_digest: String,
    pub class: String,
    pub failure_class: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_age_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lag: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at_ms: Option<i64>,
    pub observed_at_ms: i64,
    pub write_authority: bool,
    pub permit_authority: bool,
}

pub fn parse_source_health_query(
    namespace: &str,
    source_instance: &str,
    type_digest: &str,
    delayed_after_ms: Option<i64>,
    contract_version: Option<&str>,
) -> Result<SourceHealthQuery, String> {
    required("namespace", namespace)?;
    required("source instance", source_instance)?;
    required("type digest", type_digest)?;
    if !crate::obs::console::is_safe_namespace(namespace) {
        return Err("source_health_invalid: namespace is invalid".into());
    }
    if identity_looks_secret(source_instance) || identity_looks_secret(type_digest) {
        return Err("source_health_invalid: identity must not contain secret-like text".into());
    }
    if !is_digest(type_digest) {
        return Err("source_health_invalid: type digest is invalid".into());
    }
    if let Some(version) = contract_version
        && version != HEALTH_CONTRACT
    {
        return Err("source_health_invalid: unsupported source health version".into());
    }
    let delayed_after_ms = delayed_after_ms.unwrap_or(DEFAULT_DELAYED_AFTER_MS);
    if delayed_after_ms <= 0 {
        return Err("source_health_invalid: delayed_after_ms must be positive".into());
    }
    Ok(SourceHealthQuery {
        namespace: namespace.to_string(),
        source_instance: source_instance.to_string(),
        type_digest: type_digest.to_string(),
        delayed_after_ms,
        contract_version: contract_version.map(str::to_string),
    })
}

pub fn report_source_health(
    db: &RuntimeDb,
    actor: &str,
    query: &SourceHealthQuery,
    now_ms: i64,
) -> Result<SourceHealth, String> {
    if actor.trim().is_empty() {
        return Err("source_health_invalid: actor is required".into());
    }
    if now_ms < 0 {
        return Err("source_health_invalid: observation time must be non-negative".into());
    }
    if !principal_can_access_namespace(db, actor, &query.namespace)? {
        let report = undisclosed(query, now_ms);
        audit_health(db, actor, &report)?;
        return Ok(report);
    }
    let state = db
        .get_source_sync_state(&query.namespace, &query.source_instance, &query.type_digest)
        .map_err(|_| "source health identity is unavailable".to_string())?;
    let report = match state {
        Some(state) => project_source_health(&state, query, now_ms),
        None => undisclosed(query, now_ms),
    };
    audit_health(db, actor, &report)?;
    Ok(report)
}

pub fn project_source_health(
    state: &SourceSyncState,
    query: &SourceHealthQuery,
    now_ms: i64,
) -> SourceHealth {
    match classify(state, query, now_ms) {
        Ok(mut report) => {
            report.source_instance = query.source_instance.clone();
            report.type_digest = query.type_digest.clone();
            report
        }
        Err(closed) => fail_closed(query, now_ms, closed),
    }
}

pub fn latest_source_health_audit(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<Option<Decision>, String> {
    let decisions = db.list_decisions(&DecisionFilter {
        action: Some("source.health".into()),
        target_id: Some(namespace.into()),
        limit: 8,
        ..Default::default()
    })?;
    Ok(decisions.into_iter().next())
}

#[derive(Debug, Clone, Copy)]
enum ClosedClass {
    InvalidCheckpoint,
    UnknownVersion,
    ForeignIdentity,
    Ambiguous,
}

fn classify(
    state: &SourceSyncState,
    query: &SourceHealthQuery,
    now_ms: i64,
) -> Result<SourceHealth, ClosedClass> {
    if state.binding.namespace != query.namespace
        || state.binding.source_instance != query.source_instance
        || state.binding.type_digest != query.type_digest
    {
        return Err(ClosedClass::ForeignIdentity);
    }
    if let Some(checkpoint) = &state.checkpoint {
        validate_checkpoint(&state.binding, checkpoint)?;
    }
    if let Some(generation) = &state.current_generation
        && generation.binding_id != state.binding.binding_id
    {
        return Err(ClosedClass::ForeignIdentity);
    }
    if let Some(open) = &state.open_transaction {
        if open.status != SourceBatchStatus::Open {
            return Err(ClosedClass::Ambiguous);
        }
        if open.binding_id != state.binding.binding_id || open.namespace != state.binding.namespace
        {
            return Err(ClosedClass::ForeignIdentity);
        }
        if !known_batch_version(&open.contract_version) {
            return Err(ClosedClass::UnknownVersion);
        }
    }
    if let Some(result) = &state.last_result {
        if !known_batch_version(&result.transaction.contract_version) {
            return Err(ClosedClass::UnknownVersion);
        }
        if result.transaction.status == SourceBatchStatus::Open {
            return Err(ClosedClass::Ambiguous);
        }
        if result.transaction.binding_id != state.binding.binding_id {
            return Err(ClosedClass::ForeignIdentity);
        }
        match result.transaction.outcome {
            OperationOutcome::Partial => {
                return Ok(report(
                    query,
                    now_ms,
                    CLASS_UNAVAILABLE,
                    FAILURE_AMBIGUOUS,
                    OUTCOME_PARTIAL,
                    None,
                    None,
                    None,
                ));
            }
            OperationOutcome::Unknown => {
                return Ok(report(
                    query,
                    now_ms,
                    CLASS_UNAVAILABLE,
                    FAILURE_AMBIGUOUS,
                    OUTCOME_UNKNOWN,
                    None,
                    None,
                    None,
                ));
            }
            OperationOutcome::Success
            | OperationOutcome::Denial
            | OperationOutcome::Unavailable => {}
        }
        if result.checkpoint_advanced && state.checkpoint.is_none() {
            return Err(ClosedClass::Ambiguous);
        }
    }

    if let Some(generation) = &state.current_generation
        && generation.status == SourceSyncGenerationStatus::RecoveryRequired
    {
        return Ok(blocked(query, now_ms, FAILURE_RECOVERY_REQUIRED, state));
    }
    if state.open_transaction.is_some() {
        return Ok(blocked(query, now_ms, FAILURE_OPEN_TRANSACTION, state));
    }
    if let Some(latest) = &state.latest_transaction {
        match latest.status {
            SourceBatchStatus::Aborted => {
                return Ok(blocked(query, now_ms, FAILURE_ABORTED, state));
            }
            SourceBatchStatus::Quarantined => {
                return Ok(blocked(query, now_ms, FAILURE_QUARANTINED, state));
            }
            SourceBatchStatus::Open => {
                return Ok(blocked(query, now_ms, FAILURE_OPEN_TRANSACTION, state));
            }
            SourceBatchStatus::Committed => {}
        }
    }
    if let Some(result) = &state.last_result {
        match result.transaction.status {
            SourceBatchStatus::Aborted => {
                return Ok(blocked(query, now_ms, FAILURE_ABORTED, state));
            }
            SourceBatchStatus::Quarantined => {
                return Ok(blocked(query, now_ms, FAILURE_QUARANTINED, state));
            }
            SourceBatchStatus::Committed | SourceBatchStatus::Open => {}
        }
    }

    let last_success_at_ms = last_success_at(state);
    let Some(last_success_at_ms) = last_success_at_ms else {
        return Ok(undisclosed(query, now_ms));
    };
    if last_success_at_ms > now_ms {
        return Err(ClosedClass::InvalidCheckpoint);
    }
    let checkpoint_age_ms = now_ms - last_success_at_ms;
    let lag = Some(compute_lag(state));
    let class = if checkpoint_age_ms > query.delayed_after_ms {
        CLASS_DELAYED
    } else {
        CLASS_HEALTHY
    };
    Ok(report(
        query,
        now_ms,
        class,
        FAILURE_NONE,
        OUTCOME_SUCCESS,
        Some(checkpoint_age_ms),
        lag,
        Some(last_success_at_ms),
    ))
}

fn validate_checkpoint(
    binding: &SourceBinding,
    checkpoint: &SourceCheckpoint,
) -> Result<(), ClosedClass> {
    if !known_batch_version(&checkpoint.contract_version) {
        return Err(ClosedClass::UnknownVersion);
    }
    if checkpoint.binding_id != binding.binding_id || checkpoint.namespace != binding.namespace {
        return Err(ClosedClass::ForeignIdentity);
    }
    if checkpoint.cursor.is_empty()
        || checkpoint.advanced_at_ms < 0
        || contains_secret_like_text(&checkpoint.cursor)
    {
        return Err(ClosedClass::InvalidCheckpoint);
    }
    Ok(())
}

fn known_batch_version(version: &str) -> bool {
    version == SOURCE_BATCH_VERSION || version == SOURCE_BATCH_V2_VERSION
}

fn last_success_at(state: &SourceSyncState) -> Option<i64> {
    if let Some(checkpoint) = &state.checkpoint {
        return Some(checkpoint.advanced_at_ms);
    }
    None
}

fn compute_lag(state: &SourceSyncState) -> i64 {
    let committed = state
        .checkpoint
        .as_ref()
        .and_then(|checkpoint| checkpoint.committed_offset)
        .or_else(|| {
            state
                .current_generation
                .as_ref()
                .and_then(|generation| generation.committed_offset)
        })
        .unwrap_or(0);
    let observed = state
        .open_transaction
        .as_ref()
        .and_then(|transaction| transaction.offset_end)
        .or_else(|| {
            state
                .latest_transaction
                .as_ref()
                .and_then(|transaction| transaction.offset_end)
        })
        .unwrap_or(committed);
    if observed > committed {
        i64::try_from(observed - committed).unwrap_or(i64::MAX)
    } else if state.open_transaction.is_some() {
        1
    } else {
        0
    }
}

fn blocked(
    query: &SourceHealthQuery,
    now_ms: i64,
    failure_class: &'static str,
    state: &SourceSyncState,
) -> SourceHealth {
    let last_success_at_ms = last_success_at(state).filter(|stamp| *stamp <= now_ms);
    let checkpoint_age_ms = last_success_at_ms.map(|stamp| now_ms - stamp);
    report(
        query,
        now_ms,
        CLASS_BLOCKED,
        failure_class,
        OUTCOME_DENIAL,
        checkpoint_age_ms,
        Some(compute_lag(state)),
        last_success_at_ms,
    )
}

fn fail_closed(query: &SourceHealthQuery, now_ms: i64, closed: ClosedClass) -> SourceHealth {
    let (failure_class, outcome) = match closed {
        ClosedClass::InvalidCheckpoint => (FAILURE_INVALID_CHECKPOINT, OUTCOME_DENIAL),
        ClosedClass::UnknownVersion => (FAILURE_UNKNOWN_VERSION, OUTCOME_DENIAL),
        ClosedClass::ForeignIdentity => (FAILURE_FOREIGN_IDENTITY, OUTCOME_DENIAL),
        ClosedClass::Ambiguous => (FAILURE_AMBIGUOUS, OUTCOME_UNKNOWN),
    };
    report(
        query,
        now_ms,
        CLASS_UNAVAILABLE,
        failure_class,
        outcome,
        None,
        None,
        None,
    )
}

fn undisclosed(query: &SourceHealthQuery, now_ms: i64) -> SourceHealth {
    report(
        query,
        now_ms,
        CLASS_UNAVAILABLE,
        FAILURE_ABSENT,
        OUTCOME_UNAVAILABLE,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn report(
    query: &SourceHealthQuery,
    now_ms: i64,
    class: &'static str,
    failure_class: &'static str,
    outcome: &'static str,
    checkpoint_age_ms: Option<i64>,
    lag: Option<i64>,
    last_success_at_ms: Option<i64>,
) -> SourceHealth {
    SourceHealth {
        contract_version: HEALTH_CONTRACT.into(),
        namespace: query.namespace.clone(),
        source_instance: query.source_instance.clone(),
        type_digest: query.type_digest.clone(),
        class: class.into(),
        failure_class: failure_class.into(),
        outcome: outcome.into(),
        checkpoint_age_ms,
        lag,
        last_success_at_ms,
        observed_at_ms: now_ms,
        write_authority: false,
        permit_authority: false,
    }
}

fn audit_health(db: &RuntimeDb, actor: &str, report: &SourceHealth) -> Result<(), String> {
    db.record_decisions_idempotently(&[Decision {
        id: format!(
            "source.health:{}:{}:{}:{}",
            report.namespace,
            health_audit_identity_digest(report),
            actor,
            report.observed_at_ms
        ),
        timestamp: report.observed_at_ms,
        actor: actor.to_string(),
        action: "source.health".into(),
        reason: format!("recorded {HEALTH_CONTRACT} authorized source health"),
        evidence: HashMap::from([
            ("contract_version".into(), HEALTH_CONTRACT.into()),
            ("namespace".into(), report.namespace.clone()),
            ("class".into(), report.class.clone()),
            ("failure_class".into(), report.failure_class.clone()),
            ("outcome".into(), report.outcome.clone()),
            ("write_authority".into(), "false".into()),
            ("permit_authority".into(), "false".into()),
        ]),
        target_id: report.namespace.clone(),
        outcome: report.outcome.clone(),
    }])
}

fn health_audit_identity_digest(report: &SourceHealth) -> String {
    let mut hasher = Sha256::new();
    hasher.update(report.namespace.as_bytes());
    hasher.update(b"\n");
    hasher.update(report.source_instance.as_bytes());
    hasher.update(b"\n");
    hasher.update(report.type_digest.as_bytes());
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
        return Err(format!("source_health_invalid: {label} is required"));
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
        GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_GITHUB, SourceBatch, SourceBatchTransaction,
        SourceCheckpoint, SourceDeliveryMode, SourceRecord, SourceSyncGeneration,
    };
    use std::collections::BTreeMap;

    const PRODUCER: &str = "connector/github-primary";
    const PAYLOAD_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn query() -> SourceHealthQuery {
        parse_source_health_query(
            "acme",
            "acme/ops",
            GITHUB_OBJECT_SYNC_TYPE_DIGEST,
            Some(DEFAULT_DELAYED_AFTER_MS),
            Some(HEALTH_CONTRACT),
        )
        .unwrap()
    }

    fn binding() -> SourceBinding {
        SourceBinding {
            binding_id: "bind-1".into(),
            namespace: "acme".into(),
            producer_identity: PRODUCER.into(),
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            family: FAMILY_OBJECT_SYNC.into(),
            adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
            adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
            type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
            created_at_ms: 10,
            active: true,
        }
    }

    fn checkpoint(advanced_at_ms: i64) -> SourceCheckpoint {
        SourceCheckpoint {
            binding_id: "bind-1".into(),
            namespace: "acme".into(),
            cursor: "cursor:1".into(),
            committed_batch_digest: PAYLOAD_DIGEST.into(),
            advanced_at_ms,
            contract_version: SOURCE_BATCH_VERSION.into(),
            delivery_mode: None,
            sync_generation: None,
            source_feed_epoch: None,
            committed_offset: Some(1),
        }
    }

    fn committed_result(advanced: bool) -> crate::sekai::object_sync::SourceBatchResult {
        crate::sekai::object_sync::SourceBatchResult {
            transaction: SourceBatchTransaction {
                transaction_id: "txn-1".into(),
                binding_id: "bind-1".into(),
                namespace: "acme".into(),
                producer_identity: PRODUCER.into(),
                idempotency_key: "batch-1".into(),
                batch_digest: PAYLOAD_DIGEST.into(),
                current_cursor: String::new(),
                proposed_next_cursor: "cursor:1".into(),
                status: SourceBatchStatus::Committed,
                outcome: OperationOutcome::Success,
                opened_at_ms: 20,
                closed_at_ms: Some(30),
                reason: String::new(),
                contract_version: SOURCE_BATCH_VERSION.into(),
                delivery_mode: None,
                sync_generation: None,
                source_feed_epoch: None,
                offset_start: None,
                offset_end: Some(1),
                snapshot_complete: None,
            },
            records: Vec::new(),
            checkpoint_advanced: advanced,
        }
    }

    fn healthy_state() -> SourceSyncState {
        SourceSyncState {
            binding: binding(),
            checkpoint: Some(checkpoint(100)),
            open_transaction: None,
            last_result: Some(committed_result(true)),
            current_generation: None,
            latest_transaction: None,
            updated_at_ms: 100,
        }
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

    #[test]
    fn healthy_delayed_blocked_unavailable_and_hidden_are_stable() {
        let healthy = project_source_health(&healthy_state(), &query(), 200);
        assert_eq!(healthy.class, CLASS_HEALTHY);
        assert_eq!(healthy.failure_class, FAILURE_NONE);
        assert_eq!(healthy.outcome, OUTCOME_SUCCESS);
        assert_eq!(healthy.checkpoint_age_ms, Some(100));
        assert_eq!(healthy.lag, Some(0));
        assert_eq!(healthy.last_success_at_ms, Some(100));
        assert!(!healthy.write_authority);
        assert!(!healthy.permit_authority);

        let delayed = project_source_health(
            &healthy_state(),
            &query(),
            100 + DEFAULT_DELAYED_AFTER_MS + 1,
        );
        assert_eq!(delayed.class, CLASS_DELAYED);
        assert_eq!(delayed.failure_class, FAILURE_NONE);
        assert_eq!(delayed.outcome, OUTCOME_SUCCESS);

        let mut blocked_state = healthy_state();
        blocked_state.open_transaction = Some(SourceBatchTransaction {
            transaction_id: "txn-open".into(),
            binding_id: "bind-1".into(),
            namespace: "acme".into(),
            producer_identity: PRODUCER.into(),
            idempotency_key: "batch-open".into(),
            batch_digest: PAYLOAD_DIGEST.into(),
            current_cursor: "cursor:1".into(),
            proposed_next_cursor: "cursor:2".into(),
            status: SourceBatchStatus::Open,
            outcome: OperationOutcome::Unknown,
            opened_at_ms: 150,
            closed_at_ms: None,
            reason: String::new(),
            contract_version: SOURCE_BATCH_VERSION.into(),
            delivery_mode: None,
            sync_generation: None,
            source_feed_epoch: None,
            offset_start: None,
            offset_end: None,
            snapshot_complete: None,
        });
        let blocked = project_source_health(&blocked_state, &query(), 200);
        assert_eq!(blocked.class, CLASS_BLOCKED);
        assert_eq!(blocked.failure_class, FAILURE_OPEN_TRANSACTION);
        assert_eq!(blocked.outcome, OUTCOME_DENIAL);

        let db = RuntimeDb::memory();
        let authorized = report_source_health(&db, "root", &query(), 200).unwrap();
        let hidden = report_source_health(&db, "stranger", &query(), 200).unwrap();
        let unknown = report_source_health(
            &db,
            "root",
            &parse_source_health_query(
                "acme",
                "missing/repo",
                GITHUB_OBJECT_SYNC_TYPE_DIGEST,
                None,
                None,
            )
            .unwrap(),
            200,
        )
        .unwrap();
        assert_eq!(authorized.class, CLASS_UNAVAILABLE);
        assert_eq!(authorized.failure_class, FAILURE_ABSENT);
        assert_eq!(authorized.outcome, OUTCOME_UNAVAILABLE);
        assert_eq!(hidden.class, hidden_shape(&unknown).class);
        assert_eq!(hidden.failure_class, hidden_shape(&unknown).failure_class);
        assert_eq!(hidden.outcome, hidden_shape(&unknown).outcome);
        assert_eq!(hidden.checkpoint_age_ms, None);
        assert_eq!(hidden.lag, None);
        assert_eq!(hidden.last_success_at_ms, None);
        assert_eq!(hidden.contract_version, unknown.contract_version);
    }

    fn hidden_shape(report: &SourceHealth) -> SourceHealth {
        let mut shaped = report.clone();
        shaped.source_instance = query().source_instance;
        shaped.type_digest = query().type_digest;
        shaped
    }

    #[test]
    fn unknown_version_foreign_identity_and_invalid_checkpoint_fail_closed() {
        let mut unknown = healthy_state();
        unknown.checkpoint.as_mut().unwrap().contract_version = "sekai.source-batch/v9".into();
        let denied = project_source_health(&unknown, &query(), 200);
        assert_eq!(denied.class, CLASS_UNAVAILABLE);
        assert_eq!(denied.failure_class, FAILURE_UNKNOWN_VERSION);
        assert_eq!(denied.outcome, OUTCOME_DENIAL);
        assert_eq!(denied.checkpoint_age_ms, None);

        let mut foreign = healthy_state();
        foreign.checkpoint.as_mut().unwrap().namespace = "other".into();
        let denied = project_source_health(&foreign, &query(), 200);
        assert_eq!(denied.failure_class, FAILURE_FOREIGN_IDENTITY);

        let mut invalid = healthy_state();
        invalid.checkpoint.as_mut().unwrap().cursor = "ghp_not-a-checkpoint".into();
        let denied = project_source_health(&invalid, &query(), 200);
        assert_eq!(denied.failure_class, FAILURE_INVALID_CHECKPOINT);

        let mut ambiguous = healthy_state();
        ambiguous.last_result.as_mut().unwrap().transaction.outcome = OperationOutcome::Unknown;
        let denied = project_source_health(&ambiguous, &query(), 200);
        assert_eq!(denied.class, CLASS_UNAVAILABLE);
        assert_eq!(denied.failure_class, FAILURE_AMBIGUOUS);
        assert_eq!(denied.outcome, OUTCOME_UNKNOWN);
        assert_ne!(denied.class, CLASS_HEALTHY);
    }

    #[test]
    fn recovery_required_and_aborted_are_blocked() {
        let mut recovery = healthy_state();
        recovery.current_generation = Some(SourceSyncGeneration {
            binding_id: "bind-1".into(),
            sync_generation: 1,
            status: SourceSyncGenerationStatus::RecoveryRequired,
            delivery_mode: SourceDeliveryMode::ChangeFeed,
            source_feed_epoch: Some("epoch-1".into()),
            committed_offset: Some(1),
            reason: "missing_range".into(),
            created_at_ms: 10,
            updated_at_ms: 40,
        });
        let blocked = project_source_health(&recovery, &query(), 200);
        assert_eq!(blocked.class, CLASS_BLOCKED);
        assert_eq!(blocked.failure_class, FAILURE_RECOVERY_REQUIRED);

        let mut aborted = healthy_state();
        aborted.last_result.as_mut().unwrap().transaction.status = SourceBatchStatus::Aborted;
        aborted.last_result.as_mut().unwrap().checkpoint_advanced = false;
        let blocked = project_source_health(&aborted, &query(), 200);
        assert_eq!(blocked.class, CLASS_BLOCKED);
        assert_eq!(blocked.failure_class, FAILURE_ABORTED);
    }

    #[test]
    fn request_errors_fail_before_state_lookup() {
        assert!(
            parse_source_health_query(
                "acme",
                "acme/ops",
                GITHUB_OBJECT_SYNC_TYPE_DIGEST,
                None,
                Some("sekai.source-health/v0")
            )
            .unwrap_err()
            .contains("unsupported source health version")
        );
        assert!(
            parse_source_health_query("", "acme/ops", GITHUB_OBJECT_SYNC_TYPE_DIGEST, None, None)
                .unwrap_err()
                .contains("namespace is required")
        );
        assert!(
            parse_source_health_query("acme", "acme/ops", "not-a-digest", None, None)
                .unwrap_err()
                .contains("type digest is invalid")
        );
        assert!(
            parse_source_health_query(
                "acme",
                "sk-not-a-source",
                GITHUB_OBJECT_SYNC_TYPE_DIGEST,
                None,
                None
            )
            .unwrap_err()
            .contains("secret-like text")
        );
        let db = RuntimeDb::memory();
        assert!(
            report_source_health(&db, "", &query(), 200)
                .unwrap_err()
                .contains("actor is required")
        );
    }

    #[test]
    fn sqlite_apply_then_report_is_idempotent_and_resumes_from_durable_state() {
        let db = RuntimeDb::memory();
        let first = batch("", "cursor:1", "batch-1");
        db.apply_source_batch(&first, PRODUCER, 100).unwrap();
        let query = query();
        let first_report = report_source_health(&db, "root", &query, 200).unwrap();
        assert_eq!(first_report.class, CLASS_HEALTHY);
        assert_eq!(first_report.last_success_at_ms, Some(100));
        let replay = report_source_health(&db, "root", &query, 200).unwrap();
        assert_eq!(replay, first_report);
        let delayed =
            report_source_health(&db, "root", &query, 100 + DEFAULT_DELAYED_AFTER_MS + 5).unwrap();
        assert_eq!(delayed.class, CLASS_DELAYED);

        let second = batch("cursor:1", "cursor:2", "batch-2");
        db.apply_source_batch(&second, PRODUCER, 300).unwrap();
        let restarted = report_source_health(&db, "root", &query, 310).unwrap();
        assert_eq!(restarted.class, CLASS_HEALTHY);
        assert_eq!(restarted.last_success_at_ms, Some(300));
        assert_ne!(
            restarted.last_success_at_ms,
            first_report.last_success_at_ms
        );

        let hidden = report_source_health(&db, "stranger", &query, 310).unwrap();
        let unknown = report_source_health(
            &db,
            "root",
            &parse_source_health_query(
                "acme",
                "ghost/repo",
                GITHUB_OBJECT_SYNC_TYPE_DIGEST,
                None,
                None,
            )
            .unwrap(),
            310,
        )
        .unwrap();
        assert_eq!(hidden.class, CLASS_UNAVAILABLE);
        assert_eq!(hidden.failure_class, unknown.failure_class);
        assert_eq!(hidden.outcome, unknown.outcome);
        assert_eq!(hidden.checkpoint_age_ms, unknown.checkpoint_age_ms);
        assert_eq!(hidden.lag, unknown.lag);
        assert_eq!(hidden.last_success_at_ms, unknown.last_success_at_ms);

        let audit = latest_source_health_audit(&db, "acme").unwrap().unwrap();
        assert_eq!(audit.action, "source.health");
        assert!(!audit.id.contains("acme/ops"));
        assert!(
            !audit
                .evidence
                .values()
                .any(|value| value.contains("cursor:") || value.contains("acme/ops"))
        );
        assert_eq!(
            audit.evidence.get("write_authority").map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn recovery_required_generation_is_blocked_after_durable_apply() {
        let db = RuntimeDb::memory();
        let mut snapshot = batch("", "cursor:snapshot", "snapshot-1");
        snapshot.contract_version = SOURCE_BATCH_V2_VERSION.into();
        snapshot.delivery = Some(crate::sekai::object_sync::SourceDeliveryWindow {
            mode: SourceDeliveryMode::Snapshot,
            sync_generation: 1,
            source_feed_epoch: Some("epoch-1".into()),
            offset_start: None,
            offset_end: Some(40),
            snapshot_complete: true,
        });
        snapshot.batch_digest = snapshot.canonical_digest().unwrap();
        db.apply_source_batch(&snapshot, PRODUCER, 100).unwrap();

        let mut feed = batch("cursor:snapshot", "cursor:41", "feed-41");
        feed.contract_version = SOURCE_BATCH_V2_VERSION.into();
        feed.records[0].source_sequence = Some(41);
        feed.delivery = Some(crate::sekai::object_sync::SourceDeliveryWindow {
            mode: SourceDeliveryMode::ChangeFeed,
            sync_generation: 1,
            source_feed_epoch: Some("epoch-1".into()),
            offset_start: Some(40),
            offset_end: Some(41),
            snapshot_complete: false,
        });
        feed.batch_digest = feed.canonical_digest().unwrap();
        db.apply_source_batch(&feed, PRODUCER, 200).unwrap();

        let mut missing = batch("cursor:41", "cursor:missing", "missing");
        missing.contract_version = SOURCE_BATCH_V2_VERSION.into();
        missing.records[0].source_sequence = Some(51);
        missing.delivery = Some(crate::sekai::object_sync::SourceDeliveryWindow {
            mode: SourceDeliveryMode::ChangeFeed,
            sync_generation: 1,
            source_feed_epoch: Some("epoch-1".into()),
            offset_start: Some(50),
            offset_end: Some(51),
            snapshot_complete: false,
        });
        missing.batch_digest = missing.canonical_digest().unwrap();
        assert!(
            db.apply_source_batch(&missing, PRODUCER, 400)
                .unwrap_err()
                .starts_with("missing_range:")
        );

        let blocked = report_source_health(&db, "root", &query(), 410).unwrap();
        assert_eq!(blocked.class, CLASS_BLOCKED);
        assert_eq!(blocked.failure_class, FAILURE_RECOVERY_REQUIRED);
        assert_eq!(blocked.last_success_at_ms, Some(200));
    }
}
