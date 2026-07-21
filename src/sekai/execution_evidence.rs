//! Durable host-reported lifecycle evidence for redeemed external-action permits.
//!
//! Host reports remain attributed observations. They do not prove that Chisei
//! performed an effect or that an independently observed downstream outcome
//! occurred.

use crate::chisei::external_permit::{HostContext, Permit, Redemption};
use crate::chisei::receipt::{
    GovernedReference, OperationReceiptEvent, ReceiptEventKind, ReceiptSurface,
};
use crate::db::sekai::SekaiDb;
use crate::shomei::{AttestationBundle, canonical_json};
use ed25519_dalek::VerifyingKey;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const EXECUTION_EVIDENCE_TYPE: &str = "external_action_execution";
pub const EXECUTION_EVIDENCE_SCHEMA: &str = "external-action.execution-evidence/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLifecycleState {
    Accepted,
    Started,
    Completed,
    Failed,
    Cancelled,
    OutcomeUnknown,
}

impl ExecutionLifecycleState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::OutcomeUnknown
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Started => "started",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEvidence {
    pub version: String,
    pub permit_id: String,
    pub redemption_id: String,
    pub execution_id: String,
    pub host_identity: String,
    pub lifecycle_state: ExecutionLifecycleState,
    pub observed_at_ms: i64,
    #[serde(default)]
    pub started_at_ms: Option<i64>,
    #[serde(default)]
    pub finished_at_ms: Option<i64>,
    #[serde(default)]
    pub enforced_preconditions: BTreeMap<String, String>,
    #[serde(default)]
    pub normalized_effects: Vec<String>,
    #[serde(default)]
    pub affected_resource_references: Vec<String>,
    #[serde(default)]
    pub cost_micros: u64,
    #[serde(default)]
    pub resource_use: BTreeMap<String, u64>,
    #[serde(default)]
    pub artifact_hashes: Vec<String>,
    #[serde(default)]
    pub exit_classification: String,
    #[serde(default)]
    pub error_classification: String,
    #[serde(default)]
    pub compensation_evidence_hashes: Vec<String>,
    pub host_schema_version: String,
    pub host_software_version: String,
}

impl ExecutionEvidence {
    pub fn validate(&self) -> Result<(), String> {
        for (field, value) in [
            ("permit_id", self.permit_id.as_str()),
            ("redemption_id", self.redemption_id.as_str()),
            ("execution_id", self.execution_id.as_str()),
            ("host_identity", self.host_identity.as_str()),
            ("host_schema_version", self.host_schema_version.as_str()),
            ("host_software_version", self.host_software_version.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("execution evidence {field} is required"));
            }
        }
        if self.version != EXECUTION_EVIDENCE_SCHEMA {
            return Err("unsupported execution evidence version".into());
        }
        if self.lifecycle_state.is_terminal() != self.finished_at_ms.is_some() {
            return Err(
                "terminal evidence requires finished_at_ms and non-terminal evidence forbids it"
                    .into(),
            );
        }
        if self
            .started_at_ms
            .is_some_and(|started| started > self.observed_at_ms)
            || self
                .finished_at_ms
                .is_some_and(|finished| finished > self.observed_at_ms)
            || matches!(self.lifecycle_state, ExecutionLifecycleState::Started)
                && self.started_at_ms.is_none()
        {
            return Err("execution evidence timestamps are inconsistent".into());
        }
        if self
            .started_at_ms
            .zip(self.finished_at_ms)
            .is_some_and(|(started, finished)| finished < started)
        {
            return Err("execution evidence finished_at_ms precedes started_at_ms".into());
        }
        if self.lifecycle_state == ExecutionLifecycleState::Completed
            && !self.error_classification.is_empty()
        {
            return Err("completed evidence cannot carry an error classification".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEvidenceAlert {
    pub alert_id: String,
    pub kind: String,
    pub permit_id: String,
    pub redemption_id: String,
    pub execution_id: String,
    pub observed_at_ms: i64,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionReceiptStatus {
    pub requested: String,
    pub authorization: String,
    pub permit: String,
    pub redemption: String,
    pub host_execution: String,
    pub independent_effect_verification: String,
    pub downstream_outcome: String,
}

impl ExternalActionReceiptStatus {
    pub fn from_report(report: Option<&ExecutionEvidence>) -> Self {
        Self {
            requested: "recorded".into(),
            authorization: "permitted".into(),
            permit: "issued".into(),
            redemption: "redeemed".into(),
            host_execution: report
                .map(|value| value.lifecycle_state.as_str())
                .unwrap_or("unknown")
                .into(),
            independent_effect_verification: "unknown".into(),
            downstream_outcome: "unknown".into(),
        }
    }
}

impl SekaiDb {
    fn ensure_execution_evidence_tables(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_external_action_execution_evidence (
                submission_id TEXT PRIMARY KEY,
                permit_id TEXT NOT NULL,
                redemption_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                producer_identity TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                source_sequence INTEGER NOT NULL,
                content_digest TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                projection_status TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_external_execution_evidence
                ON sekai_external_action_execution_evidence(execution_id, source_sequence);
             CREATE TABLE IF NOT EXISTS sekai_external_action_execution_state (
                redemption_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL,
                permit_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_instance TEXT NOT NULL,
                source_record_id TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                source_sequence INTEGER NOT NULL,
                terminal INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sekai_external_action_execution_alerts (
                alert_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                permit_id TEXT NOT NULL,
                redemption_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                summary TEXT NOT NULL
             );",
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Project one already-admitted Sekai envelope into the external-action
    /// lifecycle. The source envelope remains the authoritative evidence.
    pub fn record_execution_evidence(&self, submission_id: &str) -> Result<bool, String> {
        self.ensure_execution_evidence_tables()?;
        let submission = self
            .get_evidence_submission(submission_id)?
            .ok_or_else(|| "execution evidence submission not found".to_string())?;
        if submission.evidence_type != EXECUTION_EVIDENCE_TYPE {
            return Ok(false);
        }
        if !submission.lifecycle_state.is_usable() {
            return Err("execution evidence must be available before lifecycle projection".into());
        }
        let envelope = submission
            .envelope
            .ok_or_else(|| "execution evidence envelope is unavailable".to_string())?;
        let report = self
            .validate_execution_evidence_envelope(&envelope, &submission.producer_identity)?
            .ok_or_else(|| "execution evidence envelope was not recognized".to_string())?;

        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let existing_status: Option<String> = tx
            .query_row(
                "SELECT projection_status FROM sekai_external_action_execution_evidence
                 WHERE submission_id=?1",
                [submission_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(status) = existing_status {
            tx.commit().map_err(|error| error.to_string())?;
            return if status == "projected" {
                Ok(true)
            } else {
                Ok(false)
            };
        }
        let current: Option<(String, i64, bool, String, String, String)> = tx
            .query_row(
                "SELECT lifecycle_state,source_sequence,terminal,
                        source_type,source_instance,source_record_id
             FROM sekai_external_action_execution_state WHERE redemption_id=?1",
                [&report.redemption_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get::<_, i64>(2)? != 0,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let transition_ok = valid_transition(
            current.as_ref(),
            submission.source_sequence,
            report.lifecycle_state,
            &envelope.source_type,
            &envelope.source_instance,
            &envelope.source_record_id,
        );

        let json = serde_json::to_string(&report).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_external_action_execution_evidence
             (submission_id,permit_id,redemption_id,execution_id,producer_identity,lifecycle_state,
              source_sequence,content_digest,evidence_json,observed_at_ms,projection_status)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                submission_id,
                report.permit_id,
                report.redemption_id,
                report.execution_id,
                report.host_identity,
                report.lifecycle_state.as_str(),
                submission.source_sequence,
                submission.content_digest,
                json,
                report.observed_at_ms,
                if transition_ok {
                    "projected"
                } else {
                    "conflict"
                }
            ],
        )
        .map_err(|error| error.to_string())?;
        if !transition_ok {
            let alert = conflict_alert(&report, submission_id, submission.received_at_ms);
            insert_alert_and_audit(&tx, &alert)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO sekai_external_action_execution_state
             (redemption_id,execution_id,permit_id,source_type,source_instance,source_record_id,
              lifecycle_state,source_sequence,terminal,updated_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(redemption_id) DO UPDATE SET lifecycle_state=excluded.lifecycle_state,
               source_sequence=excluded.source_sequence,terminal=excluded.terminal,updated_at_ms=excluded.updated_at_ms",
            params![report.redemption_id, report.execution_id, report.permit_id,
                envelope.source_type, envelope.source_instance, envelope.source_record_id,
                report.lifecycle_state.as_str(), submission.source_sequence,
                report.lifecycle_state.is_terminal(), submission.received_at_ms],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn validate_execution_evidence_envelope(
        &self,
        envelope: &crate::sekai::evidence::EvidenceEnvelope,
        authenticated_producer: &str,
    ) -> Result<Option<ExecutionEvidence>, String> {
        if envelope.evidence_type != EXECUTION_EVIDENCE_TYPE {
            return Ok(None);
        }
        self.ensure_execution_evidence_tables()?;
        let report: ExecutionEvidence =
            serde_json::from_value(envelope.content.clone()).map_err(|_| {
                "execution evidence content does not match the registered schema".to_string()
            })?;
        report.validate()?;
        if report.observed_at_ms != envelope.observed_at_ms {
            return Err("execution evidence timestamp does not match its admitted envelope".into());
        }
        if envelope.source_record_id != report.execution_id {
            return Err("execution evidence source record does not match its execution".into());
        }
        if report.host_identity != authenticated_producer {
            return Err("execution evidence host attribution does not match its producer".into());
        }
        let redemption_json: String = self
            .conn()
            .query_row(
                "SELECT redemption_json FROM chisei_external_action_redemptions
             WHERE permit_id=?1 AND execution_id=?2",
                params![report.permit_id, report.execution_id],
                |row| row.get(0),
            )
            .map_err(|_| {
                "execution evidence does not reference a durable redemption".to_string()
            })?;
        let redemption: Redemption =
            serde_json::from_str(&redemption_json).map_err(|error| error.to_string())?;
        if redemption.redemption_id != report.redemption_id {
            return Err("execution evidence redemption binding changed".into());
        }
        if redemption.executor != authenticated_producer {
            return Err("execution evidence producer did not redeem the referenced permit".into());
        }
        if report.observed_at_ms < redemption.redeemed_at_ms
            || report
                .started_at_ms
                .is_some_and(|value| value < redemption.redeemed_at_ms)
            || report
                .finished_at_ms
                .is_some_and(|value| value < redemption.redeemed_at_ms)
        {
            return Err("execution evidence predates permit redemption".into());
        }
        Ok(Some(report))
    }

    /// Persist idempotent governance alerts for redemptions whose signed
    /// evidence window elapsed without terminal host evidence.
    pub fn reconcile_missing_execution_evidence(
        &self,
        now_ms: i64,
    ) -> Result<Vec<ExecutionEvidenceAlert>, String> {
        self.ensure_external_permit_tables()?;
        self.ensure_execution_evidence_tables()?;
        let mut conn = self.conn();
        let rows = {
            let mut statement = conn
                .prepare(
                    "SELECT r.redemption_json,r.evidence_due_at_ms
                     FROM chisei_external_action_redemptions r
                     LEFT JOIN sekai_external_action_execution_state s
                       ON s.redemption_id=r.redemption_id AND s.terminal=1
                          AND s.updated_at_ms<=r.evidence_due_at_ms
                     LEFT JOIN sekai_external_action_execution_alerts a
                       ON a.alert_id=('missing-execution-evidence:' || r.redemption_id)
                     WHERE r.evidence_due_at_ms>0 AND r.evidence_due_at_ms<=?1
                       AND s.redemption_id IS NULL AND a.alert_id IS NULL
                     ORDER BY r.evidence_due_at_ms,r.redemption_id LIMIT 100",
                )
                .map_err(|error| error.to_string())?;
            statement
                .query_map([now_ms], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        let mut alerts = Vec::new();
        for (row, evidence_due_at_ms) in rows {
            let redemption: Redemption =
                serde_json::from_str(&row).map_err(|error| error.to_string())?;
            let alert = ExecutionEvidenceAlert {
                alert_id: format!("missing-execution-evidence:{}", redemption.redemption_id),
                kind: "missing_execution_evidence".into(),
                permit_id: redemption.permit_id,
                redemption_id: redemption.redemption_id,
                execution_id: redemption.execution_id,
                observed_at_ms: now_ms,
                summary: "redeemed external action has no terminal host evidence within its signed window".into(),
            };
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            let still_missing: bool = tx
                .query_row(
                    "SELECT NOT EXISTS(
                         SELECT 1 FROM sekai_external_action_execution_state
                         WHERE redemption_id=?1 AND terminal=1 AND updated_at_ms<=?3
                     ) AND NOT EXISTS(
                         SELECT 1 FROM sekai_external_action_execution_alerts
                         WHERE alert_id=?2
                     )",
                    params![alert.redemption_id, alert.alert_id, evidence_due_at_ms],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if still_missing {
                insert_alert_and_audit(&tx, &alert)?;
            }
            tx.commit().map_err(|error| error.to_string())?;
            if still_missing {
                alerts.push(alert);
            }
        }
        Ok(alerts)
    }
}

fn valid_transition(
    current: Option<&(String, i64, bool, String, String, String)>,
    source_sequence: i64,
    next: ExecutionLifecycleState,
    source_type: &str,
    source_instance: &str,
    source_record_id: &str,
) -> bool {
    match current {
        None => next == ExecutionLifecycleState::Accepted,
        Some((state, sequence, terminal, current_type, current_instance, current_record)) => {
            source_sequence > *sequence
                && !*terminal
                && current_type == source_type
                && current_instance == source_instance
                && current_record == source_record_id
                && matches!(
                    (state.as_str(), next),
                    ("accepted", ExecutionLifecycleState::Started)
                        | ("accepted", ExecutionLifecycleState::Completed)
                        | ("accepted", ExecutionLifecycleState::Failed)
                        | ("accepted", ExecutionLifecycleState::Cancelled)
                        | ("accepted", ExecutionLifecycleState::OutcomeUnknown)
                        | ("started", ExecutionLifecycleState::Completed)
                        | ("started", ExecutionLifecycleState::Failed)
                        | ("started", ExecutionLifecycleState::Cancelled)
                        | ("started", ExecutionLifecycleState::OutcomeUnknown)
                )
        }
    }
}

fn conflict_alert(
    report: &ExecutionEvidence,
    submission_id: &str,
    received_at_ms: i64,
) -> ExecutionEvidenceAlert {
    ExecutionEvidenceAlert {
        alert_id: format!(
            "conflicting-execution-evidence:{}:{}",
            report.redemption_id, submission_id
        ),
        kind: "conflicting_execution_evidence".into(),
        permit_id: report.permit_id.clone(),
        redemption_id: report.redemption_id.clone(),
        execution_id: report.execution_id.clone(),
        observed_at_ms: received_at_ms,
        summary: "host lifecycle report conflicts with previously admitted execution evidence"
            .into(),
    }
}

fn insert_alert_and_audit(
    conn: &rusqlite::Connection,
    alert: &ExecutionEvidenceAlert,
) -> Result<(), String> {
    let inserted = conn
        .execute(
            "INSERT OR IGNORE INTO sekai_external_action_execution_alerts
         (alert_id,kind,permit_id,redemption_id,execution_id,observed_at_ms,summary)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                alert.alert_id,
                alert.kind,
                alert.permit_id,
                alert.redemption_id,
                alert.execution_id,
                alert.observed_at_ms,
                alert.summary
            ],
        )
        .map_err(|error| error.to_string())?;
    if inserted == 1 {
        crate::sekai::ledger::insert_chained_decision(
            conn,
            &crate::sekai::audit::Decision {
                id: format!("{}:audit", alert.alert_id),
                timestamp: alert.observed_at_ms,
                actor: "sekai:execution-reconciliation".into(),
                action: "external_action_execution/alert".into(),
                reason: alert.kind.clone(),
                evidence: HashMap::from([
                    ("permit_id".into(), alert.permit_id.clone()),
                    ("redemption_id".into(), alert.redemption_id.clone()),
                    ("execution_id".into(), alert.execution_id.clone()),
                ]),
                target_id: alert.execution_id.clone(),
                outcome: "alert".into(),
            },
        )?;
    }
    Ok(())
}

/// Shared host-side conformance check. Executors must advertise every
/// enforcement capability before they can redeem or report execution.
pub fn verify_for_executor(
    permit: &Permit,
    trusted_key: &VerifyingKey,
    trusted_issuer: &str,
    trusted_key_id: &str,
    context: &HostContext,
    now_ms: i64,
) -> Result<(), String> {
    permit.verify_trust(trusted_issuer, trusted_key_id)?;
    permit.verify_signature(trusted_key)?;
    permit.verify_host_context(context, now_ms)
}

pub fn receipt_event(
    permit: &Permit,
    report: &ExecutionEvidence,
    submission_id: &str,
    permit_digest: &str,
    evidence_digest: &str,
) -> OperationReceiptEvent {
    OperationReceiptEvent {
        event_id: format!(
            "external-action:{}:{}",
            report.execution_id,
            report.lifecycle_state.as_str()
        ),
        operation_id: permit.operation_id.clone(),
        parent_event_id: None,
        timestamp_ms: report.observed_at_ms,
        kind: ReceiptEventKind::ActionPerformed,
        surface: ReceiptSurface::Action,
        actor: report.host_identity.clone(),
        references: vec![
            GovernedReference {
                kind: "external_action_permit".into(),
                reference: report.permit_id.clone(),
                content_hash: Some(permit_digest.into()),
                disclosed_fields: vec![],
                omitted: false,
                omission_reason: None,
            },
            GovernedReference {
                kind: "host_execution_evidence".into(),
                reference: submission_id.into(),
                content_hash: Some(evidence_digest.into()),
                disclosed_fields: vec![],
                omitted: false,
                omission_reason: None,
            },
        ],
        attributes: BTreeMap::from([
            ("authorization_stage".into(), "redeemed".into()),
            (
                "execution_stage".into(),
                report.lifecycle_state.as_str().into(),
            ),
            ("effect_verification".into(), "host_report_only".into()),
        ]),
    }
}

/// Embed the signed permit and host report into an existing Shomei receipt
/// bundle. Offline verification proves bundle integrity, not unobserved host
/// enforcement or physical effects.
pub fn attach_to_shomei_bundle(
    bundle: &mut AttestationBundle,
    permit: &Permit,
    report: &ExecutionEvidence,
    submission_id: &str,
) -> Result<(), String> {
    bundle.attach_artifact(
        &permit.permit_id,
        Some("application/json".into()),
        &canonical_json(permit)?,
    )?;
    bundle.attach_artifact(
        submission_id,
        Some("application/json".into()),
        &canonical_json(report)?,
    )
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::external_action::PERMIT_VERSION;
    use crate::chisei::external_permit::{REDEMPTION_MODE, SIGNATURE_ALGORITHM};
    use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, OperationReceipt, UncoveredSurface};
    use crate::domain::Object;
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
        EvidenceSignal, EvidenceTarget, SchemaCompatibility,
    };
    use crate::sekai::evidence_store::{
        EvidenceProducerCapability, EvidenceSchemaDefinition, canonical_content_digest,
    };
    use ed25519_dalek::SigningKey;

    fn permit(executor: &str, capability: &str) -> (Permit, SigningKey) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut permit = Permit {
            version: PERMIT_VERSION.into(),
            permit_id: format!("permit-{executor}"),
            authorization_id: "authorization-1".into(),
            request_digest: "request-digest".into(),
            issuer: "issuer:test".into(),
            subject_actor: "agent:test".into(),
            namespace: "local".into(),
            operation_id: "operation-1".into(),
            requesting_harness: "harness:v1".into(),
            executor: executor.into(),
            action_type: "write_file".into(),
            parameter_schema: "write-file/v1".into(),
            canonical_arguments_digest: "arguments-digest".into(),
            target_selectors: vec!["workspace/file.txt".into()],
            immutable_preconditions: BTreeMap::from([("etag".into(), "v1".into())]),
            allowed_effects: vec!["file_updated".into()],
            required_host_capabilities: vec![capability.into()],
            constraints: vec![format!("host_capability:{capability}")],
            risk_class: "write".into(),
            budget_micros: 100,
            volume_limit: 1,
            blast_radius_limit: 1,
            max_invocations: 1,
            not_before_ms: 1_000,
            expires_at_ms: 2_000,
            redemption_mode: REDEMPTION_MODE.into(),
            approval_identities: vec![],
            policy_version: "policy/v1".into(),
            schema_version: "write-file/v1".into(),
            capability_version: "write_file/v1".into(),
            pricing_version: "pricing/v1".into(),
            nonce: "nonce".into(),
            delegation_depth: 0,
            parent_permit_id: String::new(),
            revocation_handle: "revoke-1".into(),
            signature_algorithm: SIGNATURE_ALGORITHM.into(),
            key_id: "key-1".into(),
            public_key: String::new(),
            issued_at_ms: 1_000,
            revocation_latency_ms: 0,
            signed_digest: String::new(),
            signature: vec![],
        };
        permit.sign(&key).unwrap();
        (permit, key)
    }

    fn context(permit: &Permit, capabilities: Vec<String>) -> HostContext {
        HostContext {
            executor: permit.executor.clone(),
            requesting_harness: permit.requesting_harness.clone(),
            canonical_arguments_digest: permit.canonical_arguments_digest.clone(),
            target_selectors: permit.target_selectors.clone(),
            observed_preconditions: permit.immutable_preconditions.clone(),
            host_capabilities: capabilities,
        }
    }

    fn report(state: ExecutionLifecycleState) -> ExecutionEvidence {
        ExecutionEvidence {
            version: EXECUTION_EVIDENCE_SCHEMA.into(),
            permit_id: "permit-1".into(),
            redemption_id: "redemption-1".into(),
            execution_id: "execution-1".into(),
            host_identity: "executor:file".into(),
            lifecycle_state: state,
            observed_at_ms: 1_500,
            started_at_ms: (!matches!(state, ExecutionLifecycleState::Accepted)).then_some(1_200),
            finished_at_ms: state.is_terminal().then_some(1_400),
            enforced_preconditions: BTreeMap::new(),
            normalized_effects: vec![],
            affected_resource_references: vec![],
            cost_micros: 0,
            resource_use: BTreeMap::new(),
            artifact_hashes: vec![],
            exit_classification: String::new(),
            error_classification: String::new(),
            compensation_evidence_hashes: vec![],
            host_schema_version: "host-evidence/v1".into(),
            host_software_version: "executor/1.0".into(),
        }
    }

    fn envelope(report: &ExecutionEvidence, sequence: i64) -> EvidenceEnvelope {
        let content = serde_json::to_value(report).unwrap();
        EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "host_executor".into(),
            source_instance: "executor:file:instance-1".into(),
            source_record_id: report.execution_id.clone(),
            source_version: format!("state-{sequence}"),
            source_sequence: sequence,
            target: EvidenceTarget {
                namespace: "local".into(),
                object_external_id: "action:1".into(),
                object_kind: "action".into(),
            },
            evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
            signal: EvidenceSignal::Delivery,
            schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
            schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: report.observed_at_ms,
            collected_at_ms: report.observed_at_ms,
            expires_at_ms: None,
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: report.host_identity.clone(),
            confidence_bps: 8_000,
            classification: EvidenceClassification::Internal,
            provenance: BTreeMap::new(),
            idempotency_key: format!("execution-{}-{sequence}", report.execution_id),
            intent: EvidenceIntent::Upsert,
            causality: None,
        }
    }

    #[test]
    fn lifecycle_states_remain_distinct_and_unknown_is_terminal() {
        let states = [
            ExecutionLifecycleState::Accepted,
            ExecutionLifecycleState::Started,
            ExecutionLifecycleState::Completed,
            ExecutionLifecycleState::Failed,
            ExecutionLifecycleState::Cancelled,
            ExecutionLifecycleState::OutcomeUnknown,
        ];
        let encoded = states
            .into_iter()
            .map(|state| serde_json::to_string(&state).unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(encoded.len(), 6);
        assert!(!ExecutionLifecycleState::Accepted.is_terminal());
        assert!(ExecutionLifecycleState::OutcomeUnknown.is_terminal());
        assert!(
            report(ExecutionLifecycleState::OutcomeUnknown)
                .validate()
                .is_ok()
        );
        let status = ExternalActionReceiptStatus::from_report(None);
        assert_eq!(status.host_execution, "unknown");
        assert_eq!(status.independent_effect_verification, "unknown");
        assert_eq!(status.downstream_outcome, "unknown");
    }

    #[test]
    fn two_materially_different_executors_share_conformance_and_refuse_gaps() {
        for (executor, capability) in [
            ("executor:filesystem", "atomic_rename"),
            ("executor:http", "conditional_request"),
        ] {
            let (permit, key) = permit(executor, capability);
            verify_for_executor(
                &permit,
                &key.verifying_key(),
                "issuer:test",
                "key-1",
                &context(&permit, vec![capability.into()]),
                1_500,
            )
            .unwrap();
            let error = verify_for_executor(
                &permit,
                &key.verifying_key(),
                "issuer:test",
                "key-1",
                &context(&permit, vec![]),
                1_500,
            )
            .unwrap_err();
            assert!(error.contains("cannot enforce"));
        }
    }

    #[test]
    fn overdue_redemption_alerts_without_promoting_success() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.set_permit_kill_switch("executor", "unused", false, "", 0)
            .unwrap();
        let redemption = Redemption {
            version: "external-action.redemption/v1".into(),
            permit_id: "permit-1".into(),
            redemption_id: "redemption-1".into(),
            executor: "executor:file".into(),
            execution_id: "execution-1".into(),
            idempotency_key: "redeem-1".into(),
            redeemed_at_ms: 1_000,
            invocation_ordinal: 1,
            evidence_due_at_ms: 2_000,
        };
        db.conn()
            .execute(
                "INSERT INTO chisei_external_action_redemptions
                 (permit_id,idempotency_key,execution_id,redemption_json,redeemed_at_ms,invocation_ordinal,redemption_id,evidence_due_at_ms)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    redemption.permit_id,
                    redemption.idempotency_key,
                    redemption.execution_id,
                    serde_json::to_string(&redemption).unwrap(),
                    redemption.redeemed_at_ms,
                    redemption.invocation_ordinal,
                    redemption.redemption_id,
                    redemption.evidence_due_at_ms
                ],
            )
            .unwrap();
        assert!(
            db.reconcile_missing_execution_evidence(1_999)
                .unwrap()
                .is_empty()
        );
        let alerts = db.reconcile_missing_execution_evidence(2_000).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "missing_execution_evidence");
        assert!(!alerts[0].summary.contains("success"));
        assert_eq!(
            db.reconcile_missing_execution_evidence(2_001)
                .unwrap()
                .len(),
            0
        );
        let persisted: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_external_action_execution_alerts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, 1);
        let governance_events: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_decisions
                 WHERE action='external_action_execution/alert'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(governance_events, 1);
    }

    #[test]
    fn admitted_funnel_reports_advance_without_collapsing_terminal_state() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "action-1".into(),
            kind: "action".into(),
            name: "action".into(),
            namespace: "local".into(),
            external_id: "action:1".into(),
            properties: Default::default(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.upsert_evidence_producer(
            &EvidenceProducerCapability {
                producer_identity: "executor:file".into(),
                config_version: 1,
                source_types: vec!["host_executor".into()],
                source_instances: vec!["executor:file:instance-1".into()],
                namespaces: vec!["local".into()],
                evidence_types: vec![EXECUTION_EVIDENCE_TYPE.into()],
                target_kinds: vec!["action".into()],
                classification_ceiling: EvidenceClassification::Internal,
                allowed_intents: vec![EvidenceIntent::Upsert],
                allow_operation_attachment: false,
                replay_window_ms: 60_000,
                max_clock_skew_ms: 60_000,
                max_payload_bytes: 64 * 1024,
                max_relationships: 8,
                rate_limit_per_minute: 100,
                max_retained_submissions: 100,
                revoked: false,
            },
            1_000,
        )
        .unwrap();
        db.register_evidence_schema(
            &EvidenceSchemaDefinition {
                schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
                schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
                evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
                compatible_versions: vec![],
            },
            1_000,
        )
        .unwrap();
        db.set_permit_kill_switch("executor", "unused", false, "", 0)
            .unwrap();
        let redemption = Redemption {
            version: "external-action.redemption/v1".into(),
            permit_id: "permit-1".into(),
            redemption_id: "redemption-1".into(),
            executor: "executor:file".into(),
            execution_id: "execution-1".into(),
            idempotency_key: "redeem-1".into(),
            redeemed_at_ms: 1_000,
            invocation_ordinal: 1,
            evidence_due_at_ms: 2_000,
        };
        db.conn().execute(
            "INSERT INTO chisei_external_action_redemptions
             (permit_id,idempotency_key,execution_id,redemption_json,redeemed_at_ms,invocation_ordinal,redemption_id,evidence_due_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![redemption.permit_id, redemption.idempotency_key, redemption.execution_id,
                serde_json::to_string(&redemption).unwrap(), redemption.redeemed_at_ms,
                redemption.invocation_ordinal, redemption.redemption_id,
                redemption.evidence_due_at_ms],
        ).unwrap();

        for (sequence, state) in [
            (1, ExecutionLifecycleState::Accepted),
            (2, ExecutionLifecycleState::Started),
            (3, ExecutionLifecycleState::OutcomeUnknown),
        ] {
            let mut value = report(state);
            value.observed_at_ms += sequence;
            let envelope = envelope(&value, sequence);
            let admitted = db
                .submit_evidence(&envelope, "executor:file", value.observed_at_ms)
                .unwrap();
            assert!(admitted.accepted);
            db.project_evidence_submission(&admitted.submission.id, value.observed_at_ms)
                .unwrap();
            assert!(
                db.record_execution_evidence(&admitted.submission.id)
                    .unwrap()
            );
            assert!(
                db.record_execution_evidence(&admitted.submission.id)
                    .unwrap()
            );
        }
        let state: String = db
            .conn()
            .query_row(
                "SELECT lifecycle_state FROM sekai_external_action_execution_state
             WHERE execution_id='execution-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "outcome_unknown");
        assert!(
            db.reconcile_missing_execution_evidence(2_500)
                .unwrap()
                .is_empty()
        );

        let mut conflict = report(ExecutionLifecycleState::Failed);
        conflict.observed_at_ms = 1_600;
        let conflict = envelope(&conflict, 4);
        let admitted = db
            .submit_evidence(&conflict, "executor:file", conflict.observed_at_ms)
            .unwrap();
        db.project_evidence_submission(&admitted.submission.id, conflict.observed_at_ms)
            .unwrap();
        assert!(
            !db.record_execution_evidence(&admitted.submission.id)
                .unwrap()
        );
        assert!(
            !db.record_execution_evidence(&admitted.submission.id)
                .unwrap()
        );
        let conflicts: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_external_action_execution_alerts
             WHERE kind='conflicting_execution_evidence'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(conflicts, 1);

        let mut spoofed = report(ExecutionLifecycleState::Accepted);
        spoofed.host_identity = "executor:other".into();
        let mut spoofed = envelope(&spoofed, 5);
        assert!(
            db.validate_execution_evidence_envelope(&spoofed, "executor:other")
                .unwrap_err()
                .contains("did not redeem")
        );
        spoofed.observed_at_ms += 1;
        assert!(
            db.validate_execution_evidence_envelope(&spoofed, "executor:other")
                .unwrap_err()
                .contains("timestamp")
        );

        let second = Redemption {
            permit_id: "permit-2".into(),
            redemption_id: "redemption-2".into(),
            idempotency_key: "redeem-2".into(),
            ..redemption.clone()
        };
        db.conn().execute(
            "INSERT INTO chisei_external_action_redemptions
             (permit_id,idempotency_key,execution_id,redemption_json,redeemed_at_ms,invocation_ordinal,redemption_id,evidence_due_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![second.permit_id, second.idempotency_key, second.execution_id,
                serde_json::to_string(&second).unwrap(), second.redeemed_at_ms,
                second.invocation_ordinal, second.redemption_id, second.evidence_due_at_ms],
        ).unwrap();
        let mut reused_execution = report(ExecutionLifecycleState::Accepted);
        reused_execution.permit_id = second.permit_id;
        reused_execution.redemption_id = second.redemption_id;
        assert!(
            db.validate_execution_evidence_envelope(
                &envelope(&reused_execution, 1),
                "executor:file"
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn shomei_verifies_embedded_signed_permit_and_host_report_offline() {
        let (permit, _) = permit("executor:filesystem", "atomic_rename");
        let mut report = report(ExecutionLifecycleState::Completed);
        report.permit_id = permit.permit_id.clone();
        let permit_bytes = canonical_json(&permit).unwrap();
        let evidence_bytes = canonical_json(&report).unwrap();
        let mut host_event = receipt_event(
            &permit,
            &report,
            "submission-1",
            &sha256(&permit_bytes),
            &sha256(&evidence_bytes),
        );
        host_event.parent_event_id = Some("budget".into());
        let event = |id: &str, parent: Option<&str>, kind, surface| OperationReceiptEvent {
            event_id: id.into(),
            operation_id: permit.operation_id.clone(),
            parent_event_id: parent.map(str::to_string),
            timestamp_ms: 1_100,
            kind,
            surface,
            actor: "agent:test".into(),
            references: vec![],
            attributes: BTreeMap::new(),
        };
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: permit.operation_id.clone(),
            parent_operation_id: None,
            namespace: permit.namespace.clone(),
            operation_class: "external_action".into(),
            initiating_actor: permit.subject_actor.clone(),
            schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
            policy_version: permit.policy_version.clone(),
            started_at_ms: 1_000,
            completed_at_ms: Some(1_500),
            events: vec![
                event(
                    "intent",
                    None,
                    ReceiptEventKind::IntentRecorded,
                    ReceiptSurface::Intent,
                ),
                event(
                    "policy",
                    Some("intent"),
                    ReceiptEventKind::PolicyDecided,
                    ReceiptSurface::Policy,
                ),
                event(
                    "route",
                    Some("policy"),
                    ReceiptEventKind::RouteSelected,
                    ReceiptSurface::Routing,
                ),
                event(
                    "budget",
                    Some("route"),
                    ReceiptEventKind::BudgetDecided,
                    ReceiptSurface::Budget,
                ),
                host_event,
            ],
            uncovered_surfaces: vec![UncoveredSurface {
                surface: ReceiptSurface::Outcome,
                reason: "host execution evidence is not independent outcome verification".into(),
            }],
            reporter_grants: vec![],
        };
        let mut bundle = AttestationBundle::unsigned(receipt).unwrap();
        attach_to_shomei_bundle(&mut bundle, &permit, &report, "submission-1").unwrap();
        let bundle_key = SigningKey::from_bytes(&[9; 32]);
        bundle
            .sign(&bundle_key, "shomei:test", "bundle-key", 1_600)
            .unwrap();
        let mut trusted = crate::shomei::TrustedKeyring::at_time(1_700);
        trusted
            .trust("shomei:test", "bundle-key", bundle_key.verifying_key())
            .unwrap();
        let verification = crate::shomei::verify_bundle(&bundle, &trusted);
        assert!(
            verification.integrity.valid,
            "{:?}",
            verification.integrity.errors
        );
        assert!(!verification.policy.compliant);
    }
}
