//! Durable admission state for externally produced evidence.

use crate::db::sekai::SekaiDb;
use crate::sekai::evidence::{
    EvidenceClassification, EvidenceEnvelope, EvidenceIntent, EvidenceLifecycleState,
    EvidenceLimits,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceProducerCapability {
    pub producer_identity: String,
    pub config_version: i64,
    pub source_instances: Vec<String>,
    pub namespaces: Vec<String>,
    pub evidence_types: Vec<String>,
    pub target_kinds: Vec<String>,
    pub classification_ceiling: EvidenceClassification,
    pub allowed_intents: Vec<EvidenceIntent>,
    pub allow_operation_attachment: bool,
    pub replay_window_ms: i64,
    pub max_payload_bytes: usize,
    pub max_relationships: usize,
    pub rate_limit_per_minute: u32,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSchemaDefinition {
    pub schema_id: String,
    pub schema_version: String,
    pub evidence_type: String,
    #[serde(default)]
    pub compatible_versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceSubmissionRecord {
    pub id: String,
    pub producer_identity: String,
    pub source_type: String,
    pub source_instance: String,
    pub source_record_id: String,
    pub source_version: String,
    pub source_sequence: i64,
    pub namespace: String,
    pub target_external_id: String,
    pub target_kind: String,
    pub evidence_type: String,
    pub schema_id: String,
    pub schema_version: String,
    pub idempotency_key: String,
    pub content_digest: String,
    pub classification: EvidenceClassification,
    pub intent: EvidenceIntent,
    pub lifecycle_state: EvidenceLifecycleState,
    pub rejection_code: Option<String>,
    pub rejection_summary: Option<String>,
    pub observed_at_ms: i64,
    pub collected_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub received_at_ms: i64,
    pub updated_at_ms: i64,
    pub envelope: Option<EvidenceEnvelope>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceAdmission {
    pub submission: EvidenceSubmissionRecord,
    pub accepted: bool,
    pub deduplicated: bool,
}

impl SekaiDb {
    pub(crate) fn migrate_evidence(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_evidence_producers (
                producer_identity TEXT PRIMARY KEY,
                config_version INTEGER NOT NULL,
                capability_json TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sekai_evidence_producer_history (
                producer_identity TEXT NOT NULL,
                config_version INTEGER NOT NULL,
                capability_json TEXT NOT NULL,
                recorded_at_ms INTEGER NOT NULL,
                PRIMARY KEY (producer_identity, config_version)
            );
            CREATE TABLE IF NOT EXISTS sekai_evidence_schemas (
                schema_id TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                definition_json TEXT NOT NULL,
                registered_at_ms INTEGER NOT NULL,
                PRIMARY KEY (schema_id, schema_version)
            );
            CREATE TABLE IF NOT EXISTS sekai_evidence_submissions (
                id TEXT PRIMARY KEY,
                producer_identity TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_instance TEXT NOT NULL,
                source_record_id TEXT NOT NULL,
                source_version TEXT NOT NULL,
                source_sequence INTEGER NOT NULL,
                namespace TEXT NOT NULL,
                target_external_id TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                schema_id TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                content_digest TEXT NOT NULL,
                classification TEXT NOT NULL,
                intent TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                rejection_code TEXT,
                rejection_summary TEXT,
                observed_at_ms INTEGER NOT NULL,
                collected_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER,
                received_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                envelope_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_submission_source
                ON sekai_evidence_submissions(source_instance, source_record_id, source_sequence);
            CREATE INDEX IF NOT EXISTS idx_evidence_submission_filters
                ON sekai_evidence_submissions(namespace, lifecycle_state, evidence_type, received_at_ms);
            CREATE TABLE IF NOT EXISTS sekai_evidence_idempotency (
                producer_identity TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                envelope_digest TEXT NOT NULL,
                submission_id TEXT NOT NULL,
                PRIMARY KEY (producer_identity, idempotency_key)
            );
            CREATE TABLE IF NOT EXISTS sekai_evidence_lifecycle_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submission_id TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                reason_code TEXT,
                recorded_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_lifecycle_submission
                ON sekai_evidence_lifecycle_history(submission_id, id);",
        )
        .map_err(|error| error.to_string())
    }

    pub fn upsert_evidence_producer(
        &self,
        capability: &EvidenceProducerCapability,
        now_ms: i64,
    ) -> Result<(), String> {
        validate_capability(capability)?;
        let capability_json =
            serde_json::to_string(capability).map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut registrations = tx
            .prepare(
                "SELECT capability_json FROM sekai_evidence_producers
                 WHERE producer_identity != ?1",
            )
            .map_err(|error| error.to_string())?;
        let existing_capabilities = registrations
            .query_map([&capability.producer_identity], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(registrations);
        for existing_json in existing_capabilities {
            let existing: EvidenceProducerCapability =
                serde_json::from_str(&existing_json).map_err(|error| error.to_string())?;
            if let Some(instance) = capability
                .source_instances
                .iter()
                .find(|instance| existing.source_instances.contains(instance))
            {
                return Err(format!(
                    "source instance {instance} is already owned by {}",
                    existing.producer_identity
                ));
            }
        }
        let current_version = tx
            .query_row(
                "SELECT config_version FROM sekai_evidence_producers WHERE producer_identity = ?1",
                [&capability.producer_identity],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if current_version.is_some_and(|version| capability.config_version <= version) {
            return Err("producer config version must increase".to_string());
        }
        tx.execute(
            "INSERT INTO sekai_evidence_producers
             (producer_identity, config_version, capability_json, revoked, updated_at_ms)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(producer_identity) DO UPDATE SET
                config_version=excluded.config_version,
                capability_json=excluded.capability_json,
                revoked=excluded.revoked,
                updated_at_ms=excluded.updated_at_ms",
            params![
                capability.producer_identity,
                capability.config_version,
                capability_json,
                capability.revoked,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_evidence_producer_history
             (producer_identity, config_version, capability_json, recorded_at_ms)
             VALUES (?1,?2,?3,?4)",
            params![
                capability.producer_identity,
                capability.config_version,
                capability_json,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn register_evidence_schema(
        &self,
        definition: &EvidenceSchemaDefinition,
        now_ms: i64,
    ) -> Result<(), String> {
        for (field, value) in [
            ("schema_id", definition.schema_id.as_str()),
            ("schema_version", definition.schema_version.as_str()),
            ("evidence_type", definition.evidence_type.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{field} is required"));
            }
        }
        let definition_json =
            serde_json::to_string(definition).map_err(|error| error.to_string())?;
        let conn = self.conn();
        let existing = conn
            .query_row(
                "SELECT definition_json FROM sekai_evidence_schemas
                 WHERE schema_id=?1 AND schema_version=?2",
                params![definition.schema_id, definition.schema_version],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(existing) = existing {
            return if existing == definition_json {
                Ok(())
            } else {
                Err("registered evidence schema versions are immutable".to_string())
            };
        }
        conn.execute(
            "INSERT INTO sekai_evidence_schemas
             (schema_id, schema_version, evidence_type, definition_json, registered_at_ms)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                definition.schema_id,
                definition.schema_version,
                definition.evidence_type,
                definition_json,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn submit_evidence(
        &self,
        envelope: &EvidenceEnvelope,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<EvidenceAdmission, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let envelope_digest = canonical_envelope_digest(envelope)?;

        if let Some((submission_id, stored_digest)) = tx
            .query_row(
                "SELECT submission_id, envelope_digest FROM sekai_evidence_idempotency
                 WHERE producer_identity = ?1 AND idempotency_key = ?2",
                params![authenticated_producer, envelope.idempotency_key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
        {
            if stored_digest == envelope_digest {
                let submission = get_submission_tx(&tx, &submission_id)?.ok_or_else(|| {
                    "idempotency record references missing submission".to_string()
                })?;
                tx.commit().map_err(|error| error.to_string())?;
                return Ok(EvidenceAdmission {
                    accepted: submission.lifecycle_state.is_admitted(),
                    submission,
                    deduplicated: true,
                });
            }
            return persist_rejection(
                tx,
                envelope,
                authenticated_producer,
                now_ms,
                "idempotency_conflict",
                "idempotency key was already used for different content",
            );
        }

        let submission_id = format!("evidence-{}", Uuid::new_v4().simple());
        insert_received(
            &tx,
            &submission_id,
            envelope,
            authenticated_producer,
            now_ms,
        )?;

        let computed_digest = canonical_content_digest(&envelope.content)?;
        if computed_digest != envelope.content_digest {
            return reject_existing(
                tx,
                &submission_id,
                now_ms,
                "digest_mismatch",
                "content digest did not match canonical content",
            );
        }

        let capability = load_capability(&tx, authenticated_producer)?;
        let limits = capability
            .as_ref()
            .map_or_else(EvidenceLimits::default, |capability| EvidenceLimits {
                max_content_bytes: capability.max_payload_bytes,
                max_relationships: capability.max_relationships,
                max_subject_references: capability.max_relationships,
            });
        if let Err(errors) = envelope.validate_contract(limits) {
            return reject_existing(
                tx,
                &submission_id,
                now_ms,
                "invalid_contract",
                &format!(
                    "evidence contract failed {} validation checks",
                    errors.len()
                ),
            );
        }
        transition(
            &tx,
            &submission_id,
            EvidenceLifecycleState::Validated,
            None,
            now_ms,
        )?;

        if envelope.producer_identity != authenticated_producer {
            return reject_existing(
                tx,
                &submission_id,
                now_ms,
                "producer_mismatch",
                "authenticated producer did not match envelope attribution",
            );
        }
        let Some(capability) = capability else {
            return reject_existing(
                tx,
                &submission_id,
                now_ms,
                "producer_unregistered",
                "producer is not registered",
            );
        };
        let recent_count = tx
            .query_row(
                "SELECT COUNT(*) FROM sekai_evidence_submissions
                 WHERE producer_identity=?1 AND received_at_ms>=?2",
                params![capability.producer_identity, now_ms.saturating_sub(60_000)],
                |row| row.get::<_, u32>(0),
            )
            .map_err(|error| error.to_string())?;
        if let Err((code, summary)) = authorize(&capability, envelope, now_ms, recent_count) {
            return reject_existing(tx, &submission_id, now_ms, code, summary);
        }

        if !schema_is_accepted(&tx, envelope)? {
            return reject_existing(
                tx,
                &submission_id,
                now_ms,
                "schema_incompatible",
                "evidence schema is not registered or compatible",
            );
        }

        let source_collision = tx
            .query_row(
                "SELECT id, content_digest FROM sekai_evidence_submissions
                 WHERE source_type=?1 AND source_instance=?2 AND source_record_id=?3
                   AND source_version=?4 AND lifecycle_state != 'rejected' AND id != ?5
                 LIMIT 1",
                params![
                    envelope.source_type,
                    envelope.source_instance,
                    envelope.source_record_id,
                    envelope.source_version,
                    submission_id,
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((existing_id, digest)) = source_collision {
            if digest != envelope.content_digest {
                return reject_existing(
                    tx,
                    &submission_id,
                    now_ms,
                    "source_identity_collision",
                    "source record version was already observed with different content",
                );
            }
            tx.execute(
                "DELETE FROM sekai_evidence_lifecycle_history WHERE submission_id=?1",
                [&submission_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "DELETE FROM sekai_evidence_submissions WHERE id=?1",
                [&submission_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_evidence_idempotency
                 (producer_identity, idempotency_key, envelope_digest, submission_id)
                 VALUES (?1,?2,?3,?4)",
                params![
                    authenticated_producer,
                    envelope.idempotency_key,
                    envelope_digest,
                    existing_id,
                ],
            )
            .map_err(|error| error.to_string())?;
            let submission = get_submission_tx(&tx, &existing_id)?
                .ok_or_else(|| "deduplicated source submission disappeared".to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(EvidenceAdmission {
                accepted: submission.lifecycle_state.is_admitted(),
                submission,
                deduplicated: true,
            });
        }

        transition(
            &tx,
            &submission_id,
            EvidenceLifecycleState::Deduplicated,
            None,
            now_ms,
        )?;
        transition(
            &tx,
            &submission_id,
            EvidenceLifecycleState::Authorized,
            None,
            now_ms,
        )?;
        tx.execute(
            "INSERT INTO sekai_evidence_idempotency
             (producer_identity, idempotency_key, envelope_digest, submission_id)
             VALUES (?1,?2,?3,?4)",
            params![
                authenticated_producer,
                envelope.idempotency_key,
                envelope_digest,
                submission_id,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE sekai_evidence_submissions SET envelope_json=?2, updated_at_ms=?3 WHERE id=?1",
            params![
                submission_id,
                serde_json::to_string(envelope).map_err(|error| error.to_string())?,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        let submission = get_submission_tx(&tx, &submission_id)?
            .ok_or_else(|| "accepted submission disappeared".to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(EvidenceAdmission {
            submission,
            accepted: true,
            deduplicated: false,
        })
    }

    pub fn get_evidence_submission(
        &self,
        submission_id: &str,
    ) -> Result<Option<EvidenceSubmissionRecord>, String> {
        let conn = self.conn();
        get_submission_conn(&conn, submission_id)
    }

    pub fn evidence_lifecycle_history(
        &self,
        submission_id: &str,
    ) -> Result<Vec<EvidenceLifecycleState>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT lifecycle_state FROM sekai_evidence_lifecycle_history
                 WHERE submission_id=?1 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([submission_id], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            row.map_err(|error| error.to_string()).and_then(|value| {
                EvidenceLifecycleState::parse(&value)
                    .ok_or_else(|| format!("unknown evidence lifecycle state {value}"))
            })
        })
        .collect()
    }
}

pub fn canonical_content_digest(content: &serde_json::Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(content).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn canonical_envelope_digest(envelope: &EvidenceEnvelope) -> Result<String, String> {
    let bytes = serde_json::to_vec(envelope).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_capability(capability: &EvidenceProducerCapability) -> Result<(), String> {
    if capability.producer_identity.trim().is_empty() {
        return Err("producer identity is required".to_string());
    }
    if capability.config_version <= 0 {
        return Err("producer config version must be positive".to_string());
    }
    if capability.source_instances.is_empty()
        || capability.namespaces.is_empty()
        || capability.evidence_types.is_empty()
        || capability.target_kinds.is_empty()
        || capability.allowed_intents.is_empty()
    {
        return Err("producer capabilities must be explicit and non-empty".to_string());
    }
    if capability.replay_window_ms <= 0
        || capability.max_payload_bytes == 0
        || capability.max_relationships == 0
        || capability.rate_limit_per_minute == 0
    {
        return Err("producer quotas must be positive".to_string());
    }
    Ok(())
}

fn load_capability(
    tx: &Transaction<'_>,
    producer: &str,
) -> Result<Option<EvidenceProducerCapability>, String> {
    tx.query_row(
        "SELECT capability_json FROM sekai_evidence_producers WHERE producer_identity=?1",
        [producer],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|error| error.to_string())?
    .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
    .transpose()
}

fn authorize<'a>(
    capability: &EvidenceProducerCapability,
    envelope: &EvidenceEnvelope,
    now_ms: i64,
    recent_count: u32,
) -> Result<(), (&'a str, &'a str)> {
    if capability.revoked {
        return Err(("producer_revoked", "producer registration is revoked"));
    }
    if !capability
        .source_instances
        .contains(&envelope.source_instance)
    {
        return Err(("source_forbidden", "producer does not own source instance"));
    }
    if !capability.namespaces.contains(&envelope.target.namespace) {
        return Err(("namespace_forbidden", "producer cannot submit to namespace"));
    }
    if !capability.evidence_types.contains(&envelope.evidence_type) {
        return Err((
            "evidence_type_forbidden",
            "producer cannot submit evidence type",
        ));
    }
    if !capability
        .target_kinds
        .contains(&envelope.target.object_kind)
    {
        return Err((
            "target_kind_forbidden",
            "producer cannot target object kind",
        ));
    }
    if envelope.classification > capability.classification_ceiling {
        return Err((
            "classification_forbidden",
            "classification exceeds producer ceiling",
        ));
    }
    if !capability.allowed_intents.contains(&envelope.intent) {
        return Err(("intent_forbidden", "producer cannot use lifecycle intent"));
    }
    if envelope.causality.as_ref().is_some_and(|causality| {
        causality.operation_id.is_some() && !capability.allow_operation_attachment
    }) {
        return Err((
            "operation_forbidden",
            "producer cannot attach operation evidence",
        ));
    }
    if envelope.collected_at_ms < now_ms.saturating_sub(capability.replay_window_ms) {
        return Err((
            "replay_window_expired",
            "submission falls outside replay window",
        ));
    }
    if recent_count > capability.rate_limit_per_minute {
        return Err(("rate_limited", "producer submission rate exceeded"));
    }
    Ok(())
}

fn schema_is_accepted(tx: &Transaction<'_>, envelope: &EvidenceEnvelope) -> Result<bool, String> {
    let mut statement = tx
        .prepare(
            "SELECT definition_json FROM sekai_evidence_schemas
             WHERE schema_id=?1 AND evidence_type=?2",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![envelope.schema_id, envelope.evidence_type], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|error| error.to_string())?;
    for row in rows {
        let definition: EvidenceSchemaDefinition =
            serde_json::from_str(&row.map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        if definition.schema_version == envelope.schema_version
            || (matches!(
                envelope.schema_compatibility,
                crate::sekai::evidence::SchemaCompatibility::BackwardCompatible
            ) && definition
                .compatible_versions
                .contains(&envelope.schema_version))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn insert_received(
    tx: &Transaction<'_>,
    id: &str,
    envelope: &EvidenceEnvelope,
    authenticated_producer: &str,
    now_ms: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_evidence_submissions
         (id, producer_identity, source_type, source_instance, source_record_id, source_version,
          source_sequence, namespace, target_external_id, target_kind, evidence_type, schema_id,
          schema_version, idempotency_key, content_digest, classification, intent, lifecycle_state,
          observed_at_ms, collected_at_ms, expires_at_ms, received_at_ms, updated_at_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
        params![
            id,
            authenticated_producer,
            envelope.source_type,
            envelope.source_instance,
            envelope.source_record_id,
            envelope.source_version,
            envelope.source_sequence,
            envelope.target.namespace,
            envelope.target.object_external_id,
            envelope.target.object_kind,
            envelope.evidence_type,
            envelope.schema_id,
            envelope.schema_version,
            envelope.idempotency_key,
            envelope.content_digest,
            envelope.classification.as_str(),
            intent_str(envelope.intent),
            EvidenceLifecycleState::Received.as_str(),
            envelope.observed_at_ms,
            envelope.collected_at_ms,
            envelope.expires_at_ms,
            now_ms,
            now_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    transition(tx, id, EvidenceLifecycleState::Received, None, now_ms)
}

fn transition(
    tx: &Transaction<'_>,
    submission_id: &str,
    state: EvidenceLifecycleState,
    reason_code: Option<&str>,
    now_ms: i64,
) -> Result<(), String> {
    tx.execute(
        "UPDATE sekai_evidence_submissions SET lifecycle_state=?2, updated_at_ms=?3 WHERE id=?1",
        params![submission_id, state.as_str(), now_ms],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_evidence_lifecycle_history
         (submission_id, lifecycle_state, reason_code, recorded_at_ms) VALUES (?1,?2,?3,?4)",
        params![submission_id, state.as_str(), reason_code, now_ms],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn persist_rejection(
    tx: Transaction<'_>,
    envelope: &EvidenceEnvelope,
    authenticated_producer: &str,
    now_ms: i64,
    code: &str,
    summary: &str,
) -> Result<EvidenceAdmission, String> {
    let submission_id = format!("evidence-{}", Uuid::new_v4().simple());
    insert_received(
        &tx,
        &submission_id,
        envelope,
        authenticated_producer,
        now_ms,
    )?;
    reject_existing(tx, &submission_id, now_ms, code, summary)
}

fn reject_existing(
    tx: Transaction<'_>,
    submission_id: &str,
    now_ms: i64,
    code: &str,
    summary: &str,
) -> Result<EvidenceAdmission, String> {
    tx.execute(
        "UPDATE sekai_evidence_submissions
         SET lifecycle_state='rejected', rejection_code=?2, rejection_summary=?3,
             envelope_json=NULL, updated_at_ms=?4 WHERE id=?1",
        params![submission_id, code, summary, now_ms],
    )
    .map_err(|error| error.to_string())?;
    transition(
        &tx,
        submission_id,
        EvidenceLifecycleState::Rejected,
        Some(code),
        now_ms,
    )?;
    let submission = get_submission_tx(&tx, submission_id)?
        .ok_or_else(|| "rejected submission disappeared".to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(EvidenceAdmission {
        submission,
        accepted: false,
        deduplicated: false,
    })
}

fn get_submission_tx(
    tx: &Transaction<'_>,
    submission_id: &str,
) -> Result<Option<EvidenceSubmissionRecord>, String> {
    tx.query_row(submission_query(), [submission_id], row_to_submission)
        .optional()
        .map_err(|error| error.to_string())
}

fn get_submission_conn(
    conn: &rusqlite::Connection,
    submission_id: &str,
) -> Result<Option<EvidenceSubmissionRecord>, String> {
    conn.query_row(submission_query(), [submission_id], row_to_submission)
        .optional()
        .map_err(|error| error.to_string())
}

fn submission_query() -> &'static str {
    "SELECT id, producer_identity, source_type, source_instance, source_record_id, source_version,
            source_sequence, namespace, target_external_id, target_kind, evidence_type, schema_id,
            schema_version, idempotency_key, content_digest, classification, intent, lifecycle_state,
            rejection_code, rejection_summary, observed_at_ms, collected_at_ms, expires_at_ms,
            received_at_ms, updated_at_ms, envelope_json
     FROM sekai_evidence_submissions WHERE id=?1"
}

fn row_to_submission(row: &rusqlite::Row<'_>) -> Result<EvidenceSubmissionRecord, rusqlite::Error> {
    let classification: String = row.get(15)?;
    let intent: String = row.get(16)?;
    let state: String = row.get(17)?;
    let envelope_json: Option<String> = row.get(25)?;
    let classification = parse_classification(&classification)
        .ok_or_else(|| invalid_stored_enum(15, "classification", &classification))?;
    let intent = parse_intent(&intent).ok_or_else(|| invalid_stored_enum(16, "intent", &intent))?;
    let lifecycle_state = EvidenceLifecycleState::parse(&state)
        .ok_or_else(|| invalid_stored_enum(17, "lifecycle state", &state))?;
    let envelope = envelope_json
        .map(|json| {
            serde_json::from_str(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    25,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()?;
    Ok(EvidenceSubmissionRecord {
        id: row.get(0)?,
        producer_identity: row.get(1)?,
        source_type: row.get(2)?,
        source_instance: row.get(3)?,
        source_record_id: row.get(4)?,
        source_version: row.get(5)?,
        source_sequence: row.get(6)?,
        namespace: row.get(7)?,
        target_external_id: row.get(8)?,
        target_kind: row.get(9)?,
        evidence_type: row.get(10)?,
        schema_id: row.get(11)?,
        schema_version: row.get(12)?,
        idempotency_key: row.get(13)?,
        content_digest: row.get(14)?,
        classification,
        intent,
        lifecycle_state,
        rejection_code: row.get(18)?,
        rejection_summary: row.get(19)?,
        observed_at_ms: row.get(20)?,
        collected_at_ms: row.get(21)?,
        expires_at_ms: row.get(22)?,
        received_at_ms: row.get(23)?,
        updated_at_ms: row.get(24)?,
        envelope,
    })
}

fn intent_str(intent: EvidenceIntent) -> &'static str {
    match intent {
        EvidenceIntent::Upsert => "upsert",
        EvidenceIntent::Retract => "retract",
        EvidenceIntent::MarkStale => "mark_stale",
    }
}

fn parse_intent(value: &str) -> Option<EvidenceIntent> {
    Some(match value {
        "upsert" => EvidenceIntent::Upsert,
        "retract" => EvidenceIntent::Retract,
        "mark_stale" => EvidenceIntent::MarkStale,
        _ => return None,
    })
}

fn parse_classification(value: &str) -> Option<EvidenceClassification> {
    Some(match value {
        "public" => EvidenceClassification::Public,
        "internal" => EvidenceClassification::Internal,
        "confidential" => EvidenceClassification::Confidential,
        "restricted" => EvidenceClassification::Restricted,
        _ => return None,
    })
}

fn invalid_stored_enum(index: usize, field: &str, value: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown evidence {field} {value}"),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceCausality, EvidenceSignal, EvidenceTarget,
        SchemaCompatibility,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    fn configured_db() -> SekaiDb {
        let db = SekaiDb::new(":memory:").unwrap();
        db.upsert_evidence_producer(
            &EvidenceProducerCapability {
                producer_identity: "producer:checks".into(),
                config_version: 1,
                source_instances: vec!["checks-primary".into()],
                namespaces: vec!["acme".into()],
                evidence_types: vec!["verification.result".into()],
                target_kinds: vec!["service".into()],
                classification_ceiling: EvidenceClassification::Confidential,
                allowed_intents: vec![
                    EvidenceIntent::Upsert,
                    EvidenceIntent::Retract,
                    EvidenceIntent::MarkStale,
                ],
                allow_operation_attachment: true,
                replay_window_ms: 10_000,
                max_payload_bytes: 1_024,
                max_relationships: 4,
                rate_limit_per_minute: 20,
                revoked: false,
            },
            100,
        )
        .unwrap();
        db.register_evidence_schema(
            &EvidenceSchemaDefinition {
                schema_id: "verification.result".into(),
                schema_version: "1.0.0".into(),
                evidence_type: "verification.result".into(),
                compatible_versions: vec![],
            },
            100,
        )
        .unwrap();
        db
    }

    fn envelope() -> EvidenceEnvelope {
        let content = json!({"result": "passed"});
        EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "verification_system".into(),
            source_instance: "checks-primary".into(),
            source_record_id: "run-7".into(),
            source_version: "attempt-1".into(),
            source_sequence: 1,
            target: EvidenceTarget {
                namespace: "acme".into(),
                object_external_id: "service:payments".into(),
                object_kind: "service".into(),
            },
            evidence_type: "verification.result".into(),
            signal: EvidenceSignal::Verification,
            schema_id: "verification.result".into(),
            schema_version: "1.0.0".into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: 1_000,
            collected_at_ms: 1_010,
            expires_at_ms: Some(2_000),
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: "producer:checks".into(),
            confidence_bps: 9_500,
            classification: EvidenceClassification::Internal,
            provenance: BTreeMap::new(),
            idempotency_key: "delivery-7".into(),
            intent: EvidenceIntent::Upsert,
            causality: Some(EvidenceCausality {
                operation_id: Some("op-7".into()),
                parent_operation_id: None,
                attempt_id: Some("attempt-1".into()),
                model_call_id: None,
                subject_references: vec!["service:payments".into()],
                trace_context: BTreeMap::new(),
            }),
        }
    }

    #[test]
    fn persists_authorized_submission_and_lifecycle() {
        let db = configured_db();
        let admission = db
            .submit_evidence(&envelope(), "producer:checks", 1_100)
            .unwrap();
        assert!(admission.accepted);
        assert_eq!(
            admission.submission.lifecycle_state,
            EvidenceLifecycleState::Authorized
        );
        assert!(admission.submission.envelope.is_some());
        assert_eq!(
            db.evidence_lifecycle_history(&admission.submission.id)
                .unwrap(),
            vec![
                EvidenceLifecycleState::Received,
                EvidenceLifecycleState::Validated,
                EvidenceLifecycleState::Deduplicated,
                EvidenceLifecycleState::Authorized,
            ]
        );
    }

    #[test]
    fn idempotent_replay_returns_original_submission() {
        let db = configured_db();
        let first = db
            .submit_evidence(&envelope(), "producer:checks", 1_100)
            .unwrap();
        let replay = db
            .submit_evidence(&envelope(), "producer:checks", 1_200)
            .unwrap();
        assert!(replay.deduplicated);
        assert_eq!(replay.submission.id, first.submission.id);
    }

    #[test]
    fn idempotency_key_cannot_move_identical_content_to_another_target() {
        let db = configured_db();
        db.submit_evidence(&envelope(), "producer:checks", 1_100)
            .unwrap();
        let mut moved = envelope();
        moved.target.object_external_id = "service:other".into();
        let admission = db
            .submit_evidence(&moved, "producer:checks", 1_200)
            .unwrap();
        assert_eq!(
            admission.submission.rejection_code.as_deref(),
            Some("idempotency_conflict")
        );
    }

    #[test]
    fn source_replay_with_new_delivery_key_reuses_original() {
        let db = configured_db();
        let first = db
            .submit_evidence(&envelope(), "producer:checks", 1_100)
            .unwrap();
        let mut replayed = envelope();
        replayed.idempotency_key = "delivery-7-retry".into();
        let replay = db
            .submit_evidence(&replayed, "producer:checks", 1_200)
            .unwrap();
        assert!(replay.deduplicated);
        assert_eq!(replay.submission.id, first.submission.id);
    }

    #[test]
    fn rejects_digest_mismatch_without_retaining_payload() {
        let db = configured_db();
        let mut evidence = envelope();
        evidence.content_digest = "0".repeat(64);
        let admission = db
            .submit_evidence(&evidence, "producer:checks", 1_100)
            .unwrap();
        assert!(!admission.accepted);
        assert_eq!(
            admission.submission.rejection_code.as_deref(),
            Some("digest_mismatch")
        );
        assert!(admission.submission.envelope.is_none());
    }

    #[test]
    fn rejects_cross_namespace_before_projection() {
        let db = configured_db();
        let mut evidence = envelope();
        evidence.target.namespace = "other".into();
        let admission = db
            .submit_evidence(&evidence, "producer:checks", 1_100)
            .unwrap();
        assert_eq!(
            admission.submission.rejection_code.as_deref(),
            Some("namespace_forbidden")
        );
        assert!(admission.submission.envelope.is_none());
    }

    #[test]
    fn rejects_source_version_content_collision() {
        let db = configured_db();
        db.submit_evidence(&envelope(), "producer:checks", 1_100)
            .unwrap();
        let mut collision = envelope();
        collision.idempotency_key = "delivery-other".into();
        collision.content = json!({"result": "failed"});
        collision.content_digest = canonical_content_digest(&collision.content).unwrap();
        let admission = db
            .submit_evidence(&collision, "producer:checks", 1_200)
            .unwrap();
        assert_eq!(
            admission.submission.rejection_code.as_deref(),
            Some("source_identity_collision")
        );
    }

    #[test]
    fn registered_schema_versions_are_immutable() {
        let db = configured_db();
        let changed = EvidenceSchemaDefinition {
            schema_id: "verification.result".into(),
            schema_version: "1.0.0".into(),
            evidence_type: "different.type".into(),
            compatible_versions: vec![],
        };
        assert_eq!(
            db.register_evidence_schema(&changed, 200).unwrap_err(),
            "registered evidence schema versions are immutable"
        );
    }

    #[test]
    fn source_instances_have_one_registered_owner() {
        let db = configured_db();
        let conflicting = EvidenceProducerCapability {
            producer_identity: "producer:other".into(),
            config_version: 1,
            source_instances: vec!["checks-primary".into()],
            namespaces: vec!["acme".into()],
            evidence_types: vec!["verification.result".into()],
            target_kinds: vec!["service".into()],
            classification_ceiling: EvidenceClassification::Internal,
            allowed_intents: vec![EvidenceIntent::Upsert],
            allow_operation_attachment: false,
            replay_window_ms: 1_000,
            max_payload_bytes: 1_024,
            max_relationships: 1,
            rate_limit_per_minute: 1,
            revoked: false,
        };
        assert!(
            db.upsert_evidence_producer(&conflicting, 200)
                .unwrap_err()
                .contains("already owned")
        );
    }
}
