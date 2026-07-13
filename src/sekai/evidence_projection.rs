//! Atomic projection of admitted evidence into governed Sekai graph state.

use crate::db::sekai::SekaiDb;
use crate::domain::{KIND_EXTERNAL_EVIDENCE, REL_DERIVED_FROM, REL_EVIDENCE_FOR};
use crate::sekai::audit::{Decision, ObjectChange, insert_object_changes};
use crate::sekai::evidence::{EvidenceClassification, EvidenceIntent, EvidenceLifecycleState};
use crate::sekai::evidence_store::{EvidenceSubmissionRecord, get_submission_tx, transition};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

pub const EVIDENCE_PROJECTION_VERSION: &str = "sekai.evidence.projection/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceProjectionOutcome {
    pub submission_id: String,
    pub evidence_object_id: Option<String>,
    pub target_object_id: Option<String>,
    pub lifecycle_state: EvidenceLifecycleState,
    pub projected: bool,
    pub failure_code: Option<String>,
}

#[derive(Debug)]
struct ResolvedRelationship {
    related_submission_id: String,
    related_object_id: String,
    source_relation: String,
}

impl SekaiDb {
    pub fn project_evidence_submission(
        &self,
        submission_id: &str,
        now_ms: i64,
    ) -> Result<EvidenceProjectionOutcome, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let submission = get_submission_tx(&tx, submission_id)?
            .ok_or_else(|| "evidence submission not found".to_string())?;

        if let Some((evidence_object_id, target_object_id)) = tx
            .query_row(
                "SELECT evidence_object_id, target_object_id FROM sekai_evidence_projections
                 WHERE submission_id=?1",
                [submission_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
        {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(EvidenceProjectionOutcome {
                submission_id: submission.id,
                evidence_object_id: Some(evidence_object_id),
                target_object_id: Some(target_object_id),
                lifecycle_state: submission.lifecycle_state,
                projected: true,
                failure_code: None,
            });
        }

        let retryable_quarantine = submission.lifecycle_state
            == EvidenceLifecycleState::Quarantined
            && submission
                .rejection_code
                .as_deref()
                .is_some_and(|code| code.starts_with("projection_"));
        if submission.lifecycle_state != EvidenceLifecycleState::Authorized && !retryable_quarantine
        {
            return Err(format!(
                "submission {} is not eligible for projection from state {}",
                submission.id,
                submission.lifecycle_state.as_str()
            ));
        }
        let envelope = submission
            .envelope
            .as_ref()
            .ok_or_else(|| "admitted evidence is missing its authoritative envelope".to_string())?;

        let targets = {
            let mut statement = tx
                .prepare(
                    "SELECT id, kind FROM sekai_objects
                     WHERE namespace=?1 AND external_id=?2 ORDER BY id LIMIT 2",
                )
                .map_err(|error| error.to_string())?;
            statement
                .query_map(
                    params![
                        envelope.target.namespace,
                        envelope.target.object_external_id
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        let [(target_object_id, target_kind)] = targets.as_slice() else {
            let (code, summary) = if targets.is_empty() {
                (
                    "projection_target_missing",
                    "target object does not exist in the authorized namespace",
                )
            } else {
                (
                    "projection_target_ambiguous",
                    "target external identity resolves to multiple objects",
                )
            };
            return quarantine(tx, &submission, now_ms, code, summary);
        };
        if target_kind != &envelope.target.object_kind {
            return quarantine(
                tx,
                &submission,
                now_ms,
                "projection_target_kind_mismatch",
                "target object kind does not match the admitted envelope",
            );
        }

        if let Some(operation_id) = envelope
            .causality
            .as_ref()
            .and_then(|causality| causality.operation_id.as_deref())
        {
            let operation_namespace = tx
                .query_row(
                    "SELECT namespace FROM chisei_operation_receipts WHERE operation_id=?1",
                    [operation_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if operation_namespace.as_deref() != Some(envelope.target.namespace.as_str()) {
                return quarantine(
                    tx,
                    &submission,
                    now_ms,
                    "projection_operation_unavailable",
                    "operation evidence target is absent or belongs to another namespace",
                );
            }
        }

        let mut resolved_relationships = Vec::with_capacity(envelope.relationships.len());
        for relationship in &envelope.relationships {
            let target_source_type = if relationship.target_source_type.is_empty() {
                &envelope.source_type
            } else {
                &relationship.target_source_type
            };
            let target_source_instance = if relationship.target_source_instance.is_empty() {
                &envelope.source_instance
            } else {
                &relationship.target_source_instance
            };
            let resolved = tx
                .query_row(
                    "SELECT identity.submission_id, projection.evidence_object_id
                     FROM sekai_evidence_source_identity AS identity
                     JOIN sekai_evidence_projections AS projection
                       ON projection.submission_id = identity.submission_id
                     WHERE identity.source_type=?1 AND identity.source_instance=?2
                       AND identity.source_record_id=?3
                     ORDER BY identity.source_sequence DESC LIMIT 1",
                    params![
                        target_source_type,
                        target_source_instance,
                        relationship.target_source_record_id
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some((related_submission_id, related_object_id)) = resolved else {
                return quarantine(
                    tx,
                    &submission,
                    now_ms,
                    "projection_relationship_unavailable",
                    "related source record has no reproducible projection",
                );
            };
            resolved_relationships.push(ResolvedRelationship {
                related_submission_id,
                related_object_id,
                source_relation: relationship.relation.clone(),
            });
        }

        let prior_available = tx
            .query_row(
                "SELECT submissions.id, submissions.source_sequence, projection.evidence_object_id
                 FROM sekai_evidence_submissions AS submissions
                 JOIN sekai_evidence_projections AS projection
                   ON projection.submission_id = submissions.id
                 WHERE submissions.source_type=?1 AND submissions.source_instance=?2
                   AND submissions.source_record_id=?3
                   AND submissions.lifecycle_state='available' AND submissions.id != ?4
                 ORDER BY submissions.source_sequence DESC LIMIT 1",
                params![
                    envelope.source_type,
                    envelope.source_instance,
                    envelope.source_record_id,
                    submission.id,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let has_earlier_lifecycle_target = prior_available
            .as_ref()
            .is_some_and(|(_, sequence, _)| *sequence < envelope.source_sequence);
        if !matches!(envelope.intent, EvidenceIntent::Upsert) && !has_earlier_lifecycle_target {
            return quarantine(
                tx,
                &submission,
                now_ms,
                "projection_lifecycle_target_missing",
                "lifecycle marker has no available earlier evidence version",
            );
        }

        let target_grants = {
            let mut statement = tx
                .prepare("SELECT principal, role FROM sekai_grants WHERE object_id=?1")
                .map_err(|error| error.to_string())?;
            statement
                .query_map([target_object_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };

        let evidence_object_id = format!("evidence-object-{}", submission.id);
        let source_identity_hash = source_identity_hash(
            &envelope.source_type,
            &envelope.source_instance,
            &envelope.source_record_id,
            envelope.source_sequence,
        );
        let final_state = if matches!(envelope.intent, EvidenceIntent::Upsert) {
            if prior_available
                .as_ref()
                .is_some_and(|(_, sequence, _)| *sequence > envelope.source_sequence)
            {
                EvidenceLifecycleState::Superseded
            } else if envelope
                .expires_at_ms
                .is_some_and(|expires_at| expires_at <= now_ms)
            {
                EvidenceLifecycleState::Stale
            } else {
                EvidenceLifecycleState::Available
            }
        } else {
            EvidenceLifecycleState::Available
        };
        let properties = serde_json::to_string(&HashMap::from([
            (
                "authoritative_store",
                "sekai_evidence_submissions".to_string(),
            ),
            ("submission_id", submission.id.clone()),
            ("source_type", envelope.source_type.clone()),
            ("source_instance", envelope.source_instance.clone()),
            ("source_identity_hash", source_identity_hash.clone()),
            ("source_version", envelope.source_version.clone()),
            ("source_sequence", envelope.source_sequence.to_string()),
            ("evidence_type", envelope.evidence_type.clone()),
            ("schema_id", envelope.schema_id.clone()),
            ("schema_version", envelope.schema_version.clone()),
            ("content_digest", envelope.content_digest.clone()),
            (
                "classification",
                envelope.classification.as_str().to_string(),
            ),
            ("lifecycle_state", final_state.as_str().to_string()),
            (
                "projection_version",
                EVIDENCE_PROJECTION_VERSION.to_string(),
            ),
            ("observed_at_ms", envelope.observed_at_ms.to_string()),
        ]))
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_objects
             (id, kind, name, namespace, external_id, properties, created, updated)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?7)",
            params![
                evidence_object_id,
                KIND_EXTERNAL_EVIDENCE,
                envelope.evidence_type,
                envelope.target.namespace,
                format!("evidence:{source_identity_hash}"),
                properties,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_links (id, from_id, to_id, relation, created)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                format!("evidence-target-{}", submission.id),
                evidence_object_id,
                target_object_id,
                REL_EVIDENCE_FOR,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        for relationship in &resolved_relationships {
            tx.execute(
                "INSERT INTO sekai_links (id, from_id, to_id, relation, created)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    format!(
                        "evidence-lineage-{}-{}-{}",
                        submission.id,
                        relationship.related_submission_id,
                        short_hash(&relationship.source_relation)
                    ),
                    evidence_object_id,
                    relationship.related_object_id,
                    REL_DERIVED_FROM,
                    now_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_evidence_relationship_projections
                 (submission_id, related_submission_id, source_relation) VALUES (?1,?2,?3)",
                params![
                    submission.id,
                    relationship.related_submission_id,
                    relationship.source_relation,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute(
            "INSERT INTO sekai_evidence_projections
             (submission_id, evidence_object_id, target_object_id, projection_version,
              source_sequence, projected_at_ms) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                submission.id,
                evidence_object_id,
                target_object_id,
                EVIDENCE_PROJECTION_VERSION,
                envelope.source_sequence,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_evidence_observations
             (submission_id, evidence_object_id, signal, confidence_bps, observed_at_ms,
              projection_version) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                submission.id,
                evidence_object_id,
                envelope.signal.as_str(),
                envelope.confidence_bps,
                envelope.observed_at_ms,
                EVIDENCE_PROJECTION_VERSION,
            ],
        )
        .map_err(|error| error.to_string())?;
        if let Some(operation_id) = envelope
            .causality
            .as_ref()
            .and_then(|causality| causality.operation_id.as_deref())
        {
            tx.execute(
                "INSERT INTO sekai_evidence_operation_links (submission_id, operation_id)
                 VALUES (?1,?2)",
                params![submission.id, operation_id],
            )
            .map_err(|error| error.to_string())?;
        }

        for (principal, role) in &target_grants {
            tx.execute(
                "INSERT INTO sekai_grants (id, object_id, principal, role, created)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    format!("grant-{}-{}", submission.id, short_hash(principal)),
                    evidence_object_id,
                    principal,
                    role,
                    now_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        if envelope.classification != EvidenceClassification::Public
            && !target_grants
                .iter()
                .any(|(principal, _)| principal == &submission.producer_identity)
        {
            tx.execute(
                "INSERT INTO sekai_grants (id, object_id, principal, role, created)
                 VALUES (?1,?2,?3,'viewer',?4)",
                params![
                    format!("grant-{}-producer", submission.id),
                    evidence_object_id,
                    submission.producer_identity,
                    now_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        }

        let changes = [ObjectChange {
            id: Uuid::new_v4().to_string(),
            object_id: evidence_object_id.clone(),
            field: "_created".into(),
            old_value: String::new(),
            new_value: format!("{KIND_EXTERNAL_EVIDENCE}/{}", envelope.evidence_type),
            changed_by: submission.producer_identity.clone(),
            timestamp: now_ms,
        }];
        insert_object_changes(&tx, &changes)?;

        if matches!(envelope.intent, EvidenceIntent::Upsert) {
            if final_state != EvidenceLifecycleState::Superseded {
                let mut statement = tx
                    .prepare(
                        "SELECT submissions.id, projection.evidence_object_id
                         FROM sekai_evidence_submissions AS submissions
                         JOIN sekai_evidence_projections AS projection
                           ON projection.submission_id = submissions.id
                         WHERE submissions.source_type=?1
                           AND submissions.source_instance=?2
                           AND submissions.source_record_id=?3
                           AND submissions.source_sequence<?4
                           AND submissions.lifecycle_state='available'",
                    )
                    .map_err(|error| error.to_string())?;
                let older = statement
                    .query_map(
                        params![
                            envelope.source_type,
                            envelope.source_instance,
                            envelope.source_record_id,
                            envelope.source_sequence,
                        ],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .map_err(|error| error.to_string())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?;
                drop(statement);
                for (older_submission_id, older_object_id) in older {
                    transition(
                        &tx,
                        &older_submission_id,
                        EvidenceLifecycleState::Superseded,
                        None,
                        now_ms,
                    )?;
                    update_object_lifecycle(
                        &tx,
                        &older_object_id,
                        EvidenceLifecycleState::Superseded,
                        now_ms,
                    )?;
                }
            }
        } else if let Some((prior_id, _, prior_object_id)) = &prior_available {
            let prior_state = match envelope.intent {
                EvidenceIntent::Retract => EvidenceLifecycleState::Retracted,
                EvidenceIntent::MarkStale => EvidenceLifecycleState::Stale,
                EvidenceIntent::Upsert => unreachable!(),
            };
            transition(&tx, prior_id, prior_state, None, now_ms)?;
            update_object_lifecycle(&tx, prior_object_id, prior_state, now_ms)?;
        }

        tx.execute(
            "UPDATE sekai_evidence_submissions
             SET rejection_code=NULL, rejection_summary=NULL WHERE id=?1",
            [&submission.id],
        )
        .map_err(|error| error.to_string())?;
        transition(
            &tx,
            &submission.id,
            EvidenceLifecycleState::Projected,
            None,
            now_ms,
        )?;
        transition(&tx, &submission.id, final_state, None, now_ms)?;
        crate::sekai::ledger::insert_chained_decision(
            &tx,
            &Decision {
                id: format!("evidence-projection-{}", submission.id),
                timestamp: now_ms,
                actor: submission.producer_identity.clone(),
                action: "evidence.project".into(),
                reason: "admitted external evidence projected atomically".into(),
                evidence: HashMap::from([
                    ("submission_id".into(), submission.id.clone()),
                    ("content_digest".into(), envelope.content_digest.clone()),
                    ("evidence_type".into(), envelope.evidence_type.clone()),
                    ("source_type".into(), envelope.source_type.clone()),
                    (
                        "classification".into(),
                        envelope.classification.as_str().into(),
                    ),
                    (
                        "projection_version".into(),
                        EVIDENCE_PROJECTION_VERSION.into(),
                    ),
                    ("lifecycle_state".into(), final_state.as_str().into()),
                ]),
                target_id: evidence_object_id.clone(),
                outcome: final_state.as_str().into(),
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(EvidenceProjectionOutcome {
            submission_id: submission.id,
            evidence_object_id: Some(evidence_object_id),
            target_object_id: Some(target_object_id.clone()),
            lifecycle_state: final_state,
            projected: true,
            failure_code: None,
        })
    }
}

fn quarantine(
    tx: Transaction<'_>,
    submission: &EvidenceSubmissionRecord,
    now_ms: i64,
    code: &str,
    summary: &str,
) -> Result<EvidenceProjectionOutcome, String> {
    tx.execute(
        "UPDATE sekai_evidence_submissions
         SET rejection_code=?2, rejection_summary=?3, updated_at_ms=?4 WHERE id=?1",
        params![submission.id, code, summary, now_ms],
    )
    .map_err(|error| error.to_string())?;
    transition(
        &tx,
        &submission.id,
        EvidenceLifecycleState::Quarantined,
        Some(code),
        now_ms,
    )?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(EvidenceProjectionOutcome {
        submission_id: submission.id.clone(),
        evidence_object_id: None,
        target_object_id: None,
        lifecycle_state: EvidenceLifecycleState::Quarantined,
        projected: false,
        failure_code: Some(code.to_string()),
    })
}

fn update_object_lifecycle(
    tx: &Transaction<'_>,
    object_id: &str,
    state: EvidenceLifecycleState,
    now_ms: i64,
) -> Result<(), String> {
    let properties_json = tx
        .query_row(
            "SELECT properties FROM sekai_objects WHERE id=?1",
            [object_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| error.to_string())?;
    let mut properties: HashMap<String, String> =
        serde_json::from_str(&properties_json).map_err(|error| error.to_string())?;
    properties.insert("lifecycle_state".into(), state.as_str().into());
    tx.execute(
        "UPDATE sekai_objects SET properties=?2, updated=?3 WHERE id=?1",
        params![
            object_id,
            serde_json::to_string(&properties).map_err(|error| error.to_string())?,
            now_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn source_identity_hash(
    source_type: &str,
    source_instance: &str,
    source_record_id: &str,
    sequence: i64,
) -> String {
    let bytes = serde_json::to_vec(&(source_type, source_instance, source_record_id, sequence))
        .unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

fn short_hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceEnvelope, EvidenceRelationship, EvidenceSignal,
        EvidenceTarget, SchemaCompatibility,
    };
    use crate::sekai::evidence_store::{
        EvidenceProducerCapability, EvidenceSchemaDefinition, canonical_content_digest,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Barrier};

    fn setup() -> SekaiDb {
        setup_at(":memory:")
    }

    fn setup_at(path: &str) -> SekaiDb {
        let db = SekaiDb::new(path).unwrap();
        db.create_object(&Object {
            id: "service-1".into(),
            kind: "service".into(),
            name: "payments".into(),
            namespace: "acme".into(),
            external_id: "service:payments".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
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
                allow_operation_attachment: false,
                replay_window_ms: 100_000,
                max_clock_skew_ms: 1_000,
                max_payload_bytes: 1_024,
                max_relationships: 4,
                rate_limit_per_minute: 100,
                max_retained_submissions: 100_000,
                revoked: false,
            },
            1,
        )
        .unwrap();
        db.register_evidence_schema(
            &EvidenceSchemaDefinition {
                schema_id: "verification.result".into(),
                schema_version: "1.0.0".into(),
                evidence_type: "verification.result".into(),
                compatible_versions: vec![],
            },
            1,
        )
        .unwrap();
        db
    }

    fn envelope(record: &str, sequence: i64, intent: EvidenceIntent) -> EvidenceEnvelope {
        let content = json!({"result": "passed", "sequence": sequence});
        EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "verification_system".into(),
            source_instance: "checks-primary".into(),
            source_record_id: record.into(),
            source_version: format!("v{sequence}"),
            source_sequence: sequence,
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
            observed_at_ms: 100 + sequence,
            collected_at_ms: 110 + sequence,
            expires_at_ms: None,
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: "producer:checks".into(),
            confidence_bps: 9_000,
            classification: EvidenceClassification::Internal,
            provenance: BTreeMap::new(),
            idempotency_key: format!("delivery-{record}-{sequence}"),
            intent,
            causality: None,
        }
    }

    fn admit(db: &SekaiDb, evidence: &EvidenceEnvelope) -> String {
        db.submit_evidence(evidence, "producer:checks", 200)
            .unwrap()
            .submission
            .id
    }

    #[test]
    fn projects_graph_observation_lineage_and_audit_atomically() {
        let db = setup();
        let submission_id = admit(&db, &envelope("run-1", 1, EvidenceIntent::Upsert));
        let outcome = db.project_evidence_submission(&submission_id, 300).unwrap();
        assert_eq!(outcome.lifecycle_state, EvidenceLifecycleState::Available);
        let evidence_object = db
            .get_object(outcome.evidence_object_id.as_deref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(evidence_object.kind, KIND_EXTERNAL_EVIDENCE);
        assert!(!evidence_object.properties.contains_key("content"));
        assert_eq!(
            evidence_object.properties["authoritative_store"],
            "sekai_evidence_submissions"
        );
        let conn = db.conn();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sekai_evidence_observations WHERE submission_id=?1",
                [&submission_id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sekai_decisions WHERE action='evidence.project'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn newer_projection_supersedes_older_version() {
        let db = setup();
        let first = admit(&db, &envelope("run-1", 1, EvidenceIntent::Upsert));
        db.project_evidence_submission(&first, 300).unwrap();
        let second = admit(&db, &envelope("run-1", 2, EvidenceIntent::Upsert));
        let projection = db.project_evidence_submission(&second, 400).unwrap();
        assert_eq!(
            db.get_evidence_submission(&first)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Superseded
        );
        assert_eq!(
            db.get_evidence_submission(&second)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Available
        );
        let usable = db
            .list_usable_evidence_for_targets(
                &[projection.target_object_id.unwrap()],
                &["verification.result".into()],
                450,
                8,
            )
            .unwrap();
        assert_eq!(usable.len(), 1);
        assert_eq!(usable[0].submission.id, second);
    }

    #[test]
    fn out_of_order_projection_never_replaces_newer_evidence() {
        let db = setup();
        let newer = admit(&db, &envelope("run-1", 2, EvidenceIntent::Upsert));
        db.project_evidence_submission(&newer, 300).unwrap();
        let older = admit(&db, &envelope("run-1", 1, EvidenceIntent::Upsert));
        let outcome = db.project_evidence_submission(&older, 400).unwrap();
        assert_eq!(outcome.lifecycle_state, EvidenceLifecycleState::Superseded);
        assert_eq!(
            db.get_evidence_submission(&newer)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Available
        );
    }

    #[test]
    fn concurrent_projection_converges_on_newest_evidence() {
        let path = std::env::temp_dir().join(format!(
            "sekai-evidence-concurrency-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db = Arc::new(setup_at(path.to_str().unwrap()));
        let barrier = Arc::new(Barrier::new(2));
        let handles = [1_i64, 2_i64].map(|sequence| {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let submission_id = admit(
                    &db,
                    &envelope("run-concurrent", sequence, EvidenceIntent::Upsert),
                );
                barrier.wait();
                db.project_evidence_submission(&submission_id, 300 + sequence)
                    .unwrap();
                submission_id
            })
        });
        let [older, newer] = handles.map(|handle| handle.join().unwrap());

        assert_eq!(
            db.get_evidence_submission(&older)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Superseded
        );
        assert_eq!(
            db.get_evidence_submission(&newer)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Available
        );

        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn out_of_order_retraction_cannot_remove_newer_evidence() {
        let db = setup();
        let newer = admit(&db, &envelope("run-1", 2, EvidenceIntent::Upsert));
        db.project_evidence_submission(&newer, 300).unwrap();
        let older_marker = admit(&db, &envelope("run-1", 1, EvidenceIntent::Retract));
        let outcome = db.project_evidence_submission(&older_marker, 400).unwrap();
        assert_eq!(
            outcome.failure_code.as_deref(),
            Some("projection_lifecycle_target_missing")
        );
        assert_eq!(
            db.get_evidence_submission(&newer)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Available
        );
    }

    #[test]
    fn newer_expired_version_supersedes_older_available_evidence() {
        let db = setup();
        let first = admit(&db, &envelope("run-1", 1, EvidenceIntent::Upsert));
        db.project_evidence_submission(&first, 300).unwrap();
        let mut expired = envelope("run-1", 2, EvidenceIntent::Upsert);
        expired.expires_at_ms = Some(350);
        let second = admit(&db, &expired);
        let outcome = db.project_evidence_submission(&second, 400).unwrap();
        assert_eq!(outcome.lifecycle_state, EvidenceLifecycleState::Stale);
        assert_eq!(
            db.get_evidence_submission(&first)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Superseded
        );
    }

    #[test]
    fn retraction_removes_prior_version_from_usable_state() {
        let db = setup();
        let original = admit(&db, &envelope("run-1", 1, EvidenceIntent::Upsert));
        db.project_evidence_submission(&original, 300).unwrap();
        let marker = admit(&db, &envelope("run-1", 2, EvidenceIntent::Retract));
        db.project_evidence_submission(&marker, 400).unwrap();
        assert_eq!(
            db.get_evidence_submission(&original)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Retracted
        );
    }

    #[test]
    fn missing_target_quarantines_without_graph_mutation() {
        let db = setup();
        let mut evidence = envelope("run-1", 1, EvidenceIntent::Upsert);
        evidence.target.object_external_id = "service:missing".into();
        let submission_id = admit(&db, &evidence);
        let outcome = db.project_evidence_submission(&submission_id, 300).unwrap();
        assert!(!outcome.projected);
        assert_eq!(
            outcome.failure_code.as_deref(),
            Some("projection_target_missing")
        );
        let conn = db.conn();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sekai_evidence_projections",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn projection_write_failure_rolls_back_every_surface() {
        let db = setup();
        let submission_id = admit(&db, &envelope("run-1", 1, EvidenceIntent::Upsert));
        db.create_object(&Object {
            id: format!("evidence-object-{submission_id}"),
            kind: "collision".into(),
            name: "collision".into(),
            namespace: "acme".into(),
            external_id: "collision".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        assert!(db.project_evidence_submission(&submission_id, 300).is_err());
        assert_eq!(
            db.get_evidence_submission(&submission_id)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Authorized
        );
        let conn = db.conn();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sekai_evidence_projections",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn relationship_projection_uses_complete_source_identity() {
        let db = setup();
        let correct = admit(&db, &envelope("shared", 1, EvidenceIntent::Upsert));
        db.project_evidence_submission(&correct, 300).unwrap();
        let mut other_type = envelope("shared", 2, EvidenceIntent::Upsert);
        other_type.source_type = "other_verification_system".into();
        other_type.idempotency_key = "other-type".into();
        let other = admit(&db, &other_type);
        db.project_evidence_submission(&other, 310).unwrap();
        assert_eq!(
            db.get_evidence_submission(&correct)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Available
        );
        assert_eq!(
            db.get_evidence_submission(&other)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            EvidenceLifecycleState::Available
        );

        let mut dependent = envelope("dependent", 3, EvidenceIntent::Upsert);
        dependent.relationships = vec![EvidenceRelationship {
            relation: "verified_by".into(),
            target_source_type: "verification_system".into(),
            target_source_instance: "checks-primary".into(),
            target_source_record_id: "shared".into(),
        }];
        let dependent_id = admit(&db, &dependent);
        db.project_evidence_submission(&dependent_id, 320).unwrap();
        let conn = db.conn();
        let related: String = conn
            .query_row(
                "SELECT related_submission_id FROM sekai_evidence_relationship_projections
                 WHERE submission_id=?1",
                [&dependent_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(related, correct);
    }
}
