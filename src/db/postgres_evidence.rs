use crate::db::postgres::PostgresDb;
use crate::sekai::evidence::{
    DEFAULT_EVIDENCE_ENVELOPE_HEADROOM_BYTES, EvidenceEnvelope, EvidenceLifecycleState,
    EvidenceLimits, SchemaCompatibility,
};
use crate::sekai::evidence_projection::{EVIDENCE_PROJECTION_VERSION, EvidenceProjectionOutcome};
use crate::sekai::evidence_store::{
    EvidenceAdmission, EvidenceProducerCapability, EvidenceSchemaDefinition,
    EvidenceSubmissionFilter, EvidenceSubmissionRecord, authorize, canonical_content_digest,
    canonical_envelope_digest, intent_str, parse_classification, parse_intent,
    submission_is_admitted, validate_capability,
};
use crate::sekai::ontology::{
    Cardinality, OntologyClass, OntologyProperty, OntologyRegistry, OntologyRelation,
};
use crate::{domain::KIND_EXTERNAL_EVIDENCE, sekai::audit::Decision};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const SUBMISSION_COLUMNS: &str =
    "id,producer_identity,source_type,source_instance,source_record_id,source_version,
     source_sequence,namespace,target_external_id,target_kind,evidence_type,schema_id,
     schema_version,idempotency_key,content_digest,classification,intent,lifecycle_state,
     rejection_code,rejection_summary,observed_at_ms,collected_at_ms,expires_at_ms,
     received_at_ms,updated_at_ms,envelope_json";

impl PostgresDb {
    pub fn upsert_evidence_producer(
        &self,
        capability: &EvidenceProducerCapability,
        now_ms: i64,
    ) -> Result<(), String> {
        validate_capability(capability)?;
        let json = serde_json::to_string(capability).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 250))",
            &[&capability.producer_identity],
        )
        .map_err(|error| error.to_string())?;
        let mut source_instances = capability.source_instances.clone();
        source_instances.sort();
        source_instances.dedup();
        for instance in source_instances {
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 255))",
                &[&instance],
            )
            .map_err(|error| error.to_string())?;
        }
        let registrations = tx
            .query(
                "SELECT capability_json FROM sekai_evidence_producers
                 WHERE producer_identity<>$1",
                &[&capability.producer_identity],
            )
            .map_err(|error| error.to_string())?;
        for row in registrations {
            let existing: EvidenceProducerCapability =
                serde_json::from_str(row.get::<_, String>(0).as_str())
                    .map_err(|error| error.to_string())?;
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
        let current = tx
            .query_opt(
                "SELECT config_version FROM sekai_evidence_producers
                 WHERE producer_identity=$1 FOR UPDATE",
                &[&capability.producer_identity],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, i64>(0));
        if current.is_some_and(|version| capability.config_version <= version) {
            return Err("producer config version must increase".into());
        }
        tx.execute(
            "INSERT INTO sekai_evidence_producers
             (producer_identity,config_version,capability_json,revoked,updated_at_ms)
             VALUES($1,$2,$3,$4,$5)
             ON CONFLICT(producer_identity) DO UPDATE SET
              config_version=EXCLUDED.config_version,capability_json=EXCLUDED.capability_json,
              revoked=EXCLUDED.revoked,updated_at_ms=EXCLUDED.updated_at_ms",
            &[
                &capability.producer_identity,
                &capability.config_version,
                &json,
                &capability.revoked,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_evidence_producer_history
             (producer_identity,config_version,capability_json,recorded_at_ms)
             VALUES($1,$2,$3,$4)",
            &[
                &capability.producer_identity,
                &capability.config_version,
                &json,
                &now_ms,
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
        let json = serde_json::to_string(definition).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 251))",
            &[&format!(
                "{}:{}",
                definition.schema_id, definition.schema_version
            )],
        )
        .map_err(|error| error.to_string())?;
        if let Some(row) = tx
            .query_opt(
                "SELECT definition_json FROM sekai_evidence_schemas
                 WHERE schema_id=$1 AND schema_version=$2",
                &[&definition.schema_id, &definition.schema_version],
            )
            .map_err(|error| error.to_string())?
        {
            return if row.get::<_, String>(0) == json {
                Ok(())
            } else {
                Err("registered evidence schema versions are immutable".into())
            };
        }
        tx.execute(
            "INSERT INTO sekai_evidence_schemas
             (schema_id,schema_version,evidence_type,definition_json,registered_at_ms)
             VALUES($1,$2,$3,$4,$5)",
            &[
                &definition.schema_id,
                &definition.schema_version,
                &definition.evidence_type,
                &json,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn submit_evidence(
        &self,
        envelope: &EvidenceEnvelope,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<EvidenceAdmission, String> {
        let envelope_digest = canonical_envelope_digest(envelope)?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 252))",
            &[&format!(
                "{authenticated_producer}:{}",
                envelope.idempotency_key
            )],
        )
        .map_err(|error| error.to_string())?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 257))",
            &[&authenticated_producer],
        )
        .map_err(|error| error.to_string())?;
        if let Some(row) = tx
            .query_opt(
                "SELECT submission_id,envelope_digest FROM sekai_evidence_idempotency
                 WHERE producer_identity=$1 AND idempotency_key=$2",
                &[&authenticated_producer, &envelope.idempotency_key],
            )
            .map_err(|error| error.to_string())?
        {
            let id: String = row.get(0);
            if row.get::<_, String>(1) == envelope_digest {
                let submission = get_submission(&mut tx, &id)?.ok_or_else(|| {
                    "idempotency record references missing submission".to_string()
                })?;
                tx.commit().map_err(|error| error.to_string())?;
                return Ok(EvidenceAdmission {
                    accepted: submission_is_admitted(&submission),
                    submission,
                    deduplicated: true,
                });
            }
            return reject_new(
                tx,
                envelope,
                authenticated_producer,
                now_ms,
                "idempotency_conflict",
                "idempotency key was already used for different content",
            );
        }

        let id = format!("evidence-{}", uuid::Uuid::new_v4().simple());
        insert_received(&mut tx, &id, envelope, authenticated_producer, now_ms)?;
        if canonical_content_digest(&envelope.content)? != envelope.content_digest {
            return reject_existing(
                tx,
                &id,
                now_ms,
                "digest_mismatch",
                "content digest did not match canonical content",
            );
        }
        let capability = tx
            .query_opt(
                "SELECT capability_json FROM sekai_evidence_producers
                 WHERE producer_identity=$1",
                &[&authenticated_producer],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                serde_json::from_str::<EvidenceProducerCapability>(row.get::<_, String>(0).as_str())
                    .map_err(|error| error.to_string())
            })
            .transpose()?;
        let limits = capability
            .as_ref()
            .map_or_else(EvidenceLimits::default, |value| EvidenceLimits {
                max_content_bytes: value.max_payload_bytes,
                max_envelope_bytes: value
                    .max_payload_bytes
                    .saturating_add(DEFAULT_EVIDENCE_ENVELOPE_HEADROOM_BYTES),
                max_relationships: value.max_relationships,
                max_subject_references: value.max_relationships,
            });
        if let Err(errors) = envelope.validate_contract(limits) {
            return reject_existing(
                tx,
                &id,
                now_ms,
                "invalid_contract",
                &format!(
                    "evidence contract failed {} validation checks",
                    errors.len()
                ),
            );
        }
        transition(
            &mut tx,
            &id,
            EvidenceLifecycleState::Validated,
            None,
            now_ms,
        )?;
        if envelope.producer_identity != authenticated_producer {
            return reject_existing(
                tx,
                &id,
                now_ms,
                "producer_mismatch",
                "authenticated producer did not match envelope attribution",
            );
        }
        let Some(capability) = capability else {
            return reject_existing(
                tx,
                &id,
                now_ms,
                "producer_unregistered",
                "producer is not registered",
            );
        };
        let recent: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM sekai_evidence_submissions
                 WHERE producer_identity=$1 AND received_at_ms>=$2",
                &[&authenticated_producer, &now_ms.saturating_sub(60_000)],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if let Err((code, summary)) = authorize(&capability, envelope, now_ms, recent as u32) {
            return reject_existing(tx, &id, now_ms, code, summary);
        }
        if !schema_is_accepted(&mut tx, envelope)? {
            return reject_existing(
                tx,
                &id,
                now_ms,
                "schema_incompatible",
                "evidence schema is not registered or compatible",
            );
        }
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 253))",
            &[&format!(
                "{}:{}:{}",
                envelope.source_type, envelope.source_instance, envelope.source_record_id
            )],
        )
        .map_err(|error| error.to_string())?;
        if let Some(row) = tx
            .query_opt(
                "SELECT submission_id,content_digest FROM sekai_evidence_source_identity
                 WHERE source_type=$1 AND source_instance=$2 AND source_record_id=$3
                   AND (source_sequence=$4 OR source_version=$5) LIMIT 1",
                &[
                    &envelope.source_type,
                    &envelope.source_instance,
                    &envelope.source_record_id,
                    &envelope.source_sequence,
                    &envelope.source_version,
                ],
            )
            .map_err(|error| error.to_string())?
        {
            let existing_id: String = row.get(0);
            if row.get::<_, String>(1) != envelope.content_digest {
                return reject_existing(
                    tx,
                    &id,
                    now_ms,
                    "source_identity_collision",
                    "source record version was already observed with different content",
                );
            }
            let aliases: i64 = tx
                .query_one(
                    "SELECT COUNT(*) FROM sekai_evidence_idempotency WHERE submission_id=$1",
                    &[&existing_id],
                )
                .map_err(|error| error.to_string())?
                .get(0);
            if aliases >= 16 {
                return reject_existing(
                    tx,
                    &id,
                    now_ms,
                    "idempotency_alias_capacity_exceeded",
                    "source submission has exhausted its delivery alias quota",
                );
            }
            tx.execute("DELETE FROM sekai_evidence_submissions WHERE id=$1", &[&id])
                .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_evidence_idempotency
                 (producer_identity,idempotency_key,envelope_digest,submission_id)
                 VALUES($1,$2,$3,$4)",
                &[
                    &authenticated_producer,
                    &envelope.idempotency_key,
                    &envelope_digest,
                    &existing_id,
                ],
            )
            .map_err(|error| error.to_string())?;
            let submission = get_submission(&mut tx, &existing_id)?
                .ok_or_else(|| "deduplicated source submission disappeared".to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(EvidenceAdmission {
                accepted: submission_is_admitted(&submission),
                submission,
                deduplicated: true,
            });
        }
        let retained: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM sekai_evidence_submissions
                 WHERE producer_identity=$1 AND lifecycle_state<>'rejected'",
                &[&capability.producer_identity],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if retained > capability.max_retained_submissions as i64 {
            return reject_existing(
                tx,
                &id,
                now_ms,
                "retained_capacity_exceeded",
                "producer retained evidence quota is exhausted",
            );
        }
        transition(
            &mut tx,
            &id,
            EvidenceLifecycleState::Deduplicated,
            None,
            now_ms,
        )?;
        transition(
            &mut tx,
            &id,
            EvidenceLifecycleState::Authorized,
            None,
            now_ms,
        )?;
        tx.execute(
            "INSERT INTO sekai_evidence_idempotency
             (producer_identity,idempotency_key,envelope_digest,submission_id)
             VALUES($1,$2,$3,$4)",
            &[
                &authenticated_producer,
                &envelope.idempotency_key,
                &envelope_digest,
                &id,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_evidence_source_identity
             (source_type,source_instance,source_record_id,source_sequence,source_version,
              content_digest,submission_id) VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[
                &envelope.source_type,
                &envelope.source_instance,
                &envelope.source_record_id,
                &envelope.source_sequence,
                &envelope.source_version,
                &envelope.content_digest,
                &id,
            ],
        )
        .map_err(|error| error.to_string())?;
        let envelope_json = serde_json::to_string(envelope).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE sekai_evidence_submissions SET envelope_json=$2,updated_at_ms=$3 WHERE id=$1",
            &[&id, &envelope_json, &now_ms],
        )
        .map_err(|error| error.to_string())?;
        let submission = get_submission(&mut tx, &id)?
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
        id: &str,
    ) -> Result<Option<EvidenceSubmissionRecord>, String> {
        let mut connection = self.connection()?;
        get_submission(&mut *connection, id)
    }

    pub fn evidence_lifecycle_history(
        &self,
        id: &str,
    ) -> Result<Vec<EvidenceLifecycleState>, String> {
        self.connection()?
            .query(
                "SELECT lifecycle_state FROM sekai_evidence_lifecycle_history
                 WHERE submission_id=$1 ORDER BY id",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let value: String = row.get(0);
                EvidenceLifecycleState::parse(&value)
                    .ok_or_else(|| format!("unknown evidence lifecycle state {value}"))
            })
            .collect()
    }

    pub fn list_evidence_submissions(
        &self,
        filter: &EvidenceSubmissionFilter,
    ) -> Result<Vec<EvidenceSubmissionRecord>, String> {
        let lifecycle = filter
            .lifecycle_state
            .map(|value| value.as_str().to_string());
        self.connection()?
            .query(
                &format!(
                    "SELECT {SUBMISSION_COLUMNS} FROM sekai_evidence_submissions
                     WHERE ($1::text IS NULL OR producer_identity=$1)
                       AND ($2::text IS NULL OR source_instance=$2)
                       AND ($3::text IS NULL OR namespace=$3)
                       AND ($4::text IS NULL OR lifecycle_state=$4)
                       AND ($5::text IS NULL OR target_external_id=$5)
                       AND ($6::text IS NULL OR evidence_type=$6)
                     ORDER BY received_at_ms DESC,id DESC LIMIT $7 OFFSET $8"
                ),
                &[
                    &filter.producer_identity,
                    &filter.source_instance,
                    &filter.namespace,
                    &lifecycle,
                    &filter.target_external_id,
                    &filter.evidence_type,
                    &if filter.limit > 0 {
                        filter.limit.min(500)
                    } else {
                        100
                    },
                    &filter.offset.max(0),
                ],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_submission)
            .collect()
    }

    pub fn project_evidence_submission(
        &self,
        id: &str,
        now: i64,
    ) -> Result<EvidenceProjectionOutcome, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 254))",
            &[&id],
        )
        .map_err(|error| error.to_string())?;
        let submission = get_submission(&mut tx, id)?
            .ok_or_else(|| "evidence submission not found".to_string())?;
        if let Some(row) = tx
            .query_opt(
                "SELECT evidence_object_id,target_object_id FROM sekai_evidence_projections
                 WHERE submission_id=$1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
        {
            return Ok(EvidenceProjectionOutcome {
                submission_id: id.into(),
                evidence_object_id: Some(row.get(0)),
                target_object_id: Some(row.get(1)),
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
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 256))",
            &[&format!(
                "{}:{}:{}",
                envelope.source_type, envelope.source_instance, envelope.source_record_id
            )],
        )
        .map_err(|error| error.to_string())?;
        let targets = tx
            .query(
                "SELECT id,kind FROM sekai_objects
                 WHERE namespace=$1 AND external_id=$2 ORDER BY id LIMIT 2 FOR UPDATE",
                &[
                    &envelope.target.namespace,
                    &envelope.target.object_external_id,
                ],
            )
            .map_err(|error| error.to_string())?;
        let failure = if targets.is_empty() {
            Some((
                "projection_target_missing",
                "target object does not exist in the authorized namespace",
            ))
        } else if targets.len() > 1 {
            Some((
                "projection_target_ambiguous",
                "target external identity resolves to multiple objects",
            ))
        } else if targets[0].get::<_, String>(1) != envelope.target.object_kind {
            Some((
                "projection_target_kind_mismatch",
                "target object kind does not match the admitted envelope",
            ))
        } else {
            None
        };
        if let Some((code, summary)) = failure {
            tx.execute(
                "UPDATE sekai_evidence_submissions SET rejection_code=$2,rejection_summary=$3
                 WHERE id=$1",
                &[&id, &code, &summary],
            )
            .map_err(|error| error.to_string())?;
            transition(
                &mut tx,
                id,
                EvidenceLifecycleState::Quarantined,
                Some(code),
                now,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(EvidenceProjectionOutcome {
                submission_id: id.into(),
                evidence_object_id: None,
                target_object_id: None,
                lifecycle_state: EvidenceLifecycleState::Quarantined,
                projected: false,
                failure_code: Some(code.into()),
            });
        }
        let target_id: String = targets[0].get(0);
        if let Some(operation_id) = envelope
            .causality
            .as_ref()
            .and_then(|causality| causality.operation_id.as_deref())
        {
            let namespace = tx
                .query_opt(
                    "SELECT namespace FROM chisei_operation_receipts WHERE operation_id=$1",
                    &[&operation_id],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, String>(0));
            if namespace.as_deref() != Some(envelope.target.namespace.as_str()) {
                return quarantine_projection(
                    tx,
                    &submission,
                    now,
                    "projection_operation_unavailable",
                    "operation evidence target is absent or belongs to another namespace",
                );
            }
        }
        let mut relationships = Vec::with_capacity(envelope.relationships.len());
        for relationship in &envelope.relationships {
            let source_type = if relationship.target_source_type.is_empty() {
                &envelope.source_type
            } else {
                &relationship.target_source_type
            };
            let source_instance = if relationship.target_source_instance.is_empty() {
                &envelope.source_instance
            } else {
                &relationship.target_source_instance
            };
            let resolved = tx
                .query_opt(
                    "SELECT i.submission_id,p.evidence_object_id
                     FROM sekai_evidence_source_identity i JOIN sekai_evidence_projections p
                       ON p.submission_id=i.submission_id
                     WHERE i.source_type=$1 AND i.source_instance=$2 AND i.source_record_id=$3
                     ORDER BY i.source_sequence DESC LIMIT 1",
                    &[
                        &source_type,
                        &source_instance,
                        &relationship.target_source_record_id,
                    ],
                )
                .map_err(|error| error.to_string())?;
            let Some(row) = resolved else {
                return quarantine_projection(
                    tx,
                    &submission,
                    now,
                    "projection_relationship_unavailable",
                    "related source record has no reproducible projection",
                );
            };
            relationships.push((
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                relationship.relation.clone(),
            ));
        }
        let prior = tx
            .query_opt(
                "SELECT s.id,s.source_sequence,p.evidence_object_id
                 FROM sekai_evidence_submissions s JOIN sekai_evidence_projections p
                   ON p.submission_id=s.id
                 WHERE s.source_type=$1 AND s.source_instance=$2 AND s.source_record_id=$3
                   AND s.lifecycle_state='available' AND s.id<>$4
                 ORDER BY s.source_sequence DESC LIMIT 1 FOR UPDATE",
                &[
                    &envelope.source_type,
                    &envelope.source_instance,
                    &envelope.source_record_id,
                    &id,
                ],
            )
            .map_err(|error| error.to_string())?;
        if envelope.intent != crate::sekai::evidence::EvidenceIntent::Upsert
            && prior
                .as_ref()
                .is_none_or(|row| row.get::<_, i64>(1) >= envelope.source_sequence)
        {
            let code = "projection_lifecycle_target_missing";
            tx.execute(
                "UPDATE sekai_evidence_submissions SET rejection_code=$2,
                 rejection_summary='lifecycle marker has no available earlier evidence version'
                 WHERE id=$1",
                &[&id, &code],
            )
            .map_err(|error| error.to_string())?;
            transition(
                &mut tx,
                id,
                EvidenceLifecycleState::Quarantined,
                Some(code),
                now,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(EvidenceProjectionOutcome {
                submission_id: id.into(),
                evidence_object_id: None,
                target_object_id: None,
                lifecycle_state: EvidenceLifecycleState::Quarantined,
                projected: false,
                failure_code: Some(code.into()),
            });
        }
        let final_state = if envelope.intent == crate::sekai::evidence::EvidenceIntent::Upsert {
            if prior
                .as_ref()
                .is_some_and(|row| row.get::<_, i64>(1) > envelope.source_sequence)
            {
                EvidenceLifecycleState::Superseded
            } else if envelope.expires_at_ms.is_some_and(|expires| expires <= now) {
                EvidenceLifecycleState::Stale
            } else {
                EvidenceLifecycleState::Available
            }
        } else {
            EvidenceLifecycleState::Available
        };
        let identity = serde_json::to_vec(&(
            &envelope.source_type,
            &envelope.source_instance,
            &envelope.source_record_id,
            envelope.source_sequence,
        ))
        .map_err(|error| error.to_string())?;
        let identity_hash = format!("{:x}", Sha256::digest(identity));
        let object_id = format!("evidence-object-{id}");
        let properties = serde_json::to_string(&HashMap::from([
            (
                "authoritative_store",
                "sekai_evidence_submissions".to_string(),
            ),
            ("submission_id", id.to_string()),
            ("source_type", envelope.source_type.clone()),
            ("source_instance", envelope.source_instance.clone()),
            ("source_identity_hash", identity_hash.clone()),
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
             (id,kind,name,namespace,external_id,properties,created,updated)
             VALUES($1,$2,$3,$4,$5,$6,$7,$7)",
            &[
                &object_id,
                &KIND_EXTERNAL_EVIDENCE,
                &envelope.evidence_type,
                &envelope.target.namespace,
                &format!("evidence:{identity_hash}"),
                &properties,
                &now,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_object_changes
             (id,object_id,field,old_value,new_value,changed_by,timestamp)
             VALUES($1,$2,'_created','',$3,$4,$5)",
            &[
                &uuid::Uuid::new_v4().to_string(),
                &object_id,
                &format!("{KIND_EXTERNAL_EVIDENCE}/{}", envelope.evidence_type),
                &submission.producer_identity,
                &now,
            ],
        )
        .map_err(|error| error.to_string())?;
        let ontology = load_ontology_registry(&mut tx)?;
        for (related_submission_id, related_object_id, source_relation) in &relationships {
            let related_kind: String = tx
                .query_one(
                    "SELECT kind FROM sekai_objects WHERE id=$1",
                    &[&related_object_id],
                )
                .map_err(|error| error.to_string())?
                .get(0);
            validate_link_constraint(
                &ontology,
                KIND_EXTERNAL_EVIDENCE,
                &related_kind,
                "derived_from",
            )?;
            let link_hash = format!("{:x}", Sha256::digest(source_relation.as_bytes()));
            tx.execute(
                "INSERT INTO sekai_links(id,from_id,to_id,relation,created)
                 VALUES($1,$2,$3,'derived_from',$4)",
                &[
                    &format!(
                        "evidence-lineage-{id}-{related_submission_id}-{}",
                        &link_hash[..16]
                    ),
                    &object_id,
                    &related_object_id,
                    &now,
                ],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_evidence_relationship_projections
                 (submission_id,related_submission_id,source_relation) VALUES($1,$2,$3)",
                &[&id, &related_submission_id, &source_relation],
            )
            .map_err(|error| error.to_string())?;
        }
        validate_link_constraint(
            &ontology,
            KIND_EXTERNAL_EVIDENCE,
            &envelope.target.object_kind,
            "evidence_for",
        )?;
        tx.execute(
            "INSERT INTO sekai_links(id,from_id,to_id,relation,created)
             VALUES($1,$2,$3,'evidence_for',$4)",
            &[
                &format!("evidence-target-{id}"),
                &object_id,
                &target_id,
                &now,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_evidence_observations
             (submission_id,evidence_object_id,signal,confidence_bps,observed_at_ms,
              projection_version) VALUES($1,$2,$3,$4,$5,$6)",
            &[
                &id,
                &object_id,
                &envelope.signal.as_str(),
                &(envelope.confidence_bps as i64),
                &envelope.observed_at_ms,
                &EVIDENCE_PROJECTION_VERSION,
            ],
        )
        .map_err(|error| error.to_string())?;
        if let Some(operation_id) = envelope
            .causality
            .as_ref()
            .and_then(|causality| causality.operation_id.as_deref())
        {
            tx.execute(
                "INSERT INTO sekai_evidence_operation_links(submission_id,operation_id)
                 VALUES($1,$2)",
                &[&id, &operation_id],
            )
            .map_err(|error| error.to_string())?;
        }
        let target_grants = tx
            .query(
                "SELECT principal,role FROM sekai_grants WHERE object_id=$1",
                &[&target_id],
            )
            .map_err(|error| error.to_string())?;
        for grant in &target_grants {
            let principal: String = grant.get(0);
            let role: String = grant.get(1);
            let grant_hash = format!("{:x}", Sha256::digest(principal.as_bytes()));
            tx.execute(
                "INSERT INTO sekai_grants(id,object_id,principal,role,created)
                 VALUES($1,$2,$3,$4,$5)",
                &[
                    &format!("grant-{id}-{}", &grant_hash[..16]),
                    &object_id,
                    &principal,
                    &role,
                    &now,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        if envelope.classification != crate::sekai::evidence::EvidenceClassification::Public
            && !target_grants
                .iter()
                .any(|row| row.get::<_, String>(0) == submission.producer_identity)
        {
            tx.execute(
                "INSERT INTO sekai_grants(id,object_id,principal,role,created)
                 VALUES($1,$2,$3,'viewer',$4)",
                &[
                    &format!("grant-{id}-producer"),
                    &object_id,
                    &submission.producer_identity,
                    &now,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute(
            "INSERT INTO sekai_evidence_projections
             (submission_id,evidence_object_id,target_object_id,projection_version,
              source_sequence,projected_at_ms) VALUES($1,$2,$3,$4,$5,$6)",
            &[
                &id,
                &object_id,
                &target_id,
                &EVIDENCE_PROJECTION_VERSION,
                &envelope.source_sequence,
                &now,
            ],
        )
        .map_err(|error| error.to_string())?;
        if envelope.intent == crate::sekai::evidence::EvidenceIntent::Upsert {
            if final_state != EvidenceLifecycleState::Superseded {
                for row in tx
                    .query(
                        "SELECT s.id,p.evidence_object_id FROM sekai_evidence_submissions s
                     JOIN sekai_evidence_projections p ON p.submission_id=s.id
                     WHERE s.source_type=$1 AND s.source_instance=$2 AND s.source_record_id=$3
                       AND s.source_sequence<$4 AND s.lifecycle_state='available' FOR UPDATE",
                        &[
                            &envelope.source_type,
                            &envelope.source_instance,
                            &envelope.source_record_id,
                            &envelope.source_sequence,
                        ],
                    )
                    .map_err(|error| error.to_string())?
                {
                    let older_id: String = row.get(0);
                    transition(
                        &mut tx,
                        &older_id,
                        EvidenceLifecycleState::Superseded,
                        None,
                        now,
                    )?;
                    update_object_lifecycle(
                        &mut tx,
                        &row.get::<_, String>(1),
                        EvidenceLifecycleState::Superseded,
                        now,
                    )?;
                }
            }
        } else if let Some(prior) = prior {
            let state = match envelope.intent {
                crate::sekai::evidence::EvidenceIntent::Retract => {
                    EvidenceLifecycleState::Retracted
                }
                crate::sekai::evidence::EvidenceIntent::MarkStale => EvidenceLifecycleState::Stale,
                crate::sekai::evidence::EvidenceIntent::Upsert => unreachable!(),
            };
            let prior_id: String = prior.get(0);
            transition(&mut tx, &prior_id, state, None, now)?;
            update_object_lifecycle(&mut tx, &prior.get::<_, String>(2), state, now)?;
        }
        tx.execute(
            "UPDATE sekai_evidence_submissions
             SET rejection_code=NULL,rejection_summary=NULL WHERE id=$1",
            &[&id],
        )
        .map_err(|error| error.to_string())?;
        transition(&mut tx, id, EvidenceLifecycleState::Projected, None, now)?;
        transition(&mut tx, id, final_state, None, now)?;
        insert_projection_decision(
            &mut tx,
            &Decision {
                id: format!("evidence-projection-{id}"),
                timestamp: now,
                actor: submission.producer_identity,
                action: "evidence.project".into(),
                reason: "admitted external evidence projected atomically".into(),
                evidence: HashMap::from([
                    ("submission_id".into(), id.into()),
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
                target_id: object_id.clone(),
                outcome: final_state.as_str().into(),
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(EvidenceProjectionOutcome {
            submission_id: id.into(),
            evidence_object_id: Some(object_id),
            target_object_id: Some(target_id),
            lifecycle_state: final_state,
            projected: true,
            failure_code: None,
        })
    }
}

fn load_ontology_registry(tx: &mut postgres::Transaction<'_>) -> Result<OntologyRegistry, String> {
    let classes = tx
        .query(
            "SELECT name,description,superclasses_json,equivalent_json,disjoint_json,
                    properties_json,mapped_kind FROM sekai_ontology_classes ORDER BY name",
            &[],
        )
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|row| {
            Ok(OntologyClass {
                name: row.get(0),
                description: row.get(1),
                superclasses: serde_json::from_str(row.get::<_, String>(2).as_str())
                    .map_err(|error| error.to_string())?,
                equivalent_classes: serde_json::from_str(row.get::<_, String>(3).as_str())
                    .map_err(|error| error.to_string())?,
                disjoint_classes: serde_json::from_str(row.get::<_, String>(4).as_str())
                    .map_err(|error| error.to_string())?,
                properties: serde_json::from_str::<Vec<OntologyProperty>>(
                    row.get::<_, String>(5).as_str(),
                )
                .map_err(|error| error.to_string())?,
                is_builtin: false,
                mapped_kind: row.get(6),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relations = tx
        .query(
            "SELECT name,description,domain,range,cardinality_json,inverse,transitive,
                    mapped_relation FROM sekai_ontology_relations ORDER BY name",
            &[],
        )
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|row| {
            Ok(OntologyRelation {
                name: row.get(0),
                description: row.get(1),
                domain: row.get(2),
                range: row.get(3),
                cardinality: serde_json::from_str::<Cardinality>(row.get::<_, String>(4).as_str())
                    .map_err(|error| error.to_string())?,
                inverse: row.get(5),
                transitive: row.get::<_, i64>(6) != 0,
                is_builtin: false,
                mapped_relation: row.get(7),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(OntologyRegistry::from_parts(classes, relations))
}

fn validate_link_constraint(
    registry: &OntologyRegistry,
    from_kind: &str,
    to_kind: &str,
    mapped_relation: &str,
) -> Result<(), String> {
    if registry
        .constraints_for_mapped_relation(mapped_relation)
        .into_iter()
        .any(|constraint| {
            !registry.kind_satisfies_class(from_kind, &constraint.domain)
                || !registry.kind_satisfies_class(to_kind, &constraint.range)
        })
    {
        return Err("link endpoints violate ontology constraint".into());
    }
    Ok(())
}

fn quarantine_projection(
    mut tx: postgres::Transaction<'_>,
    submission: &EvidenceSubmissionRecord,
    now: i64,
    code: &str,
    summary: &str,
) -> Result<EvidenceProjectionOutcome, String> {
    tx.execute(
        "UPDATE sekai_evidence_submissions
         SET rejection_code=$2,rejection_summary=$3,updated_at_ms=$4 WHERE id=$1",
        &[&submission.id, &code, &summary, &now],
    )
    .map_err(|error| error.to_string())?;
    transition(
        &mut tx,
        &submission.id,
        EvidenceLifecycleState::Quarantined,
        Some(code),
        now,
    )?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(EvidenceProjectionOutcome {
        submission_id: submission.id.clone(),
        evidence_object_id: None,
        target_object_id: None,
        lifecycle_state: EvidenceLifecycleState::Quarantined,
        projected: false,
        failure_code: Some(code.into()),
    })
}

fn update_object_lifecycle(
    tx: &mut postgres::Transaction<'_>,
    id: &str,
    state: EvidenceLifecycleState,
    now: i64,
) -> Result<(), String> {
    let row = tx
        .query_one(
            "SELECT properties FROM sekai_objects WHERE id=$1 FOR UPDATE",
            &[&id],
        )
        .map_err(|error| error.to_string())?;
    let mut properties: HashMap<String, String> =
        serde_json::from_str(row.get::<_, String>(0).as_str())
            .map_err(|error| error.to_string())?;
    properties.insert("lifecycle_state".into(), state.as_str().into());
    let json = serde_json::to_string(&properties).map_err(|error| error.to_string())?;
    tx.execute(
        "UPDATE sekai_objects SET properties=$2,updated=$3 WHERE id=$1",
        &[&id, &json, &now],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn insert_projection_decision(
    tx: &mut postgres::Transaction<'_>,
    decision: &Decision,
) -> Result<(), String> {
    tx.query_one("SELECT pg_advisory_xact_lock(25012)", &[])
        .map_err(|error| error.to_string())?;
    let head = tx
        .query_opt(
            "SELECT seq,entry_hash FROM sekai_decisions
             WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1 FOR UPDATE",
            &[],
        )
        .map_err(|error| error.to_string())?;
    let (head_seq, head_hash) = head
        .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))
        .unwrap_or((0, String::new()));
    let sequence = head_seq + 1;
    let evidence = serde_json::to_string(&decision.evidence).map_err(|error| error.to_string())?;
    let hash = crate::sekai::ledger::entry_hash(sequence, &head_hash, decision, &evidence);
    tx.execute(
        "INSERT INTO sekai_decisions
         (id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        &[
            &decision.id,
            &decision.timestamp,
            &decision.actor,
            &decision.action,
            &decision.reason,
            &evidence,
            &decision.target_id,
            &decision.outcome,
            &sequence,
            &head_hash,
            &hash,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn schema_is_accepted(
    tx: &mut postgres::Transaction<'_>,
    envelope: &EvidenceEnvelope,
) -> Result<bool, String> {
    for row in tx
        .query(
            "SELECT definition_json FROM sekai_evidence_schemas
             WHERE schema_id=$1 AND evidence_type=$2",
            &[&envelope.schema_id, &envelope.evidence_type],
        )
        .map_err(|error| error.to_string())?
    {
        let definition: EvidenceSchemaDefinition =
            serde_json::from_str(row.get::<_, String>(0).as_str())
                .map_err(|error| error.to_string())?;
        if definition.schema_version == envelope.schema_version
            || (envelope.schema_compatibility == SchemaCompatibility::BackwardCompatible
                && definition
                    .compatible_versions
                    .contains(&envelope.schema_version))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn insert_received(
    tx: &mut postgres::Transaction<'_>,
    id: &str,
    envelope: &EvidenceEnvelope,
    producer: &str,
    now: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_evidence_submissions
         (id,producer_identity,source_type,source_instance,source_record_id,source_version,
          source_sequence,namespace,target_external_id,target_kind,evidence_type,schema_id,
          schema_version,idempotency_key,content_digest,classification,intent,lifecycle_state,
          observed_at_ms,collected_at_ms,expires_at_ms,received_at_ms,updated_at_ms)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'received',
                $18,$19,$20,$21,$21)",
        &[
            &id,
            &producer,
            &envelope.source_type,
            &envelope.source_instance,
            &envelope.source_record_id,
            &envelope.source_version,
            &envelope.source_sequence,
            &envelope.target.namespace,
            &envelope.target.object_external_id,
            &envelope.target.object_kind,
            &envelope.evidence_type,
            &envelope.schema_id,
            &envelope.schema_version,
            &envelope.idempotency_key,
            &envelope.content_digest,
            &envelope.classification.as_str(),
            &intent_str(envelope.intent),
            &envelope.observed_at_ms,
            &envelope.collected_at_ms,
            &envelope.expires_at_ms,
            &now,
        ],
    )
    .map_err(|error| error.to_string())?;
    transition(tx, id, EvidenceLifecycleState::Received, None, now)
}

fn transition(
    tx: &mut postgres::Transaction<'_>,
    id: &str,
    state: EvidenceLifecycleState,
    reason: Option<&str>,
    now: i64,
) -> Result<(), String> {
    tx.execute(
        "UPDATE sekai_evidence_submissions SET lifecycle_state=$2,updated_at_ms=$3 WHERE id=$1",
        &[&id, &state.as_str(), &now],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_evidence_lifecycle_history
         (submission_id,lifecycle_state,reason_code,recorded_at_ms) VALUES($1,$2,$3,$4)",
        &[&id, &state.as_str(), &reason, &now],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn reject_new(
    mut tx: postgres::Transaction<'_>,
    envelope: &EvidenceEnvelope,
    producer: &str,
    now: i64,
    code: &str,
    summary: &str,
) -> Result<EvidenceAdmission, String> {
    let id = format!("evidence-{}", uuid::Uuid::new_v4().simple());
    insert_received(&mut tx, &id, envelope, producer, now)?;
    reject_existing(tx, &id, now, code, summary)
}

fn reject_existing(
    mut tx: postgres::Transaction<'_>,
    id: &str,
    now: i64,
    code: &str,
    summary: &str,
) -> Result<EvidenceAdmission, String> {
    tx.execute(
        "UPDATE sekai_evidence_submissions SET lifecycle_state='rejected',
         rejection_code=$2,rejection_summary=$3,envelope_json=NULL,updated_at_ms=$4 WHERE id=$1",
        &[&id, &code, &summary, &now],
    )
    .map_err(|error| error.to_string())?;
    transition(
        &mut tx,
        id,
        EvidenceLifecycleState::Rejected,
        Some(code),
        now,
    )?;
    tx.execute(
        "DELETE FROM sekai_evidence_submissions
         WHERE id IN (
           SELECT id FROM sekai_evidence_submissions
           WHERE lifecycle_state='rejected'
           ORDER BY updated_at_ms DESC,id DESC OFFSET 10000
         )",
        &[],
    )
    .map_err(|error| error.to_string())?;
    let submission = get_submission(&mut tx, id)?
        .ok_or_else(|| "rejected submission disappeared".to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(EvidenceAdmission {
        submission,
        accepted: false,
        deduplicated: false,
    })
}

fn get_submission(
    client: &mut impl postgres::GenericClient,
    id: &str,
) -> Result<Option<EvidenceSubmissionRecord>, String> {
    client
        .query_opt(
            &format!("SELECT {SUBMISSION_COLUMNS} FROM sekai_evidence_submissions WHERE id=$1"),
            &[&id],
        )
        .map_err(|error| error.to_string())?
        .map(row_to_submission)
        .transpose()
}

fn row_to_submission(row: postgres::Row) -> Result<EvidenceSubmissionRecord, String> {
    let classification: String = row.get(15);
    let intent: String = row.get(16);
    let lifecycle: String = row.get(17);
    Ok(EvidenceSubmissionRecord {
        id: row.get(0),
        producer_identity: row.get(1),
        source_type: row.get(2),
        source_instance: row.get(3),
        source_record_id: row.get(4),
        source_version: row.get(5),
        source_sequence: row.get(6),
        namespace: row.get(7),
        target_external_id: row.get(8),
        target_kind: row.get(9),
        evidence_type: row.get(10),
        schema_id: row.get(11),
        schema_version: row.get(12),
        idempotency_key: row.get(13),
        content_digest: row.get(14),
        classification: parse_classification(&classification)
            .ok_or_else(|| format!("unknown evidence classification {classification}"))?,
        intent: parse_intent(&intent).ok_or_else(|| format!("unknown evidence intent {intent}"))?,
        lifecycle_state: EvidenceLifecycleState::parse(&lifecycle)
            .ok_or_else(|| format!("unknown evidence lifecycle state {lifecycle}"))?,
        rejection_code: row.get(18),
        rejection_summary: row.get(19),
        observed_at_ms: row.get(20),
        collected_at_ms: row.get(21),
        expires_at_ms: row.get(22),
        received_at_ms: row.get(23),
        updated_at_ms: row.get(24),
        envelope: row
            .get::<_, Option<String>>(25)
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()?,
    })
}
