use crate::db::postgres::PostgresDb;
use crate::sekai::audit::Decision;
use crate::sekai::retention::contains_subject_reference;
use crate::sekai::retention::{
    ArchiveRun, ArchiveVerification, RetentionPolicy, SubjectErasureRequest, SubjectErasureResult,
};
use postgres::{GenericClient, Row};
use sha2::{Digest, Sha256};

#[derive(Debug)]
struct ArchiveRecord {
    dataset: String,
    source_key: String,
    payload: String,
}

impl PostgresDb {
    pub fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String> {
        if policy.dataset.trim().is_empty() {
            return Err("dataset is required".into());
        }
        if !matches!(
            policy.dataset.as_str(),
            "audit" | "llm_calls" | "task_observations"
        ) {
            return Err("dataset must be audit, llm_calls, or task_observations".into());
        }
        if policy.retention_days <= 0 {
            return Err("retention_days must be positive".into());
        }
        let mut connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO sekai_retention_policies
                 (dataset,namespace,data_class,retention_days,updated)
                 VALUES($1,$2,$3,$4,$5)
                 ON CONFLICT(dataset,namespace,data_class) DO UPDATE SET
                  retention_days=EXCLUDED.retention_days,updated=EXCLUDED.updated",
                &[
                    &policy.dataset,
                    &policy.namespace,
                    &policy.data_class,
                    &policy.retention_days,
                    &policy.updated,
                ],
            )
            .map(|_| ())
            .map_err(err)
    }

    pub fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String> {
        let mut connection = self.connection()?;
        connection
            .query(
                "SELECT dataset,namespace,data_class,retention_days,updated
                 FROM sekai_retention_policies ORDER BY dataset,namespace,data_class",
                &[],
            )
            .map_err(err)
            .map(|rows| rows.into_iter().map(row_policy).collect())
    }

    pub fn erase_subject(
        &self,
        request: &SubjectErasureRequest,
    ) -> Result<SubjectErasureResult, String> {
        if !matches!(
            request.subject_kind.as_str(),
            "agent" | "user" | "work_unit"
        ) {
            return Err("subject_kind must be agent, user, or work_unit".into());
        }
        if request.subject.trim().is_empty() {
            return Err("subject must not be empty".into());
        }
        if request.requested_by.trim().is_empty() {
            return Err("requested_by must not be empty".into());
        }
        let subject_hash = format!("erased-{}", uuid::Uuid::new_v4().simple());
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        tx.query_one("SELECT pg_advisory_xact_lock(251,251)", &[])
            .map_err(err)?;
        tx.query_one("SELECT pg_advisory_xact_lock(25012)", &[])
            .map_err(err)?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,251))",
            &[&format!(
                "subject-erasure:{}:{}",
                request.subject_kind, request.subject
            )],
        )
        .map_err(err)?;
        let mut result = SubjectErasureResult {
            subject_hash: subject_hash.clone(),
            ..SubjectErasureResult::default()
        };
        redact_archived_subject(
            &mut tx,
            &request.subject_kind,
            &request.subject,
            &subject_hash,
            request.timestamp,
        )?;
        erase_supported_subject_data(&mut tx, request, &subject_hash, &mut result)?;
        if let Some(location) =
            unsupported_subject_location(&mut tx, &request.subject_kind, &request.subject)?
        {
            return Err(format!(
                "subject erasure cannot safely complete while subject data remains in {location}"
            ));
        }
        let rows = tx
            .query(
                "SELECT reference_id,blob_id,namespace,actor,operation_id,causal_identity,
                        retention_hold,legal_hold,archived,receipt_required,
                        attestation_required,retention_until_ms
                 FROM sekai_content_references ORDER BY reference_id FOR UPDATE",
                &[],
            )
            .map_err(err)?
            .into_iter()
            .filter(|row| {
                let values = match request.subject_kind.as_str() {
                    "work_unit" => [row.get::<_, String>(4), row.get::<_, String>(5)].to_vec(),
                    "agent" | "user" => [row.get::<_, String>(3)].to_vec(),
                    _ => unreachable!(),
                };
                values.iter().any(|value| {
                    value == &request.subject
                        || value_mentions_subject(value, &request.subject_kind, &request.subject)
                })
            })
            .collect::<Vec<_>>();
        if rows.iter().any(|row| {
            row.get::<_, bool>(6)
                || row.get::<_, bool>(7)
                || row.get::<_, bool>(8)
                || row.get::<_, bool>(9)
                || row.get::<_, bool>(10)
                || row
                    .get::<_, Option<i64>>(11)
                    .is_some_and(|until| until > request.timestamp)
        }) {
            return Err("subject erasure is blocked by a retaining obligation".into());
        }
        let subject_reference_ids = rows
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<std::collections::BTreeSet<_>>();
        let subject_blob_ids = rows
            .iter()
            .map(|row| row.get::<_, String>(1))
            .collect::<std::collections::BTreeSet<_>>();
        for blob_id in &subject_blob_ids {
            let shared = tx
                .query(
                    "SELECT reference_id,released_at_ms,retention_hold,legal_hold,archived,
                            receipt_required,attestation_required,retention_until_ms
                     FROM sekai_content_references WHERE blob_id=$1 FOR UPDATE",
                    &[&blob_id],
                )
                .map_err(err)?
                .into_iter()
                .any(|row| {
                    let reference_id: String = row.get(0);
                    !subject_reference_ids.contains(&reference_id)
                        && (row.get::<_, Option<i64>>(1).is_none()
                            || row.get::<_, bool>(2)
                            || row.get::<_, bool>(3)
                            || row.get::<_, bool>(4)
                            || row.get::<_, bool>(5)
                            || row.get::<_, bool>(6)
                            || row
                                .get::<_, Option<i64>>(7)
                                .is_some_and(|until| until > request.timestamp))
                });
            if shared {
                return Err(
                    "subject erasure is blocked by another readable content reference".into(),
                );
            }
        }
        let mut subject_blob_ids = std::collections::BTreeSet::new();
        for row in rows {
            let reference_id: String = row.get(0);
            let blob_id: String = row.get(1);
            let namespace: String = row.get(2);
            subject_blob_ids.insert(blob_id.clone());
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,251))",
                &[&namespace],
            )
            .map_err(err)?;
            tx.execute(
                "UPDATE sekai_content_references SET
                 actor=$1,operation_id=$1,causal_identity=$1,
                 released_at_ms=COALESCE(released_at_ms,$2),release_reason='subject erasure'
                 WHERE reference_id=$3",
                &[&subject_hash, &request.timestamp, &reference_id],
            )
            .map_err(err)?;
            tx.execute(
                "UPDATE sekai_content_events
                 SET actor=$1,reason='subject erasure tombstone'
                 WHERE reference_id=$2",
                &[&subject_hash, &reference_id],
            )
            .map_err(err)?;
            tx.execute(
                "INSERT INTO sekai_content_events
                 (id,event_kind,blob_id,reference_id,actor,reason,created_at_ms)
                 VALUES($1,'subject_erased',$2,$3,$4,$5,$6)",
                &[
                    &format!("content-event-{}", uuid::Uuid::new_v4().simple()),
                    &blob_id,
                    &reference_id,
                    &"privacy.erasure",
                    &"subject erasure completed",
                    &request.timestamp,
                ],
            )
            .map_err(err)?;
        }
        let mut erased = 0;
        for blob_id in subject_blob_ids {
            erased += tx
                .execute(
                    "UPDATE sekai_content_blobs b SET content=NULL,erased_at_ms=$1
                     WHERE id=$2 AND content IS NOT NULL AND NOT EXISTS (
                       SELECT 1 FROM sekai_content_references r WHERE r.blob_id=b.id AND (
                         r.released_at_ms IS NULL OR r.retention_hold OR r.legal_hold OR r.archived
                         OR r.receipt_required OR r.attestation_required
                         OR COALESCE(r.retention_until_ms,0)>$1))",
                    &[&request.timestamp, &blob_id],
                )
                .map_err(err)?;
        }
        let _payloads_erased = erased;
        append_subject_erasure_decision(&mut tx, request, &result)?;
        tx.commit().map_err(err)?;
        Ok(result)
    }

    /// Archive immutable lifecycle evidence before removing it from the hot
    /// event table. References, payloads, objects, and reconciliation decisions
    /// stay in place so archive maintenance cannot sever lineage.
    pub fn archive_lifecycle_records(&self, cutoff_ms: i64) -> Result<ArchiveRun, String> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        tx.query_one("SELECT pg_advisory_xact_lock_shared(251,251)", &[])
            .map_err(err)?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('sekai.lifecycle.archive',251))",
            &[],
        )
        .map_err(err)?;
        let mut records = tx
            .query(
                "SELECT id,event_kind,blob_id,reference_id,actor,reason,created_at_ms
                 FROM sekai_content_events WHERE created_at_ms<$1 ORDER BY id FOR UPDATE",
                &[&cutoff_ms],
            )
            .map_err(err)?
            .into_iter()
            .map(|row| ArchiveRecord {
                dataset: "content_events".into(),
                source_key: row.get(0),
                payload: serde_json::json!({
                    "event_kind": row.get::<_, String>(1),
                    "blob_id": row.get::<_, String>(2),
                    "reference_id": row.get::<_, Option<String>>(3),
                    "actor": row.get::<_, String>(4),
                    "reason": row.get::<_, String>(5),
                    "created_at_ms": row.get::<_, i64>(6),
                })
                .to_string(),
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            (&left.dataset, &left.source_key).cmp(&(&right.dataset, &right.source_key))
        });
        if records.is_empty() {
            tx.commit().map_err(err)?;
            return Ok(ArchiveRun::default());
        }
        let hashes = records.iter().map(record_hash).collect::<Vec<_>>();
        let content_hash = hash_json(&hashes)?;
        let batch_id = hash_json(&(cutoff_ms, &content_hash))?;
        tx.execute(
            "INSERT INTO sekai_archive_batches
             (id,cutoff_ms,content_hash,record_count,created_at_ms)
             VALUES($1,$2,$3,$4,$2) ON CONFLICT(id) DO NOTHING",
            &[
                &batch_id,
                &cutoff_ms,
                &content_hash,
                &(records.len() as i64),
            ],
        )
        .map_err(err)?;
        let batch = tx
            .query_one(
                "SELECT cutoff_ms,content_hash,record_count FROM sekai_archive_batches WHERE id=$1",
                &[&batch_id],
            )
            .map_err(err)?;
        if batch.get::<_, i64>(0) != cutoff_ms
            || batch.get::<_, String>(1) != content_hash
            || batch.get::<_, i64>(2) != records.len() as i64
        {
            return Err("archive batch identity conflicts with existing content".into());
        }
        for (record, payload_hash) in records.iter().zip(&hashes) {
            tx.execute(
                "INSERT INTO sekai_archive_records
                 (dataset,source_key,payload,payload_hash,archived_at_ms)
                 VALUES($1,$2,$3,$4,$5) ON CONFLICT(dataset,source_key) DO NOTHING",
                &[
                    &record.dataset,
                    &record.source_key,
                    &record.payload,
                    &payload_hash,
                    &cutoff_ms,
                ],
            )
            .map_err(err)?;
            let stored: String = tx
                .query_one(
                    "SELECT payload_hash FROM sekai_archive_records
                     WHERE dataset=$1 AND source_key=$2",
                    &[&record.dataset, &record.source_key],
                )
                .map_err(err)?
                .get(0);
            if stored != *payload_hash {
                return Err(format!(
                    "archive record {}:{} conflicts with existing content",
                    record.dataset, record.source_key
                ));
            }
            tx.execute(
                "INSERT INTO sekai_archive_batch_records(batch_id,dataset,source_key)
                 VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&batch_id, &record.dataset, &record.source_key],
            )
            .map_err(err)?;
        }
        verify_batch(&mut tx, &batch_id)?;
        for record in &records {
            tx.execute(
                "DELETE FROM sekai_content_events WHERE id=$1",
                &[&record.source_key],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        Ok(ArchiveRun {
            batch_id,
            content_hash,
            audit_archived: records.len() as i32,
            ..ArchiveRun::default()
        })
    }

    pub fn verify_lifecycle_archive(&self, batch_id: &str) -> Result<ArchiveVerification, String> {
        if batch_id.trim().is_empty() {
            return Err("batch_id is required".into());
        }
        let mut connection = self.connection()?;
        match verify_batch(&mut *connection, batch_id) {
            Ok((records, batches)) => Ok(ArchiveVerification {
                ok: true,
                records_checked: records,
                batches_checked: batches,
                error: String::new(),
            }),
            Err(error) => Ok(ArchiveVerification {
                ok: false,
                error,
                ..ArchiveVerification::default()
            }),
        }
    }
}

fn append_subject_erasure_decision(
    client: &mut impl GenericClient,
    request: &SubjectErasureRequest,
    result: &SubjectErasureResult,
) -> Result<(), String> {
    let head = client
        .query_opt(
            "SELECT seq,entry_hash FROM sekai_decisions
             WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1 FOR UPDATE",
            &[],
        )
        .map_err(err)?;
    let (head_seq, head_hash) = head
        .map(|row| {
            (
                row.get::<_, i64>(0),
                row.get::<_, Option<String>>(1).unwrap_or_default(),
            )
        })
        .unwrap_or((0, String::new()));
    let evidence = std::collections::HashMap::from([
        ("subject_kind".into(), request.subject_kind.clone()),
        ("subject_hash".into(), result.subject_hash.clone()),
        (
            "requester_hash".into(),
            format!("requester-{}", uuid::Uuid::new_v4().simple()),
        ),
        ("reason_hash".into(), sha256(request.reason.as_bytes())),
        (
            "audit_tombstoned".into(),
            result.audit_tombstoned.to_string(),
        ),
        ("objects_deleted".into(), result.objects_deleted.to_string()),
        (
            "objects_tombstoned".into(),
            result.objects_tombstoned.to_string(),
        ),
        (
            "work_units_deleted".into(),
            result.work_units_deleted.to_string(),
        ),
        (
            "task_observations_deleted".into(),
            result.task_observations_deleted.to_string(),
        ),
    ]);
    let decision = Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: request.timestamp,
        actor: "privacy.erasure".into(),
        action: "privacy.subject_erased".into(),
        reason: "subject erasure completed".into(),
        evidence,
        target_id: String::new(),
        outcome: "erased".into(),
    };
    let evidence_json = serde_json::to_string(&decision.evidence).map_err(err)?;
    let sequence = head_seq + 1;
    let entry_hash =
        crate::sekai::ledger::entry_hash(sequence, &head_hash, &decision, &evidence_json);
    client
        .execute(
            "INSERT INTO sekai_decisions
             (id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            &[
                &decision.id,
                &decision.timestamp,
                &decision.actor,
                &decision.action,
                &decision.reason,
                &evidence_json,
                &decision.target_id,
                &decision.outcome,
                &sequence,
                &head_hash,
                &entry_hash,
            ],
        )
        .map(|_| ())
        .map_err(err)
}

fn unsupported_subject_location(
    client: &mut impl GenericClient,
    subject_kind: &str,
    subject: &str,
) -> Result<Option<String>, String> {
    let columns = client
        .query(
            "SELECT table_name,column_name FROM information_schema.columns
             WHERE table_schema=current_schema()
               AND data_type IN ('text','character varying','character','json','jsonb')
               AND table_name NOT IN (
                 'sekai_content_references','sekai_content_events','sekai_content_blobs')
             ORDER BY table_name,column_name",
            &[],
        )
        .map_err(err)?;
    for row in columns {
        let table: String = row.get(0);
        let column: String = row.get(1);
        let quoted_table = quote_identifier(&table);
        let quoted_column = quote_identifier(&column);
        let query = format!(
            "SELECT {quoted_column}::text FROM {quoted_table} WHERE {quoted_column} IS NOT NULL"
        );
        let found = client
            .query(&query, &[])
            .map_err(err)?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .any(|value| value == subject || value_mentions_subject(&value, subject_kind, subject));
        if found {
            return Ok(Some(format!("{table}.{column}")));
        }
    }
    Ok(None)
}

fn erase_supported_subject_data(
    client: &mut impl GenericClient,
    request: &SubjectErasureRequest,
    subject_hash: &str,
    result: &mut SubjectErasureResult,
) -> Result<(), String> {
    let subject = request.subject.as_str();

    for row in client
        .query(
            "SELECT id,data FROM sekai_dataset_rows
             WHERE dataset_id='llm_calls' ORDER BY id FOR UPDATE",
            &[],
        )
        .map_err(err)?
    {
        let id: i64 = row.get(0);
        let data: String = row.get(1);
        if value_mentions_subject(&data, &request.subject_kind, subject) {
            result.llm_calls_deleted += client
                .execute("DELETE FROM sekai_dataset_rows WHERE id=$1", &[&id])
                .map_err(err)? as i32;
        }
    }

    for row in client
        .query(
            "SELECT request_id,component_id,namespace,model,status,packages_json,context_json
             FROM sekai_task_observations ORDER BY request_id,component_id FOR UPDATE",
            &[],
        )
        .map_err(err)?
    {
        let values = (0..7)
            .map(|index| row.get::<_, String>(index))
            .collect::<Vec<_>>();
        if values.iter().any(|value| {
            value == subject || value_mentions_subject(value, &request.subject_kind, subject)
        }) {
            result.task_observations_deleted += client
                .execute(
                    "DELETE FROM sekai_task_observations
                     WHERE request_id=$1 AND component_id=$2",
                    &[&values[0], &values[1]],
                )
                .map_err(err)? as i32;
        }
    }

    let object_rows = client
        .query(
            "SELECT id,kind,name,namespace,external_id,properties
             FROM sekai_objects ORDER BY id FOR UPDATE",
            &[],
        )
        .map_err(err)?;
    let mut object_ids = Vec::new();
    for row in object_rows {
        let id: String = row.get(0);
        let kind: String = row.get(1);
        let name: String = row.get(2);
        let external_id: String = row.get(4);
        let properties: String = row.get(5);
        let represents_subject = id == subject
            || (kind == request.subject_kind && (external_id == subject || name == subject));
        if represents_subject {
            object_ids.push(id);
            continue;
        }
        if value_mentions_subject(&name, &request.subject_kind, subject)
            || value_mentions_subject(&external_id, &request.subject_kind, subject)
            || value_mentions_subject(&properties, &request.subject_kind, subject)
        {
            let redacted_name =
                redact_subject_value(&name, &request.subject_kind, subject, subject_hash);
            let redacted_external =
                redact_subject_value(&external_id, &request.subject_kind, subject, subject_hash);
            let redacted_properties =
                redact_subject_value(&properties, &request.subject_kind, subject, subject_hash);
            result.objects_tombstoned += client
                .execute(
                    "UPDATE sekai_objects SET name=$1,external_id=$2,properties=$3 WHERE id=$4",
                    &[
                        &redacted_name,
                        &redacted_external,
                        &redacted_properties,
                        &id,
                    ],
                )
                .map_err(err)? as i32;
        }
    }
    for object_id in object_ids {
        let object_tombstone = format!("{subject_hash}-{}", &sha256(object_id.as_bytes())[..16]);
        client
            .execute(
                "UPDATE sekai_reconciliation_candidates SET object_id=$2
                 WHERE object_id=$1",
                &[&object_id, &object_tombstone],
            )
            .map_err(err)?;
        for row in client
            .query(
                "SELECT id,subjects_json,canonical_object_id
                 FROM sekai_reconciliation_decisions
                 WHERE canonical_object_id=$1 OR POSITION($1 IN subjects_json)>0
                 FOR UPDATE",
                &[&object_id],
            )
            .map_err(err)?
        {
            let decision_id: String = row.get(0);
            let mut subjects =
                serde_json::from_str::<Vec<String>>(row.get::<_, String>(1).as_str())
                    .map_err(err)?;
            for subject in &mut subjects {
                if *subject == object_id {
                    *subject = object_tombstone.clone();
                }
            }
            let canonical: Option<String> = row.get(2);
            let canonical = canonical.map(|value| {
                if value == object_id {
                    object_tombstone.clone()
                } else {
                    value
                }
            });
            client
                .execute(
                    "UPDATE sekai_reconciliation_decisions
                     SET subjects_json=$1,canonical_object_id=$2 WHERE id=$3",
                    &[
                        &serde_json::to_string(&subjects).map_err(err)?,
                        &canonical,
                        &decision_id,
                    ],
                )
                .map_err(err)?;
        }
        result.links_deleted += client
            .execute(
                "DELETE FROM sekai_links WHERE from_id=$1 OR to_id=$1",
                &[&object_id],
            )
            .map_err(err)? as i32;
        result.work_unit_references_tombstoned += client
            .execute(
                "UPDATE sekai_work_units SET target_object_id=$2
                 WHERE target_object_id=$1",
                &[&object_id, &object_tombstone],
            )
            .map_err(err)? as i32;
        result.work_unit_references_tombstoned += client
            .execute(
                "UPDATE sekai_datasets SET object_id=$2 WHERE object_id=$1",
                &[&object_id, &object_tombstone],
            )
            .map_err(err)? as i32;
        result.work_unit_references_tombstoned += client
            .execute(
                "UPDATE sekai_evidence_projections SET
                 evidence_object_id=CASE WHEN evidence_object_id=$1 THEN $2 ELSE evidence_object_id END,
                 target_object_id=CASE WHEN target_object_id=$1 THEN $2 ELSE target_object_id END
                 WHERE evidence_object_id=$1 OR target_object_id=$1",
                &[&object_id, &object_tombstone],
            )
            .map_err(err)? as i32;
        result.grants_deleted += client
            .execute("DELETE FROM sekai_grants WHERE object_id=$1", &[&object_id])
            .map_err(err)? as i32;
        result.object_changes_tombstoned += client
            .execute(
                "UPDATE sekai_object_changes SET
                 object_id=CASE WHEN object_id=$1 THEN $2 ELSE object_id END,
                 old_value=CASE WHEN old_value=$1 THEN $3 ELSE old_value END,
                 new_value=CASE WHEN new_value=$1 THEN $3 ELSE new_value END,
                 changed_by=CASE WHEN changed_by=$1 THEN $3 ELSE changed_by END
                 WHERE object_id=$1 OR old_value=$1 OR new_value=$1 OR changed_by=$1",
                &[&object_id, &object_tombstone, &subject_hash],
            )
            .map_err(err)? as i32;
        result.objects_deleted += client
            .execute("DELETE FROM sekai_objects WHERE id=$1", &[&object_id])
            .map_err(err)? as i32;
    }
    for row in client
        .query(
            "SELECT id,external_identity FROM sekai_reconciliation_cases FOR UPDATE",
            &[],
        )
        .map_err(err)?
    {
        let id: String = row.get(0);
        let identity: String = row.get(1);
        if identity == subject || value_mentions_subject(&identity, &request.subject_kind, subject)
        {
            client
                .execute(
                    "UPDATE sekai_reconciliation_cases SET external_identity=$1 WHERE id=$2",
                    &[
                        &format!("{subject_hash}:{}", &sha256(id.as_bytes())[..16]),
                        &id,
                    ],
                )
                .map_err(err)?;
        }
    }

    result.grants_deleted += client
        .execute("DELETE FROM sekai_grants WHERE principal=$1", &[&subject])
        .map_err(err)? as i32;
    result.credentials_deleted += client
        .execute(
            "DELETE FROM sekai_principal_credentials WHERE principal=$1",
            &[&subject],
        )
        .map_err(err)? as i32;
    for row in client
        .query(
            "SELECT id,owner_principal,filter FROM sekai_object_sets ORDER BY id FOR UPDATE",
            &[],
        )
        .map_err(err)?
    {
        let id: String = row.get(0);
        let owner: String = row.get(1);
        let filter: String = row.get(2);
        if owner == subject || value_mentions_subject(&filter, &request.subject_kind, subject) {
            result.object_sets_deleted += client
                .execute("DELETE FROM sekai_object_sets WHERE id=$1", &[&id])
                .map_err(err)? as i32;
        }
    }

    let work_units = client
        .query(
            "SELECT id,actor,target_object_id,requested_spec,scope_id,failure_reason,
                    cancel_reason,owner_principal,creator_principal
             FROM sekai_work_units ORDER BY id FOR UPDATE",
            &[],
        )
        .map_err(err)?
        .into_iter()
        .filter_map(|row| {
            let id: String = row.get(0);
            let identity_columns: &[usize] = if request.subject_kind == "work_unit" {
                &[0, 1, 2, 4, 7, 8]
            } else {
                &[1, 2, 4, 7, 8]
            };
            let matches = identity_columns.iter().copied().any(|index| {
                let value = row.get::<_, String>(index);
                value == subject || value_mentions_subject(&value, &request.subject_kind, subject)
            });
            matches.then_some(id)
        })
        .collect::<Vec<_>>();
    for row in client
        .query(
            "SELECT id,requested_spec,failure_reason,cancel_reason
             FROM sekai_work_units ORDER BY id FOR UPDATE",
            &[],
        )
        .map_err(err)?
    {
        let id: String = row.get(0);
        if work_units.contains(&id) {
            continue;
        }
        let spec: String = row.get(1);
        let failure: String = row.get(2);
        let cancellation: String = row.get(3);
        if [&spec, &failure, &cancellation]
            .into_iter()
            .any(|value| value_mentions_subject(value, &request.subject_kind, subject))
        {
            result.work_unit_text_tombstoned += client
                .execute(
                    "UPDATE sekai_work_units SET requested_spec=$1,failure_reason=$2,
                     cancel_reason=$3 WHERE id=$4",
                    &[
                        &redact_subject_value(&spec, &request.subject_kind, subject, subject_hash),
                        &redact_subject_value(
                            &failure,
                            &request.subject_kind,
                            subject,
                            subject_hash,
                        ),
                        &redact_subject_value(
                            &cancellation,
                            &request.subject_kind,
                            subject,
                            subject_hash,
                        ),
                        &id,
                    ],
                )
                .map_err(err)? as i32;
        }
    }
    for work_unit in work_units {
        client
            .execute(
                "DELETE FROM sekai_reconciliations WHERE work_unit_id=$1
                 OR reservation_id IN (
                   SELECT id FROM sekai_reservations WHERE work_unit_id=$1)",
                &[&work_unit],
            )
            .map_err(err)?;
        client
            .execute(
                "DELETE FROM sekai_run_events WHERE work_unit_id=$1",
                &[&work_unit],
            )
            .map_err(err)?;
        client
            .execute(
                "DELETE FROM sekai_coordination_requests WHERE work_unit_id=$1",
                &[&work_unit],
            )
            .map_err(err)?;
        client
            .execute(
                "DELETE FROM sekai_reservations WHERE work_unit_id=$1",
                &[&work_unit],
            )
            .map_err(err)?;
        result.work_units_deleted += client
            .execute("DELETE FROM sekai_work_units WHERE id=$1", &[&work_unit])
            .map_err(err)? as i32;
    }
    result.coordination_references_tombstoned += client
        .execute(
            "UPDATE sekai_coordination_requests SET principal=$2
             WHERE principal=$1",
            &[&subject, &subject_hash],
        )
        .map_err(err)? as i32;
    result.contention_scopes_tombstoned += client
        .execute(
            "UPDATE sekai_contention_scopes SET owner_principal=$2
             WHERE owner_principal=$1",
            &[&subject, &subject_hash],
        )
        .map_err(err)? as i32;
    let budget_rows = client
        .query(
            "SELECT scope_id,parent_scope_id FROM chisei_budget_limits FOR UPDATE",
            &[],
        )
        .map_err(err)?
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
        .collect::<Vec<_>>();
    let mut budget_scopes = budget_rows
        .iter()
        .filter(|(scope, parent)| {
            [scope, parent].into_iter().any(|value| {
                value == subject || value_mentions_subject(value, &request.subject_kind, subject)
            })
        })
        .map(|(scope, _)| scope.clone())
        .collect::<std::collections::BTreeSet<_>>();
    loop {
        let before = budget_scopes.len();
        for (scope, parent) in &budget_rows {
            if budget_scopes.contains(parent) {
                budget_scopes.insert(scope.clone());
            }
        }
        if budget_scopes.len() == before {
            break;
        }
    }
    for scope in budget_scopes {
        result.budget_records_deleted += client
            .execute(
                "DELETE FROM chisei_budget_usage WHERE scope_id=$1",
                &[&scope],
            )
            .map_err(err)? as i32;
        result.budget_records_deleted += client
            .execute(
                "DELETE FROM chisei_budget_limits WHERE scope_id=$1",
                &[&scope],
            )
            .map_err(err)? as i32;
    }

    for row in client
        .query(
            "SELECT id,decision_id,policy_kind,policy_scope,policy_snapshot,inputs,decision
             FROM sekai_attestations ORDER BY id FOR UPDATE",
            &[],
        )
        .map_err(err)?
    {
        let id: String = row.get(0);
        if (0..7).any(|index| {
            let value = row.get::<_, String>(index);
            value == subject || value_mentions_subject(&value, &request.subject_kind, subject)
        }) {
            result.attestations_deleted += client
                .execute("DELETE FROM sekai_attestations WHERE id=$1", &[&id])
                .map_err(err)? as i32;
        }
    }
    tombstone_decisions(client, request, subject_hash, result)
}

fn tombstone_decisions(
    client: &mut impl GenericClient,
    request: &SubjectErasureRequest,
    subject_hash: &str,
    result: &mut SubjectErasureResult,
) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome,
                    seq,prev_hash,entry_hash
             FROM sekai_decisions WHERE seq IS NOT NULL ORDER BY seq FOR UPDATE",
            &[],
        )
        .map_err(err)?;
    if rows.is_empty() {
        return Ok(());
    }
    let first_previous: String = rows[0].get::<_, Option<String>>(9).unwrap_or_default();
    let mut previous = first_previous.clone();
    let mut decisions = Vec::with_capacity(rows.len());
    for row in rows {
        let evidence: String = row.get(5);
        let mut decision = Decision {
            id: row.get(0),
            timestamp: row.get(1),
            actor: row.get(2),
            action: row.get(3),
            reason: row.get(4),
            evidence: serde_json::from_str(&evidence).unwrap_or_default(),
            target_id: row.get(6),
            outcome: row.get(7),
        };
        let sequence: i64 = row.get(8);
        let stored_previous: String = row.get::<_, Option<String>>(9).unwrap_or_default();
        let stored_hash: String = row.get::<_, Option<String>>(10).unwrap_or_default();
        if stored_previous != previous
            || crate::sekai::ledger::entry_hash(sequence, &previous, &decision, &evidence)
                != stored_hash
        {
            return Err("audit ledger verification failed before subject erasure".into());
        }
        let matches = [
            decision.actor.as_str(),
            decision.reason.as_str(),
            decision.target_id.as_str(),
            evidence.as_str(),
        ]
        .iter()
        .any(|value| {
            *value == request.subject
                || value_mentions_subject(value, &request.subject_kind, &request.subject)
        });
        if matches {
            decision.actor = "privacy.erasure".into();
            decision.action = "privacy.subject_tombstone".into();
            decision.reason = "subject data erased".into();
            decision.evidence =
                std::collections::HashMap::from([("subject_hash".into(), subject_hash.into())]);
            decision.target_id.clear();
            decision.outcome = "erased".into();
            result.audit_tombstoned += 1;
        }
        previous = stored_hash;
        decisions.push((sequence, decision));
    }
    previous = first_previous;
    for (sequence, decision) in decisions {
        let evidence = serde_json::to_string(&decision.evidence).map_err(err)?;
        let hash = crate::sekai::ledger::entry_hash(sequence, &previous, &decision, &evidence);
        client
            .execute(
                "UPDATE sekai_decisions SET actor=$1,action=$2,reason=$3,evidence=$4,
                 target_id=$5,outcome=$6,prev_hash=$7,entry_hash=$8 WHERE seq=$9",
                &[
                    &decision.actor,
                    &decision.action,
                    &decision.reason,
                    &evidence,
                    &decision.target_id,
                    &decision.outcome,
                    &previous,
                    &hash,
                    &sequence,
                ],
            )
            .map_err(err)?;
        previous = hash;
    }
    Ok(())
}

fn redact_archived_subject(
    client: &mut impl GenericClient,
    subject_kind: &str,
    subject: &str,
    subject_hash: &str,
    now_ms: i64,
) -> Result<(), String> {
    let batch_ids = client
        .query("SELECT id FROM sekai_archive_batches ORDER BY id", &[])
        .map_err(err)?
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    for batch_id in batch_ids {
        verify_batch(client, &batch_id)?;
    }
    let rows = client
        .query(
            "SELECT dataset,source_key,payload,payload_hash FROM sekai_archive_records
             ORDER BY dataset,source_key FOR UPDATE",
            &[],
        )
        .map_err(err)?;
    let mut touched_batches = std::collections::BTreeSet::new();
    for row in rows {
        let dataset: String = row.get(0);
        let source_key: String = row.get(1);
        let payload: String = row.get(2);
        if !value_mentions_subject(&payload, subject_kind, subject) {
            continue;
        }
        let old_hash: String = row.get(3);
        let redacted_payload = redact_subject_value(&payload, subject_kind, subject, subject_hash);
        let record = ArchiveRecord {
            dataset: dataset.clone(),
            source_key: source_key.clone(),
            payload: redacted_payload.clone(),
        };
        let new_hash = record_hash(&record);
        client
            .execute(
                "UPDATE sekai_archive_records SET payload=$1,payload_hash=$2
                 WHERE dataset=$3 AND source_key=$4",
                &[&redacted_payload, &new_hash, &dataset, &source_key],
            )
            .map_err(err)?;
        client
            .execute(
                "INSERT INTO sekai_archive_redactions
                 (id,dataset,source_key,old_payload_hash,new_payload_hash,subject_hash,redacted_at_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &format!("archive-redaction-{}", uuid::Uuid::new_v4().simple()),
                    &dataset,
                    &source_key,
                    &old_hash,
                    &new_hash,
                    &subject_hash,
                    &now_ms,
                ],
            )
            .map_err(err)?;
        for batch in client
            .query(
                "SELECT batch_id FROM sekai_archive_batch_records
                 WHERE dataset=$1 AND source_key=$2",
                &[&dataset, &source_key],
            )
            .map_err(err)?
        {
            touched_batches.insert(batch.get::<_, String>(0));
        }
    }
    for batch_id in touched_batches {
        let hashes = client
            .query(
                "SELECT r.payload_hash FROM sekai_archive_batch_records m
                 JOIN sekai_archive_records r
                   ON r.dataset=m.dataset AND r.source_key=m.source_key
                 WHERE m.batch_id=$1 ORDER BY r.dataset,r.source_key",
                &[&batch_id],
            )
            .map_err(err)?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
        client
            .execute(
                "UPDATE sekai_archive_batches SET content_hash=$1 WHERE id=$2",
                &[&hash_json(&hashes)?, &batch_id],
            )
            .map_err(err)?;
    }
    Ok(())
}

fn redact_subject_value(
    value: &str,
    subject_kind: &str,
    subject: &str,
    subject_hash: &str,
) -> String {
    if !value_mentions_subject(value, subject_kind, subject) {
        return value.to_string();
    }
    fn redact_json(
        value: &mut serde_json::Value,
        subject_kind: &str,
        subject: &str,
        subject_hash: &str,
    ) {
        match value {
            serde_json::Value::String(text)
                if text == subject || contains_subject_reference(text, subject_kind, subject) =>
            {
                *text = if text == subject {
                    subject_hash.to_string()
                } else {
                    "[redacted subject reference]".into()
                };
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    redact_json(value, subject_kind, subject, subject_hash);
                }
            }
            serde_json::Value::Object(values) => {
                let original = std::mem::take(values);
                for (key, mut value) in original {
                    redact_json(&mut value, subject_kind, subject, subject_hash);
                    let key = if key == subject {
                        subject_hash.to_string()
                    } else if contains_subject_reference(&key, subject_kind, subject) {
                        format!("[redacted-subject-key]-{}", &sha256(key.as_bytes())[..16])
                    } else {
                        key
                    };
                    values.insert(key, value);
                }
            }
            _ => {}
        }
    }
    if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(value) {
        redact_json(&mut json, subject_kind, subject, subject_hash);
        return json.to_string();
    }
    if value == subject {
        subject_hash.into()
    } else {
        "[redacted subject reference]".into()
    }
}

fn value_mentions_subject(value: &str, subject_kind: &str, subject: &str) -> bool {
    fn json_mentions(value: &serde_json::Value, subject_kind: &str, subject: &str) -> bool {
        match value {
            serde_json::Value::String(value) => {
                value == subject || contains_subject_reference(value, subject_kind, subject)
            }
            serde_json::Value::Array(values) => values
                .iter()
                .any(|value| json_mentions(value, subject_kind, subject)),
            serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
                key == subject
                    || contains_subject_reference(key, subject_kind, subject)
                    || json_mentions(value, subject_kind, subject)
            }),
            _ => false,
        }
    }
    serde_json::from_str::<serde_json::Value>(value)
        .ok()
        .is_some_and(|value| json_mentions(&value, subject_kind, subject))
        || contains_subject_reference(value, subject_kind, subject)
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn verify_batch(client: &mut impl GenericClient, batch_id: &str) -> Result<(i64, i64), String> {
    let batch = client
        .query_opt(
            "SELECT content_hash,record_count FROM sekai_archive_batches WHERE id=$1",
            &[&batch_id],
        )
        .map_err(err)?
        .ok_or_else(|| "archive batch not found".to_string())?;
    let rows = client
        .query(
            "SELECT r.dataset,r.source_key,r.payload,r.payload_hash
             FROM sekai_archive_batch_records m
             JOIN sekai_archive_records r
               ON r.dataset=m.dataset AND r.source_key=m.source_key
             WHERE m.batch_id=$1 ORDER BY r.dataset,r.source_key",
            &[&batch_id],
        )
        .map_err(err)?;
    if rows.len() as i64 != batch.get::<_, i64>(1) {
        return Err("archive batch manifest does not match record count".into());
    }
    let mut hashes = Vec::with_capacity(rows.len());
    for row in rows {
        let record = ArchiveRecord {
            dataset: row.get(0),
            source_key: row.get(1),
            payload: row.get(2),
        };
        let calculated = record_hash(&record);
        if calculated != row.get::<_, String>(3) {
            return Err("archive record payload hash does not match".into());
        }
        hashes.push(calculated);
    }
    if hash_json(&hashes)? != batch.get::<_, String>(0) {
        return Err("archive batch content hash does not match".into());
    }
    Ok((hashes.len() as i64, 1))
}

fn record_hash(record: &ArchiveRecord) -> String {
    sha256(
        serde_json::to_string(&(&record.dataset, &record.source_key, &record.payload))
            .unwrap_or_default()
            .as_bytes(),
    )
}

fn hash_json(value: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(err)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn row_policy(row: Row) -> RetentionPolicy {
    RetentionPolicy {
        dataset: row.get(0),
        namespace: row.get(1),
        data_class: row.get(2),
        retention_days: row.get(3),
        updated: row.get(4),
    }
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::deduplication::{ContentReferenceRequest, ContentScope};

    fn database() -> PostgresDb {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
        match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => {
                let certificate = std::fs::read(path).expect("read PostgreSQL test CA certificate");
                PostgresDb::connect_with_ca_certificate(&url, 8, &certificate).unwrap()
            }
            Err(_) => PostgresDb::connect(&url, 8).unwrap(),
        }
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_corrupt_archives_and_blobs_fail_closed() {
        let db = database();
        let prefix = format!("corrupt-{}", uuid::Uuid::new_v4().simple());
        let scope = ContentScope {
            namespace: prefix.clone(),
            classification: "confidential".into(),
            encryption_key_id: "key".into(),
            residency: "eu".into(),
        };
        let request = ContentReferenceRequest {
            reference_id: format!("{prefix}:reference"),
            actor: "actor".into(),
            operation_id: "operation".into(),
            causal_identity: "cause".into(),
            idempotency_key: format!("{prefix}:put"),
            retention_until_ms: None,
            retention_hold: false,
            legal_hold: false,
            archived: false,
            receipt_required: false,
            attestation_required: false,
            preserve_tombstone: true,
        };
        let admission = db
            .put_scoped_content(&scope, &request, b"original", 100)
            .unwrap();
        let archived = db.archive_lifecycle_records(200).unwrap();
        let mut connection = db.connection().unwrap();
        connection
            .execute(
                "UPDATE sekai_archive_records SET payload='corrupt'
                 WHERE dataset='content_events' AND source_key IN (
                   SELECT source_key FROM sekai_archive_batch_records WHERE batch_id=$1)",
                &[&archived.batch_id],
            )
            .unwrap();
        assert!(!db.verify_lifecycle_archive(&archived.batch_id).unwrap().ok);

        connection
            .execute(
                "UPDATE sekai_content_blobs SET content=$1 WHERE id=$2",
                &[&b"corrupt".as_slice(), &admission.reference.blob_id],
            )
            .unwrap();
        let mut replay = request;
        replay.reference_id = format!("{prefix}:second-reference");
        replay.idempotency_key = format!("{prefix}:second-put");
        assert!(
            db.put_scoped_content(&scope, &replay, b"original", 300)
                .is_err()
        );
    }
}
