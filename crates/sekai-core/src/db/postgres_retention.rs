use crate::db::postgres::PostgresDb;
use crate::sekai::audit::Decision;
use crate::sekai::retention::{
    AUDIT_DATASET, CONTENT_EVENTS_DATASET, DAY_MS, LLM_CALLS_DATASET, ObservationPlan,
    RETENTION_BATCH_SIZE, RETENTION_TOMBSTONE_CONTEXT, RetainedObservation, effective_policy,
    fold_observation_baseline, llm_call_expired, plan_audit_prefix, plan_observation_retention,
};
use crate::sekai::retention::{
    ArchiveErasureSubject, ArchivedErasure, CONTENT_EVENT_ERASED_REASON, erase_archived_record,
    tombstone_archived_decision,
};
use crate::sekai::retention::{
    ArchiveRun, ArchiveVerification, RetentionPolicy, SubjectErasureRequest, SubjectErasureResult,
};
use crate::sekai::retention::{
    legacy_redact_subject_value as redact_subject_value,
    legacy_value_mentions_subject as value_mentions_subject,
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
        if !crate::sekai::retention::RETENTION_DATASETS.contains(&policy.dataset.as_str()) {
            return Err(
                "dataset must be audit, llm_calls, task_observations, or content_events".into(),
            );
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
        // The references the hot path tombstones below, read before the
        // residue scan so the archived events of them are erased first.
        let archived_reference_ids = tx
            .query(
                "SELECT reference_id,actor,operation_id,causal_identity
                 FROM sekai_content_references",
                &[],
            )
            .map_err(err)?
            .into_iter()
            .filter(|row| {
                content_reference_matches(
                    [row.get(1), row.get(2), row.get(3)],
                    &request.subject_kind,
                    &request.subject,
                )
            })
            .map(|row| row.get::<_, String>(0))
            .collect();
        let represented_objects = represented_object_ids(&mut tx, request)?;
        redact_archived_subject(
            &mut tx,
            &ArchiveErasureSubject {
                kind: &request.subject_kind,
                subject: &request.subject,
                hash: &subject_hash,
                // The objects that are the subject, as the hot erasure below
                // finds them: their archived changes keep no value.
                object_ids: &represented_objects,
                reference_ids: &archived_reference_ids,
            },
            request.timestamp,
        )?;
        erase_supported_subject_data(&mut tx, request, &subject_hash, &mut result)?;
        if result.llm_calls_deleted > 0 {
            match crate::db::postgres_dataset::snapshot_dataset_version_pg(
                &mut tx,
                "llm_calls",
                "",
                "",
                "subject-erasure",
                "",
                request.timestamp,
            ) {
                Err(error) if error == crate::sekai::dataset_version::DATASET_NOT_FOUND => {}
                other => {
                    other.map_err(err)?;
                }
            }
        }
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
                content_reference_matches(
                    [row.get(3), row.get(4), row.get(5)],
                    &request.subject_kind,
                    &request.subject,
                )
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
                "UPDATE sekai_content_events SET actor=$1,reason=$2 WHERE reference_id=$3",
                &[&subject_hash, &CONTENT_EVENT_ERASED_REASON, &reference_id],
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
        let mut run = self.archive_content_events(cutoff_ms)?;
        // Earlier callers read the count here.
        run.audit_archived = run.content_events_archived;
        Ok(run)
    }

    /// The retention entry point on PostgreSQL (ADR 0141), as on SQLite:
    /// LLM calls, task observations and content events past their stored
    /// policies move into the in-database archive and are deleted or
    /// redacted in the hot tables, in batches of at most
    /// `RETENTION_BATCH_SIZE` records per dataset, one transaction each,
    /// until nothing is left. Each batch claims the archive lock for its
    /// transaction and locks the rows it reads, so replicas running at once
    /// take turns batch by batch and archive every record once; a crash
    /// loses only the uncommitted batch, which a rerun redoes. A dry run
    /// counts everything in one pass and rolls it back. Decisions, their
    /// attestations and object changes (all under the `audit` policy) go
    /// only after the ledger verifies, once per run under the ledger lock,
    /// and the run refuses naming the failure otherwise.
    pub fn archive_retained_records(&self, now: i64, dry_run: bool) -> Result<ArchiveRun, String> {
        if dry_run {
            return self.archive_retained_batch(
                now,
                true,
                i64::MAX,
                &mut RetentionCursor::default(),
            );
        }
        let limit = i64::try_from(RETENTION_BATCH_SIZE).unwrap_or(i64::MAX);
        let mut cursor = RetentionCursor::default();
        let mut total = ArchiveRun::default();
        while !cursor.done() {
            let batch = self.archive_retained_batch(now, false, limit, &mut cursor)?;
            if !batch.batch_id.is_empty() {
                total.absorb(batch);
            }
        }
        self.finish_retention_run(now, total.llm_calls_archived > 0)?;
        Ok(total)
    }

    /// After a run's last batch, on every run: drop calls past their policy
    /// from the `llm_calls` versions and branches, so a run that crashed
    /// before this step is completed by the next one. Records an `archive`
    /// version when this run archived calls.
    fn finish_retention_run(&self, now: i64, archived_calls: bool) -> Result<(), String> {
        let policies = self.list_retention_policies()?;
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        // The order erasure takes: the retention lock, then the dataset rows.
        tx.query_one("SELECT pg_advisory_xact_lock_shared(251,251)", &[])
            .map_err(err)?;
        crate::db::postgres::lock_dataset_rows(&mut tx, LLM_CALLS_DATASET)?;
        erase_expired_llm_call_versions(&mut tx, &policies, now, archived_calls)?;
        tx.commit().map_err(err)
    }

    /// One batch: at most `limit` records per dataset, moved and removed in
    /// one transaction. Records already moved are gone from the hot tables or
    /// marked, so the next batch, or a rerun after a crash, starts where this
    /// one ended.
    fn archive_retained_batch(
        &self,
        now: i64,
        dry_run: bool,
        limit: i64,
        cursor: &mut RetentionCursor,
    ) -> Result<ArchiveRun, String> {
        let policies = self.list_retention_policies()?;
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        // Shared with other batches, exclusive against erasure; then the
        // per-batch claim every replica's batch takes, so batches never
        // interleave; then the rows lock `llm_calls` writers take.
        tx.query_one("SELECT pg_advisory_xact_lock_shared(251,251)", &[])
            .map_err(err)?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('sekai.lifecycle.archive',251))",
            &[],
        )
        .map_err(err)?;
        let audit_policy = policies
            .iter()
            .any(|policy| policy.dataset == AUDIT_DATASET);
        if audit_policy && !cursor.audit_done {
            // The ledger lock every decision writer takes, before the rows
            // lock as in erasure: the ledger cannot move under this batch.
            tx.query_one("SELECT pg_advisory_xact_lock(25012)", &[])
                .map_err(err)?;
        }
        crate::db::postgres::lock_dataset_rows(&mut tx, LLM_CALLS_DATASET)?;
        let full = |rows: usize| i64::try_from(rows).unwrap_or(i64::MAX) >= limit;
        let mut records = Vec::<ArchiveRecord>::new();

        // Audit records go only after the ledger verifies, once per run, in
        // this batch's transaction; a failure refuses the whole run.
        if audit_policy && !cursor.ledger_verified {
            let verification = crate::db::postgres_decision::verify_ledger_in(&mut tx)?;
            if !verification.ok {
                return Err(format!(
                    "audit ledger verification failed before retention: {}",
                    verification.error
                ));
            }
            cursor.ledger_verified = true;
        }
        let mut audit_archived = 0;
        let mut prefix_end = None;
        if audit_policy && !cursor.audit_done {
            let rows = tx
                .query(
                    "SELECT seq,timestamp,evidence FROM sekai_decisions
                     ORDER BY seq LIMIT $1",
                    &[&limit.saturating_add(1)],
                )
                .map_err(err)?
                .into_iter()
                .map(|row| {
                    let evidence = serde_json::from_str(row.get(2)).unwrap_or_default();
                    let (namespace, data_class) =
                        crate::sekai::ledger::lifecycle_scope_from_evidence(&evidence);
                    (row.get(0), row.get(1), namespace, data_class)
                })
                .collect::<Vec<_>>();
            let (end, done) = plan_audit_prefix(
                rows,
                &policies,
                now,
                usize::try_from(limit).unwrap_or(usize::MAX),
            );
            cursor.audit_done = done;
            prefix_end = end;
        } else {
            cursor.audit_done = true;
        }
        if let Some(prefix_end) = prefix_end {
            for row in tx
                .query(
                    "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome,
                            seq,prev_hash,entry_hash
                     FROM sekai_decisions WHERE seq <= $1 ORDER BY seq FOR UPDATE",
                    &[&prefix_end],
                )
                .map_err(err)?
            {
                let evidence: String = row.get(5);
                let (namespace, data_class) = crate::sekai::ledger::lifecycle_scope_from_evidence(
                    &serde_json::from_str(&evidence).unwrap_or_default(),
                );
                // The payload SQLite archives for a decision.
                records.push(ArchiveRecord {
                    dataset: "audit.decisions".into(),
                    source_key: row.get(0),
                    payload: serde_json::json!({
                        "id": row.get::<_, String>(0), "timestamp": row.get::<_, i64>(1),
                        "actor": row.get::<_, String>(2), "action": row.get::<_, String>(3),
                        "reason": row.get::<_, String>(4), "evidence": evidence,
                        "target_id": row.get::<_, String>(6), "outcome": row.get::<_, String>(7),
                        "seq": row.get::<_, i64>(8), "prev_hash": row.get::<_, String>(9),
                        "entry_hash": row.get::<_, String>(10),
                        "namespace": namespace, "data_class": data_class,
                    })
                    .to_string(),
                });
                audit_archived += 1;
            }
            for row in tx
                .query(
                    "SELECT a.id,a.decision_id,a.policy_kind,a.policy_scope,a.policy_version,
                            a.policy_snapshot,a.inputs,a.decision,a.content_hash,a.created
                     FROM sekai_attestations a JOIN sekai_decisions d ON d.id=a.decision_id
                     WHERE d.seq <= $1 ORDER BY a.id FOR UPDATE OF a",
                    &[&prefix_end],
                )
                .map_err(err)?
            {
                records.push(ArchiveRecord {
                    dataset: "audit.attestations".into(),
                    source_key: row.get(0),
                    payload: serde_json::json!({
                        "id": row.get::<_, String>(0), "decision_id": row.get::<_, String>(1),
                        "policy_kind": row.get::<_, String>(2),
                        "policy_scope": row.get::<_, String>(3),
                        "policy_version": row.get::<_, String>(4),
                        "policy_snapshot": row.get::<_, String>(5),
                        "inputs": row.get::<_, String>(6), "decision": row.get::<_, String>(7),
                        "content_hash": row.get::<_, String>(8), "created": row.get::<_, i64>(9),
                    })
                    .to_string(),
                });
                audit_archived += 1;
            }
        }

        let mut llm_ids = Vec::new();
        if !cursor.llm_done {
            let rows = tx
                .query(
                    "SELECT id,data FROM sekai_dataset_rows WHERE dataset_id=$1 AND id>$2
                     ORDER BY id LIMIT $3 FOR UPDATE",
                    &[&LLM_CALLS_DATASET, &cursor.llm_after, &limit],
                )
                .map_err(err)?;
            cursor.llm_done = !full(rows.len());
            if let Some(last) = rows.last() {
                cursor.llm_after = last.get(0);
            }
            for row in rows {
                let id: i64 = row.get(0);
                let data: String = row.get(1);
                let values = serde_json::from_str(&data).unwrap_or_default();
                if llm_call_expired(&values, &policies, now) {
                    llm_ids.push(id);
                    records.push(ArchiveRecord {
                        dataset: LLM_CALLS_DATASET.into(),
                        source_key: id.to_string(),
                        payload: data,
                    });
                }
            }
        }

        let mut observations = Vec::new();
        if !cursor.observations_done {
            let (component, timestamp, request) = cursor.observation_after.clone().map_or(
                (None, 0, String::new()),
                |(component, timestamp, request)| (Some(component), timestamp, request),
            );
            let rows = tx
                .query(
                    "SELECT request_id,namespace,data_class,component_id,model,status,timestamp,
                            packages_json,context_json,retention_tombstone
                     FROM sekai_task_observations
                     WHERE $1::TEXT IS NULL OR (component_id,timestamp,request_id) > ($1,$2,$3)
                     ORDER BY component_id,timestamp,request_id LIMIT $4 FOR UPDATE",
                    &[&component, &timestamp, &request, &limit],
                )
                .map_err(err)?;
            cursor.observations_done = !full(rows.len());
            observations = rows
                .into_iter()
                .map(|row| RetainedObservation {
                    key: (row.get::<_, String>(0), row.get::<_, String>(3)),
                    request_id: row.get(0),
                    namespace: row.get(1),
                    data_class: row.get(2),
                    component_id: row.get(3),
                    model: row.get(4),
                    status: row.get(5),
                    timestamp: row.get(6),
                    packages_json: row.get(7),
                    context_json: row.get(8),
                    retention_tombstone: row.get(9),
                })
                .collect::<Vec<_>>();
            if let Some(last) = observations.last() {
                cursor.observation_after = Some((
                    last.component_id.clone(),
                    last.timestamp,
                    last.request_id.clone(),
                ));
            }
        }
        let ObservationPlan {
            records: observation_records,
            folded,
            redacted,
        } = plan_observation_retention(
            observations,
            &policies,
            now,
            &mut cursor.retained_components,
        );
        let observations_archived = observation_records.len();
        records.extend(observation_records.into_iter().map(ArchiveRecord::from));

        // Object changes follow the dataset-wide audit policy, as on SQLite,
        // so they pass the same ledger gate above: an `audit` policy means
        // the ledger was verified in this run before anything moves.
        // Archived rows leave the table, so each batch reads the oldest.
        let mut change_ids = Vec::new();
        if let (false, Some(policy)) = (
            cursor.object_changes_done,
            effective_policy(&policies, crate::sekai::retention::AUDIT_DATASET, "", ""),
        ) {
            let cutoff = now - i64::from(policy.retention_days) * DAY_MS;
            let rows = tx
                .query(
                    "SELECT id,object_id,field,old_value,new_value,changed_by,timestamp
                     FROM sekai_object_changes WHERE timestamp<$1
                     ORDER BY timestamp,id LIMIT $2 FOR UPDATE",
                    &[&cutoff, &limit],
                )
                .map_err(err)?;
            cursor.object_changes_done = !full(rows.len());
            for row in rows {
                let id: String = row.get(0);
                // The payload SQLite archives for an object change.
                records.push(ArchiveRecord {
                    dataset: "audit.object_changes".into(),
                    source_key: id.clone(),
                    payload: serde_json::json!({
                        "id": id, "object_id": row.get::<_, String>(1),
                        "field": row.get::<_, String>(2),
                        "old_value": row.get::<_, String>(3),
                        "new_value": row.get::<_, String>(4),
                        "changed_by": row.get::<_, String>(5),
                        "timestamp": row.get::<_, i64>(6),
                    })
                    .to_string(),
                });
                change_ids.push(id);
            }
        } else {
            cursor.object_changes_done = true;
        }

        // Content events carry no namespace or class: only the dataset-wide
        // policy applies.
        let mut event_ids = Vec::new();
        if let (false, Some(policy)) = (
            cursor.content_events_done,
            effective_policy(&policies, CONTENT_EVENTS_DATASET, "", ""),
        ) {
            let cutoff = now - i64::from(policy.retention_days) * DAY_MS;
            let rows = tx
                .query(
                    "SELECT id,event_kind,blob_id,reference_id,actor,reason,created_at_ms
                     FROM sekai_content_events WHERE created_at_ms<$1
                     ORDER BY id LIMIT $2 FOR UPDATE",
                    &[&cutoff, &limit],
                )
                .map_err(err)?;
            cursor.content_events_done = !full(rows.len());
            for row in rows {
                event_ids.push(row.get::<_, String>(0));
                records.push(content_event_record(&row));
            }
        } else {
            cursor.content_events_done = true;
        }

        let mut run = ArchiveRun {
            audit_archived: audit_archived + change_ids.len() as i32,
            llm_calls_archived: llm_ids.len() as i32,
            task_observations_archived: observations_archived as i32,
            task_observations_redacted: redacted.len() as i32,
            content_events_archived: event_ids.len() as i32,
            dry_run,
            ..ArchiveRun::default()
        };
        if records.is_empty() {
            tx.commit().map_err(err)?;
            return Ok(run);
        }
        (run.batch_id, run.content_hash) = write_archive_batch(&mut tx, now, records)?;
        run.batches = 1;
        if let Some(prefix_end) = prefix_end {
            // As on SQLite: the archived prefix leaves the ledger and its last
            // entry becomes the anchor later verification resumes from.
            let anchor_hash: String = tx
                .query_one(
                    "SELECT entry_hash FROM sekai_decisions WHERE seq=$1",
                    &[&prefix_end],
                )
                .map_err(err)?
                .get(0);
            tx.execute(
                "DELETE FROM sekai_attestations WHERE decision_id IN
                 (SELECT id FROM sekai_decisions WHERE seq <= $1)",
                &[&prefix_end],
            )
            .map_err(err)?;
            tx.execute(
                "DELETE FROM sekai_decisions WHERE seq <= $1",
                &[&prefix_end],
            )
            .map_err(err)?;
            let audit_cutoff = effective_policy(&policies, AUDIT_DATASET, "", "")
                .map_or(now, |policy| {
                    now - i64::from(policy.retention_days) * DAY_MS
                });
            tx.execute(
                "INSERT INTO sekai_ledger_anchors (seq,entry_hash,reason,created)
                 VALUES($1,$2,$3,$4)
                 ON CONFLICT(seq) DO UPDATE SET entry_hash=excluded.entry_hash,
                   reason=excluded.reason,created=excluded.created",
                &[
                    &prefix_end,
                    &anchor_hash,
                    &format!("archived before {audit_cutoff}"),
                    &now,
                ],
            )
            .map_err(err)?;
        }
        for id in &event_ids {
            tx.execute("DELETE FROM sekai_content_events WHERE id=$1", &[id])
                .map_err(err)?;
        }
        for id in &llm_ids {
            tx.execute("DELETE FROM sekai_dataset_rows WHERE id=$1", &[id])
                .map_err(err)?;
        }
        for id in &change_ids {
            tx.execute("DELETE FROM sekai_object_changes WHERE id=$1", &[id])
                .map_err(err)?;
        }
        // A dry run does the once-per-run version work here and rolls it
        // back; a run does it after its last batch.
        if dry_run && !llm_ids.is_empty() {
            erase_expired_llm_call_versions(&mut tx, &policies, now, true)?;
        }
        for (component_id, (namespace, rows)) in folded {
            let baseline = tx
                .query_opt(
                    "SELECT task_total,task_succeeded,consecutive_failures
                     FROM sekai_task_observation_baselines WHERE component_id=$1 FOR UPDATE",
                    &[&component_id],
                )
                .map_err(err)?
                .map_or((0, 0, 0), |row| (row.get(0), row.get(1), row.get(2)));
            let statuses = rows
                .iter()
                .map(|(_, status)| status.clone())
                .collect::<Vec<_>>();
            let (total, succeeded, failures) = fold_observation_baseline(baseline, &statuses);
            tx.execute(
                "INSERT INTO sekai_task_observation_baselines
                 (component_id,namespace,task_total,task_succeeded,consecutive_failures,created)
                 VALUES($1,$2,$3,$4,$5,$6)
                 ON CONFLICT(component_id) DO UPDATE SET namespace=excluded.namespace,
                   task_total=excluded.task_total,task_succeeded=excluded.task_succeeded,
                   consecutive_failures=excluded.consecutive_failures,created=excluded.created",
                &[
                    &component_id,
                    &namespace,
                    &total,
                    &succeeded,
                    &failures,
                    &(now / 1000),
                ],
            )
            .map_err(err)?;
            for ((request_id, component_id), _) in rows {
                tx.execute(
                    "DELETE FROM sekai_task_observations WHERE request_id=$1 AND component_id=$2",
                    &[&request_id, &component_id],
                )
                .map_err(err)?;
            }
        }
        for (request_id, component_id) in redacted {
            // As on SQLite: the row stays, as a marked tombstone that keeps
            // nothing of the observation.
            tx.execute(
                "UPDATE sekai_task_observations
                 SET request_id=$1,namespace='',data_class='unclassified',model='[redacted]',
                     packages_json='[]',context_json=$2,retention_tombstone=TRUE
                 WHERE request_id=$3 AND component_id=$4",
                &[
                    &format!("retention-tombstone:{}", uuid::Uuid::new_v4().simple()),
                    &RETENTION_TOMBSTONE_CONTEXT,
                    &request_id,
                    &component_id,
                ],
            )
            .map_err(err)?;
        }
        if dry_run {
            tx.rollback().map_err(err)?;
        } else {
            tx.commit().map_err(err)?;
        }
        Ok(run)
    }

    /// Verify every batch of the in-database archive; an empty one verifies.
    pub fn verify_retention_archive(&self) -> Result<ArchiveVerification, String> {
        let mut connection = self.connection()?;
        // One snapshot for every query, so a concurrent erasure or run is
        // seen whole or not at all.
        let mut tx = connection
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(err)?;
        let verification = verify_retention_archive_pg(&mut tx)?;
        tx.commit().map_err(err)?;
        Ok(verification)
    }

    /// Batches and archived records per dataset in the in-database archive.
    pub fn retention_archive_status(
        &self,
    ) -> Result<crate::sekai::retention::ArchiveStatus, String> {
        let mut connection = self.connection()?;
        let summary = connection
            .query_one(
                "SELECT COUNT(*), MAX(cutoff_ms) FROM sekai_archive_batches",
                &[],
            )
            .map_err(err)?;
        let records = connection
            .query(
                "SELECT dataset, COUNT(*) FROM sekai_archive_records
                 GROUP BY dataset ORDER BY dataset",
                &[],
            )
            .map_err(err)?
            .into_iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
            .collect();
        Ok(crate::sekai::retention::ArchiveStatus {
            batches: summary.get(0),
            records,
            last_cutoff_ms: summary.get(1),
        })
    }

    /// Archive content events created before `cutoff_ms` and remove them
    /// from the hot table, in bounded batches, one transaction each, until
    /// none is left.
    fn archive_content_events(&self, cutoff_ms: i64) -> Result<ArchiveRun, String> {
        let limit = i64::try_from(RETENTION_BATCH_SIZE).unwrap_or(i64::MAX);
        let mut total = ArchiveRun::default();
        loop {
            let batch = self.archive_content_event_batch(cutoff_ms, limit)?;
            if batch.batch_id.is_empty() {
                return Ok(total);
            }
            total.absorb(batch);
        }
    }

    fn archive_content_event_batch(
        &self,
        cutoff_ms: i64,
        limit: i64,
    ) -> Result<ArchiveRun, String> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        tx.query_one("SELECT pg_advisory_xact_lock_shared(251,251)", &[])
            .map_err(err)?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('sekai.lifecycle.archive',251))",
            &[],
        )
        .map_err(err)?;
        let rows = tx
            .query(
                "SELECT id,event_kind,blob_id,reference_id,actor,reason,created_at_ms
                 FROM sekai_content_events WHERE created_at_ms<$1 ORDER BY id LIMIT $2 FOR UPDATE",
                &[&cutoff_ms, &limit],
            )
            .map_err(err)?;
        if rows.is_empty() {
            tx.commit().map_err(err)?;
            return Ok(ArchiveRun::default());
        }
        let records = rows.iter().map(content_event_record).collect();
        let (batch_id, content_hash) = write_archive_batch(&mut tx, cutoff_ms, records)?;
        // Hot rows are deleted by their own ids; the archive keys them opaquely.
        for row in &rows {
            tx.execute(
                "DELETE FROM sekai_content_events WHERE id=$1",
                &[&row.get::<_, String>(0)],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        Ok(ArchiveRun {
            batch_id,
            content_hash,
            content_events_archived: rows.len() as i32,
            batches: 1,
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

/// Where a PostgreSQL retention run has got to, carried from batch to
/// batch so each batch reads at most one page per dataset. Content events
/// leave the hot table and restart at the oldest remaining; LLM calls and
/// observations, which keep rows a batch did not archive, resume after the
/// last key read.
#[derive(Debug, Default)]
struct RetentionCursor {
    ledger_verified: bool,
    audit_done: bool,
    llm_after: i64,
    llm_done: bool,
    /// `(component_id, timestamp, request_id)` of the last observation read.
    observation_after: Option<(String, i64, String)>,
    /// Components with a retained row read so far: their later expired rows
    /// are redacted in place rather than folded.
    retained_components: std::collections::BTreeSet<String>,
    observations_done: bool,
    content_events_done: bool,
    object_changes_done: bool,
}

impl RetentionCursor {
    fn done(&self) -> bool {
        self.audit_done
            && self.llm_done
            && self.observations_done
            && self.content_events_done
            && self.object_changes_done
    }
}

impl From<crate::sekai::retention::ArchiveRecord> for ArchiveRecord {
    fn from(record: crate::sekai::retention::ArchiveRecord) -> Self {
        Self {
            dataset: record.dataset.into(),
            source_key: record.source_key,
            payload: record.payload,
        }
    }
}

/// A content event row (`id,event_kind,blob_id,reference_id,actor,reason,
/// created_at_ms`) as its archive record; the same payload SQLite archives.
fn content_event_record(row: &Row) -> ArchiveRecord {
    ArchiveRecord {
        dataset: CONTENT_EVENTS_DATASET.into(),
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
    }
}

/// Write one archive batch of `records` (natural keys; keyed opaquely here)
/// and verify it, returning its id and content hash. Idempotent: the batch
/// id is a hash of `cutoff_ms` and its content, and a record already there
/// must hold the same payload.
fn write_archive_batch(
    tx: &mut impl GenericClient,
    cutoff_ms: i64,
    mut records: Vec<ArchiveRecord>,
) -> Result<(String, String), String> {
    for record in &mut records {
        record.source_key =
            crate::sekai::retention::archive_source_key(&record.dataset, &record.source_key);
    }
    records.sort_by(|left, right| {
        (&left.dataset, &left.source_key).cmp(&(&right.dataset, &right.source_key))
    });
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
    verify_batch(tx, &batch_id)?;
    Ok((batch_id, content_hash))
}

/// Drop calls past their policy from the `llm_calls` branches and versions,
/// and record an `archive` version when `snapshot`. Only the rows the policy
/// selects go: branches, change-bundle previews included, keep every other
/// row, and nothing is written when no row has expired. Unreadable version
/// rows go too, as on SQLite. The caller holds the rows lock.
fn erase_expired_llm_call_versions(
    tx: &mut postgres::Transaction<'_>,
    policies: &[RetentionPolicy],
    now: i64,
    snapshot: bool,
) -> Result<(), String> {
    let expired = |data: &str| {
        serde_json::from_str(data).is_ok_and(|values| llm_call_expired(&values, policies, now))
    };
    let branch_rows = tx
        .query(
            "SELECT name,row_id,data FROM sekai_dataset_branch_rows
             WHERE dataset_id=$1 FOR UPDATE",
            &[&LLM_CALLS_DATASET],
        )
        .map_err(err)?
        .into_iter()
        .filter(|row| expired(row.get(2)))
        .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
        .collect::<Vec<_>>();
    let version_rows = tx
        .query(
            "SELECT version_id,row_id,data FROM sekai_dataset_version_rows
             WHERE dataset_id=$1 FOR UPDATE",
            &[&LLM_CALLS_DATASET],
        )
        .map_err(err)?
        .into_iter()
        .filter(|row| {
            let data: &str = row.get(2);
            serde_json::from_str::<std::collections::HashMap<String, String>>(data).is_err()
                || expired(data)
        })
        .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
        .collect::<Vec<_>>();
    for (name, row_id) in &branch_rows {
        tx.execute(
            "DELETE FROM sekai_dataset_branch_rows
             WHERE dataset_id=$1 AND name=$2 AND row_id=$3",
            &[&LLM_CALLS_DATASET, name, row_id],
        )
        .map_err(err)?;
    }
    for (version_id, row_id) in &version_rows {
        tx.execute(
            "DELETE FROM sekai_dataset_version_rows
             WHERE dataset_id=$1 AND version_id=$2 AND row_id=$3",
            &[&LLM_CALLS_DATASET, version_id, row_id],
        )
        .map_err(err)?;
    }
    if !version_rows.is_empty() {
        tx.execute(
            "UPDATE sekai_dataset_versions SET row_count = (
                SELECT COUNT(*) FROM sekai_dataset_version_rows
                WHERE dataset_id = sekai_dataset_versions.dataset_id
                  AND version_id = sekai_dataset_versions.version_id
             ) WHERE dataset_id=$1",
            &[&LLM_CALLS_DATASET],
        )
        .map_err(err)?;
    }
    if snapshot {
        match crate::db::postgres_dataset::snapshot_dataset_version_pg(
            tx,
            LLM_CALLS_DATASET,
            "",
            "",
            "archive",
            "",
            now,
        ) {
            Err(error) if error == crate::sekai::dataset_version::DATASET_NOT_FOUND => {}
            other => {
                other?;
            }
        }
    }
    Ok(())
}

fn append_subject_erasure_decision(
    client: &mut impl GenericClient,
    request: &SubjectErasureRequest,
    result: &SubjectErasureResult,
) -> Result<(), String> {
    let (head_seq, head_hash) = crate::db::postgres_decision::chain_head(client)?;
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

    // Same order as dataset and branch writers: the dataset rows lock first.
    client
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&crate::db::postgres::advisory_lock_key(&[
                "dataset_rows",
                "llm_calls",
            ])],
        )
        .map_err(err)?;
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
    let version_rows = client
        .query(
            "SELECT version_id, row_id, data FROM sekai_dataset_version_rows
             WHERE dataset_id = 'llm_calls'",
            &[],
        )
        .map_err(err)?;
    for row in version_rows {
        let version_id: String = row.get(0);
        let row_id: i64 = row.get(1);
        let data: String = row.get(2);
        if value_mentions_subject(&data, &request.subject_kind, subject) {
            client
                .execute(
                    "DELETE FROM sekai_dataset_version_rows
                     WHERE dataset_id = 'llm_calls' AND version_id = $1 AND row_id = $2",
                    &[&version_id, &row_id],
                )
                .map_err(err)?;
        }
    }
    crate::db::postgres_dataset_branch::edit_branch_rows_pg(client, "llm_calls", &|row| {
        let mentions = row
            .and_then(|values| serde_json::to_string(&values).ok())
            .is_none_or(|data| value_mentions_subject(&data, &request.subject_kind, subject));
        if mentions {
            crate::sekai::dataset_branch::BranchRowEdit::Delete
        } else {
            crate::sekai::dataset_branch::BranchRowEdit::Keep
        }
    })?;
    client
        .execute(
            "UPDATE sekai_dataset_versions SET row_count = (
                SELECT COUNT(*) FROM sekai_dataset_version_rows
                WHERE dataset_id = sekai_dataset_versions.dataset_id
                  AND version_id = sekai_dataset_versions.version_id
             ) WHERE dataset_id = 'llm_calls'",
            &[],
        )
        .map_err(err)?;

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
    // Retention folds expired observations into a component baseline that
    // keeps the component and namespace: the same rule removes it.
    for row in client
        .query(
            "SELECT component_id,namespace FROM sekai_task_observation_baselines
             ORDER BY component_id FOR UPDATE",
            &[],
        )
        .map_err(err)?
    {
        let component_id: String = row.get(0);
        let namespace: String = row.get(1);
        if [&component_id, &namespace].iter().any(|value| {
            *value == subject || value_mentions_subject(value, &request.subject_kind, subject)
        }) {
            client
                .execute(
                    "DELETE FROM sekai_task_observation_baselines WHERE component_id=$1",
                    &[&component_id],
                )
                .map_err(err)?;
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
    if postgres_relation_exists(client, "chisei_budget_limits")? {
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
                    value == subject
                        || value_mentions_subject(value, &request.subject_kind, subject)
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
    }
    // Work-unit defaults (#1862) a principal's scope carries.
    if postgres_relation_exists(client, "chisei_budget_work_unit_defaults")? {
        let default_scopes = client
            .query(
                "SELECT DISTINCT scope_id FROM chisei_budget_work_unit_defaults",
                &[],
            )
            .map_err(err)?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .filter(|scope| {
                scope == subject || value_mentions_subject(scope, &request.subject_kind, subject)
            })
            .collect::<Vec<_>>();
        for scope in default_scopes {
            result.budget_records_deleted += client
                .execute(
                    "DELETE FROM chisei_budget_work_unit_defaults WHERE scope_id=$1",
                    &[&scope],
                )
                .map_err(err)? as i32;
        }
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

/// Whether PostgreSQL's own hot erasure would delete this archived record:
/// an LLM call whose data mentions the subject, or an observation with a
/// column that does (see `erase_supported_subject_data`). Archived records
/// are erased by the shared per-dataset rules on top, so the archive is
/// never weaker than the hot table on either backend.
fn postgres_hot_rule_deletes(
    dataset: &str,
    payload: &str,
    subject: &ArchiveErasureSubject<'_>,
) -> bool {
    let mentions = |value: &str| {
        value == subject.subject || value_mentions_subject(value, subject.kind, subject.subject)
    };
    match dataset {
        LLM_CALLS_DATASET => mentions(payload),
        crate::sekai::retention::TASK_OBSERVATIONS_DATASET => {
            serde_json::from_str::<serde_json::Value>(payload).is_ok_and(|row| {
                [
                    "request_id",
                    "component_id",
                    "namespace",
                    "model",
                    "status",
                    "packages_json",
                    "context_json",
                ]
                .iter()
                .any(|field| row[field].as_str().is_some_and(mentions))
            })
        }
        _ => false,
    }
}

/// The objects that are the erasure subject, by the rule the hot erasure
/// applies to `sekai_objects`: the subject's id, or its name or external id
/// on an object of the subject's kind.
fn represented_object_ids(
    client: &mut impl GenericClient,
    request: &SubjectErasureRequest,
) -> Result<Vec<String>, String> {
    Ok(client
        .query(
            "SELECT id FROM sekai_objects
             WHERE id=$1 OR (kind=$2 AND (external_id=$1 OR name=$1)) ORDER BY id",
            &[&request.subject, &request.subject_kind],
        )
        .map_err(err)?
        .into_iter()
        .map(|row| row.get(0))
        .collect())
}

/// Whether a content reference, by its `[actor, operation_id,
/// causal_identity]`, belongs to the subject: actors for agents and users,
/// the operation and causal identity for work units.
fn content_reference_matches(columns: [String; 3], kind: &str, subject: &str) -> bool {
    let [actor, operation_id, causal_identity] = columns;
    let values = match kind {
        "work_unit" => vec![operation_id, causal_identity],
        _ => vec![actor],
    };
    values
        .iter()
        .any(|value| value == subject || value_mentions_subject(value, kind, subject))
}

/// Erase the subject from every archived record by its dataset's hot-path
/// rule ([`erase_archived_record`]), record each rewrite, and recompute the
/// content hash and count of each batch it touched.
fn redact_archived_subject(
    client: &mut impl GenericClient,
    subject: &ArchiveErasureSubject<'_>,
    now_ms: i64,
) -> Result<(), String> {
    let subject_hash = subject.hash;
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
    // Archived decisions tombstone by the shared ledger rule or by this
    // backend's hot rule (`tombstone_decisions`); the attestations of a
    // tombstoned decision go, as in the hot table.
    let mut erased_decisions = std::collections::BTreeSet::new();
    let mut tombstoned = std::collections::BTreeMap::new();
    for row in &rows {
        if row.get::<_, &str>(0) != "audit.decisions" {
            continue;
        }
        let pg_hot_rule = |json: &serde_json::Value| {
            ["actor", "reason", "target_id", "evidence"]
                .iter()
                .any(|field| {
                    json[field].as_str().is_some_and(|value| {
                        value == subject.subject
                            || value_mentions_subject(value, subject.kind, subject.subject)
                    })
                })
        };
        if let Some((redacted, original_id)) = tombstone_archived_decision(
            row.get(2),
            subject.kind,
            subject.subject,
            subject.hash,
            now_ms,
            subject.object_ids,
            &pg_hot_rule,
        ) {
            erased_decisions.insert(original_id);
            tombstoned.insert(row.get::<_, String>(1), redacted);
        }
    }
    let mut touched_batches = std::collections::BTreeSet::new();
    for row in rows {
        let dataset: String = row.get(0);
        let source_key: String = row.get(1);
        let payload: String = row.get(2);
        let erasure = match dataset.as_str() {
            "audit.decisions" => tombstoned
                .remove(&source_key)
                .map_or(ArchivedErasure::Keep, ArchivedErasure::Rewrite),
            "audit.attestations"
                if serde_json::from_str::<serde_json::Value>(&payload)
                    .ok()
                    .and_then(|json| json["decision_id"].as_str().map(str::to_string))
                    .is_some_and(|id| erased_decisions.contains(&id)) =>
            {
                ArchivedErasure::Delete
            }
            _ if postgres_hot_rule_deletes(&dataset, &payload, subject) => ArchivedErasure::Delete,
            _ => erase_archived_record(&dataset, &payload, subject),
        };
        let redacted_payload = match erasure {
            ArchivedErasure::Keep => continue,
            ArchivedErasure::Rewrite(redacted) => redacted,
            ArchivedErasure::Delete => {
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
                for table in [
                    "sekai_archive_batch_records",
                    "sekai_archive_redactions",
                    "sekai_archive_records",
                ] {
                    client
                        .execute(
                            &format!("DELETE FROM {table} WHERE dataset=$1 AND source_key=$2"),
                            &[&dataset, &source_key],
                        )
                        .map_err(err)?;
                }
                continue;
            }
        };
        let old_hash: String = row.get(3);
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
                "UPDATE sekai_archive_batches SET content_hash=$1,record_count=$2 WHERE id=$3",
                &[&hash_json(&hashes)?, &(hashes.len() as i64), &batch_id],
            )
            .map_err(err)?;
    }
    Ok(())
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// Verify every batch of the in-database archive, and that no record lacks
/// a batch manifest; an empty archive verifies.
fn verify_retention_archive_pg(
    client: &mut impl GenericClient,
) -> Result<ArchiveVerification, String> {
    let batch_ids = client
        .query("SELECT id FROM sekai_archive_batches ORDER BY id", &[])
        .map_err(err)?
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    let mut verification = ArchiveVerification {
        ok: true,
        ..ArchiveVerification::default()
    };
    // As on SQLite: a record no batch manifest names (its manifest lost)
    // fails verification, not only records reachable from a batch.
    let orphans: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM sekai_archive_records r
             WHERE NOT EXISTS (
                SELECT 1 FROM sekai_archive_batch_records link
                JOIN sekai_archive_batches batch ON batch.id=link.batch_id
                WHERE link.dataset=r.dataset AND link.source_key=r.source_key)",
            &[],
        )
        .map_err(err)?
        .get(0);
    if orphans > 0 {
        verification.ok = false;
        verification.error = "archive contains records without a batch manifest".into();
        return Ok(verification);
    }
    for batch_id in batch_ids {
        match verify_batch(client, &batch_id) {
            Ok((records, batches)) => {
                verification.records_checked += records;
                verification.batches_checked += batches;
            }
            Err(error) => {
                verification.ok = false;
                verification.error = error;
                return Ok(verification);
            }
        }
    }
    Ok(verification)
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

fn postgres_relation_exists(client: &mut impl GenericClient, table: &str) -> Result<bool, String> {
    let row = client
        .query_opt(
            "SELECT 1 FROM pg_tables
             WHERE schemaname = current_schema() AND tablename = $1",
            &[&table],
        )
        .map_err(err)?;
    Ok(row.is_some())
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

    /// Serializes the tests here that archive: they share one database.
    static ARCHIVING: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn archiving() -> std::sync::MutexGuard<'static, ()> {
        ARCHIVING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A run that committed one batch and then died, plus a batch rolled
    /// back mid-way, leave a rerun to archive every remaining record once:
    /// nothing duplicated, nothing lost.
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_retention_resumes_after_an_interrupted_run() {
        let _serial = archiving();
        let db = database();
        let prefix = format!("resume-{}", uuid::Uuid::new_v4().simple());
        let backlog = 600;
        let _ = db.create_dataset(&crate::sekai::dataset::Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
            partition_keys: Vec::new(),
        });
        db.append_dataset_rows(
            LLM_CALLS_DATASET,
            &(0..backlog)
                .map(|index| {
                    std::collections::HashMap::from([
                        ("project".to_string(), prefix.clone()),
                        ("call".to_string(), index.to_string()),
                        ("timestamp_ms".to_string(), "1".to_string()),
                    ])
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: LLM_CALLS_DATASET.into(),
            namespace: prefix.clone(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        let now = 2 * DAY_MS;
        let first = db
            .archive_retained_batch(
                now,
                false,
                i64::try_from(RETENTION_BATCH_SIZE).unwrap(),
                &mut RetentionCursor::default(),
            )
            .unwrap();
        assert!(first.llm_calls_archived > 0);
        // A batch that dies before commit: the dry run's rolled-back batch.
        db.archive_retained_records(now, true).unwrap();
        db.archive_retained_records(now, false).unwrap();
        let mut connection = db.connection().unwrap();
        let count = |connection: &mut postgres::Client, sql: &str| -> i64 {
            connection
                .query_one(sql, &[&format!("%\"{prefix}\"%")])
                .unwrap()
                .get(0)
        };
        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) FROM sekai_archive_records
                 WHERE dataset='llm_calls' AND payload LIKE $1"
            ),
            backlog
        );
        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) FROM sekai_dataset_rows
                 WHERE dataset_id='llm_calls' AND data LIKE $1"
            ),
            0
        );
        assert!(db.verify_retention_archive().unwrap().ok);
    }

    /// Retention leaves `llm_calls` change-bundle previews alone: a run with
    /// nothing expiring writes nothing to them, and a run drops only the
    /// preview rows its policy selects.
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_retention_keeps_change_bundle_previews() {
        let _serial = archiving();
        let db = database();
        let prefix = format!("preview-{}", uuid::Uuid::new_v4().simple());
        let branch = format!(
            "{}{prefix}",
            crate::sekai::dataset_branch::BUNDLE_BRANCH_PREFIX
        );
        let call = |at: i64| {
            serde_json::json!({"project": prefix, "timestamp_ms": at.to_string()}).to_string()
        };
        let mut connection = db.connection().unwrap();
        connection
            .execute(
                "INSERT INTO sekai_dataset_branches (dataset_id,name,created_at_ms)
                 VALUES('llm_calls',$1,1)",
                &[&branch],
            )
            .unwrap();
        for (row_id, at) in [(1_i64, 1_i64), (2, 10 * DAY_MS)] {
            connection
                .execute(
                    "INSERT INTO sekai_dataset_branch_rows (dataset_id,name,row_id,data)
                     VALUES('llm_calls',$1,$2,$3)",
                    &[&branch, &row_id, &call(at)],
                )
                .unwrap();
        }
        let rows = |connection: &mut postgres::Client| -> Vec<i64> {
            connection
                .query(
                    "SELECT row_id FROM sekai_dataset_branch_rows
                     WHERE dataset_id='llm_calls' AND name=$1 ORDER BY row_id",
                    &[&branch],
                )
                .unwrap()
                .into_iter()
                .map(|row| row.get(0))
                .collect()
        };
        // No policy for this project yet: nothing expires, nothing changes.
        db.archive_retained_records(3 * DAY_MS, false).unwrap();
        assert_eq!(rows(&mut connection), [1, 2]);
        db.set_retention_policy(&RetentionPolicy {
            dataset: LLM_CALLS_DATASET.into(),
            namespace: prefix.clone(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        db.archive_retained_records(3 * DAY_MS, false).unwrap();
        assert_eq!(rows(&mut connection), [2]);
        connection
            .batch_execute(&format!(
                "DELETE FROM sekai_dataset_branch_rows WHERE name='{branch}';
                 DELETE FROM sekai_dataset_branches WHERE name='{branch}';"
            ))
            .unwrap();
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_corrupt_archives_and_blobs_fail_closed() {
        let _serial = archiving();
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
        // Remove the corrupted batch: other tests verify the whole archive
        // of this shared database.
        connection
            .batch_execute(&format!(
                "DELETE FROM sekai_archive_redactions WHERE (dataset,source_key) IN
                   (SELECT dataset,source_key FROM sekai_archive_batch_records WHERE batch_id='{id}');
                 CREATE TEMP TABLE corrupt_keys AS
                   SELECT dataset,source_key FROM sekai_archive_batch_records WHERE batch_id='{id}';
                 DELETE FROM sekai_archive_batch_records WHERE batch_id='{id}';
                 DELETE FROM sekai_archive_records WHERE (dataset,source_key) IN
                   (SELECT dataset,source_key FROM corrupt_keys);
                 DELETE FROM sekai_archive_batches WHERE id='{id}';
                 DROP TABLE corrupt_keys;",
                id = archived.batch_id
            ))
            .unwrap();

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

    /// A record no batch manifest names fails verification, as on SQLite.
    /// The orphan exists only inside a transaction that is rolled back, so
    /// nothing invalid is ever visible to other tests or agents.
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_orphan_archive_records_fail_verification() {
        let db = database();
        let key = format!("orphan-{}", uuid::Uuid::new_v4().simple());
        let mut connection = db.connection().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute(
            "INSERT INTO sekai_archive_records
             (dataset,source_key,payload,payload_hash,archived_at_ms)
             VALUES('content_events',$1,'{}','x',1)",
            &[&key],
        )
        .unwrap();
        let verification = verify_retention_archive_pg(&mut tx).unwrap();
        tx.rollback().unwrap();
        assert!(!verification.ok);
        assert!(verification.error.contains("without a batch manifest"));
    }
}
