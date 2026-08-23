use std::collections::{BTreeMap, HashMap};

use postgres::{GenericClient, IsolationLevel, Row};

use crate::db::object_sync::{ApplyError, PreparedBatch, PreparedRecord, validate_binding};
use crate::db::postgres::PostgresDb;
use crate::db::postgres_audit::{insert_changes, lock_object_lifecycle};
use crate::domain::Object;
use crate::sekai::audit::object_diff_changes;
use crate::sekai::object_sync::{
    OperationOutcome, SOURCE_GITHUB, SourceBatch, SourceBatchResult, SourceBatchStatus,
    SourceBatchTransaction, SourceBinding, SourceCheckpoint, SourceRecordResult, SourceSyncState,
    SyncDecision,
};

const SOURCE_LOCK_SEED: i64 = 665;
const IDEMPOTENCY_LOCK_SEED: i64 = 666;

#[derive(Debug)]
enum OpenDisposition {
    Open,
    Committed(Box<SourceBatchResult>),
}

#[derive(Debug)]
struct StoredBinding {
    binding: SourceBinding,
    updated_at_ms: i64,
}

#[derive(Debug)]
struct StoredBatch {
    transaction: SourceBatchTransaction,
    result_json: String,
}

#[derive(Debug)]
struct StoredIdentity {
    binding_id: String,
    type_digest: String,
    type_name: String,
    object_id: String,
    source_version: String,
    payload_digest: String,
}

impl PostgresDb {
    pub fn apply_source_batch(
        &self,
        batch: &SourceBatch,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<SourceBatchResult, String> {
        batch
            .validate_for_producer(authenticated_producer)
            .map_err(|error| error.to_string())?;
        if now_ms <= 0 {
            return Err("invalid_timestamp: now_ms must be positive".into());
        }
        let prepared = PreparedBatch::new(batch).map_err(|error| error.to_string())?;
        match self
            .persist_source_batch_open(batch, &prepared, now_ms)
            .map_err(|error| error.to_string())?
        {
            OpenDisposition::Committed(result) => Ok(*result),
            OpenDisposition::Open => self
                .commit_source_batch(batch, &prepared, authenticated_producer, now_ms)
                .map_err(|error| error.to_string()),
        }
    }

    fn persist_source_batch_open(
        &self,
        batch: &SourceBatch,
        prepared: &PreparedBatch,
        now_ms: i64,
    ) -> Result<OpenDisposition, ApplyError> {
        let mut connection = self.connection().map_err(ApplyError::storage)?;
        let mut transaction = connection.transaction()?;
        lock_batch_identities(&mut transaction, batch)?;

        if let Some(stored) = load_batch_by_key(
            &mut transaction,
            &batch.namespace,
            &batch.producer_identity,
            &batch.idempotency_key,
            true,
        )? {
            if stored.transaction.batch_digest != batch.batch_digest {
                return Err(ApplyError::denied(
                    "idempotency_conflict",
                    "idempotency key is already bound to different canonical batch input",
                ));
            }
            if stored.transaction.transaction_id != prepared.transaction_id
                || stored.transaction.binding_id != prepared.binding_id
            {
                return Err(ApplyError::denied(
                    "replay_identity_conflict",
                    "stored replay identity does not match the canonical batch identity",
                ));
            }
            return match stored.transaction.status {
                SourceBatchStatus::Committed => {
                    let result = parse_stored_result(&stored)?;
                    transaction.commit()?;
                    Ok(OpenDisposition::Committed(Box::new(result)))
                }
                SourceBatchStatus::Open => {
                    let binding = load_binding_by_id(&mut transaction, &prepared.binding_id, true)?
                        .ok_or_else(|| {
                            ApplyError::denied(
                                "orphaned_open_transaction",
                                "open transaction has no stable source binding",
                            )
                        })?;
                    validate_binding(&binding.binding, batch)?;
                    transaction.commit()?;
                    Ok(OpenDisposition::Open)
                }
                SourceBatchStatus::Aborted => Err(ApplyError::denied(
                    "batch_aborted",
                    "matching source batch was durably aborted and cannot become success",
                )),
            };
        }

        let binding = match load_binding_by_source(
            &mut transaction,
            &batch.namespace,
            &batch.source,
            &batch.source_instance,
            true,
        )? {
            Some(binding) => {
                validate_binding(&binding.binding, batch)?;
                binding
            }
            None => {
                let binding = SourceBinding {
                    binding_id: prepared.binding_id.clone(),
                    namespace: batch.namespace.clone(),
                    producer_identity: batch.producer_identity.clone(),
                    source: batch.source.clone(),
                    source_instance: batch.source_instance.clone(),
                    family: batch.family.clone(),
                    adapter_id: batch.adapter_id.clone(),
                    adapter_version: batch.adapter_version.clone(),
                    type_digest: batch.type_digest.clone(),
                    created_at_ms: now_ms,
                    active: true,
                };
                transaction.execute(
                    "INSERT INTO sekai_source_bindings (
                        binding_id, namespace, producer_identity, source, source_instance,
                        family, adapter_id, adapter_version, type_digest, created_at_ms,
                        active, updated_at_ms
                     ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, $10
                     )",
                    &[
                        &binding.binding_id,
                        &binding.namespace,
                        &binding.producer_identity,
                        &binding.source,
                        &binding.source_instance,
                        &binding.family,
                        &binding.adapter_id,
                        &binding.adapter_version,
                        &binding.type_digest,
                        &binding.created_at_ms,
                    ],
                )?;
                StoredBinding {
                    binding,
                    updated_at_ms: now_ms,
                }
            }
        };

        preflight_commit_state(&mut transaction, &binding.binding, batch, &prepared.records)?;
        let open_exists: bool = transaction
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM sekai_source_batch_transactions
                    WHERE binding_id = $1 AND status = 'OPEN'
                 )",
                &[&prepared.binding_id],
            )?
            .get(0);
        if open_exists {
            return Err(ApplyError::denied(
                "open_transaction_conflict",
                "source binding already has a different open transaction",
            ));
        }

        transaction.execute(
            "INSERT INTO sekai_source_batch_transactions (
                transaction_id, binding_id, namespace, producer_identity, idempotency_key,
                batch_digest, batch_json, current_cursor, proposed_next_cursor, status,
                outcome, opened_at_ms, closed_at_ms, reason, result_json
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, 'OPEN',
                'unavailable', $10, NULL, 'awaiting atomic commit', ''
             )",
            &[
                &prepared.transaction_id,
                &prepared.binding_id,
                &batch.namespace,
                &batch.producer_identity,
                &batch.idempotency_key,
                &batch.batch_digest,
                &prepared.batch_json,
                &batch.current_cursor,
                &batch.proposed_next_cursor,
                &now_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(OpenDisposition::Open)
    }

    fn commit_source_batch(
        &self,
        batch: &SourceBatch,
        prepared: &PreparedBatch,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<SourceBatchResult, ApplyError> {
        let mut connection = self.connection().map_err(ApplyError::storage)?;
        let mut transaction = connection.transaction()?;
        lock_batch_identities(&mut transaction, batch)?;
        let stored = load_batch_by_key(
            &mut transaction,
            &batch.namespace,
            &batch.producer_identity,
            &batch.idempotency_key,
            true,
        )?
        .ok_or_else(|| {
            ApplyError::denied(
                "missing_open_transaction",
                "source batch has no durable open transaction",
            )
        })?;
        if stored.transaction.batch_digest != batch.batch_digest {
            return Err(ApplyError::denied(
                "idempotency_conflict",
                "idempotency key is already bound to different canonical batch input",
            ));
        }
        match stored.transaction.status {
            SourceBatchStatus::Committed => {
                let result = parse_stored_result(&stored)?;
                transaction.commit()?;
                return Ok(result);
            }
            SourceBatchStatus::Aborted => {
                return Err(ApplyError::denied(
                    "batch_aborted",
                    "matching source batch was durably aborted and cannot become success",
                ));
            }
            SourceBatchStatus::Open => {}
        }

        let binding = load_binding_by_id(&mut transaction, &prepared.binding_id, true)?
            .ok_or_else(|| {
                ApplyError::denied(
                    "orphaned_open_transaction",
                    "open transaction has no stable source binding",
                )
            })?;
        let preflight = validate_binding(&binding.binding, batch).and_then(|()| {
            preflight_commit_state(&mut transaction, &binding.binding, batch, &prepared.records)
        });
        if let Err(error) = preflight {
            if !error.is_denial() {
                return Err(error);
            }
            transaction.execute(
                "UPDATE sekai_source_batch_transactions
                 SET status = 'ABORTED', outcome = 'denial', closed_at_ms = $1, reason = $2
                 WHERE transaction_id = $3 AND status = 'OPEN'",
                &[&now_ms, &error.to_string(), &prepared.transaction_id],
            )?;
            transaction.execute(
                "UPDATE sekai_source_bindings SET updated_at_ms = $1 WHERE binding_id = $2",
                &[&now_ms, &prepared.binding_id],
            )?;
            transaction.commit()?;
            return Err(error);
        }

        let mut record_results = Vec::with_capacity(prepared.records.len());
        for prepared_record in &prepared.records {
            let before = load_object(&mut transaction, &prepared_record.object.object_id, true)?;
            transaction
                .execute(
                    "DELETE FROM sekai_source_identities
                     WHERE namespace=$1 AND source_id=$2",
                    &[&batch.namespace, &prepared_record.source_id],
                )
                .map_err(ApplyError::storage)?;
            let object = Object {
                id: prepared_record.object.object_id.clone(),
                kind: prepared_record.object.type_name.clone(),
                name: prepared_record.display_name.clone(),
                namespace: batch.namespace.clone(),
                external_id: prepared_record.source_id.clone(),
                properties: serde_json::from_str::<BTreeMap<String, String>>(
                    &prepared_record.properties_json,
                )
                .map_err(ApplyError::storage)?
                .into_iter()
                .collect::<HashMap<_, _>>(),
                created: before
                    .as_ref()
                    .map(|object| object.created)
                    .unwrap_or(prepared_record.observed_at_ms.min(now_ms)),
                updated: now_ms,
            };
            transaction.execute(
                "INSERT INTO sekai_objects
                    (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT(id) DO UPDATE SET
                    kind = EXCLUDED.kind,
                    name = EXCLUDED.name,
                    namespace = EXCLUDED.namespace,
                    external_id = EXCLUDED.external_id,
                    properties = EXCLUDED.properties,
                    updated = EXCLUDED.updated",
                &[
                    &object.id,
                    &object.kind,
                    &object.name,
                    &object.namespace,
                    &object.external_id,
                    &prepared_record.properties_json,
                    &object.created,
                    &object.updated,
                ],
            )?;
            insert_changes(
                &mut transaction,
                &object_diff_changes(
                    authenticated_producer,
                    before.as_ref(),
                    Some(&object),
                    now_ms,
                ),
            )
            .map_err(ApplyError::storage)?;

            let reason = match prepared_record.decision {
                SyncDecision::Upsert(_) => "upserted",
                SyncDecision::Tombstone(_) => "tombstoned",
                SyncDecision::Conflict { .. } | SyncDecision::Reject { .. } => {
                    return Err(ApplyError::storage(
                        "prepared sync decision changed after validation",
                    ));
                }
            };
            let record_result = SourceRecordResult {
                transaction_id: prepared.transaction_id.clone(),
                source_id: prepared_record.source_id.clone(),
                source_version: prepared_record.object.source_version.clone(),
                decision: prepared_record.decision.clone(),
                outcome: OperationOutcome::Success,
                reason: reason.into(),
            };
            let synced_object_json =
                serde_json::to_string(&prepared_record.object).map_err(ApplyError::storage)?;
            let lineage_json =
                serde_json::to_string(&prepared_record.lineage).map_err(ApplyError::storage)?;
            let decision_json =
                serde_json::to_string(&prepared_record.decision).map_err(ApplyError::storage)?;
            transaction.execute(
                "INSERT INTO sekai_source_identities (
                    namespace, source_id, binding_id, type_digest, type_name, object_id,
                    source_version, payload_digest, tombstoned, synced_object_json,
                    lineage_json, last_transaction_id, updated_at_ms
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
                 )
                 ON CONFLICT(namespace, source_id) DO UPDATE SET
                    source_version = EXCLUDED.source_version,
                    payload_digest = EXCLUDED.payload_digest,
                    tombstoned = EXCLUDED.tombstoned,
                    synced_object_json = EXCLUDED.synced_object_json,
                    lineage_json = EXCLUDED.lineage_json,
                    last_transaction_id = EXCLUDED.last_transaction_id,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[
                    &batch.namespace,
                    &prepared_record.source_id,
                    &prepared.binding_id,
                    &batch.type_digest,
                    &prepared_record.object.type_name,
                    &prepared_record.object.object_id,
                    &prepared_record.object.source_version,
                    &prepared_record.object.payload_digest,
                    &prepared_record.object.tombstoned,
                    &synced_object_json,
                    &lineage_json,
                    &prepared.transaction_id,
                    &now_ms,
                ],
            )?;
            transaction.execute(
                "INSERT INTO sekai_source_record_results (
                    transaction_id, source_id, source_version, decision_json,
                    outcome, reason, lineage_json
                 ) VALUES ($1, $2, $3, $4, 'success', $5, $6)",
                &[
                    &prepared.transaction_id,
                    &prepared_record.source_id,
                    &prepared_record.object.source_version,
                    &decision_json,
                    &reason,
                    &lineage_json,
                ],
            )?;
            record_results.push(record_result);
        }

        let committed_transaction = SourceBatchTransaction {
            transaction_id: prepared.transaction_id.clone(),
            binding_id: prepared.binding_id.clone(),
            namespace: batch.namespace.clone(),
            producer_identity: batch.producer_identity.clone(),
            idempotency_key: batch.idempotency_key.clone(),
            batch_digest: batch.batch_digest.clone(),
            current_cursor: batch.current_cursor.clone(),
            proposed_next_cursor: batch.proposed_next_cursor.clone(),
            status: SourceBatchStatus::Committed,
            outcome: OperationOutcome::Success,
            opened_at_ms: stored.transaction.opened_at_ms,
            closed_at_ms: Some(now_ms),
            reason: "committed".into(),
        };
        let result = SourceBatchResult {
            transaction: committed_transaction,
            records: record_results,
            checkpoint_advanced: true,
        };
        let result_json = serde_json::to_string(&result).map_err(ApplyError::storage)?;
        let updated = transaction.execute(
            "UPDATE sekai_source_batch_transactions
             SET status = 'COMMITTED', outcome = 'success', closed_at_ms = $1,
                 reason = 'committed', result_json = $2
             WHERE transaction_id = $3 AND status = 'OPEN'",
            &[&now_ms, &result_json, &prepared.transaction_id],
        )?;
        if updated != 1 {
            return Err(ApplyError::storage(
                "open source batch changed during atomic commit",
            ));
        }
        transaction.execute(
            "INSERT INTO sekai_source_checkpoints (
                binding_id, namespace, cursor, committed_batch_digest, advanced_at_ms
             ) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(binding_id) DO UPDATE SET
                namespace = EXCLUDED.namespace,
                cursor = EXCLUDED.cursor,
                committed_batch_digest = EXCLUDED.committed_batch_digest,
                advanced_at_ms = EXCLUDED.advanced_at_ms",
            &[
                &prepared.binding_id,
                &batch.namespace,
                &batch.proposed_next_cursor,
                &batch.batch_digest,
                &now_ms,
            ],
        )?;
        transaction.execute(
            "UPDATE sekai_source_bindings SET updated_at_ms = $1 WHERE binding_id = $2",
            &[&now_ms, &prepared.binding_id],
        )?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn get_source_sync_state(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<SourceSyncState>, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(|error| error.to_string())?;
        let Some(binding) =
            load_binding_for_state(&mut transaction, namespace, source_instance, type_digest)
                .map_err(|error| error.to_string())?
        else {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        let checkpoint = load_checkpoint(&mut transaction, &binding.binding.binding_id)
            .map_err(|error| error.to_string())?;
        let open_transaction =
            load_latest_transaction(&mut transaction, &binding.binding.binding_id, "OPEN")
                .map_err(|error| error.to_string())?
                .map(|stored| stored.transaction);
        let last_stored =
            load_latest_transaction(&mut transaction, &binding.binding.binding_id, "COMMITTED")
                .map_err(|error| error.to_string())?;
        let last_result = last_stored
            .as_ref()
            .map(parse_stored_result)
            .transpose()
            .map_err(|error| error.to_string())?;
        let mut updated_at_ms = binding.updated_at_ms;
        if let Some(checkpoint) = &checkpoint {
            updated_at_ms = updated_at_ms.max(checkpoint.advanced_at_ms);
        }
        if let Some(transaction) = &open_transaction {
            updated_at_ms = updated_at_ms.max(transaction.opened_at_ms);
        }
        if let Some(stored) = &last_stored {
            updated_at_ms = updated_at_ms.max(
                stored
                    .transaction
                    .closed_at_ms
                    .unwrap_or(stored.transaction.opened_at_ms),
            );
        }
        let state = SourceSyncState {
            binding: binding.binding,
            checkpoint,
            open_transaction,
            last_result,
            updated_at_ms,
        };
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(Some(state))
    }
}

fn lock_batch_identities(
    transaction: &mut postgres::Transaction<'_>,
    batch: &SourceBatch,
) -> Result<(), ApplyError> {
    let source_identity = format!(
        "{}\n{}\n{}",
        batch.namespace, batch.source, batch.source_instance
    );
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
        &[&source_identity, &SOURCE_LOCK_SEED],
    )?;
    let idempotency_identity = format!(
        "{}\n{}\n{}",
        batch.namespace, batch.producer_identity, batch.idempotency_key
    );
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
        &[&idempotency_identity, &IDEMPOTENCY_LOCK_SEED],
    )?;
    Ok(())
}

fn preflight_commit_state(
    transaction: &mut postgres::Transaction<'_>,
    binding: &SourceBinding,
    batch: &SourceBatch,
    records: &[PreparedRecord],
) -> Result<(), ApplyError> {
    let checkpoint = load_checkpoint(transaction, &binding.binding_id)?;
    match checkpoint {
        Some(checkpoint) if checkpoint.cursor != batch.current_cursor => {
            return Err(ApplyError::denied(
                "stale_cursor",
                "current cursor does not match the plane-owned checkpoint",
            ));
        }
        None if !batch.current_cursor.is_empty() => {
            return Err(ApplyError::denied(
                "foreign_cursor",
                "current cursor is foreign to a binding without a checkpoint",
            ));
        }
        Some(_) | None => {}
    }

    let mut object_ids = records
        .iter()
        .map(|record| record.object.object_id.as_str())
        .collect::<Vec<_>>();
    object_ids.sort_unstable();
    object_ids.dedup();
    for object_id in object_ids {
        lock_object_lifecycle(transaction, object_id).map_err(ApplyError::storage)?;
    }

    for record in records {
        let identity = load_identity(transaction, &batch.namespace, &record.source_id, true)?;
        let object = load_object(transaction, &record.object.object_id, true)?;
        match (&identity, &object) {
            (Some(identity), Some(object)) => {
                if identity.binding_id != binding.binding_id
                    || identity.type_digest != batch.type_digest
                    || identity.type_name != record.object.type_name
                    || identity.object_id != record.object.object_id
                    || object.namespace != batch.namespace
                    || object.external_id != record.source_id
                    || object.kind != record.object.type_name
                {
                    return Err(ApplyError::denied(
                        "type_identity_conflict",
                        "source identity conflicts with its bound type or graph object",
                    ));
                }
                let projected_properties =
                    serde_json::from_str::<HashMap<String, String>>(&record.properties_json)
                        .map_err(|error| ApplyError::storage(error.to_string()))?;
                if identity.source_version == record.object.source_version
                    && (identity.payload_digest != record.object.payload_digest
                        || object.name != record.display_name
                        || object.properties != projected_properties)
                {
                    return Err(ApplyError::denied(
                        "source_revision_conflict",
                        "immutable source version is bound to different payload content",
                    ));
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(ApplyError::denied(
                    "ambiguous_identity_state",
                    "source identity and graph object do not form a complete applied pair",
                ));
            }
            (None, None) => {}
        }
        let collision: bool = transaction
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM sekai_objects
                    WHERE namespace = $1 AND external_id = $2 AND id <> $3
                 )",
                &[
                    &batch.namespace,
                    &record.source_id,
                    &record.object.object_id,
                ],
            )?
            .get(0);
        if collision {
            return Err(ApplyError::denied(
                "source_identity_conflict",
                "source identity is already projected to a different graph object",
            ));
        }
    }
    Ok(())
}

fn load_object(
    client: &mut impl GenericClient,
    object_id: &str,
    for_update: bool,
) -> Result<Option<Object>, ApplyError> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    client
        .query_opt(
            &format!(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects WHERE id = $1{suffix}"
            ),
            &[&object_id],
        )?
        .map(object_from_row)
        .transpose()
}

fn object_from_row(row: Row) -> Result<Object, ApplyError> {
    let properties_json: String = row.get(5);
    Ok(Object {
        id: row.get(0),
        kind: row.get(1),
        name: row.get(2),
        namespace: row.get(3),
        external_id: row.get(4),
        properties: serde_json::from_str(&properties_json).map_err(ApplyError::storage)?,
        created: row.get(6),
        updated: row.get(7),
    })
}

fn load_identity(
    client: &mut impl GenericClient,
    namespace: &str,
    source_id: &str,
    for_update: bool,
) -> Result<Option<StoredIdentity>, ApplyError> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    Ok(client
        .query_opt(
            &format!(
                "SELECT binding_id, type_digest, type_name, object_id,
                        source_version, payload_digest
                 FROM sekai_source_identities
                 WHERE namespace = $1 AND source_id = $2{suffix}"
            ),
            &[&namespace, &source_id],
        )?
        .map(|row| StoredIdentity {
            binding_id: row.get(0),
            type_digest: row.get(1),
            type_name: row.get(2),
            object_id: row.get(3),
            source_version: row.get(4),
            payload_digest: row.get(5),
        }))
}

fn load_checkpoint(
    client: &mut impl GenericClient,
    binding_id: &str,
) -> Result<Option<SourceCheckpoint>, ApplyError> {
    Ok(client
        .query_opt(
            "SELECT binding_id, namespace, cursor, committed_batch_digest, advanced_at_ms
             FROM sekai_source_checkpoints WHERE binding_id = $1",
            &[&binding_id],
        )?
        .map(|row| SourceCheckpoint {
            binding_id: row.get(0),
            namespace: row.get(1),
            cursor: row.get(2),
            committed_batch_digest: row.get(3),
            advanced_at_ms: row.get(4),
        }))
}

fn load_binding_by_source(
    client: &mut impl GenericClient,
    namespace: &str,
    source: &str,
    source_instance: &str,
    for_update: bool,
) -> Result<Option<StoredBinding>, ApplyError> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    client
        .query_opt(
            &format!(
                "SELECT binding_id, namespace, producer_identity, source, source_instance,
                        family, adapter_id, adapter_version, type_digest, created_at_ms,
                        active, updated_at_ms
                 FROM sekai_source_bindings
                 WHERE namespace = $1 AND source = $2 AND source_instance = $3{suffix}"
            ),
            &[&namespace, &source, &source_instance],
        )?
        .map(stored_binding_from_row)
        .transpose()
}

fn load_binding_by_id(
    client: &mut impl GenericClient,
    binding_id: &str,
    for_update: bool,
) -> Result<Option<StoredBinding>, ApplyError> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    client
        .query_opt(
            &format!(
                "SELECT binding_id, namespace, producer_identity, source, source_instance,
                        family, adapter_id, adapter_version, type_digest, created_at_ms,
                        active, updated_at_ms
                 FROM sekai_source_bindings WHERE binding_id = $1{suffix}"
            ),
            &[&binding_id],
        )?
        .map(stored_binding_from_row)
        .transpose()
}

fn load_binding_for_state(
    client: &mut impl GenericClient,
    namespace: &str,
    source_instance: &str,
    type_digest: &str,
) -> Result<Option<StoredBinding>, ApplyError> {
    client
        .query_opt(
            "SELECT binding_id, namespace, producer_identity, source, source_instance,
                    family, adapter_id, adapter_version, type_digest, created_at_ms,
                    active, updated_at_ms
             FROM sekai_source_bindings
             WHERE namespace = $1 AND source = $2
               AND source_instance = $3 AND type_digest = $4
             ORDER BY binding_id LIMIT 1",
            &[&namespace, &SOURCE_GITHUB, &source_instance, &type_digest],
        )?
        .map(stored_binding_from_row)
        .transpose()
}

fn stored_binding_from_row(row: Row) -> Result<StoredBinding, ApplyError> {
    Ok(StoredBinding {
        binding: SourceBinding {
            binding_id: row.get(0),
            namespace: row.get(1),
            producer_identity: row.get(2),
            source: row.get(3),
            source_instance: row.get(4),
            family: row.get(5),
            adapter_id: row.get(6),
            adapter_version: row.get(7),
            type_digest: row.get(8),
            created_at_ms: row.get(9),
            active: row.get(10),
        },
        updated_at_ms: row.get(11),
    })
}

const BATCH_SELECT: &str =
    "SELECT transaction_id, binding_id, namespace, producer_identity, idempotency_key,
            batch_digest, current_cursor, proposed_next_cursor, status, outcome,
            opened_at_ms, closed_at_ms, reason, result_json
     FROM sekai_source_batch_transactions";

fn load_batch_by_key(
    client: &mut impl GenericClient,
    namespace: &str,
    producer_identity: &str,
    idempotency_key: &str,
    for_update: bool,
) -> Result<Option<StoredBatch>, ApplyError> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    client
        .query_opt(
            &format!(
                "{BATCH_SELECT}
                 WHERE namespace = $1 AND producer_identity = $2 AND idempotency_key = $3{suffix}"
            ),
            &[&namespace, &producer_identity, &idempotency_key],
        )?
        .map(stored_batch_from_row)
        .transpose()
}

fn load_latest_transaction(
    client: &mut impl GenericClient,
    binding_id: &str,
    status: &str,
) -> Result<Option<StoredBatch>, ApplyError> {
    client
        .query_opt(
            &format!(
                "{BATCH_SELECT}
                 WHERE binding_id = $1 AND status = $2
                 ORDER BY COALESCE(closed_at_ms, opened_at_ms) DESC, transaction_id DESC
                 LIMIT 1"
            ),
            &[&binding_id, &status],
        )?
        .map(stored_batch_from_row)
        .transpose()
}

fn stored_batch_from_row(row: Row) -> Result<StoredBatch, ApplyError> {
    let status: String = row.get(8);
    let status = match status.as_str() {
        "OPEN" => SourceBatchStatus::Open,
        "COMMITTED" => SourceBatchStatus::Committed,
        "ABORTED" => SourceBatchStatus::Aborted,
        _ => return Err(ApplyError::storage("invalid source batch status")),
    };
    let outcome: String = row.get(9);
    let outcome = match outcome.as_str() {
        "success" => OperationOutcome::Success,
        "denial" => OperationOutcome::Denial,
        "unavailable" => OperationOutcome::Unavailable,
        _ => return Err(ApplyError::storage("invalid source batch outcome")),
    };
    Ok(StoredBatch {
        transaction: SourceBatchTransaction {
            transaction_id: row.get(0),
            binding_id: row.get(1),
            namespace: row.get(2),
            producer_identity: row.get(3),
            idempotency_key: row.get(4),
            batch_digest: row.get(5),
            current_cursor: row.get(6),
            proposed_next_cursor: row.get(7),
            status,
            outcome,
            opened_at_ms: row.get(10),
            closed_at_ms: row.get(11),
            reason: row.get(12),
        },
        result_json: row.get(13),
    })
}

fn parse_stored_result(stored: &StoredBatch) -> Result<SourceBatchResult, ApplyError> {
    if stored.transaction.status != SourceBatchStatus::Committed || stored.result_json.is_empty() {
        return Err(ApplyError::storage(
            "committed source batch is missing its stored result",
        ));
    }
    serde_json::from_str(&stored.result_json).map_err(|error| {
        ApplyError::storage(format!("invalid stored source batch result: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_seeds_are_stable_and_distinct() {
        assert_eq!(SOURCE_LOCK_SEED, 665);
        assert_eq!(IDEMPOTENCY_LOCK_SEED, 666);
        assert_ne!(SOURCE_LOCK_SEED, IDEMPOTENCY_LOCK_SEED);
    }
}
