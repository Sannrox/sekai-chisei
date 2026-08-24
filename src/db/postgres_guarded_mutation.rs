use crate::db::postgres::PostgresDb;
use crate::domain::Object;
use crate::sekai::audit::{ObjectChange, object_diff_changes};
use crate::sekai::lease::{
    Lease, LeaseError, canonical_object_input, guarded_mutation_digest, object_state_matches,
    validate_text,
};
use std::time::Instant;

const OBJECT_COLUMNS: &str = "id, kind, name, namespace, external_id, properties, created, updated";

impl PostgresDb {
    #[allow(clippy::too_many_arguments)]
    pub fn guarded_object_replay(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        operation: &str,
        target_id: &str,
        request_object: &Object,
    ) -> Result<Option<Object>, LeaseError> {
        validate_text(namespace, "namespace")?;
        validate_text(key, "key")?;
        validate_text(token, "fencing_token")?;
        validate_text(request_id, "request_id")?;
        let input_json = canonical_object_input(request_object)?;
        let digest = guarded_mutation_digest(operation, target_id, token, &input_json);
        let stored = self
            .connection()
            .map_err(storage)?
            .query_opt(
                "SELECT operation,target_id,request_digest,response_json
                 FROM sekai_guarded_object_mutations
                 WHERE lease_namespace=$1 AND lease_key=$2 AND request_id=$3",
                &[&namespace, &key, &request_id],
            )
            .map_err(storage)?;
        let Some(row) = stored else {
            return Ok(None);
        };
        let stored_operation: String = row.get(0);
        let stored_target: String = row.get(1);
        let stored_digest: String = row.get(2);
        let response: String = row.get(3);
        if stored_operation != operation || stored_target != target_id || stored_digest != digest {
            return Err(LeaseError::Conflict(
                "request_id is already bound to different guarded mutation input".into(),
            ));
        }
        serde_json::from_str(&response).map(Some).map_err(storage)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guarded_create_object(
        &self,
        object: &Object,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, LeaseError> {
        if object.id.starts_with("namespace:") && object.kind != "namespace" {
            return Err(LeaseError::Mutation(
                "namespace:* object IDs are reserved for namespace boundaries".into(),
            ));
        }
        if object.external_id.starts_with("namespace:") && object.kind != "namespace" {
            return Err(LeaseError::Mutation(
                "namespace:* external IDs are reserved for namespace boundaries".into(),
            ));
        }
        let input_json = canonical_object_input(object)?;
        self.guarded_object_mutation(
            namespace,
            key,
            token,
            request_id,
            "create",
            &object.id,
            &input_json,
            actor,
            now_ms,
            |tx, transaction_now_ms| {
                lock_object(tx, &object.id)?;
                let historical_changes: i64 = tx
                    .query_one(
                        "SELECT COUNT(*) FROM sekai_object_changes WHERE object_id=$1",
                        &[&object.id.as_str()],
                    )
                    .map_err(storage)?
                    .get(0);
                if historical_changes > 0 {
                    return Err(LeaseError::Mutation(
                        "object IDs with audit history cannot be reused".into(),
                    ));
                }
                let props =
                    crate::domain::storage_properties_json(&object.properties).map_err(storage)?;
                tx.execute(
                    "INSERT INTO sekai_objects
                        (id,kind,name,namespace,external_id,properties,created,updated)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                    &[
                        &object.id,
                        &object.kind,
                        &object.name,
                        &object.namespace,
                        &object.external_id,
                        &props,
                        &object.created,
                        &object.updated,
                    ],
                )
                .map_err(storage)?;
                insert_changes(
                    tx,
                    &object_diff_changes(actor, None, Some(object), transaction_now_ms),
                )?;
                Ok(object.clone())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guarded_update_object(
        &self,
        object: &Object,
        request_object: &Object,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, LeaseError> {
        if object.external_id.starts_with("namespace:") && object.kind != "namespace" {
            return Err(LeaseError::Mutation(
                "namespace:* external IDs are reserved for namespace boundaries".into(),
            ));
        }
        let input_json = canonical_object_input(request_object)?;
        self.guarded_object_mutation(
            namespace,
            key,
            token,
            request_id,
            "update",
            &object.id,
            &input_json,
            actor,
            now_ms,
            |tx, transaction_now_ms| {
                lock_object(tx, &object.id)?;
                let before = tx
                    .query_opt(
                        &format!(
                            "SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE id=$1 FOR UPDATE"
                        ),
                        &[&object.id.as_str()],
                    )
                    .map_err(storage)?
                    .map(row_to_object)
                    .transpose()?
                    .ok_or_else(|| LeaseError::Mutation("not found".into()))?;
                if !expected.is_some_and(|expected| object_state_matches(expected, &before)) {
                    return Err(LeaseError::Mutation(
                        "object changed since authorization".into(),
                    ));
                }
                if before.namespace != object.namespace {
                    return Err(LeaseError::Mutation("object namespace is immutable".into()));
                }
                if before.kind != object.kind {
                    return Err(LeaseError::Mutation(
                        "object kind changes require ontology validation unavailable on PostgreSQL"
                            .into(),
                    ));
                }
                let props =
                    crate::domain::storage_properties_json(&object.properties).map_err(storage)?;
                tx.execute(
                    "UPDATE sekai_objects SET
                        kind=$2,name=$3,namespace=$4,external_id=$5,properties=$6,updated=$7
                     WHERE id=$1",
                    &[
                        &object.id,
                        &object.kind,
                        &object.name,
                        &object.namespace,
                        &object.external_id,
                        &props,
                        &object.updated,
                    ],
                )
                .map_err(storage)?;
                insert_changes(
                    tx,
                    &object_diff_changes(actor, Some(&before), Some(object), transaction_now_ms),
                )?;
                Ok(object.clone())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guarded_delete_object(
        &self,
        object_id: &str,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), LeaseError> {
        let input_json = serde_json::to_string(object_id).map_err(storage)?;
        self.guarded_object_mutation(
            namespace,
            key,
            token,
            request_id,
            "delete",
            object_id,
            &input_json,
            actor,
            now_ms,
            |tx, transaction_now_ms| {
                lock_object(tx, object_id)?;
                let before = tx
                    .query_opt(
                        &format!(
                            "SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE id=$1 FOR UPDATE"
                        ),
                        &[&object_id],
                    )
                    .map_err(storage)?
                    .map(row_to_object)
                    .transpose()?
                    .ok_or_else(|| LeaseError::Mutation("not found".into()))?;
                if !expected.is_some_and(|expected| object_state_matches(expected, &before)) {
                    return Err(LeaseError::Mutation(
                        "object changed since authorization".into(),
                    ));
                }
                tx.execute(
                    "DELETE FROM sekai_links WHERE from_id=$1 OR to_id=$1",
                    &[&object_id],
                )
                .map_err(storage)?;
                tx.execute("DELETE FROM sekai_objects WHERE id=$1", &[&object_id])
                    .map_err(storage)?;
                insert_changes(
                    tx,
                    &object_diff_changes(actor, Some(&before), None, transaction_now_ms),
                )?;
                Ok(Object {
                    id: before.id,
                    kind: String::new(),
                    name: String::new(),
                    namespace: String::new(),
                    external_id: String::new(),
                    properties: Default::default(),
                    created: 0,
                    updated: 0,
                })
            },
        )
        .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    fn guarded_object_mutation<F>(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        operation: &str,
        target_id: &str,
        input_json: &str,
        actor: &str,
        now_ms: i64,
        mutation: F,
    ) -> Result<Object, LeaseError>
    where
        F: FnOnce(&mut postgres::Transaction<'_>, i64) -> Result<Object, LeaseError>,
    {
        validate_text(namespace, "namespace")?;
        validate_text(key, "key")?;
        validate_text(token, "fencing_token")?;
        validate_text(request_id, "request_id")?;
        let digest = guarded_mutation_digest(operation, target_id, token, input_json);
        let lock_started = Instant::now();
        let mut connection = self.connection().map_err(storage)?;
        let mut tx = connection.transaction().map_err(storage)?;
        // Serialize with lease takeover/refresh on the same key so fencing is
        // ordered against generation changes.
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 236))",
            &[&namespace, &key],
        )
        .map_err(storage)?;
        let waited_ms = i64::try_from(lock_started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let transaction_now_ms = now_ms.saturating_add(waited_ms);
        if let Some(row) = tx
            .query_opt(
                "SELECT operation,target_id,request_digest,response_json
                 FROM sekai_guarded_object_mutations
                 WHERE lease_namespace=$1 AND lease_key=$2 AND request_id=$3",
                &[&namespace, &key, &request_id],
            )
            .map_err(storage)?
        {
            let stored_operation: String = row.get(0);
            let stored_target: String = row.get(1);
            let stored_digest: String = row.get(2);
            let response: String = row.get(3);
            if stored_operation != operation
                || stored_target != target_id
                || stored_digest != digest
            {
                return Err(LeaseError::Conflict(
                    "request_id is already bound to different guarded mutation input".into(),
                ));
            }
            return serde_json::from_str(&response).map_err(storage);
        }
        let lease = load_active_lease(&mut tx, namespace, key, token)?;
        if transaction_now_ms >= lease.expires_at_ms {
            return Err(LeaseError::Stale("lease has expired".into()));
        }
        let response = mutation(&mut tx, transaction_now_ms)?;
        let response_json = serde_json::to_string(&response).map_err(storage)?;
        let generation = i64::try_from(lease.generation)
            .map_err(|_| LeaseError::Storage("lease generation exceeds storage range".into()))?;
        tx.execute(
            "INSERT INTO sekai_guarded_object_mutations
                (lease_namespace,lease_key,request_id,operation,target_id,request_digest,
                 response_json,generation,actor,committed_at_ms)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[
                &namespace,
                &key,
                &request_id,
                &operation,
                &target_id,
                &digest,
                &response_json,
                &generation,
                &actor,
                &transaction_now_ms,
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(response)
    }
}

fn load_active_lease(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    key: &str,
    token: &str,
) -> Result<Lease, LeaseError> {
    let lease = tx
        .query_opt(
            "SELECT namespace,lease_key,generation,fencing_token,owner,status,
                    acquired_at_ms,refreshed_at_ms,expires_at_ms,released_at_ms,site_id
             FROM sekai_leases
             WHERE namespace=$1 AND lease_key=$2 FOR UPDATE",
            &[&namespace, &key],
        )
        .map_err(storage)?
        .map(row_to_lease)
        .ok_or_else(|| LeaseError::Stale("lease does not exist".into()))?;
    if lease.status != "active" || lease.fencing_token != token {
        return Err(LeaseError::Stale(
            "fencing token does not identify the active lease".into(),
        ));
    }
    Ok(lease)
}

fn lock_object(tx: &mut postgres::Transaction<'_>, object_id: &str) -> Result<(), LeaseError> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 235))",
        &[&object_id],
    )
    .map(|_| ())
    .map_err(storage)
}

fn insert_changes(
    tx: &mut postgres::Transaction<'_>,
    changes: &[ObjectChange],
) -> Result<(), LeaseError> {
    for change in changes {
        tx.execute(
            "INSERT INTO sekai_object_changes
                (id, object_id, field, old_value, new_value, changed_by, timestamp)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &change.id,
                &change.object_id,
                &change.field,
                &change.old_value,
                &change.new_value,
                &change.changed_by,
                &change.timestamp,
            ],
        )
        .map_err(storage)?;
    }
    Ok(())
}

fn row_to_object(row: postgres::Row) -> Result<Object, LeaseError> {
    let properties_json: String = row.get(5);
    Ok(Object {
        id: row.get(0),
        kind: row.get(1),
        name: row.get(2),
        namespace: row.get(3),
        external_id: row.get(4),
        properties: serde_json::from_str(&properties_json)
            .map_err(|error| LeaseError::Storage(format!("invalid object properties: {error}")))?,
        created: row.get(6),
        updated: row.get(7),
    })
}

fn row_to_lease(row: postgres::Row) -> Lease {
    let generation: i64 = row.get(2);
    let site_id: String = row
        .try_get::<_, String>(10)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| crate::sekai::lease::DEFAULT_SITE_ID.into());
    Lease {
        namespace: row.get(0),
        key: row.get(1),
        generation: u64::try_from(generation).unwrap_or_default(),
        fencing_token: row.get(3),
        owner: row.get(4),
        status: row.get(5),
        acquired_at_ms: row.get(6),
        refreshed_at_ms: row.get(7),
        expires_at_ms: row.get(8),
        released_at_ms: row.get(9),
        site_id,
    }
}

fn storage(error: impl ToString) -> LeaseError {
    LeaseError::Storage(error.to_string())
}
