use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Instant;

const MAX_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub namespace: String,
    pub key: String,
    pub generation: u64,
    pub fencing_token: String,
    pub owner: String,
    pub status: String,
    pub acquired_at_ms: i64,
    pub refreshed_at_ms: i64,
    pub expires_at_ms: i64,
    pub released_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    Invalid(String),
    Conflict(String),
    Stale(String),
    NotExpired,
    Storage(String),
    Mutation(String),
}

impl SekaiDb {
    pub(crate) fn migrate_leases(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_leases (
                    namespace TEXT NOT NULL, lease_key TEXT NOT NULL,
                    generation INTEGER NOT NULL, fencing_token TEXT NOT NULL UNIQUE,
                    owner TEXT NOT NULL, status TEXT NOT NULL,
                    acquired_at_ms INTEGER NOT NULL, refreshed_at_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER NOT NULL, released_at_ms INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(namespace, lease_key)
                );
                CREATE TABLE IF NOT EXISTS sekai_lease_requests (
                    namespace TEXT NOT NULL, lease_key TEXT NOT NULL,
                    request_id TEXT NOT NULL, operation TEXT NOT NULL,
                    request_digest TEXT NOT NULL, response_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, lease_key, request_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_lease_audit (
                    id TEXT PRIMARY KEY, namespace TEXT NOT NULL, lease_key TEXT NOT NULL,
                    generation INTEGER NOT NULL, fencing_token TEXT NOT NULL,
                    actor TEXT NOT NULL, operation TEXT NOT NULL, timestamp_ms INTEGER NOT NULL,
                    previous_owner TEXT NOT NULL, owner TEXT NOT NULL,
                    previous_expires_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL,
                    request_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sekai_lease_audit_key
                    ON sekai_lease_audit(namespace, lease_key, timestamp_ms, id);
                CREATE TABLE IF NOT EXISTS sekai_guarded_object_mutations (
                    lease_namespace TEXT NOT NULL, lease_key TEXT NOT NULL,
                    request_id TEXT NOT NULL, operation TEXT NOT NULL,
                    target_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                    response_json TEXT NOT NULL, generation INTEGER NOT NULL,
                    actor TEXT NOT NULL, committed_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(lease_namespace, lease_key, request_id)
                );",
            )
            .map_err(|error| error.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn acquire_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        validate(namespace, key, owner, ttl_ms, request_id)?;
        self.mutate_lease(
            namespace,
            key,
            request_id,
            "acquire",
            &format!("{owner}\0{ttl_ms}"),
            |tx| {
                let previous = read_lease(tx, namespace, key)?;
                if previous
                    .as_ref()
                    .is_some_and(|lease| lease.status == "active")
                {
                    return Err(LeaseError::Conflict("lease is already active".into()));
                }
                let generation = previous.as_ref().map_or(1, |lease| lease.generation + 1);
                let lease = new_lease(namespace, key, owner, generation, ttl_ms, now_ms);
                if previous.is_some() {
                    update_lease(tx, &lease)?;
                } else {
                    insert_lease(tx, &lease)?;
                }
                insert_audit(
                    tx,
                    previous.as_ref(),
                    &lease,
                    actor,
                    "acquire",
                    request_id,
                    now_ms,
                )?;
                Ok(lease)
            },
        )
    }

    pub fn get_lease(&self, namespace: &str, key: &str) -> Result<Option<Lease>, LeaseError> {
        validate_text(namespace, "namespace")?;
        validate_text(key, "key")?;
        self.conn()
            .query_row(
                "SELECT namespace,lease_key,generation,fencing_token,owner,status,acquired_at_ms,refreshed_at_ms,expires_at_ms,released_at_ms FROM sekai_leases WHERE namespace=?1 AND lease_key=?2",
                params![namespace, key],
                row_to_lease,
            )
            .optional()
            .map_err(storage)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn refresh_lease(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        validate(namespace, key, token, ttl_ms, request_id)?;
        self.mutate_lease(
            namespace,
            key,
            request_id,
            "refresh",
            &format!("{token}\0{ttl_ms}"),
            |tx| {
                let previous = active_with_token(tx, namespace, key, token)?;
                if now_ms >= previous.expires_at_ms {
                    return Err(LeaseError::Stale("lease has expired".into()));
                }
                let mut lease = previous.clone();
                lease.refreshed_at_ms = now_ms;
                lease.expires_at_ms = checked_expiry(now_ms, ttl_ms)?;
                update_lease(tx, &lease)?;
                insert_audit(
                    tx,
                    Some(&previous),
                    &lease,
                    actor,
                    "refresh",
                    request_id,
                    now_ms,
                )?;
                Ok(lease)
            },
        )
    }

    pub fn release_lease(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        validate_text(namespace, "namespace")?;
        validate_text(key, "key")?;
        validate_text(token, "fencing_token")?;
        validate_text(request_id, "request_id")?;
        self.mutate_lease(namespace, key, request_id, "release", token, |tx| {
            let previous = active_with_token(tx, namespace, key, token)?;
            let mut lease = previous.clone();
            lease.status = "released".into();
            lease.released_at_ms = now_ms;
            update_lease(tx, &lease)?;
            insert_audit(
                tx,
                Some(&previous),
                &lease,
                actor,
                "release",
                request_id,
                now_ms,
            )?;
            Ok(lease)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn takeover_expired_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at_ms: i64,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        validate(namespace, key, owner, ttl_ms, request_id)?;
        validate_text(expected_token, "expected_fencing_token")?;
        let digest = format!("{owner}\0{expected_token}\0{expected_expires_at_ms}\0{ttl_ms}");
        self.mutate_lease(namespace, key, request_id, "takeover", &digest, |tx| {
            let previous = active_with_token(tx, namespace, key, expected_token)?;
            if previous.expires_at_ms != expected_expires_at_ms {
                return Err(LeaseError::Stale("lease expiry changed".into()));
            }
            if now_ms < previous.expires_at_ms {
                return Err(LeaseError::NotExpired);
            }
            let lease = new_lease(
                namespace,
                key,
                owner,
                previous.generation + 1,
                ttl_ms,
                now_ms,
            );
            update_lease(tx, &lease)?;
            insert_audit(
                tx,
                Some(&previous),
                &lease,
                actor,
                "takeover",
                request_id,
                now_ms,
            )?;
            Ok(lease)
        })
    }

    fn mutate_lease<F>(
        &self,
        namespace: &str,
        key: &str,
        request_id: &str,
        operation: &str,
        digest: &str,
        mutation: F,
    ) -> Result<Lease, LeaseError>
    where
        F: FnOnce(&Transaction<'_>) -> Result<Lease, LeaseError>,
    {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if let Some((stored_op, stored_digest, response)) = tx.query_row(
            "SELECT operation,request_digest,response_json FROM sekai_lease_requests WHERE namespace=?1 AND lease_key=?2 AND request_id=?3",
            params![namespace,key,request_id], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)),
        ).optional().map_err(storage)? {
            if stored_op != operation || stored_digest != digest { return Err(LeaseError::Conflict("request_id is already bound to different lease input".into())); }
            return serde_json::from_str(&response).map_err(storage);
        }
        let lease = mutation(&tx)?;
        let response = serde_json::to_string(&lease).map_err(storage)?;
        tx.execute("INSERT INTO sekai_lease_requests(namespace,lease_key,request_id,operation,request_digest,response_json,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![namespace,key,request_id,operation,digest,response,lease.refreshed_at_ms]).map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(lease)
    }

    pub fn lease_audit_count(&self, namespace: &str, key: &str) -> Result<u64, String> {
        let count: i64 = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_lease_audit WHERE namespace=?1 AND lease_key=?2",
                params![namespace, key],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        Ok(count as u64)
    }

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
        let stored = self.conn().query_row(
            "SELECT operation,target_id,request_digest,response_json FROM sekai_guarded_object_mutations WHERE lease_namespace=?1 AND lease_key=?2 AND request_id=?3",
            params![namespace,key,request_id], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?)),
        ).optional().map_err(storage)?;
        let Some((stored_operation, stored_target, stored_digest, response)) = stored else {
            return Ok(None);
        };
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
            namespace, key, token, request_id, "create", &object.id, &input_json, actor, now_ms,
            |tx, transaction_now_ms| {
                let historical_changes: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM sekai_object_changes WHERE object_id=?1",
                    params![object.id], |row| row.get(0),
                ).map_err(storage)?;
                if historical_changes > 0 {
                    return Err(LeaseError::Mutation("object IDs with audit history cannot be reused".into()));
                }
                let props = serde_json::to_string(&object.properties).map_err(storage)?;
                tx.execute(
                    "INSERT INTO sekai_objects (id,kind,name,namespace,external_id,properties,created,updated) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![object.id,object.kind,object.name,object.namespace,object.external_id,props,object.created,object.updated],
                ).map_err(storage)?;
                crate::sekai::audit::insert_object_changes(tx, &crate::sekai::audit::object_diff_changes(actor, None, Some(object), transaction_now_ms)).map_err(LeaseError::Mutation)?;
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
            namespace, key, token, request_id, "update", &object.id, &input_json, actor, now_ms,
            |tx, transaction_now_ms| {
                let before = tx.query_row(
                    "SELECT id,kind,name,namespace,external_id,properties,created,updated FROM sekai_objects WHERE id=?1",
                    params![object.id], crate::db::sekai::row_to_object,
                ).optional().map_err(storage)?.ok_or_else(|| LeaseError::Mutation("not found".into()))?;
                if !expected.is_some_and(|expected| object_state_matches(expected, &before)) {
                    return Err(LeaseError::Mutation(
                        "object changed since authorization".into(),
                    ));
                }
                if before.namespace != object.namespace { return Err(LeaseError::Mutation("object namespace is immutable".into())); }
                if before.kind != object.kind {
                    crate::sekai::ontology::validate_object_kind_change(tx, &object.id, &object.kind).map_err(LeaseError::Mutation)?;
                }
                let props = serde_json::to_string(&object.properties).map_err(storage)?;
                tx.execute(
                    "UPDATE sekai_objects SET kind=?2,name=?3,namespace=?4,external_id=?5,properties=?6,updated=?7 WHERE id=?1",
                    params![object.id,object.kind,object.name,object.namespace,object.external_id,props,object.updated],
                ).map_err(storage)?;
                crate::sekai::audit::insert_object_changes(tx, &crate::sekai::audit::object_diff_changes(actor, Some(&before), Some(object), transaction_now_ms)).map_err(LeaseError::Mutation)?;
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
            namespace, key, token, request_id, "delete", object_id, &input_json, actor, now_ms,
            |tx, transaction_now_ms| {
                let before = tx.query_row(
                    "SELECT id,kind,name,namespace,external_id,properties,created,updated FROM sekai_objects WHERE id=?1",
                    params![object_id], crate::db::sekai::row_to_object,
                ).optional().map_err(storage)?.ok_or_else(|| LeaseError::Mutation("not found".into()))?;
                if !expected.is_some_and(|expected| object_state_matches(expected, &before)) {
                    return Err(LeaseError::Mutation(
                        "object changed since authorization".into(),
                    ));
                }
                tx.execute("DELETE FROM sekai_objects WHERE id=?1", params![object_id]).map_err(storage)?;
                tx.execute("DELETE FROM sekai_links WHERE from_id=?1 OR to_id=?1", params![object_id]).map_err(storage)?;
                crate::sekai::audit::insert_object_changes(tx, &crate::sekai::audit::object_diff_changes(actor, Some(&before), None, transaction_now_ms)).map_err(LeaseError::Mutation)?;
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
        ).map(|_| ())
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
        F: FnOnce(&Transaction<'_>, i64) -> Result<Object, LeaseError>,
    {
        validate_text(namespace, "namespace")?;
        validate_text(key, "key")?;
        validate_text(token, "fencing_token")?;
        validate_text(request_id, "request_id")?;
        let digest = guarded_mutation_digest(operation, target_id, token, input_json);
        let lock_started = Instant::now();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let waited_ms = i64::try_from(lock_started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let transaction_now_ms = now_ms.saturating_add(waited_ms);
        if let Some((stored_operation, stored_target, stored_digest, response)) = tx.query_row(
            "SELECT operation,target_id,request_digest,response_json FROM sekai_guarded_object_mutations WHERE lease_namespace=?1 AND lease_key=?2 AND request_id=?3",
            params![namespace,key,request_id], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?)),
        ).optional().map_err(storage)? {
            if stored_operation != operation || stored_target != target_id || stored_digest != digest {
                return Err(LeaseError::Conflict("request_id is already bound to different guarded mutation input".into()));
            }
            return serde_json::from_str(&response).map_err(storage);
        }
        let lease = active_with_token(&tx, namespace, key, token)?;
        if transaction_now_ms >= lease.expires_at_ms {
            return Err(LeaseError::Stale("lease has expired".into()));
        }
        let response = mutation(&tx, transaction_now_ms)?;
        let response_json = serde_json::to_string(&response).map_err(storage)?;
        let generation = i64::try_from(lease.generation)
            .map_err(|_| LeaseError::Storage("lease generation exceeds SQLite range".into()))?;
        tx.execute(
            "INSERT INTO sekai_guarded_object_mutations(lease_namespace,lease_key,request_id,operation,target_id,request_digest,response_json,generation,actor,committed_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![namespace,key,request_id,operation,target_id,digest,response_json,generation,actor,transaction_now_ms],
        ).map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(response)
    }
}

fn validate(
    namespace: &str,
    key: &str,
    owner: &str,
    ttl_ms: i64,
    request_id: &str,
) -> Result<(), LeaseError> {
    validate_text(namespace, "namespace")?;
    validate_text(key, "key")?;
    validate_text(owner, "owner")?;
    validate_text(request_id, "request_id")?;
    if ttl_ms <= 0 || ttl_ms > MAX_TTL_MS {
        return Err(LeaseError::Invalid(format!(
            "ttl_ms must be between 1 and {MAX_TTL_MS}"
        )));
    }
    checked_expiry(0, ttl_ms)?;
    Ok(())
}

fn object_state_matches(left: &Object, right: &Object) -> bool {
    left.id == right.id
        && left.kind == right.kind
        && left.name == right.name
        && left.namespace == right.namespace
        && left.external_id == right.external_id
        && left.properties == right.properties
        && left.created == right.created
        && left.updated == right.updated
}

fn guarded_mutation_digest(
    operation: &str,
    target_id: &str,
    token: &str,
    input_json: &str,
) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{operation}\0{target_id}\0{token}\0{input_json}").as_bytes())
    )
}

fn canonical_object_input(object: &Object) -> Result<String, LeaseError> {
    let properties = object.properties.iter().collect::<BTreeMap<_, _>>();
    serde_json::to_string(&(
        &object.id,
        &object.kind,
        &object.name,
        &object.namespace,
        &object.external_id,
        properties,
        object.created,
        object.updated,
    ))
    .map_err(storage)
}
fn validate_text(value: &str, name: &str) -> Result<(), LeaseError> {
    if value.trim().is_empty() || value.len() > 512 || value.contains('\0') {
        return Err(LeaseError::Invalid(format!("{name} is invalid")));
    }
    Ok(())
}
fn checked_expiry(now: i64, ttl: i64) -> Result<i64, LeaseError> {
    now.checked_add(ttl)
        .ok_or_else(|| LeaseError::Invalid("lease expiry overflows".into()))
}
fn new_lease(
    namespace: &str,
    key: &str,
    owner: &str,
    generation: u64,
    ttl: i64,
    now: i64,
) -> Lease {
    Lease {
        namespace: namespace.into(),
        key: key.into(),
        generation,
        fencing_token: uuid::Uuid::new_v4().to_string(),
        owner: owner.into(),
        status: "active".into(),
        acquired_at_ms: now,
        refreshed_at_ms: now,
        expires_at_ms: now + ttl,
        released_at_ms: 0,
    }
}
fn storage(error: impl std::fmt::Display) -> LeaseError {
    LeaseError::Storage(error.to_string())
}
fn read_lease(
    tx: &Transaction<'_>,
    namespace: &str,
    key: &str,
) -> Result<Option<Lease>, LeaseError> {
    tx.query_row("SELECT namespace,lease_key,generation,fencing_token,owner,status,acquired_at_ms,refreshed_at_ms,expires_at_ms,released_at_ms FROM sekai_leases WHERE namespace=?1 AND lease_key=?2", params![namespace,key], row_to_lease).optional().map_err(storage)
}
fn row_to_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<Lease> {
    Ok(Lease {
        namespace: row.get(0)?,
        key: row.get(1)?,
        generation: row.get::<_, i64>(2)? as u64,
        fencing_token: row.get(3)?,
        owner: row.get(4)?,
        status: row.get(5)?,
        acquired_at_ms: row.get(6)?,
        refreshed_at_ms: row.get(7)?,
        expires_at_ms: row.get(8)?,
        released_at_ms: row.get(9)?,
    })
}
fn active_with_token(
    tx: &Transaction<'_>,
    namespace: &str,
    key: &str,
    token: &str,
) -> Result<Lease, LeaseError> {
    let lease = read_lease(tx, namespace, key)?
        .ok_or_else(|| LeaseError::Stale("lease generation is not active".into()))?;
    if lease.status != "active" || lease.fencing_token != token {
        return Err(LeaseError::Stale("lease generation is not active".into()));
    }
    Ok(lease)
}
fn insert_lease(tx: &Transaction<'_>, lease: &Lease) -> Result<(), LeaseError> {
    let generation = i64::try_from(lease.generation)
        .map_err(|_| LeaseError::Storage("lease generation exceeds SQLite range".into()))?;
    tx.execute("INSERT INTO sekai_leases(namespace,lease_key,generation,fencing_token,owner,status,acquired_at_ms,refreshed_at_ms,expires_at_ms,released_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![lease.namespace,lease.key,generation,lease.fencing_token,lease.owner,lease.status,lease.acquired_at_ms,lease.refreshed_at_ms,lease.expires_at_ms,lease.released_at_ms]).map_err(storage)?;
    Ok(())
}
fn update_lease(tx: &Transaction<'_>, lease: &Lease) -> Result<(), LeaseError> {
    let generation = i64::try_from(lease.generation)
        .map_err(|_| LeaseError::Storage("lease generation exceeds SQLite range".into()))?;
    tx.execute("UPDATE sekai_leases SET generation=?3,fencing_token=?4,owner=?5,status=?6,acquired_at_ms=?7,refreshed_at_ms=?8,expires_at_ms=?9,released_at_ms=?10 WHERE namespace=?1 AND lease_key=?2", params![lease.namespace,lease.key,generation,lease.fencing_token,lease.owner,lease.status,lease.acquired_at_ms,lease.refreshed_at_ms,lease.expires_at_ms,lease.released_at_ms]).map_err(storage)?;
    Ok(())
}
fn insert_audit(
    tx: &Transaction<'_>,
    before: Option<&Lease>,
    after: &Lease,
    actor: &str,
    operation: &str,
    request_id: &str,
    now: i64,
) -> Result<(), LeaseError> {
    let generation = i64::try_from(after.generation)
        .map_err(|_| LeaseError::Storage("lease generation exceeds SQLite range".into()))?;
    tx.execute("INSERT INTO sekai_lease_audit(id,namespace,lease_key,generation,fencing_token,actor,operation,timestamp_ms,previous_owner,owner,previous_expires_at_ms,expires_at_ms,request_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)", params![uuid::Uuid::new_v4().to_string(),after.namespace,after.key,generation,after.fencing_token,actor,operation,now,before.map(|v|v.owner.as_str()).unwrap_or(""),after.owner,before.map(|v|v.expires_at_ms).unwrap_or(0),after.expires_at_ms,request_id]).map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Barrier};

    fn object(id: &str, name: &str) -> Object {
        Object {
            id: id.into(),
            kind: "component".into(),
            name: name.into(),
            namespace: "n".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        }
    }
    #[test]
    fn release_reacquire_and_stale_generation_are_fenced() {
        let db = SekaiDb::new(":memory:").unwrap();
        let first = db
            .acquire_lease("n", "deploy", "a", 100, "a1", "a", 10)
            .unwrap();
        db.release_lease("n", "deploy", &first.fencing_token, "r1", "a", 20)
            .unwrap();
        let second = db
            .acquire_lease("n", "deploy", "b", 100, "a2", "b", 30)
            .unwrap();
        assert_eq!(second.generation, 2);
        assert!(matches!(
            db.refresh_lease("n", "deploy", &first.fencing_token, 100, "late", "a", 40),
            Err(LeaseError::Stale(_))
        ));
        assert!(matches!(
            db.release_lease("n", "deploy", &first.fencing_token, "later", "a", 50),
            Err(LeaseError::Stale(_))
        ));
        assert_eq!(db.lease_audit_count("n", "deploy").unwrap(), 3);
    }
    #[test]
    fn expiry_boundary_takeover_and_retry_are_deterministic() {
        let db = SekaiDb::new(":memory:").unwrap();
        let first = db
            .acquire_lease("n", "k", "a", 10, "one", "a", 100)
            .unwrap();
        assert_eq!(
            db.takeover_expired_lease(
                "n",
                "k",
                "b",
                &first.fencing_token,
                110,
                10,
                "two",
                "b",
                109
            ),
            Err(LeaseError::NotExpired)
        );
        let second = db
            .takeover_expired_lease(
                "n",
                "k",
                "b",
                &first.fencing_token,
                110,
                10,
                "two",
                "b",
                110,
            )
            .unwrap();
        let replay = db
            .takeover_expired_lease(
                "n",
                "k",
                "b",
                &first.fencing_token,
                110,
                10,
                "two",
                "b",
                999,
            )
            .unwrap();
        assert_eq!(second, replay);
    }

    #[test]
    fn retry_survives_process_restart_without_a_duplicate_generation() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().into_owned();
        let first = SekaiDb::new(&path)
            .unwrap()
            .acquire_lease("n", "k", "a", 100, "request", "a", 10)
            .unwrap();
        let replay = SekaiDb::new(&path)
            .unwrap()
            .acquire_lease("n", "k", "a", 100, "request", "a", 999)
            .unwrap();
        assert_eq!(first, replay);
    }

    #[test]
    fn concurrent_acquire_has_exactly_one_winner() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Arc::new(SekaiDb::new(file.path().to_str().unwrap()).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let handles = ["a", "b"].map(|owner| {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                db.acquire_lease("n", "k", owner, 100, owner, owner, 10)
            })
        });
        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(LeaseError::Conflict(_))))
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_takeover_has_exactly_one_winner() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Arc::new(SekaiDb::new(file.path().to_str().unwrap()).unwrap());
        let first = db
            .acquire_lease("n", "k", "a", 10, "first", "a", 10)
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles = ["b", "c"].map(|owner| {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            let token = first.fencing_token.clone();
            std::thread::spawn(move || {
                barrier.wait();
                db.takeover_expired_lease("n", "k", owner, &token, 20, 100, owner, owner, 20)
            })
        });
        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(LeaseError::Stale(_))))
                .count(),
            1
        );
    }

    #[test]
    fn guarded_mutations_fence_stale_released_and_expired_generations() {
        let db = SekaiDb::new(":memory:").unwrap();
        let first = db
            .acquire_lease("n", "k", "a", 10, "lease-1", "a", 10)
            .unwrap();
        let original = object("o", "original");
        db.guarded_create_object(&original, "n", "k", &first.fencing_token, "create", "a", 11)
            .unwrap();

        let mut expired_update = original.clone();
        expired_update.name = "expired".into();
        assert!(matches!(
            db.guarded_update_object(
                &expired_update,
                &expired_update,
                Some(&original),
                "n",
                "k",
                &first.fencing_token,
                "expired-update",
                "a",
                20
            ),
            Err(LeaseError::Stale(_))
        ));
        let second = db
            .takeover_expired_lease(
                "n",
                "k",
                "b",
                &first.fencing_token,
                20,
                10,
                "lease-2",
                "b",
                20,
            )
            .unwrap();
        assert!(matches!(
            db.guarded_delete_object(
                "o",
                Some(&original),
                "n",
                "k",
                &first.fencing_token,
                "stale-delete",
                "a",
                21
            ),
            Err(LeaseError::Stale(_))
        ));
        db.release_lease("n", "k", &second.fencing_token, "release", "b", 22)
            .unwrap();
        assert!(matches!(
            db.guarded_update_object(
                &expired_update,
                &expired_update,
                Some(&original),
                "n",
                "k",
                &second.fencing_token,
                "released-update",
                "b",
                23
            ),
            Err(LeaseError::Stale(_))
        ));
        assert_eq!(db.get_object("o").unwrap().unwrap().name, "original");
    }

    #[test]
    fn guarded_delete_retry_is_idempotent_and_audits_generation_without_token() {
        let db = SekaiDb::new(":memory:").unwrap();
        let lease = db
            .acquire_lease("n", "k", "a", 100, "lease", "a", 10)
            .unwrap();
        let value = object("o", "value");
        db.guarded_create_object(&value, "n", "k", &lease.fencing_token, "create", "a", 11)
            .unwrap();
        let mut stale_authorization = value.clone();
        stale_authorization.name = "different".into();
        assert!(matches!(
            db.guarded_delete_object(
                "o",
                Some(&stale_authorization),
                "n",
                "k",
                &lease.fencing_token,
                "stale-authorization",
                "a",
                12,
            ),
            Err(LeaseError::Mutation(message)) if message == "object changed since authorization"
        ));
        db.guarded_delete_object(
            "o",
            Some(&value),
            "n",
            "k",
            &lease.fencing_token,
            "delete",
            "a",
            12,
        )
        .unwrap();
        db.guarded_delete_object(
            "o",
            None,
            "n",
            "k",
            &lease.fencing_token,
            "delete",
            "a",
            999,
        )
        .unwrap();
        let changes = db.list_object_changes("o", 100, 0).unwrap();
        assert_eq!(
            changes
                .iter()
                .filter(|change| change.field == "_created")
                .count(),
            1
        );
        assert_eq!(
            changes
                .iter()
                .filter(|change| change.field == "_deleted")
                .count(),
            1
        );
        let (generation, digest): (i64, String) = db.conn().query_row(
            "SELECT generation,request_digest FROM sekai_guarded_object_mutations WHERE request_id='delete'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(generation, 1);
        assert!(!digest.contains(&lease.fencing_token));
    }

    #[test]
    fn guarded_update_racing_takeover_has_one_serializable_order() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Arc::new(SekaiDb::new(file.path().to_str().unwrap()).unwrap());
        let first = db
            .acquire_lease("n", "k", "a", 10, "lease-1", "a", 10)
            .unwrap();
        db.create_object_with_audit(&object("o", "before"), "a")
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let update = {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            let token = first.fencing_token.clone();
            std::thread::spawn(move || {
                let value = object("o", "updated");
                barrier.wait();
                db.guarded_update_object(
                    &value,
                    &value,
                    Some(&object("o", "before")),
                    "n",
                    "k",
                    &token,
                    "update",
                    "a",
                    19,
                )
            })
        };
        let takeover = {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            let token = first.fencing_token.clone();
            std::thread::spawn(move || {
                barrier.wait();
                db.takeover_expired_lease("n", "k", "b", &token, 20, 10, "lease-2", "b", 20)
            })
        };
        let update_result = update.join().unwrap();
        let replacement = takeover.join().unwrap().unwrap();
        assert_eq!(replacement.generation, 2);
        match update_result {
            Ok(_) => assert_eq!(db.get_object("o").unwrap().unwrap().name, "updated"),
            Err(LeaseError::Stale(_)) => {
                assert_eq!(db.get_object("o").unwrap().unwrap().name, "before")
            }
            other => panic!("unexpected guarded update outcome: {other:?}"),
        }
    }

    #[test]
    fn guarded_update_binds_authorized_snapshot_and_replays_after_later_delete() {
        let db = SekaiDb::new(":memory:").unwrap();
        let lease = db
            .acquire_lease("n", "k", "a", 100, "lease", "a", 10)
            .unwrap();
        let original = object("o", "before");
        db.create_object_with_audit(&original, "a").unwrap();
        let intervening = object("o", "intervening");
        db.update_object_with_audit(&intervening, "other").unwrap();
        let intended = object("o", "intended");
        assert!(matches!(
            db.guarded_update_object(
                &intended,
                &intended,
                Some(&original),
                "n",
                "k",
                &lease.fencing_token,
                "stale-snapshot",
                "a",
                11,
            ),
            Err(LeaseError::Mutation(message)) if message == "object changed since authorization"
        ));
        let committed = db
            .guarded_update_object(
                &intended,
                &intended,
                Some(&intervening),
                "n",
                "k",
                &lease.fencing_token,
                "update",
                "a",
                12,
            )
            .unwrap();
        db.delete_object_with_audit("o", "other").unwrap();
        let replay = db
            .guarded_update_object(
                &intended,
                &intended,
                None,
                "n",
                "k",
                &lease.fencing_token,
                "update",
                "a",
                999,
            )
            .unwrap();
        assert_eq!(replay.name, committed.name);
        assert!(db.get_object("o").unwrap().is_none());
    }

    #[test]
    fn guarded_mutation_digest_is_stable_across_property_insertion_order() {
        let mut first = object("o", "value");
        first.properties.insert("alpha".into(), "1".into());
        first.properties.insert("beta".into(), "2".into());
        let mut second = object("o", "value");
        second.properties.insert("beta".into(), "2".into());
        second.properties.insert("alpha".into(), "1".into());
        assert_eq!(
            canonical_object_input(&first).unwrap(),
            canonical_object_input(&second).unwrap()
        );
    }
}
