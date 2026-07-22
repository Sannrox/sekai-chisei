use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

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
                    ON sekai_lease_audit(namespace, lease_key, timestamp_ms, id);",
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
    use std::sync::{Arc, Barrier};
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
}
