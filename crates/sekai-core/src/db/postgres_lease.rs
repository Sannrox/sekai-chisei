use crate::db::postgres::PostgresDb;
use crate::sekai::lease::{Lease, LeaseError};
use sha2::{Digest, Sha256};

const MAX_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

impl PostgresDb {
    #[allow(clippy::too_many_arguments)]
    pub fn acquire_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        validate(namespace, key, owner, ttl_ms, request_id)?;
        let site_id = crate::sekai::lease::validate_site_id_public(site_id)?;
        let digest = digest(&[owner, &ttl_ms.to_string(), &site_id]);
        self.mutate_lease(
            namespace,
            key,
            request_id,
            "acquire",
            &digest,
            actor,
            now_ms,
            |_, previous| {
                if previous
                    .as_ref()
                    .is_some_and(|lease| lease.status == "active")
                {
                    return Err(LeaseError::Conflict("lease is already active".into()));
                }
                let generation = previous.as_ref().map_or(1, |lease| lease.generation + 1);
                new_lease(namespace, key, owner, generation, ttl_ms, now_ms, &site_id)
            },
        )
    }

    pub fn get_lease(&self, namespace: &str, key: &str) -> Result<Option<Lease>, LeaseError> {
        validate_text(namespace, "namespace")?;
        validate_text(key, "key")?;
        self.connection()
            .map_err(storage)?
            .query_opt(
                "SELECT namespace,lease_key,generation,fencing_token,owner,status,
                        acquired_at_ms,refreshed_at_ms,expires_at_ms,released_at_ms,site_id
                 FROM sekai_leases WHERE namespace=$1 AND lease_key=$2",
                &[&namespace, &key],
            )
            .map(|row| row.map(row_to_lease))
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
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        validate(namespace, key, token, ttl_ms, request_id)?;
        let site_id = crate::sekai::lease::validate_site_id_public(site_id)?;
        let digest = digest(&[token, &ttl_ms.to_string(), &site_id]);
        self.mutate_lease(
            namespace,
            key,
            request_id,
            "refresh",
            &digest,
            actor,
            now_ms,
            |_, previous| {
                let mut lease = active_with_token(previous, token)?;
                crate::sekai::lease::require_site_pin(&lease, &site_id)?;
                if now_ms >= lease.expires_at_ms {
                    return Err(LeaseError::Stale("lease has expired".into()));
                }
                lease.refreshed_at_ms = now_ms;
                lease.expires_at_ms = checked_expiry(now_ms, ttl_ms)?;
                Ok(lease)
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn release_lease(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        validate_text(namespace, "namespace")?;
        validate_text(key, "key")?;
        validate_text(token, "fencing_token")?;
        validate_text(request_id, "request_id")?;
        let site_id = crate::sekai::lease::validate_site_id_public(site_id)?;
        let digest = digest(&[token, &site_id]);
        self.mutate_lease(
            namespace,
            key,
            request_id,
            "release",
            &digest,
            actor,
            now_ms,
            |_, previous| {
                let mut lease = active_with_token(previous, token)?;
                crate::sekai::lease::require_site_pin(&lease, &site_id)?;
                lease.status = "released".into();
                lease.released_at_ms = now_ms;
                Ok(lease)
            },
        )
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
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        validate(namespace, key, owner, ttl_ms, request_id)?;
        validate_text(expected_token, "expected_fencing_token")?;
        let site_id = crate::sekai::lease::validate_site_id_public(site_id)?;
        let digest = digest(&[
            owner,
            expected_token,
            &expected_expires_at_ms.to_string(),
            &ttl_ms.to_string(),
            &site_id,
        ]);
        self.mutate_lease(
            namespace,
            key,
            request_id,
            "takeover",
            &digest,
            actor,
            now_ms,
            |_, previous| {
                let previous = active_with_token(previous, expected_token)?;
                crate::sekai::lease::require_site_pin(&previous, &site_id)?;
                if previous.expires_at_ms != expected_expires_at_ms {
                    return Err(LeaseError::Stale("lease expiry changed".into()));
                }
                if now_ms < previous.expires_at_ms {
                    return Err(LeaseError::NotExpired);
                }
                new_lease(
                    namespace,
                    key,
                    owner,
                    previous.generation + 1,
                    ttl_ms,
                    now_ms,
                    &site_id,
                )
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn mutate_lease<F>(
        &self,
        namespace: &str,
        key: &str,
        request_id: &str,
        operation: &str,
        request_digest: &str,
        actor: &str,
        now_ms: i64,
        mutation: F,
    ) -> Result<Lease, LeaseError>
    where
        F: FnOnce(&mut postgres::Transaction<'_>, Option<Lease>) -> Result<Lease, LeaseError>,
    {
        let mut connection = self.connection().map_err(storage)?;
        let mut transaction = connection.transaction().map_err(storage)?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 236))",
                &[&namespace, &key],
            )
            .map_err(storage)?;
        if let Some(row) = transaction
            .query_opt(
                "SELECT operation,request_digest,response_json
                 FROM sekai_lease_requests
                 WHERE namespace=$1 AND lease_key=$2 AND request_id=$3",
                &[&namespace, &key, &request_id],
            )
            .map_err(storage)?
        {
            let stored_operation: String = row.get(0);
            let stored_digest: String = row.get(1);
            if stored_operation != operation || stored_digest != request_digest {
                return Err(LeaseError::Conflict(
                    "request_id is already bound to different lease input".into(),
                ));
            }
            let response: String = row.get(2);
            return serde_json::from_str(&response).map_err(storage);
        }
        let previous = transaction
            .query_opt(
                "SELECT namespace,lease_key,generation,fencing_token,owner,status,
                        acquired_at_ms,refreshed_at_ms,expires_at_ms,released_at_ms,site_id
                 FROM sekai_leases
                 WHERE namespace=$1 AND lease_key=$2 FOR UPDATE",
                &[&namespace, &key],
            )
            .map_err(storage)?
            .map(row_to_lease);
        let lease = mutation(&mut transaction, previous.clone())?;
        let generation = i64::try_from(lease.generation)
            .map_err(|_| LeaseError::Invalid("lease generation overflow".into()))?;
        transaction
            .execute(
                "INSERT INTO sekai_leases
                    (namespace,lease_key,generation,fencing_token,owner,status,
                     acquired_at_ms,refreshed_at_ms,expires_at_ms,released_at_ms,site_id)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                 ON CONFLICT(namespace,lease_key) DO UPDATE SET
                    generation=EXCLUDED.generation,
                    fencing_token=EXCLUDED.fencing_token,
                    owner=EXCLUDED.owner,status=EXCLUDED.status,
                    acquired_at_ms=EXCLUDED.acquired_at_ms,
                    refreshed_at_ms=EXCLUDED.refreshed_at_ms,
                    expires_at_ms=EXCLUDED.expires_at_ms,
                    released_at_ms=EXCLUDED.released_at_ms,
                    site_id=EXCLUDED.site_id",
                &[
                    &lease.namespace,
                    &lease.key,
                    &generation,
                    &lease.fencing_token,
                    &lease.owner,
                    &lease.status,
                    &lease.acquired_at_ms,
                    &lease.refreshed_at_ms,
                    &lease.expires_at_ms,
                    &lease.released_at_ms,
                    &lease.site_id,
                ],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO sekai_lease_audit
                    (id,namespace,lease_key,generation,fencing_token,actor,operation,
                     timestamp_ms,previous_owner,owner,previous_expires_at_ms,
                     expires_at_ms,request_id)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
                &[
                    &format!("lease-audit-{}", uuid::Uuid::new_v4().simple()),
                    &namespace,
                    &key,
                    &generation,
                    &lease.fencing_token,
                    &actor,
                    &operation,
                    &now_ms,
                    &previous.as_ref().map_or("", |lease| lease.owner.as_str()),
                    &lease.owner,
                    &previous.as_ref().map_or(0, |lease| lease.expires_at_ms),
                    &lease.expires_at_ms,
                    &request_id,
                ],
            )
            .map_err(storage)?;
        let response = serde_json::to_string(&lease).map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO sekai_lease_requests
                    (namespace,lease_key,request_id,operation,request_digest,response_json,created_at_ms)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &namespace,
                    &key,
                    &request_id,
                    &operation,
                    &request_digest,
                    &response,
                    &now_ms,
                ],
            )
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        Ok(lease)
    }
}

fn active_with_token(previous: Option<Lease>, token: &str) -> Result<Lease, LeaseError> {
    let lease = previous.ok_or_else(|| LeaseError::Stale("lease does not exist".into()))?;
    if lease.status != "active" || lease.fencing_token != token {
        return Err(LeaseError::Stale(
            "fencing token does not identify the active lease".into(),
        ));
    }
    Ok(lease)
}

fn new_lease(
    namespace: &str,
    key: &str,
    owner: &str,
    generation: u64,
    ttl_ms: i64,
    now_ms: i64,
    site_id: &str,
) -> Result<Lease, LeaseError> {
    Ok(Lease {
        namespace: namespace.into(),
        key: key.into(),
        generation,
        fencing_token: uuid::Uuid::new_v4().to_string(),
        owner: owner.into(),
        status: "active".into(),
        acquired_at_ms: now_ms,
        refreshed_at_ms: now_ms,
        expires_at_ms: checked_expiry(now_ms, ttl_ms)?,
        released_at_ms: 0,
        site_id: site_id.into(),
    })
}

fn checked_expiry(now_ms: i64, ttl_ms: i64) -> Result<i64, LeaseError> {
    now_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| LeaseError::Invalid("lease expiry overflow".into()))
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
    if !(1..=MAX_TTL_MS).contains(&ttl_ms) {
        return Err(LeaseError::Invalid(format!(
            "ttl_ms must be between 1 and {MAX_TTL_MS}"
        )));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<(), LeaseError> {
    if value.trim().is_empty() {
        Err(LeaseError::Invalid(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
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

fn digest(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn storage(error: impl ToString) -> LeaseError {
    LeaseError::Storage(error.to_string())
}
