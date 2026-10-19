//! Lease records, site pins, and guarded-mutation digests.
//!
//! The rusqlite host stays in the plane.

use sekai_domain::domain::Object;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

/// Default single-region site pin (`SEKAI_SITE_ID` default).
pub const DEFAULT_SITE_ID: &str = "local";
pub const OBJECT_CHANGED_SINCE_AUTHORIZATION: &str = "object changed since authorization";

fn default_site_id() -> String {
    DEFAULT_SITE_ID.into()
}

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
    /// Region/site pin. Acquire stamps the caller's site; refresh, release, and
    /// takeover require a matching pin and fail closed on foreign sites (#293).
    #[serde(default = "default_site_id")]
    pub site_id: String,
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

pub fn validate(
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

pub fn object_state_matches(left: &Object, right: &Object) -> bool {
    left.id == right.id
        && left.kind == right.kind
        && left.name == right.name
        && left.namespace == right.namespace
        && left.external_id == right.external_id
        && left.properties == right.properties
        && left.created == right.created
        && left.updated == right.updated
}

pub fn guarded_mutation_digest(
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

pub fn canonical_object_input(object: &Object) -> Result<String, LeaseError> {
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
pub fn validate_text(value: &str, name: &str) -> Result<(), LeaseError> {
    if value.trim().is_empty() || value.len() > 512 || value.contains('\0') {
        return Err(LeaseError::Invalid(format!("{name} is invalid")));
    }
    Ok(())
}
pub fn checked_expiry(now: i64, ttl: i64) -> Result<i64, LeaseError> {
    now.checked_add(ttl)
        .ok_or_else(|| LeaseError::Invalid("lease expiry overflows".into()))
}
pub fn new_lease(
    namespace: &str,
    key: &str,
    owner: &str,
    generation: u64,
    ttl: i64,
    now: i64,
    site_id: &str,
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
        site_id: site_id.into(),
    }
}
pub fn storage(error: impl std::fmt::Display) -> LeaseError {
    LeaseError::Storage(error.to_string())
}

/// Fail closed when the caller site does not match the durable lease pin.
pub fn require_site_pin(lease: &Lease, site_id: &str) -> Result<(), LeaseError> {
    if lease.site_id != site_id {
        return Err(LeaseError::Conflict(format!(
            "lease is pinned to site '{}' (caller site '{}'); foreign pin fail closed",
            lease.site_id, site_id
        )));
    }
    Ok(())
}
