//! Plane-held connector credential handles sealed to a runtime fleet key
//! (ADR 0175).
//!
//! The plane stores sealed slot bytes and a registered public key id. It
//! never sees plaintext. Issue is idempotent per handle name and content
//! digest. Revoke deletes sealed slots and keeps a tombstone so a name
//! defined both statically and on the plane stays ambiguous after revoke.

use std::collections::{BTreeSet, HashMap};

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;

pub const HANDLE_ISSUED: &str = "connector_credential_handle_issued";
pub const HANDLE_REVOKED: &str = "connector_credential_handle_revoked";
pub const FLEET_KEY_REGISTERED: &str = "runtime_fleet_key_registered";

const MAX_NAME: usize = 128;
const MAX_KEY_ID: usize = 64;
const PUBLIC_KEY_LEN: usize = 32;
const MAX_SLOT_NAME: usize = 64;
const MAX_SLOTS: usize = 16;
const MAX_BINDING: usize = 64;

/// One sealed slot as the plane stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSlot {
    pub name: String,
    pub fleet_key_id: String,
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
}

/// A plane-held handle, including a tombstone (`revoked`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialHandle {
    pub name: String,
    pub namespaces: Vec<String>,
    pub destinations: Vec<String>,
    pub fleet_key_id: String,
    pub slots: Vec<SealedSlot>,
    pub content_digest: String,
    pub issued_at_ms: i64,
    pub issued_by: String,
    pub revoked: bool,
    pub revoked_at_ms: i64,
    pub revoked_by: String,
}

/// The public half of a runtime fleet key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetKeyRecord {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub registered_at_ms: i64,
}

mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        BASE64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

fn token(value: &str, max: usize, what: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max {
        return Err(format!("{what} must be 1 to {max} bytes"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/'))
    {
        return Err(format!("{what} must match [A-Za-z0-9._/-]+"));
    }
    Ok(value.to_string())
}

fn parse_key_id(value: &str) -> Result<String, String> {
    let value = token(value, MAX_KEY_ID, "key_id")?;
    if value.contains('/') {
        return Err("key_id must match [A-Za-z0-9._-]+".into());
    }
    Ok(value)
}

fn binding_list(values: &[String], what: &str) -> Result<Vec<String>, String> {
    if values.is_empty() {
        return Err(format!("{what} required"));
    }
    if values.len() > MAX_BINDING {
        return Err(format!("{what} lists at most {MAX_BINDING} entries"));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let value = value.trim();
        if value.is_empty() || value.len() > MAX_NAME {
            return Err(format!("{what} entries must be 1 to {MAX_NAME} bytes"));
        }
        if !seen.insert(value) {
            return Err(format!("duplicate {what} {value}"));
        }
        out.push(value.to_string());
    }
    out.sort();
    Ok(out)
}

fn check_slots(slots: &[SealedSlot]) -> Result<(String, Vec<SealedSlot>), String> {
    if slots.is_empty() {
        return Err("slots required".into());
    }
    if slots.len() > MAX_SLOTS {
        return Err(format!("at most {MAX_SLOTS} slots"));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(slots.len());
    let mut fleet_key_id = String::new();
    for slot in slots {
        let name = token(&slot.name, MAX_SLOT_NAME, "slot name")?;
        if name.contains('/') {
            return Err("slot name must match [A-Za-z0-9._-]+".into());
        }
        if !seen.insert(name.clone()) {
            return Err(format!("duplicate slot {name}"));
        }
        let slot_key = parse_key_id(&slot.fleet_key_id)?;
        if fleet_key_id.is_empty() {
            fleet_key_id = slot_key;
        } else if slot_key != fleet_key_id {
            return Err("slots must share one fleet_key_id".into());
        }
        if slot.ciphertext.is_empty() {
            return Err(format!("slot {name} ciphertext required"));
        }
        out.push(SealedSlot {
            name,
            fleet_key_id: fleet_key_id.clone(),
            ciphertext: slot.ciphertext.clone(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((fleet_key_id, out))
}

fn content_digest(
    namespaces: &[String],
    destinations: &[String],
    fleet_key_id: &str,
    slots: &[SealedSlot],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update((namespaces.len() as u64).to_be_bytes());
    for value in namespaces {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update((destinations.len() as u64).to_be_bytes());
    for value in destinations {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update((fleet_key_id.len() as u64).to_be_bytes());
    hasher.update(fleet_key_id.as_bytes());
    hasher.update((slots.len() as u64).to_be_bytes());
    for slot in slots {
        hasher.update((slot.name.len() as u64).to_be_bytes());
        hasher.update(slot.name.as_bytes());
        hasher.update((slot.ciphertext.len() as u64).to_be_bytes());
        hasher.update(&slot.ciphertext);
    }
    format!("{:x}", hasher.finalize())
}

fn encode_list(values: &[String]) -> Result<String, String> {
    serde_json::to_string(values).map_err(|error| error.to_string())
}

fn decode_list(json: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt credential handle: {error}"))
}

fn encode_slots(slots: &[SealedSlot]) -> Result<String, String> {
    serde_json::to_string(slots).map_err(|error| error.to_string())
}

fn decode_slots(json: &str) -> Result<Vec<SealedSlot>, String> {
    if json.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(json).map_err(|error| format!("corrupt credential handle: {error}"))
}

fn decision_id(kind: &str, name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(name.as_bytes());
    format!("connector-credential:{kind}:{:x}", hasher.finalize())
}

fn slot_names(slots: &[SealedSlot]) -> String {
    slots
        .iter()
        .map(|slot| slot.name.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

/// Register a fleet public key. The same id and public key is a no-op; a
/// different public key for a live id is refused.
pub fn register_fleet_key(
    db: &RuntimeDb,
    id: &str,
    public_key: &[u8],
    actor: &str,
    now_ms: i64,
) -> Result<FleetKeyRecord, String> {
    let key_id = parse_key_id(id)?;
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(format!("public_key must be {PUBLIC_KEY_LEN} bytes"));
    }
    if let Some(existing) = db.get_runtime_fleet_key(&key_id)? {
        if existing.public_key == public_key {
            return Ok(existing);
        }
        return Err("fleet key already registered with a different public key".into());
    }
    let record = FleetKeyRecord {
        key_id: key_id.clone(),
        public_key: public_key.to_vec(),
        registered_at_ms: now_ms,
    };
    db.put_runtime_fleet_key(&record)?;
    let stored = db
        .get_runtime_fleet_key(&key_id)?
        .ok_or_else(|| "fleet key store unavailable".to_string())?;
    if stored.public_key != public_key {
        return Err("fleet key already registered with a different public key".into());
    }
    db.record_decisions_idempotently(&[Decision {
        id: decision_id("fleet-key", &key_id),
        timestamp: stored.registered_at_ms,
        actor: actor.into(),
        action: FLEET_KEY_REGISTERED.into(),
        reason: "runtime fleet key registered".into(),
        evidence: HashMap::from([("key_id".into(), key_id)]),
        target_id: stored.key_id.clone(),
        outcome: "registered".into(),
    }])?;
    Ok(stored)
}

/// The registered public key, if any.
pub fn get_fleet_key(db: &RuntimeDb, id: &str) -> Result<Option<FleetKeyRecord>, String> {
    let key_id = parse_key_id(id)?;
    db.get_runtime_fleet_key(&key_id)
}

/// Store a handle. Same name and digest is a no-op. A live handle with a
/// different digest is refused. A tombstone may be re-issued.
pub fn issue_handle(
    db: &RuntimeDb,
    name: &str,
    namespaces: &[String],
    destinations: &[String],
    slots: &[SealedSlot],
    actor: &str,
    now_ms: i64,
) -> Result<CredentialHandle, String> {
    let name = token(name, MAX_NAME, "name")?;
    let namespaces = binding_list(namespaces, "namespace")?;
    let destinations = binding_list(destinations, "destination")?;
    let (fleet_key_id, slots) = check_slots(slots)?;
    if db.get_runtime_fleet_key(&fleet_key_id)?.is_none() {
        return Err("fleet key not found".into());
    }
    let digest = content_digest(&namespaces, &destinations, &fleet_key_id, &slots);
    if let Some(existing) = db.get_credential_handle(&name)?
        && !existing.revoked
    {
        if existing.content_digest == digest {
            return Ok(existing);
        }
        return Err("handle already issued with different content".into());
    }
    let handle = CredentialHandle {
        name: name.clone(),
        namespaces,
        destinations,
        fleet_key_id: fleet_key_id.clone(),
        slots,
        content_digest: digest.clone(),
        issued_at_ms: now_ms,
        issued_by: actor.into(),
        revoked: false,
        revoked_at_ms: 0,
        revoked_by: String::new(),
    };
    db.put_credential_handle(&handle)?;
    let stored = db
        .get_credential_handle(&name)?
        .ok_or_else(|| "handle store unavailable".to_string())?;
    if stored.revoked {
        return Err("handle store unavailable".into());
    }
    if stored.content_digest != digest {
        return Err("handle already issued with different content".into());
    }
    db.record_decisions_idempotently(&[Decision {
        id: decision_id("issue", &format!("{name}:{digest}")),
        timestamp: stored.issued_at_ms,
        actor: actor.into(),
        action: HANDLE_ISSUED.into(),
        reason: "connector credential handle issued".into(),
        evidence: HashMap::from([
            ("name".into(), name.clone()),
            ("key_id".into(), stored.fleet_key_id.clone()),
            ("slot_names".into(), slot_names(&stored.slots)),
            ("namespaces".into(), stored.namespaces.join(",")),
            ("destinations".into(), stored.destinations.join(",")),
            ("content_digest".into(), digest),
        ]),
        target_id: name,
        outcome: "issued".into(),
    }])?;
    Ok(stored)
}

/// Delete sealed slots and keep a tombstone. Unknown names are not found.
/// A second revoke is a no-op.
pub fn revoke_handle(
    db: &RuntimeDb,
    name: &str,
    actor: &str,
    now_ms: i64,
) -> Result<CredentialHandle, String> {
    let name = token(name, MAX_NAME, "name")?;
    let Some(existing) = db.get_credential_handle(&name)? else {
        return Err("handle not found".into());
    };
    if existing.revoked {
        return Ok(existing);
    }
    let slot_names = slot_names(&existing.slots);
    let handle = CredentialHandle {
        slots: Vec::new(),
        revoked: true,
        revoked_at_ms: now_ms,
        revoked_by: actor.into(),
        ..existing
    };
    db.put_credential_handle(&handle)?;
    db.record_decisions_idempotently(&[Decision {
        id: decision_id(
            "revoke",
            &format!("{}:{}", handle.name, handle.content_digest),
        ),
        timestamp: now_ms,
        actor: actor.into(),
        action: HANDLE_REVOKED.into(),
        reason: "connector credential handle revoked".into(),
        evidence: HashMap::from([
            ("name".into(), handle.name.clone()),
            ("key_id".into(), handle.fleet_key_id.clone()),
            ("slot_names".into(), slot_names),
            ("namespaces".into(), handle.namespaces.join(",")),
            ("destinations".into(), handle.destinations.join(",")),
            ("content_digest".into(), handle.content_digest.clone()),
        ]),
        target_id: handle.name.clone(),
        outcome: "revoked".into(),
    }])?;
    Ok(handle)
}

/// The stored handle, including a tombstone.
pub fn get_handle(db: &RuntimeDb, name: &str) -> Result<Option<CredentialHandle>, String> {
    if name.trim().is_empty() {
        return Ok(None);
    }
    db.get_credential_handle(name.trim())
}

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_runtime_fleet_key (
    key_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    registered_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_credential_handle (
    name TEXT PRIMARY KEY,
    namespaces_json TEXT NOT NULL,
    destinations_json TEXT NOT NULL,
    fleet_key_id TEXT NOT NULL,
    slots_json TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    issued_at_ms INTEGER NOT NULL,
    issued_by TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at_ms INTEGER NOT NULL DEFAULT 0,
    revoked_by TEXT NOT NULL DEFAULT ''
);
";

impl SekaiDb {
    pub(crate) fn migrate_connector_credentials(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    fn get_runtime_fleet_key_row(&self, key_id: &str) -> Result<Option<FleetKeyRecord>, String> {
        self.conn()
            .query_row(
                "SELECT key_id, public_key, registered_at_ms
                 FROM sekai_runtime_fleet_key WHERE key_id = ?1",
                rusqlite::params![key_id],
                |row| {
                    Ok(FleetKeyRecord {
                        key_id: row.get(0)?,
                        public_key: row.get(1)?,
                        registered_at_ms: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn put_runtime_fleet_key_row(&self, record: &FleetKeyRecord) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_runtime_fleet_key (key_id, public_key, registered_at_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (key_id) DO NOTHING",
                rusqlite::params![record.key_id, record.public_key, record.registered_at_ms],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn get_credential_handle_row(&self, name: &str) -> Result<Option<CredentialHandle>, String> {
        let row = self
            .conn()
            .query_row(
                "SELECT name, namespaces_json, destinations_json, fleet_key_id, slots_json,
                        content_digest, issued_at_ms, issued_by, revoked, revoked_at_ms, revoked_by
                 FROM sekai_credential_handle WHERE name = ?1",
                rusqlite::params![name],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, String>(10)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        row.map(
            |(
                name,
                namespaces_json,
                destinations_json,
                fleet_key_id,
                slots_json,
                content_digest,
                issued_at_ms,
                issued_by,
                revoked,
                revoked_at_ms,
                revoked_by,
            )| {
                Ok(CredentialHandle {
                    name,
                    namespaces: decode_list(&namespaces_json)?,
                    destinations: decode_list(&destinations_json)?,
                    fleet_key_id,
                    slots: decode_slots(&slots_json)?,
                    content_digest,
                    issued_at_ms,
                    issued_by,
                    revoked: revoked != 0,
                    revoked_at_ms,
                    revoked_by,
                })
            },
        )
        .transpose()
    }

    fn put_credential_handle_row(&self, handle: &CredentialHandle) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_credential_handle (
                    name, namespaces_json, destinations_json, fleet_key_id, slots_json,
                    content_digest, issued_at_ms, issued_by, revoked, revoked_at_ms, revoked_by
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT (name) DO UPDATE SET
                    namespaces_json = excluded.namespaces_json,
                    destinations_json = excluded.destinations_json,
                    fleet_key_id = excluded.fleet_key_id,
                    slots_json = excluded.slots_json,
                    content_digest = excluded.content_digest,
                    issued_at_ms = excluded.issued_at_ms,
                    issued_by = excluded.issued_by,
                    revoked = excluded.revoked,
                    revoked_at_ms = excluded.revoked_at_ms,
                    revoked_by = excluded.revoked_by
                 WHERE sekai_credential_handle.revoked != 0
                    OR excluded.revoked != 0",
                rusqlite::params![
                    handle.name,
                    encode_list(&handle.namespaces)?,
                    encode_list(&handle.destinations)?,
                    handle.fleet_key_id,
                    encode_slots(&handle.slots)?,
                    handle.content_digest,
                    handle.issued_at_ms,
                    handle.issued_by,
                    i64::from(handle.revoked),
                    handle.revoked_at_ms,
                    handle.revoked_by,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

impl PostgresDb {
    fn get_runtime_fleet_key_row(&self, key_id: &str) -> Result<Option<FleetKeyRecord>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT key_id, public_key, registered_at_ms
                 FROM sekai_runtime_fleet_key WHERE key_id = $1",
                &[&key_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(rows.first().map(|row| FleetKeyRecord {
            key_id: row.get(0),
            public_key: row.get(1),
            registered_at_ms: row.get(2),
        }))
    }

    fn put_runtime_fleet_key_row(&self, record: &FleetKeyRecord) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_runtime_fleet_key (key_id, public_key, registered_at_ms)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (key_id) DO NOTHING",
                &[&record.key_id, &record.public_key, &record.registered_at_ms],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn get_credential_handle_row(&self, name: &str) -> Result<Option<CredentialHandle>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT name, namespaces_json, destinations_json, fleet_key_id, slots_json,
                        content_digest, issued_at_ms, issued_by, revoked, revoked_at_ms, revoked_by
                 FROM sekai_credential_handle WHERE name = $1",
                &[&name],
            )
            .map_err(|error| error.to_string())?;
        rows.first()
            .map(|row| {
                Ok(CredentialHandle {
                    name: row.get(0),
                    namespaces: decode_list(&row.get::<_, String>(1))?,
                    destinations: decode_list(&row.get::<_, String>(2))?,
                    fleet_key_id: row.get(3),
                    slots: decode_slots(&row.get::<_, String>(4))?,
                    content_digest: row.get(5),
                    issued_at_ms: row.get(6),
                    issued_by: row.get(7),
                    revoked: row.get::<_, i32>(8) != 0,
                    revoked_at_ms: row.get(9),
                    revoked_by: row.get(10),
                })
            })
            .transpose()
    }

    fn put_credential_handle_row(&self, handle: &CredentialHandle) -> Result<(), String> {
        let namespaces = encode_list(&handle.namespaces)?;
        let destinations = encode_list(&handle.destinations)?;
        let slots = encode_slots(&handle.slots)?;
        let revoked = i32::from(handle.revoked);
        self.connection()?
            .execute(
                "INSERT INTO sekai_credential_handle (
                    name, namespaces_json, destinations_json, fleet_key_id, slots_json,
                    content_digest, issued_at_ms, issued_by, revoked, revoked_at_ms, revoked_by
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (name) DO UPDATE SET
                    namespaces_json = excluded.namespaces_json,
                    destinations_json = excluded.destinations_json,
                    fleet_key_id = excluded.fleet_key_id,
                    slots_json = excluded.slots_json,
                    content_digest = excluded.content_digest,
                    issued_at_ms = excluded.issued_at_ms,
                    issued_by = excluded.issued_by,
                    revoked = excluded.revoked,
                    revoked_at_ms = excluded.revoked_at_ms,
                    revoked_by = excluded.revoked_by
                 WHERE sekai_credential_handle.revoked != 0
                    OR excluded.revoked != 0",
                &[
                    &handle.name,
                    &namespaces,
                    &destinations,
                    &handle.fleet_key_id,
                    &slots,
                    &handle.content_digest,
                    &handle.issued_at_ms,
                    &handle.issued_by,
                    &revoked,
                    &handle.revoked_at_ms,
                    &handle.revoked_by,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

impl RuntimeDb {
    pub fn get_runtime_fleet_key(&self, key_id: &str) -> Result<Option<FleetKeyRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_runtime_fleet_key_row(key_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_runtime_fleet_key_row(key_id))
            }
        }
    }

    pub fn put_runtime_fleet_key(&self, record: &FleetKeyRecord) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_runtime_fleet_key_row(record),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_runtime_fleet_key_row(record))
            }
        }
    }

    pub fn get_credential_handle(&self, name: &str) -> Result<Option<CredentialHandle>, String> {
        match self {
            Self::Sqlite(db) => db.get_credential_handle_row(name),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_credential_handle_row(name))
            }
        }
    }

    pub fn put_credential_handle(&self, handle: &CredentialHandle) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_credential_handle_row(handle),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_credential_handle_row(handle))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, byte: u8) -> (String, Vec<u8>) {
        (id.into(), vec![byte; PUBLIC_KEY_LEN])
    }

    fn slots(key_id: &str, secret: &[u8]) -> Vec<SealedSlot> {
        vec![SealedSlot {
            name: "token".into(),
            fleet_key_id: key_id.into(),
            ciphertext: secret.to_vec(),
        }]
    }

    fn contract(db: &RuntimeDb) {
        let (key_id, public) = key("fleet-1", 7);
        let registered = register_fleet_key(db, &key_id, &public, "root", 1).unwrap();
        assert_eq!(
            register_fleet_key(db, &key_id, &public, "root", 2).unwrap(),
            registered
        );
        let other = vec![9; PUBLIC_KEY_LEN];
        assert!(
            register_fleet_key(db, &key_id, &other, "root", 3)
                .unwrap_err()
                .contains("different public key")
        );

        let issued = issue_handle(
            db,
            "ops/github-bot",
            &["ops".into()],
            &["api.github.com".into()],
            &slots(&key_id, b"sealed-not-the-secret"),
            "root",
            10,
        )
        .unwrap();
        assert!(!issued.revoked);
        assert_eq!(
            issue_handle(
                db,
                "ops/github-bot",
                &["ops".into()],
                &["api.github.com".into()],
                &slots(&key_id, b"sealed-not-the-secret"),
                "root",
                11,
            )
            .unwrap()
            .content_digest,
            issued.content_digest
        );
        assert!(
            issue_handle(
                db,
                "ops/github-bot",
                &["ops".into()],
                &["api.github.com".into()],
                &slots(&key_id, b"other-sealed"),
                "root",
                12,
            )
            .unwrap_err()
            .contains("different content")
        );

        let stored = db.get_credential_handle("ops/github-bot").unwrap().unwrap();
        let encoded = encode_slots(&stored.slots).unwrap();
        assert!(!encoded.contains("the-real-token"));
        assert!(!encoded.contains("ghp_"));

        let mut clobber_key = registered.clone();
        clobber_key.public_key = other;
        clobber_key.registered_at_ms = 99;
        db.put_runtime_fleet_key(&clobber_key).unwrap();
        assert_eq!(
            db.get_runtime_fleet_key(&key_id)
                .unwrap()
                .unwrap()
                .public_key,
            public
        );
        let mut clobber_handle = stored.clone();
        clobber_handle.content_digest = "other-digest".into();
        clobber_handle.slots = slots(&key_id, b"clobber-sealed");
        db.put_credential_handle(&clobber_handle).unwrap();
        assert_eq!(
            db.get_credential_handle("ops/github-bot")
                .unwrap()
                .unwrap()
                .content_digest,
            issued.content_digest
        );

        let revoked = revoke_handle(db, "ops/github-bot", "root", 20).unwrap();
        assert!(revoked.revoked);
        assert!(revoked.slots.is_empty());
        assert_eq!(
            revoke_handle(db, "ops/github-bot", "root", 21)
                .unwrap()
                .revoked_at_ms,
            20
        );
        assert!(
            revoke_handle(db, "missing", "root", 22)
                .unwrap_err()
                .contains("not found")
        );

        let reissued = issue_handle(
            db,
            "ops/github-bot",
            &["ops".into()],
            &["api.github.com".into()],
            &slots(&key_id, b"rotated-sealed"),
            "root",
            30,
        )
        .unwrap();
        assert!(!reissued.revoked);
        assert_ne!(reissued.content_digest, issued.content_digest);

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: None,
                target_id: Some("ops/github-bot".into()),
                limit: 20,
                ..Default::default()
            })
            .unwrap();
        assert!(decisions.iter().any(|d| d.action == HANDLE_ISSUED));
        assert!(decisions.iter().any(|d| d.action == HANDLE_REVOKED));
        for decision in &decisions {
            for value in decision.evidence.values() {
                assert!(!value.contains("the-real-token"), "{value}");
                assert!(!value.contains("sealed-not-the-secret"), "{value}");
                assert!(!value.contains("rotated-sealed"), "{value}");
            }
        }
    }

    #[test]
    fn sqlite_handles_follow_the_contract() {
        contract(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_handles_follow_the_contract() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        contract(&db);
    }
}
