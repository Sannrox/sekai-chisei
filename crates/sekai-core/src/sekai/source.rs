//! Sources (`sekai.source/v1`, ADR 0148): the governed record of one
//! integration with an external system.
//!
//! A namespace administrator puts a Source naming a connector type and
//! version, configuration validated against that type, a credential
//! reference, an egress allowlist, placement labels, a sync interval, an
//! owner, markings and an optional certification pin. The plane stores the
//! credential reference, a handle the operator issued to the connector
//! runtime, and never a credential: configuration that looks like one is
//! refused.
//!
//! A Source keeps the `source` and `source_instance` tokens its batches
//! carry, so object ids (`source_id(source, source_instance, external_id)`)
//! do not change. One Source owns each `(namespace, source,
//! source_instance)`, disabled or not, and the tokens never change after
//! the Source is created.
//!
//! Every put and every disable bumps `revision`. A put names the revision
//! it read (0 to create), so two administrators cannot overwrite each other.
//! A put re-enables a disabled Source; a disable is idempotent.
//!
//! The row also carries the Source's sync claim and outcome
//! ([`crate::sekai::source_sync`]). A disable raises the claim generation
//! and ends the claim; a put that changes `every_ms` restarts the schedule.

use std::collections::BTreeMap;

use sekai_source_sdk::{
    ConnectorType, EgressAllowlist, SourceConfig, connector_type, contains_secret_like_text,
};
use sekai_types::governed_transform::validate_placement_labels;
use serde::{Deserialize, Serialize};

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::source_sync::{SyncError, SyncState};
use crate::sekai::work_claim::ClaimRecord;

pub const SOURCE_VERSION: &str = "sekai.source/v1";
pub const MAX_SOURCE_ID_BYTES: usize = 128;
pub const MAX_CREDENTIAL_REF_BYTES: usize = 128;
pub const MAX_SOURCE_MARKINGS: usize = 32;
pub const MAX_LIST_SOURCES: usize = 500;
/// The shortest sync interval; 0 means the Source has no schedule.
pub const MIN_SOURCE_EVERY_MS: i64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceStatus {
    Active,
    Disabled,
}

impl SourceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    fn parse(text: &str) -> Result<Self, String> {
        match text {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            other => Err(format!("unknown source status {other:?}")),
        }
    }
}

/// One stored Source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub namespace: String,
    /// The handle batches, exports and effects name.
    pub source_id: String,
    pub source: String,
    pub source_instance: String,
    pub spec: SourceSpec,
    pub status: SourceStatus,
    /// Bumped by every put and disable.
    pub revision: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// The sync claim and outcome; a put never writes it.
    pub sync: SyncState,
}

/// What an administrator may change with a put. Stored as JSON, so a later
/// field is additive: an older plane reads a record without it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpec {
    pub connector_type: String,
    pub connector_version: String,
    pub config: SourceConfig,
    /// The operator-issued credential handle; empty when the type needs none.
    pub credential_ref: String,
    /// Canonical egress rules (`host` or `host:port`), sorted.
    pub egress: Vec<String>,
    /// Labels a connector runtime must carry to claim this Source's work.
    pub placement: BTreeMap<String, String>,
    /// Sync interval on the transform schedule graph; 0 for none.
    pub every_ms: i64,
    pub owner: String,
    /// Sorted and deduplicated.
    pub markings: Vec<String>,
    /// The connector certification this Source is pinned to; empty for none.
    pub certification_id: String,
}

/// A put: the Source's identity, the spec, and the revision it read.
#[derive(Debug, Clone)]
pub struct PutSource {
    pub namespace: String,
    pub source_id: String,
    pub source: String,
    pub source_instance: String,
    pub spec: SourceSpec,
    /// 0 creates the Source; otherwise the revision the caller read.
    pub expected_revision: i64,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceError {
    Invalid(String),
    NotFound,
    /// The Source exists at another revision (or already exists, on create).
    RevisionConflict,
    /// Another Source owns these `source` and `source_instance` tokens.
    TokensOwned,
    Store(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid source: {message}"),
            Self::NotFound => formatter.write_str("source not found"),
            Self::RevisionConflict => formatter.write_str("source revision changed"),
            Self::TokensOwned => {
                formatter.write_str("another source owns this source and source_instance")
            }
            Self::Store(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for SourceError {}

impl From<String> for SourceError {
    fn from(message: String) -> Self {
        Self::Store(message)
    }
}

impl SourceSpec {
    /// The connector type this spec names, if the plane knows it.
    pub fn connector(&self) -> Option<&'static ConnectorType> {
        connector_type(&self.connector_type, &self.connector_version)
    }
}

/// Validate and normalize a put: canonical egress rules and markings.
pub fn validate(request: &PutSource) -> Result<SourceSpec, SourceError> {
    let invalid = |message: &str| SourceError::Invalid(message.into());
    if request.namespace.trim().is_empty() || request.namespace.trim() != request.namespace {
        return Err(invalid("namespace is required"));
    }
    if !is_handle(&request.source_id, MAX_SOURCE_ID_BYTES, false) {
        return Err(invalid(
            "source_id must be 1-128 lowercase letters, digits, '-', '_' or '.'",
        ));
    }
    let spec = &request.spec;
    let ty = spec
        .connector()
        .ok_or_else(|| invalid("unknown connector type or version"))?;
    ty.validate_tokens(&request.source, &request.source_instance)
        .map_err(|error| SourceError::Invalid(error.to_string()))?;
    ty.validate_config(&spec.config)
        .map_err(|error| SourceError::Invalid(error.to_string()))?;
    if spec.credential_ref.is_empty() {
        if ty.credential_slots.iter().any(|slot| slot.required) {
            return Err(invalid(
                "credential_ref is required for this connector type",
            ));
        }
    } else if !is_handle(&spec.credential_ref, MAX_CREDENTIAL_REF_BYTES, true)
        || contains_secret_like_text(&spec.credential_ref)
    {
        return Err(invalid(
            "credential_ref must be an operator-issued handle, never a credential",
        ));
    }
    let egress = EgressAllowlist::parse(&spec.egress)
        .map_err(|error| SourceError::Invalid(error.to_string()))?;
    ty.require_egress(&spec.config, &egress)
        .map_err(|error| SourceError::Invalid(error.to_string()))?;
    validate_placement_labels("placement", &spec.placement)
        .map_err(|error| SourceError::Invalid(error.message()))?;
    if spec.every_ms != 0 && spec.every_ms < MIN_SOURCE_EVERY_MS {
        return Err(invalid("every_ms must be 0 or at least 60000"));
    }
    if !is_handle(&spec.owner, MAX_SOURCE_ID_BYTES, true) {
        return Err(invalid("owner is required"));
    }
    let mut markings = spec.markings.clone();
    markings.sort();
    markings.dedup();
    if markings.len() > MAX_SOURCE_MARKINGS
        || !markings
            .iter()
            .all(|marking| is_handle(marking, MAX_SOURCE_ID_BYTES, true))
    {
        return Err(invalid("markings must be at most 32 marking ids"));
    }
    if !spec.certification_id.is_empty()
        && !is_handle(&spec.certification_id, MAX_SOURCE_ID_BYTES, true)
    {
        return Err(invalid("certification_id is not a certification id"));
    }
    Ok(SourceSpec {
        egress: egress.rules(),
        markings,
        ..spec.clone()
    })
}

/// A bounded token: lowercase letters, digits, `-`, `_` and `.`, plus `/`,
/// `:` and uppercase letters when `wide`.
fn is_handle(text: &str, max: usize, wide: bool) -> bool {
    (1..=max).contains(&text.len())
        && text.starts_with(|first: char| first.is_ascii_alphanumeric())
        && text.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_' | '.')
                || (wide && (character.is_ascii_uppercase() || matches!(character, '/' | ':')))
        })
}

/// Creates the Source, or replaces the spec of the revision the caller read
/// and re-enables it. The tokens are fixed at create.
pub fn put(db: &RuntimeDb, request: &PutSource) -> Result<Source, SourceError> {
    let spec = validate(request)?;
    let record_json =
        serde_json::to_string(&spec).map_err(|error| format!("encode source: {error}"))?;
    let written = if request.expected_revision == 0 {
        db.insert_source(request, &record_json)?
    } else {
        db.update_source(request, &record_json)?
    };
    if let Some(source) = written {
        return Ok(source);
    }
    // Nothing was written; say why from the current row.
    match db.get_source(&request.namespace, &request.source_id)? {
        None if request.expected_revision == 0 => Err(SourceError::TokensOwned),
        None => Err(SourceError::NotFound),
        Some(_) if request.expected_revision == 0 => Err(SourceError::RevisionConflict),
        Some(current)
            if current.source != request.source
                || current.source_instance != request.source_instance =>
        {
            Err(SourceError::Invalid(
                "source and source_instance cannot change".into(),
            ))
        }
        Some(_) => Err(SourceError::RevisionConflict),
    }
}

/// Disables the Source. Idempotent: an already disabled Source is returned
/// as it is.
pub fn disable(
    db: &RuntimeDb,
    namespace: &str,
    source_id: &str,
    now_ms: i64,
) -> Result<Source, SourceError> {
    if let Some(source) = db.disable_source(namespace, source_id, now_ms)? {
        return Ok(source);
    }
    db.get_source(namespace, source_id)?
        .ok_or(SourceError::NotFound)
}

/// Admits a batch for `source` and `source_instance` against the Source
/// that owns those tokens (ADR 0148). `handle` is the Source id the batch
/// names, or empty for a producer that predates Sources. A disabled Source
/// refuses every batch for its tokens, named or not; a named Source must
/// own them. An unnamed batch is admitted for unowned tokens and for an
/// active Source, so older producers survive a rolling deploy. The read
/// runs before the apply transaction, so a disable is best-effort for a
/// batch already in flight. The error starts with the apply-error code the
/// RPC layer maps.
pub fn admit_batch(
    db: &RuntimeDb,
    namespace: &str,
    source: &str,
    source_instance: &str,
    handle: &str,
) -> Result<(), String> {
    let owner = db.get_source_by_tokens(namespace, source, source_instance)?;
    match owner {
        Some(owner) if !handle.is_empty() && owner.source_id != handle => Err(format!(
            "source_handle_mismatch: source {handle:?} does not own this source and source_instance"
        )),
        None if !handle.is_empty() => Err(format!(
            "source_handle_mismatch: source {handle:?} does not own this source and source_instance"
        )),
        Some(owner) if owner.status != SourceStatus::Active => Err(format!(
            "source_disabled: source {:?} is disabled",
            owner.source_id
        )),
        _ => Ok(()),
    }
}

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_sources (
    namespace TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_instance TEXT NOT NULL,
    status TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, source_id),
    UNIQUE (namespace, source, source_instance)
);
";

// SQLite numbers `$n` placeholders in order of first appearance, so every
// statement here uses them in ascending order.

/// Every column a [`Row`] reads, in order.
macro_rules! columns {
    () => {
        "namespace, source_id, source, source_instance, status, revision, \
         created_at_ms, updated_at_ms, record_json, sync_due_bucket, sync_claimed_bucket, \
         sync_done_bucket, sync_claim_owner, sync_claim_generation, sync_fencing_token, \
         sync_claim_expires_at_ms, sync_lease_expiries, sync_last_success_at_ms, \
         sync_last_failure_at_ms, sync_last_failure, sync_last_runtime"
    };
}

const COLUMNS: &str = columns!();

/// The sync columns, added after the table (ADR 0149 claim record).
const SYNC_COLUMNS: [(&str, &str); 13] = [
    ("sync_every_ms", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_due_bucket", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_claimed_bucket", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_done_bucket", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_claim_owner", "TEXT NOT NULL DEFAULT ''"),
    ("sync_claim_generation", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_fencing_token", "TEXT NOT NULL DEFAULT ''"),
    ("sync_claim_expires_at_ms", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_lease_expiries", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_last_success_at_ms", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_last_failure_at_ms", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_last_failure", "TEXT NOT NULL DEFAULT ''"),
    ("sync_last_runtime", "TEXT NOT NULL DEFAULT ''"),
];

/// Writes nothing when the id or the tokens are taken.
const INSERT_SQL: &str = concat!(
    "INSERT INTO sekai_sources
    (namespace, source_id, source, source_instance, status, revision,
     created_at_ms, updated_at_ms, record_json, sync_every_ms)
VALUES ($1, $2, $3, $4, 'active', 1, $5, $5, $6, $7)
ON CONFLICT DO NOTHING
RETURNING ",
    columns!()
);

/// Fenced by the revision read; the tokens must match. A changed interval
/// restarts the schedule: buckets of the old interval mean nothing in the
/// new one, so the restart also ends a live claim under a raised
/// generation. Every SET reads the row as it was.
const UPDATE_SQL: &str = concat!(
    "UPDATE sekai_sources
SET status = 'active', revision = revision + 1, updated_at_ms = $1, record_json = $2,
    sync_due_bucket = CASE WHEN sync_every_ms = $3 THEN sync_due_bucket ELSE 0 END,
    sync_claimed_bucket = CASE WHEN sync_every_ms = $3 THEN sync_claimed_bucket ELSE 0 END,
    sync_done_bucket = CASE WHEN sync_every_ms = $3 THEN sync_done_bucket ELSE 0 END,
    sync_claim_generation = CASE WHEN sync_every_ms = $3
        THEN sync_claim_generation ELSE sync_claim_generation + 1 END,
    sync_claim_owner = CASE WHEN sync_every_ms = $3 THEN sync_claim_owner ELSE '' END,
    sync_fencing_token = CASE WHEN sync_every_ms = $3 THEN sync_fencing_token ELSE '' END,
    sync_claim_expires_at_ms = CASE WHEN sync_every_ms = $3
        THEN sync_claim_expires_at_ms ELSE 0 END,
    sync_lease_expiries = CASE WHEN sync_every_ms = $3 THEN sync_lease_expiries ELSE 0 END,
    sync_every_ms = $3
WHERE namespace = $4 AND source_id = $5 AND revision = $6
  AND source = $7 AND source_instance = $8
RETURNING ",
    columns!()
);

/// Raises the claim generation and ends the claim, so no earlier fence
/// holds (ADR 0148).
const DISABLE_SQL: &str = concat!(
    "UPDATE sekai_sources
SET status = 'disabled', revision = revision + 1, updated_at_ms = $1,
    sync_claim_generation = sync_claim_generation + 1, sync_claim_owner = '',
    sync_fencing_token = '', sync_claim_expires_at_ms = 0
WHERE namespace = $2 AND source_id = $3 AND status = 'active'
RETURNING ",
    columns!()
);

/// Moves every scheduled, active Source's due bucket forward, in one
/// namespace or (`$2` empty) all; idempotent. `NULLIF` keeps an
/// unscheduled row from dividing by zero whatever order the store
/// evaluates the conditions in.
const TICK_SQL: &str = "
UPDATE sekai_sources SET sync_due_bucket = $1 / NULLIF(sync_every_ms, 0)
WHERE status = 'active' AND sync_due_bucket < $1 / NULLIF(sync_every_ms, 0)
  AND ($2 = '' OR namespace = $2)";

/// A plane without the sync columns writes `record_json` but not
/// `sync_every_ms`, on insert and on update. Each tick first takes the
/// interval from the spec where the two differ, and restarts the schedule
/// as a put that changes the interval does.
const SQLITE_HEAL_SQL: &str = "
UPDATE sekai_sources
SET sync_every_ms = COALESCE(json_extract(record_json, '$.every_ms'), 0),
    sync_due_bucket = 0, sync_claimed_bucket = 0, sync_done_bucket = 0,
    sync_claim_generation = sync_claim_generation + 1, sync_claim_owner = '',
    sync_fencing_token = '', sync_claim_expires_at_ms = 0, sync_lease_expiries = 0
WHERE sync_every_ms <> COALESCE(json_extract(record_json, '$.every_ms'), 0)";
const POSTGRES_HEAL_SQL: &str = "
UPDATE sekai_sources
SET sync_every_ms = COALESCE((record_json::jsonb ->> 'every_ms')::bigint, 0),
    sync_due_bucket = 0, sync_claimed_bucket = 0, sync_done_bucket = 0,
    sync_claim_generation = sync_claim_generation + 1, sync_claim_owner = '',
    sync_fencing_token = '', sync_claim_expires_at_ms = 0, sync_lease_expiries = 0
WHERE sync_every_ms <> COALESCE((record_json::jsonb ->> 'every_ms')::bigint, 0)";

/// Open or lapsed sync work in a namespace after a source id, by id.
const DUE_SQL: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM sekai_sources
WHERE namespace = $1 AND source_id > $2 AND status = 'active'
  AND ((sync_claim_expires_at_ms = 0 AND sync_due_bucket > sync_done_bucket)
    OR (sync_claim_expires_at_ms > 0 AND sync_claim_expires_at_ms <= $3))
ORDER BY source_id LIMIT $4"
);

/// Writes back what [`SyncState`] holds.
const SYNC_UPDATE_SQL: &str = "
UPDATE sekai_sources
SET sync_due_bucket = $1, sync_claimed_bucket = $2, sync_done_bucket = $3,
    sync_claim_owner = $4, sync_claim_generation = $5, sync_fencing_token = $6,
    sync_claim_expires_at_ms = $7, sync_lease_expiries = $8,
    sync_last_success_at_ms = $9, sync_last_failure_at_ms = $10,
    sync_last_failure = $11, sync_last_runtime = $12
WHERE namespace = $13 AND source_id = $14";

struct Row {
    namespace: String,
    source_id: String,
    source: String,
    source_instance: String,
    status: String,
    revision: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
    record_json: String,
    sync: SyncState,
}

impl Row {
    fn decode(self) -> Result<Source, String> {
        Ok(Source {
            spec: serde_json::from_str(&self.record_json)
                .map_err(|error| format!("decode source: {error}"))?,
            status: SourceStatus::parse(&self.status)?,
            namespace: self.namespace,
            source_id: self.source_id,
            source: self.source,
            source_instance: self.source_instance,
            revision: self.revision,
            created_at_ms: self.created_at_ms,
            updated_at_ms: self.updated_at_ms,
            sync: self.sync,
        })
    }
}

fn sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        namespace: row.get(0)?,
        source_id: row.get(1)?,
        source: row.get(2)?,
        source_instance: row.get(3)?,
        status: row.get(4)?,
        revision: row.get(5)?,
        created_at_ms: row.get(6)?,
        updated_at_ms: row.get(7)?,
        record_json: row.get(8)?,
        sync: SyncState {
            due_bucket: row.get(9)?,
            claimed_bucket: row.get(10)?,
            done_bucket: row.get(11)?,
            claim: ClaimRecord {
                owner: row.get(12)?,
                generation: row.get(13)?,
                fencing_token: row.get(14)?,
                expires_at_ms: row.get(15)?,
                lease_expiries: row.get(16)?,
            },
            last_success_at_ms: row.get(17)?,
            last_failure_at_ms: row.get(18)?,
            last_failure: row.get(19)?,
            last_runtime: row.get(20)?,
        },
    })
}

fn postgres_row(row: &postgres::Row) -> Row {
    Row {
        namespace: row.get(0),
        source_id: row.get(1),
        source: row.get(2),
        source_instance: row.get(3),
        status: row.get(4),
        revision: row.get(5),
        created_at_ms: row.get(6),
        updated_at_ms: row.get(7),
        record_json: row.get(8),
        sync: SyncState {
            due_bucket: row.get(9),
            claimed_bucket: row.get(10),
            done_bucket: row.get(11),
            claim: ClaimRecord {
                owner: row.get(12),
                generation: row.get(13),
                fencing_token: row.get(14),
                expires_at_ms: row.get(15),
                lease_expiries: row.get(16),
            },
            last_success_at_ms: row.get(17),
            last_failure_at_ms: row.get(18),
            last_failure: row.get(19),
            last_runtime: row.get(20),
        },
    }
}

fn list_sql(placeholder_after: &str, placeholder_limit: &str) -> String {
    format!(
        "SELECT {COLUMNS} FROM sekai_sources
         WHERE namespace = $1 AND source_id > {placeholder_after}
         ORDER BY source_id LIMIT {placeholder_limit}"
    )
}

impl SekaiDb {
    pub fn migrate_sources(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())?;
        let present = conn
            .prepare("PRAGMA table_info(sekai_sources)")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(1))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(|error| error.to_string())?;
        for (column, definition) in SYNC_COLUMNS {
            if !present.iter().any(|name| name == column) {
                conn.execute_batch(&format!(
                    "ALTER TABLE sekai_sources ADD COLUMN {column} {definition}"
                ))
                .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    fn sqlite_source(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Option<Source>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(sql, params, sqlite_row)
            .optional()
            .map_err(|error| error.to_string())?
            .map(Row::decode)
            .transpose()
    }

    pub fn insert_source(
        &self,
        request: &PutSource,
        record_json: &str,
    ) -> Result<Option<Source>, String> {
        self.sqlite_source(
            INSERT_SQL,
            rusqlite::params![
                request.namespace,
                request.source_id,
                request.source,
                request.source_instance,
                request.now_ms,
                record_json,
                request.spec.every_ms,
            ],
        )
    }

    pub fn update_source(
        &self,
        request: &PutSource,
        record_json: &str,
    ) -> Result<Option<Source>, String> {
        self.sqlite_source(
            UPDATE_SQL,
            rusqlite::params![
                request.now_ms,
                record_json,
                request.spec.every_ms,
                request.namespace,
                request.source_id,
                request.expected_revision,
                request.source,
                request.source_instance,
            ],
        )
    }

    pub fn disable_source(
        &self,
        namespace: &str,
        source_id: &str,
        now_ms: i64,
    ) -> Result<Option<Source>, String> {
        self.sqlite_source(DISABLE_SQL, rusqlite::params![now_ms, namespace, source_id])
    }

    pub fn get_source_by_tokens(
        &self,
        namespace: &str,
        source: &str,
        source_instance: &str,
    ) -> Result<Option<Source>, String> {
        self.sqlite_source(
            &format!(
                "SELECT {COLUMNS} FROM sekai_sources
                 WHERE namespace = $1 AND source = $2 AND source_instance = $3"
            ),
            rusqlite::params![namespace, source, source_instance],
        )
    }

    pub fn get_source(&self, namespace: &str, source_id: &str) -> Result<Option<Source>, String> {
        self.sqlite_source(
            &format!("SELECT {COLUMNS} FROM sekai_sources WHERE namespace = $1 AND source_id = $2"),
            rusqlite::params![namespace, source_id],
        )
    }

    pub fn list_sources(
        &self,
        namespace: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<Source>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(&list_sql("$2", "$3"))
            .map_err(|error| error.to_string())?;
        let limit = i64::try_from(limit.min(MAX_LIST_SOURCES)).unwrap_or(0);
        let rows = statement
            .query_map(rusqlite::params![namespace, after, limit], sqlite_row)
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string())?.decode())
            .collect()
    }
}

impl PostgresDb {
    fn postgres_source(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Option<Source>, String> {
        self.connection()?
            .query_opt(sql, params)
            .map_err(|error| error.to_string())?
            .map(|row| postgres_row(&row).decode())
            .transpose()
    }

    pub fn insert_source(
        &self,
        request: &PutSource,
        record_json: &str,
    ) -> Result<Option<Source>, String> {
        self.postgres_source(
            INSERT_SQL,
            &[
                &request.namespace,
                &request.source_id,
                &request.source,
                &request.source_instance,
                &request.now_ms,
                &record_json,
                &request.spec.every_ms,
            ],
        )
    }

    pub fn update_source(
        &self,
        request: &PutSource,
        record_json: &str,
    ) -> Result<Option<Source>, String> {
        self.postgres_source(
            UPDATE_SQL,
            &[
                &request.now_ms,
                &record_json,
                &request.spec.every_ms,
                &request.namespace,
                &request.source_id,
                &request.expected_revision,
                &request.source,
                &request.source_instance,
            ],
        )
    }

    pub fn disable_source(
        &self,
        namespace: &str,
        source_id: &str,
        now_ms: i64,
    ) -> Result<Option<Source>, String> {
        self.postgres_source(DISABLE_SQL, &[&now_ms, &namespace, &source_id])
    }

    pub fn get_source_by_tokens(
        &self,
        namespace: &str,
        source: &str,
        source_instance: &str,
    ) -> Result<Option<Source>, String> {
        self.postgres_source(
            &format!(
                "SELECT {COLUMNS} FROM sekai_sources
                 WHERE namespace = $1 AND source = $2 AND source_instance = $3"
            ),
            &[&namespace, &source, &source_instance],
        )
    }

    pub fn get_source(&self, namespace: &str, source_id: &str) -> Result<Option<Source>, String> {
        self.postgres_source(
            &format!("SELECT {COLUMNS} FROM sekai_sources WHERE namespace = $1 AND source_id = $2"),
            &[&namespace, &source_id],
        )
    }

    pub fn list_sources(
        &self,
        namespace: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<Source>, String> {
        let limit = i64::try_from(limit.min(MAX_LIST_SOURCES)).unwrap_or(0);
        self.connection()?
            .query(&list_sql("$2", "$3"), &[&namespace, &after, &limit])
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| postgres_row(row).decode())
            .collect()
    }
}

impl RuntimeDb {
    pub fn insert_source(
        &self,
        request: &PutSource,
        record_json: &str,
    ) -> Result<Option<Source>, String> {
        match self {
            Self::Sqlite(db) => db.insert_source(request, record_json),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.insert_source(request, record_json))
            }
        }
    }

    pub fn update_source(
        &self,
        request: &PutSource,
        record_json: &str,
    ) -> Result<Option<Source>, String> {
        match self {
            Self::Sqlite(db) => db.update_source(request, record_json),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.update_source(request, record_json))
            }
        }
    }

    pub fn disable_source(
        &self,
        namespace: &str,
        source_id: &str,
        now_ms: i64,
    ) -> Result<Option<Source>, String> {
        match self {
            Self::Sqlite(db) => db.disable_source(namespace, source_id, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.disable_source(namespace, source_id, now_ms))
            }
        }
    }

    /// The Source that owns `source` and `source_instance` in `namespace`,
    /// active or not.
    pub fn get_source_by_tokens(
        &self,
        namespace: &str,
        source: &str,
        source_instance: &str,
    ) -> Result<Option<Source>, String> {
        match self {
            Self::Sqlite(db) => db.get_source_by_tokens(namespace, source, source_instance),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_source_by_tokens(namespace, source, source_instance)
            }),
        }
    }

    pub fn get_source(&self, namespace: &str, source_id: &str) -> Result<Option<Source>, String> {
        match self {
            Self::Sqlite(db) => db.get_source(namespace, source_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_source(namespace, source_id))
            }
        }
    }

    /// Sources in `namespace` after `after` in source id order.
    pub fn list_sources(
        &self,
        namespace: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<Source>, String> {
        match self {
            Self::Sqlite(db) => db.list_sources(namespace, after, limit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_sources(namespace, after, limit))
            }
        }
    }
}

fn sync_error(error: impl std::fmt::Display) -> SyncError {
    SyncError::Store(error.to_string())
}

impl SekaiDb {
    pub fn tick_source_syncs(&self, namespace: &str, now_ms: i64) -> Result<u64, String> {
        let conn = self.conn();
        conn.execute(SQLITE_HEAL_SQL, [])
            .map_err(|error| error.to_string())?;
        conn.execute(TICK_SQL, rusqlite::params![now_ms, namespace])
            .map(|count| count as u64)
            .map_err(|error| error.to_string())
    }

    pub fn list_due_source_syncs(
        &self,
        namespace: &str,
        after: &str,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<Source>, String> {
        let conn = self.conn();
        let mut statement = conn.prepare(DUE_SQL).map_err(|error| error.to_string())?;
        let limit = i64::try_from(limit.min(MAX_LIST_SOURCES)).unwrap_or(0);
        let rows = statement
            .query_map(
                rusqlite::params![namespace, after, now_ms, limit],
                sqlite_row,
            )
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string())?.decode())
            .collect()
    }

    /// Reads the Source, lets `change` edit its sync state and writes that
    /// back, in one immediate transaction. An error writes nothing.
    pub fn edit_source_sync(
        &self,
        namespace: &str,
        source_id: &str,
        change: impl FnOnce(&mut Source) -> Result<(), SyncError>,
    ) -> Result<Source, SyncError> {
        use rusqlite::OptionalExtension;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sync_error)?;
        let mut source = transaction
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_sources WHERE namespace = $1 AND source_id = $2"
                ),
                rusqlite::params![namespace, source_id],
                sqlite_row,
            )
            .optional()
            .map_err(sync_error)?
            .ok_or(SyncError::NotFound)?
            .decode()?;
        change(&mut source)?;
        let sync = &source.sync;
        transaction
            .execute(
                SYNC_UPDATE_SQL,
                rusqlite::params![
                    sync.due_bucket,
                    sync.claimed_bucket,
                    sync.done_bucket,
                    sync.claim.owner,
                    sync.claim.generation,
                    sync.claim.fencing_token,
                    sync.claim.expires_at_ms,
                    sync.claim.lease_expiries,
                    sync.last_success_at_ms,
                    sync.last_failure_at_ms,
                    sync.last_failure,
                    sync.last_runtime,
                    namespace,
                    source_id,
                ],
            )
            .map_err(sync_error)?;
        transaction.commit().map_err(sync_error)?;
        Ok(source)
    }
}

impl PostgresDb {
    pub fn tick_source_syncs(&self, namespace: &str, now_ms: i64) -> Result<u64, String> {
        let mut connection = self.connection()?;
        connection
            .execute(POSTGRES_HEAL_SQL, &[])
            .map_err(|error| error.to_string())?;
        connection
            .execute(TICK_SQL, &[&now_ms, &namespace])
            .map_err(|error| error.to_string())
    }

    pub fn list_due_source_syncs(
        &self,
        namespace: &str,
        after: &str,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<Source>, String> {
        let limit = i64::try_from(limit.min(MAX_LIST_SOURCES)).unwrap_or(0);
        self.connection()?
            .query(DUE_SQL, &[&namespace, &after, &now_ms, &limit])
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| postgres_row(row).decode())
            .collect()
    }

    /// Reads the Source under a row lock, lets `change` edit its sync state
    /// and writes that back, in one transaction. An error writes nothing.
    pub fn edit_source_sync(
        &self,
        namespace: &str,
        source_id: &str,
        change: impl FnOnce(&mut Source) -> Result<(), SyncError>,
    ) -> Result<Source, SyncError> {
        let mut connection = self.connection().map_err(SyncError::Store)?;
        let mut transaction = connection.transaction().map_err(sync_error)?;
        let mut source = transaction
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_sources
                     WHERE namespace = $1 AND source_id = $2 FOR UPDATE"
                ),
                &[&namespace, &source_id],
            )
            .map_err(sync_error)?
            .as_ref()
            .map(postgres_row)
            .ok_or(SyncError::NotFound)?
            .decode()?;
        change(&mut source)?;
        let sync = &source.sync;
        transaction
            .execute(
                SYNC_UPDATE_SQL,
                &[
                    &sync.due_bucket,
                    &sync.claimed_bucket,
                    &sync.done_bucket,
                    &sync.claim.owner,
                    &sync.claim.generation,
                    &sync.claim.fencing_token,
                    &sync.claim.expires_at_ms,
                    &sync.claim.lease_expiries,
                    &sync.last_success_at_ms,
                    &sync.last_failure_at_ms,
                    &sync.last_failure,
                    &sync.last_runtime,
                    &namespace,
                    &source_id,
                ],
            )
            .map_err(sync_error)?;
        transaction.commit().map_err(sync_error)?;
        Ok(source)
    }
}

/// The labels a runtime registered in a namespace (`RegisterTransformRuntime`);
/// placement matches against them for every kind (ADR 0129).
const RUNTIME_LABELS_SQL: &str =
    "SELECT labels_json FROM sekai_transform_runtime WHERE namespace = $1 AND runtime_id = $2";

fn decode_labels(json: Option<String>) -> Result<BTreeMap<String, String>, String> {
    json.map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
        .transpose()
        .map(Option::unwrap_or_default)
}

impl SekaiDb {
    pub fn registered_runtime_labels(
        &self,
        namespace: &str,
        runtime_id: &str,
    ) -> Result<BTreeMap<String, String>, String> {
        use rusqlite::OptionalExtension;
        let json = self
            .conn()
            .query_row(
                RUNTIME_LABELS_SQL,
                rusqlite::params![namespace, runtime_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        decode_labels(json)
    }
}

impl PostgresDb {
    pub fn registered_runtime_labels(
        &self,
        namespace: &str,
        runtime_id: &str,
    ) -> Result<BTreeMap<String, String>, String> {
        let json = self
            .connection()?
            .query_opt(RUNTIME_LABELS_SQL, &[&namespace, &runtime_id])
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        decode_labels(json)
    }
}

impl RuntimeDb {
    /// The labels `runtime_id` registered in `namespace`; none when it never
    /// registered.
    pub fn registered_runtime_labels(
        &self,
        namespace: &str,
        runtime_id: &str,
    ) -> Result<BTreeMap<String, String>, String> {
        match self {
            Self::Sqlite(db) => db.registered_runtime_labels(namespace, runtime_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.registered_runtime_labels(namespace, runtime_id)
            }),
        }
    }

    /// Ticks the Sources of `namespace`, or of every namespace when empty.
    pub fn tick_source_syncs(&self, namespace: &str, now_ms: i64) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.tick_source_syncs(namespace, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.tick_source_syncs(namespace, now_ms))
            }
        }
    }

    /// Open or lapsed sync work in `namespace` after `after`, by id.
    pub fn list_due_source_syncs(
        &self,
        namespace: &str,
        after: &str,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<Source>, String> {
        match self {
            Self::Sqlite(db) => db.list_due_source_syncs(namespace, after, now_ms, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_due_source_syncs(namespace, after, now_ms, limit)
            }),
        }
    }

    pub fn edit_source_sync(
        &self,
        namespace: &str,
        source_id: &str,
        change: impl FnOnce(&mut Source) -> Result<(), SyncError>,
    ) -> Result<Source, SyncError> {
        match self {
            Self::Sqlite(db) => db.edit_source_sync(namespace, source_id, change),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.edit_source_sync(namespace, source_id, change)
            }),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sekai_source_sdk::ConfigValue;
    use std::sync::Arc;

    pub(crate) fn github(ns: &str, id: &str, repo: &str) -> PutSource {
        PutSource {
            namespace: ns.into(),
            source_id: id.into(),
            source: "github".into(),
            source_instance: repo.into(),
            spec: SourceSpec {
                connector_type: "github".into(),
                connector_version: "1".into(),
                config: SourceConfig::from([(
                    "api_url".into(),
                    ConfigValue::Text("https://api.github.com".into()),
                )]),
                credential_ref: "ops/github-bot".into(),
                egress: vec!["API.github.com".into(), "api.github.com".into()],
                placement: BTreeMap::from([("zone".into(), "eu".into())]),
                every_ms: 300_000,
                owner: "team-integrations".into(),
                markings: vec!["internal".into(), "internal".into()],
                certification_id: String::new(),
            },
            expected_revision: 0,
            now_ms: 1_000,
        }
    }

    /// The Source store contract on either backend.
    fn contract(db: Arc<RuntimeDb>, ns: &str) {
        let created = put(&db, &github(ns, "repo-a", "acme/a")).unwrap();
        assert_eq!(
            (created.revision, created.status),
            (1, SourceStatus::Active)
        );
        assert_eq!(created.spec.egress, ["api.github.com"]);
        assert_eq!(created.spec.markings, ["internal"]);
        assert_eq!(db.get_source(ns, "repo-a").unwrap(), Some(created.clone()));

        // A create of an existing id, and a second Source for the same
        // tokens, are refused.
        assert_eq!(
            put(&db, &github(ns, "repo-a", "acme/a")),
            Err(SourceError::RevisionConflict)
        );
        assert_eq!(
            put(&db, &github(ns, "repo-a2", "acme/a")),
            Err(SourceError::TokensOwned)
        );

        // A put names the revision it read; a stale one loses.
        let mut update = github(ns, "repo-a", "acme/a");
        update.expected_revision = 1;
        update.spec.every_ms = 0;
        update.now_ms = 2_000;
        let updated = put(&db, &update).unwrap();
        assert_eq!((updated.revision, updated.spec.every_ms), (2, 0));
        assert_eq!(
            (updated.created_at_ms, updated.updated_at_ms),
            (1_000, 2_000)
        );
        assert_eq!(put(&db, &update), Err(SourceError::RevisionConflict));
        let mut moved = github(ns, "repo-a", "acme/b");
        moved.expected_revision = 2;
        assert!(matches!(put(&db, &moved), Err(SourceError::Invalid(_))));
        let mut missing = github(ns, "nope", "acme/n");
        missing.expected_revision = 1;
        assert_eq!(put(&db, &missing), Err(SourceError::NotFound));

        // Disable bumps the revision once and keeps the tokens owned.
        let disabled = disable(&db, ns, "repo-a", 3_000).unwrap();
        assert_eq!(
            (disabled.revision, disabled.status),
            (3, SourceStatus::Disabled)
        );
        assert_eq!(disable(&db, ns, "repo-a", 4_000).unwrap(), disabled);
        assert_eq!(disable(&db, ns, "nope", 4_000), Err(SourceError::NotFound));
        assert_eq!(
            put(&db, &github(ns, "repo-a3", "acme/a")),
            Err(SourceError::TokensOwned)
        );

        // A put of the read revision re-enables it.
        let mut enable = github(ns, "repo-a", "acme/a");
        enable.expected_revision = 3;
        assert_eq!(put(&db, &enable).unwrap().status, SourceStatus::Active);

        // List pages in id order within the namespace.
        put(&db, &github(ns, "repo-b", "acme/b")).unwrap();
        put(&db, &github(&format!("{ns}-other"), "repo-c", "acme/c")).unwrap();
        let ids = |after: &str, limit| {
            db.list_sources(ns, after, limit)
                .unwrap()
                .into_iter()
                .map(|source| source.source_id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids("", 10), ["repo-a", "repo-b"]);
        assert_eq!(ids("", 1), ["repo-a"]);
        assert_eq!(ids("repo-a", 10), ["repo-b"]);

        // A batch is admitted against the Source that owns its tokens.
        let admit = |instance: &str, handle: &str| admit_batch(&db, ns, "github", instance, handle);
        assert_eq!(admit("acme/b", ""), Ok(()));
        assert_eq!(admit("acme/b", "repo-b"), Ok(()));
        assert_eq!(admit("acme/unowned", ""), Ok(()), "no Source owns these");
        for (instance, handle) in [("acme/b", "repo-a"), ("acme/unowned", "repo-b")] {
            assert!(
                admit(instance, handle)
                    .unwrap_err()
                    .starts_with("source_handle_mismatch:")
            );
        }
        disable(&db, ns, "repo-b", 9_000).unwrap();
        for handle in ["", "repo-b"] {
            assert!(
                admit("acme/b", handle)
                    .unwrap_err()
                    .starts_with("source_disabled:")
            );
        }
    }

    #[test]
    fn sqlite_sources_put_get_list_and_disable() {
        contract(Arc::new(RuntimeDb::memory()), "acme");
    }

    #[test]
    fn a_disabled_source_stops_its_batches() {
        use crate::db::object_sync::tests::{PRODUCER, batch};
        let db = RuntimeDb::memory();
        put(&db, &github("acme", "ops", "acme/ops")).unwrap();
        db.apply_source_batch(&batch("", "cursor:1", "batch-1"), PRODUCER, 100)
            .unwrap();
        disable(&db, "acme", "ops", 200).unwrap();
        let refused = db
            .apply_source_batch(&batch("cursor:1", "cursor:2", "batch-2"), PRODUCER, 300)
            .unwrap_err();
        assert!(refused.starts_with("source_disabled:"), "{refused}");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_sources_put_get_list_and_disable() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => {
                PostgresDb::connect_with_ca_certificate(&url, 4, &std::fs::read(path).unwrap())
            }
            Err(_) => PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(Arc::new(db.unwrap()));
        let ns = format!("sources-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        contract(Arc::new(db), &ns);
    }

    #[test]
    fn a_put_refuses_credentials_unknown_types_and_open_egress() {
        let db = RuntimeDb::memory();
        let refused = |edit: &dyn Fn(&mut PutSource)| {
            let mut request = github("acme", "repo", "acme/a");
            edit(&mut request);
            assert!(
                matches!(put(&db, &request), Err(SourceError::Invalid(_))),
                "{request:?}"
            );
        };
        // Secret-like configuration and credential references.
        refused(&|r| {
            r.spec.config.insert(
                "api_url".into(),
                ConfigValue::Text("https://x-access-token:ghp_abc@api.github.com".into()),
            );
        });
        refused(&|r| r.spec.credential_ref = "ghp_0123456789abcdef".into());
        refused(&|r| r.spec.credential_ref = "Bearer abc def".into());
        refused(&|r| {
            r.spec
                .config
                .insert("token".into(), ConfigValue::Text("abc".into()));
        });
        refused(&|r| r.spec.credential_ref.clear());
        // Unknown type, a token the type does not own, and egress that does
        // not cover the configured destination.
        refused(&|r| r.spec.connector_version = "9".into());
        refused(&|r| r.source = "gitlab".into());
        refused(&|r| r.source_instance = "Acme/A".into());
        refused(&|r| r.spec.egress = vec!["uploads.github.com".into()]);
        refused(&|r| r.spec.egress.clear());
        // Schedule and placement bounds.
        refused(&|r| r.spec.every_ms = 1_000);
        refused(&|r| {
            r.spec.placement.insert("bad key!".into(), "x".into());
        });
        refused(&|r| r.source_id = "Repo A".into());
        assert_eq!(db.list_sources("acme", "", 10).unwrap(), []);
    }
}
