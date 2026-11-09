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

use std::collections::BTreeMap;

use sekai_source_sdk::{
    ConnectorType, EgressAllowlist, SourceConfig, connector_type, contains_secret_like_text,
};
use sekai_types::governed_transform::validate_placement_labels;
use serde::{Deserialize, Serialize};

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;

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

const COLUMNS: &str = "namespace, source_id, source, source_instance, status, revision, \
    created_at_ms, updated_at_ms, record_json";

/// Writes nothing when the id or the tokens are taken.
const INSERT_SQL: &str = "
INSERT INTO sekai_sources
    (namespace, source_id, source, source_instance, status, revision,
     created_at_ms, updated_at_ms, record_json)
VALUES ($1, $2, $3, $4, 'active', 1, $5, $5, $6)
ON CONFLICT DO NOTHING
RETURNING namespace, source_id, source, source_instance, status, revision,
    created_at_ms, updated_at_ms, record_json";

/// Fenced by the revision read; the tokens must match.
const UPDATE_SQL: &str = "
UPDATE sekai_sources
SET status = 'active', revision = revision + 1, updated_at_ms = $1, record_json = $2
WHERE namespace = $3 AND source_id = $4 AND revision = $5
  AND source = $6 AND source_instance = $7
RETURNING namespace, source_id, source, source_instance, status, revision,
    created_at_ms, updated_at_ms, record_json";

const DISABLE_SQL: &str = "
UPDATE sekai_sources
SET status = 'disabled', revision = revision + 1, updated_at_ms = $1
WHERE namespace = $2 AND source_id = $3 AND status = 'active'
RETURNING namespace, source_id, source, source_instance, status, revision,
    created_at_ms, updated_at_ms, record_json";

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
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_source_sdk::ConfigValue;
    use std::sync::Arc;

    fn github(ns: &str, id: &str, repo: &str) -> PutSource {
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
    }

    #[test]
    fn sqlite_sources_put_get_list_and_disable() {
        contract(Arc::new(RuntimeDb::memory()), "acme");
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
