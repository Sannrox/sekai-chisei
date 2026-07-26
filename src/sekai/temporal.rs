//! Selective bitemporal history storage (ADR 0004 / Issue #225).
//!
//! Current `sekai_objects` / `sekai_links` remain canonical. This module owns
//! the temporal policy registry, monotonic commit revisions, and retained
//! assertion versions. Atomic graph-mutation coupling (#226), historical RPCs
//! (#227), and retention collection (#228) are out of scope here.

use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

const MAX_BACKFILL_SUBJECTS: usize = 10_000;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;

/// How a bound is represented for valid time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalBoundKind {
    Known,
    Unbounded,
    Unknown,
}

impl TemporalBoundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Unbounded => "unbounded",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "known" => Some(Self::Known),
            "unbounded" => Some(Self::Unbounded),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// One endpoint of a valid-time interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalBound {
    pub kind: TemporalBoundKind,
    /// Present only when `kind == Known`. Milliseconds since Unix epoch.
    pub ms: Option<i64>,
}

impl TemporalBound {
    pub fn known(ms: i64) -> Self {
        Self {
            kind: TemporalBoundKind::Known,
            ms: Some(ms),
        }
    }

    pub fn unbounded() -> Self {
        Self {
            kind: TemporalBoundKind::Unbounded,
            ms: None,
        }
    }

    pub fn unknown() -> Self {
        Self {
            kind: TemporalBoundKind::Unknown,
            ms: None,
        }
    }

    fn validate(&self, label: &str) -> Result<(), String> {
        match self.kind {
            TemporalBoundKind::Known => {
                if self.ms.is_none() {
                    return Err(format!("{label}: known bound requires timestamp_ms"));
                }
            }
            TemporalBoundKind::Unbounded | TemporalBoundKind::Unknown => {
                if self.ms.is_some() {
                    return Err(format!(
                        "{label}: {} bound must not carry timestamp_ms",
                        self.kind.as_str()
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Schema surface that may opt into history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalSurfaceKind {
    ObjectType,
    Property,
    Relation,
}

impl TemporalSurfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObjectType => "object_type",
            Self::Property => "property",
            Self::Relation => "relation",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "object_type" => Some(Self::ObjectType),
            "property" => Some(Self::Property),
            "relation" => Some(Self::Relation),
            _ => None,
        }
    }
}

/// Versioned temporal policy for one schema surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalPolicy {
    pub namespace: String,
    pub surface_kind: TemporalSurfaceKind,
    /// Object type name, property path (`kind.prop`), or ontology/relation name.
    pub surface_name: String,
    pub enabled: bool,
    pub policy_version: i64,
    pub preserve_conflicts: bool,
    /// Optional retention window in days; None means inherit later retention work.
    pub retention_days: Option<i32>,
    pub classification_behavior: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// Commit revision at which prospective enablement took effect.
    pub enabled_at_revision: Option<i64>,
}

/// Fields accepted when creating or updating a temporal policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporalPolicyWrite {
    pub namespace: String,
    pub surface_kind: TemporalSurfaceKind,
    pub surface_name: String,
    pub enabled: bool,
    pub preserve_conflicts: bool,
    pub retention_days: Option<i32>,
    pub classification_behavior: String,
}

/// One retained assertion version. Historical payloads are append-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalAssertionVersion {
    pub assertion_id: String,
    pub version: i64,
    pub namespace: String,
    pub subject_id: String,
    pub predicate: String,
    pub object_ref: String,
    pub payload_json: String,
    pub valid_from: TemporalBound,
    pub valid_to: TemporalBound,
    pub recorded_from_revision: i64,
    pub recorded_to_revision: Option<i64>,
    pub recorded_at_ms: i64,
    pub source_observed_at_ms: Option<i64>,
    pub source_id: String,
    pub actor: String,
    pub evidence_ref: String,
    pub lineage_ref: String,
    pub is_backfill: bool,
}

/// Caller-supplied fields for appending a new assertion version.
///
/// Revisions are allocated by the store and must not be supplied here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendAssertionRequest {
    pub assertion_id: String,
    pub namespace: String,
    pub subject_id: String,
    pub predicate: String,
    pub object_ref: String,
    pub payload_json: String,
    pub valid_from: TemporalBound,
    pub valid_to: TemporalBound,
    pub source_observed_at_ms: Option<i64>,
    pub source_id: String,
    pub actor: String,
    pub evidence_ref: String,
    pub lineage_ref: String,
}

/// Bounded baseline backfill of current subjects with unknown domain validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporalBackfillRequest {
    pub namespace: String,
    pub surface_kind: TemporalSurfaceKind,
    pub surface_name: String,
    pub subject_ids: Vec<String>,
    pub predicate: String,
    pub actor: String,
    /// Opaque idempotency key; replaying the same key is a no-op success.
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalBackfillResult {
    pub created: i64,
    pub skipped_existing: i64,
    pub revision: i64,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporalStorageStats {
    pub policy_count: i64,
    pub assertion_version_count: i64,
    pub next_revision: i64,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 {
        return Err(format!("{label} must be non-empty and at most 512 bytes"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(format!("{label} must not contain control characters"));
    }
    Ok(())
}

fn validate_bounds(from: &TemporalBound, to: &TemporalBound) -> Result<(), String> {
    from.validate("valid_from")?;
    to.validate("valid_to")?;
    if let (Some(a), Some(b)) = (from.ms, to.ms)
        && a >= b
    {
        return Err("valid_from_ms must be strictly less than valid_to_ms".into());
    }
    Ok(())
}

fn validate_payload(payload_json: &str) -> Result<(), String> {
    if payload_json.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "payload_json exceeds {MAX_PAYLOAD_BYTES} byte limit"
        ));
    }
    // Ensure payload is valid JSON object or array; reject free-form text.
    let value: serde_json::Value =
        serde_json::from_str(payload_json).map_err(|e| format!("payload_json is not JSON: {e}"))?;
    if !value.is_object() && !value.is_array() {
        return Err("payload_json must be a JSON object or array".into());
    }
    Ok(())
}

fn validate_policy_surface(kind: TemporalSurfaceKind, surface_name: &str) -> Result<(), String> {
    validate_text(surface_name, "surface_name")?;
    if kind == TemporalSurfaceKind::Property && !surface_name.contains('.') {
        return Err("property surface_name must be 'object_type.property' (contains a '.')".into());
    }
    Ok(())
}

impl SekaiDb {
    pub(crate) fn migrate_temporal_history(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_temporal_policies (
                    namespace TEXT NOT NULL DEFAULT '',
                    surface_kind TEXT NOT NULL,
                    surface_name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    policy_version INTEGER NOT NULL DEFAULT 1,
                    preserve_conflicts INTEGER NOT NULL DEFAULT 0,
                    retention_days INTEGER,
                    classification_behavior TEXT NOT NULL DEFAULT 'inherit',
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    enabled_at_revision INTEGER,
                    PRIMARY KEY (namespace, surface_kind, surface_name),
                    CHECK (surface_kind IN ('object_type', 'property', 'relation')),
                    CHECK (enabled IN (0, 1)),
                    CHECK (preserve_conflicts IN (0, 1)),
                    CHECK (policy_version >= 1),
                    CHECK (retention_days IS NULL OR retention_days > 0)
                );
                CREATE TABLE IF NOT EXISTS sekai_temporal_revisions (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    next_revision INTEGER NOT NULL,
                    last_recorded_at_ms INTEGER NOT NULL,
                    CHECK (next_revision >= 1)
                );
                INSERT OR IGNORE INTO sekai_temporal_revisions
                    (id, next_revision, last_recorded_at_ms) VALUES (1, 1, 0);
                CREATE TABLE IF NOT EXISTS sekai_temporal_assertions (
                    assertion_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    namespace TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    object_ref TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    valid_from_kind TEXT NOT NULL,
                    valid_from_ms INTEGER,
                    valid_to_kind TEXT NOT NULL,
                    valid_to_ms INTEGER,
                    recorded_from_revision INTEGER NOT NULL,
                    recorded_to_revision INTEGER,
                    recorded_at_ms INTEGER NOT NULL,
                    source_observed_at_ms INTEGER,
                    source_id TEXT NOT NULL DEFAULT '',
                    actor TEXT NOT NULL DEFAULT '',
                    evidence_ref TEXT NOT NULL DEFAULT '',
                    lineage_ref TEXT NOT NULL DEFAULT '',
                    is_backfill INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (assertion_id, version),
                    CHECK (version >= 1),
                    CHECK (valid_from_kind IN ('known', 'unbounded', 'unknown')),
                    CHECK (valid_to_kind IN ('known', 'unbounded', 'unknown')),
                    CHECK ((valid_from_kind = 'known') = (valid_from_ms IS NOT NULL)),
                    CHECK ((valid_to_kind = 'known') = (valid_to_ms IS NOT NULL)),
                    CHECK (
                        valid_to_kind != 'known'
                        OR valid_from_kind != 'known'
                        OR valid_from_ms < valid_to_ms
                    ),
                    CHECK (
                        recorded_to_revision IS NULL
                        OR recorded_from_revision < recorded_to_revision
                    ),
                    CHECK (is_backfill IN (0, 1))
                );
                CREATE INDEX IF NOT EXISTS idx_temporal_assertions_as_of
                    ON sekai_temporal_assertions(
                        namespace, subject_id, predicate,
                        recorded_from_revision, recorded_to_revision,
                        valid_from_kind, valid_from_ms, valid_to_kind, valid_to_ms
                    );
                CREATE INDEX IF NOT EXISTS idx_temporal_assertions_subject
                    ON sekai_temporal_assertions(namespace, subject_id, predicate, version);
                CREATE TABLE IF NOT EXISTS sekai_temporal_backfill_runs (
                    idempotency_key TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    surface_kind TEXT NOT NULL,
                    surface_name TEXT NOT NULL,
                    created INTEGER NOT NULL,
                    skipped_existing INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    completed_at_ms INTEGER NOT NULL
                );",
            )
            .map_err(|e| e.to_string())
    }

    /// Upsert a temporal policy. Enabling is prospective: it records the current
    /// next revision and never invents earlier history.
    pub fn upsert_temporal_policy(
        &self,
        write: &TemporalPolicyWrite,
    ) -> Result<TemporalPolicy, String> {
        if !write.namespace.is_empty() {
            validate_text(&write.namespace, "namespace")?;
        }
        validate_policy_surface(write.surface_kind, &write.surface_name)?;
        if let Some(days) = write.retention_days
            && days <= 0
        {
            return Err("retention_days must be positive when set".into());
        }
        let behavior = if write.classification_behavior.is_empty() {
            "inherit".to_string()
        } else {
            validate_text(&write.classification_behavior, "classification_behavior")?;
            write.classification_behavior.clone()
        };
        let now = now_ms();
        let conn = self.conn();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;

        let existing = read_policy_tx(
            &tx,
            &write.namespace,
            write.surface_kind,
            &write.surface_name,
        )?;
        let (policy_version, created_at, enabled_at_revision) = if let Some(prev) = existing {
            let next_version = prev.policy_version + 1;
            let enabled_rev = if write.enabled {
                Some(match prev.enabled_at_revision {
                    Some(r) if prev.enabled => r,
                    _ => allocate_revision_tx(&tx, now)?.0,
                })
            } else {
                prev.enabled_at_revision
            };
            (next_version, prev.created_at_ms, enabled_rev)
        } else {
            let enabled_rev = if write.enabled {
                Some(allocate_revision_tx(&tx, now)?.0)
            } else {
                None
            };
            (1, now, enabled_rev)
        };

        let policy = TemporalPolicy {
            namespace: write.namespace.clone(),
            surface_kind: write.surface_kind,
            surface_name: write.surface_name.clone(),
            enabled: write.enabled,
            policy_version,
            preserve_conflicts: write.preserve_conflicts,
            retention_days: write.retention_days,
            classification_behavior: behavior,
            created_at_ms: created_at,
            updated_at_ms: now,
            enabled_at_revision,
        };
        tx.execute(
            "INSERT INTO sekai_temporal_policies
             (namespace, surface_kind, surface_name, enabled, policy_version,
              preserve_conflicts, retention_days, classification_behavior,
              created_at_ms, updated_at_ms, enabled_at_revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(namespace, surface_kind, surface_name) DO UPDATE SET
               enabled=excluded.enabled,
               policy_version=excluded.policy_version,
               preserve_conflicts=excluded.preserve_conflicts,
               retention_days=excluded.retention_days,
               classification_behavior=excluded.classification_behavior,
               updated_at_ms=excluded.updated_at_ms,
               enabled_at_revision=excluded.enabled_at_revision",
            params![
                policy.namespace,
                policy.surface_kind.as_str(),
                policy.surface_name,
                policy.enabled as i64,
                policy.policy_version,
                policy.preserve_conflicts as i64,
                policy.retention_days,
                policy.classification_behavior,
                policy.created_at_ms,
                policy.updated_at_ms,
                policy.enabled_at_revision,
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        // Return constructed policy without re-acquiring a pool connection
        // (in-memory pool size is 1; nested conn() would hang).
        Ok(policy)
    }

    pub fn get_temporal_policy(
        &self,
        namespace: &str,
        surface_kind: TemporalSurfaceKind,
        surface_name: &str,
    ) -> Result<Option<TemporalPolicy>, String> {
        let conn = self.conn();
        read_policy_tx(&conn, namespace, surface_kind, surface_name)
    }

    pub fn list_temporal_policies(&self) -> Result<Vec<TemporalPolicy>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT namespace, surface_kind, surface_name, enabled, policy_version,
                        preserve_conflicts, retention_days, classification_behavior,
                        created_at_ms, updated_at_ms, enabled_at_revision
                 FROM sekai_temporal_policies
                 ORDER BY namespace, surface_kind, surface_name",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], row_to_policy)
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    /// True when history is currently enabled for the surface.
    pub fn is_temporal_enabled(
        &self,
        namespace: &str,
        surface_kind: TemporalSurfaceKind,
        surface_name: &str,
    ) -> Result<bool, String> {
        Ok(self
            .get_temporal_policy(namespace, surface_kind, surface_name)?
            .is_some_and(|p| p.enabled))
    }

    /// Allocate the next monotonic commit revision (system-assigned only).
    pub fn allocate_commit_revision(&self) -> Result<(i64, i64), String> {
        let now = now_ms();
        let conn = self.conn();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let allocated = allocate_revision_tx(&tx, now)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(allocated)
    }

    pub fn peek_next_commit_revision(&self) -> Result<i64, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT next_revision FROM sekai_temporal_revisions WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())
    }

    /// Append a new assertion version, closing any open prior version for the
    /// same assertion identity. Revisions are always store-allocated.
    pub fn append_temporal_assertion(
        &self,
        request: &AppendAssertionRequest,
    ) -> Result<TemporalAssertionVersion, String> {
        validate_text(&request.assertion_id, "assertion_id")?;
        if !request.namespace.is_empty() {
            validate_text(&request.namespace, "namespace")?;
        }
        validate_text(&request.subject_id, "subject_id")?;
        validate_text(&request.predicate, "predicate")?;
        validate_bounds(&request.valid_from, &request.valid_to)?;
        validate_payload(&request.payload_json)?;
        if request.object_ref.len() > 512 {
            return Err("object_ref must be at most 512 bytes".into());
        }

        let now = now_ms();
        let conn = self.conn();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;

        let open = open_version_tx(&tx, &request.assertion_id)?;
        let next_version = match &open {
            Some(prev) => {
                if prev.version == i64::MAX {
                    return Err("assertion version overflow".into());
                }
                prev.version + 1
            }
            None => 1,
        };
        let (revision, recorded_at_ms) = allocate_revision_tx(&tx, now)?;
        if let Some(prev) = &open {
            tx.execute(
                "UPDATE sekai_temporal_assertions
                 SET recorded_to_revision = ?1
                 WHERE assertion_id = ?2 AND version = ?3
                   AND recorded_to_revision IS NULL",
                params![revision, request.assertion_id, prev.version],
            )
            .map_err(|e| e.to_string())?;
        }

        let version = TemporalAssertionVersion {
            assertion_id: request.assertion_id.clone(),
            version: next_version,
            namespace: request.namespace.clone(),
            subject_id: request.subject_id.clone(),
            predicate: request.predicate.clone(),
            object_ref: request.object_ref.clone(),
            payload_json: request.payload_json.clone(),
            valid_from: request.valid_from.clone(),
            valid_to: request.valid_to.clone(),
            recorded_from_revision: revision,
            recorded_to_revision: None,
            recorded_at_ms,
            source_observed_at_ms: request.source_observed_at_ms,
            source_id: request.source_id.clone(),
            actor: request.actor.clone(),
            evidence_ref: request.evidence_ref.clone(),
            lineage_ref: request.lineage_ref.clone(),
            is_backfill: false,
        };
        insert_assertion_tx(&tx, &version)?;
        tx.commit().map_err(|e| e.to_string())?;
        // Avoid nested pool acquire while `conn` is still held.
        Ok(version)
    }

    pub fn get_temporal_assertion(
        &self,
        assertion_id: &str,
        version: i64,
    ) -> Result<Option<TemporalAssertionVersion>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT assertion_id, version, namespace, subject_id, predicate, object_ref,
                    payload_json, valid_from_kind, valid_from_ms, valid_to_kind, valid_to_ms,
                    recorded_from_revision, recorded_to_revision, recorded_at_ms,
                    source_observed_at_ms, source_id, actor, evidence_ref, lineage_ref,
                    is_backfill
             FROM sekai_temporal_assertions
             WHERE assertion_id = ?1 AND version = ?2",
            params![assertion_id, version],
            row_to_assertion,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_temporal_assertions_for_subject(
        &self,
        namespace: &str,
        subject_id: &str,
        predicate: &str,
    ) -> Result<Vec<TemporalAssertionVersion>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT assertion_id, version, namespace, subject_id, predicate, object_ref,
                        payload_json, valid_from_kind, valid_from_ms, valid_to_kind, valid_to_ms,
                        recorded_from_revision, recorded_to_revision, recorded_at_ms,
                        source_observed_at_ms, source_id, actor, evidence_ref, lineage_ref,
                        is_backfill
                 FROM sekai_temporal_assertions
                 WHERE namespace = ?1 AND subject_id = ?2 AND predicate = ?3
                 ORDER BY assertion_id, version",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![namespace, subject_id, predicate], row_to_assertion)
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    /// Explicit bounded baseline backfill. Domain validity is always `unknown`.
    /// Unbounded (empty) subject lists are rejected. Idempotent by key.
    pub fn backfill_temporal_baseline(
        &self,
        request: &TemporalBackfillRequest,
    ) -> Result<TemporalBackfillResult, String> {
        if !request.namespace.is_empty() {
            validate_text(&request.namespace, "namespace")?;
        }
        validate_policy_surface(request.surface_kind, &request.surface_name)?;
        validate_text(&request.predicate, "predicate")?;
        validate_text(&request.actor, "actor")?;
        validate_text(&request.idempotency_key, "idempotency_key")?;
        if request.subject_ids.is_empty() {
            return Err(
                "backfill subject_ids must be non-empty (unbounded backfill rejected)".into(),
            );
        }
        if request.subject_ids.len() > MAX_BACKFILL_SUBJECTS {
            return Err(format!(
                "backfill subject_ids exceeds bound of {MAX_BACKFILL_SUBJECTS}"
            ));
        }
        for subject in &request.subject_ids {
            validate_text(subject, "subject_id")?;
        }

        let policy = self
            .get_temporal_policy(
                &request.namespace,
                request.surface_kind,
                &request.surface_name,
            )?
            .ok_or_else(|| "temporal policy must exist before backfill".to_string())?;
        if !policy.enabled {
            return Err("temporal policy is disabled; enable before backfill".into());
        }

        let now = now_ms();
        let conn = self.conn();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;

        if let Some(prior) = tx
            .query_row(
                "SELECT created, skipped_existing, revision FROM sekai_temporal_backfill_runs
                 WHERE idempotency_key = ?1",
                params![request.idempotency_key],
                |row| {
                    Ok(TemporalBackfillResult {
                        created: row.get(0)?,
                        skipped_existing: row.get(1)?,
                        revision: row.get(2)?,
                        idempotent_replay: true,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())?
        {
            return Ok(prior);
        }

        let (revision, recorded_at_ms) = allocate_revision_tx(&tx, now)?;
        let mut created = 0i64;
        let mut skipped = 0i64;

        for subject_id in &request.subject_ids {
            let assertion_id = format!(
                "backfill:{}:{}:{}:{}",
                request.namespace, request.surface_name, request.predicate, subject_id
            );
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM sekai_temporal_assertions WHERE assertion_id = ?1
                     )",
                    params![assertion_id],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if exists {
                skipped += 1;
                continue;
            }
            insert_assertion_tx(
                &tx,
                &TemporalAssertionVersion {
                    assertion_id,
                    version: 1,
                    namespace: request.namespace.clone(),
                    subject_id: subject_id.clone(),
                    predicate: request.predicate.clone(),
                    object_ref: String::new(),
                    payload_json: "{}".into(),
                    valid_from: TemporalBound::unknown(),
                    valid_to: TemporalBound::unknown(),
                    recorded_from_revision: revision,
                    recorded_to_revision: None,
                    recorded_at_ms,
                    source_observed_at_ms: None,
                    source_id: "backfill".into(),
                    actor: request.actor.clone(),
                    evidence_ref: String::new(),
                    lineage_ref: String::new(),
                    is_backfill: true,
                },
            )?;
            created += 1;
        }

        tx.execute(
            "INSERT INTO sekai_temporal_backfill_runs
             (idempotency_key, namespace, surface_kind, surface_name,
              created, skipped_existing, revision, completed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.idempotency_key,
                request.namespace,
                request.surface_kind.as_str(),
                request.surface_name,
                created,
                skipped,
                revision,
                now,
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;

        Ok(TemporalBackfillResult {
            created,
            skipped_existing: skipped,
            revision,
            idempotent_replay: false,
        })
    }

    pub fn temporal_storage_stats(&self) -> Result<TemporalStorageStats, String> {
        let conn = self.conn();
        let policy_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sekai_temporal_policies", [], |r| {
                r.get(0)
            })
            .map_err(|e| e.to_string())?;
        let assertion_version_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sekai_temporal_assertions", [], |r| {
                r.get(0)
            })
            .map_err(|e| e.to_string())?;
        let next_revision: i64 = conn
            .query_row(
                "SELECT next_revision FROM sekai_temporal_revisions WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        Ok(TemporalStorageStats {
            policy_count,
            assertion_version_count,
            next_revision,
        })
    }

    /// Reject any attempt to write a caller-chosen recorded revision.
    pub fn reject_caller_supplied_revision(revision: Option<i64>) -> Result<(), String> {
        if revision.is_some() {
            return Err(
                "recorded revisions are system-assigned and cannot be caller-supplied".into(),
            );
        }
        Ok(())
    }
}

fn allocate_revision_tx(tx: &Transaction<'_>, now_ms: i64) -> Result<(i64, i64), String> {
    let next: i64 = tx
        .query_row(
            "SELECT next_revision FROM sekai_temporal_revisions WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    let updated = tx
        .execute(
            "UPDATE sekai_temporal_revisions
             SET next_revision = ?1, last_recorded_at_ms = ?2
             WHERE id = 1 AND next_revision = ?3",
            params![next + 1, now_ms, next],
        )
        .map_err(|e| e.to_string())?;
    if updated != 1 {
        return Err("failed to allocate commit revision (concurrent update)".into());
    }
    Ok((next, now_ms))
}

fn read_policy_tx(
    conn: &rusqlite::Connection,
    namespace: &str,
    surface_kind: TemporalSurfaceKind,
    surface_name: &str,
) -> Result<Option<TemporalPolicy>, String> {
    conn.query_row(
        "SELECT namespace, surface_kind, surface_name, enabled, policy_version,
                preserve_conflicts, retention_days, classification_behavior,
                created_at_ms, updated_at_ms, enabled_at_revision
         FROM sekai_temporal_policies
         WHERE namespace = ?1 AND surface_kind = ?2 AND surface_name = ?3",
        params![namespace, surface_kind.as_str(), surface_name],
        row_to_policy,
    )
    .optional()
    .map_err(|e| e.to_string())
}

fn open_version_tx(
    tx: &Transaction<'_>,
    assertion_id: &str,
) -> Result<Option<TemporalAssertionVersion>, String> {
    tx.query_row(
        "SELECT assertion_id, version, namespace, subject_id, predicate, object_ref,
                payload_json, valid_from_kind, valid_from_ms, valid_to_kind, valid_to_ms,
                recorded_from_revision, recorded_to_revision, recorded_at_ms,
                source_observed_at_ms, source_id, actor, evidence_ref, lineage_ref,
                is_backfill
         FROM sekai_temporal_assertions
         WHERE assertion_id = ?1 AND recorded_to_revision IS NULL
         ORDER BY version DESC
         LIMIT 1",
        params![assertion_id],
        row_to_assertion,
    )
    .optional()
    .map_err(|e| e.to_string())
}

fn insert_assertion_tx(
    tx: &Transaction<'_>,
    version: &TemporalAssertionVersion,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_temporal_assertions
         (assertion_id, version, namespace, subject_id, predicate, object_ref, payload_json,
          valid_from_kind, valid_from_ms, valid_to_kind, valid_to_ms,
          recorded_from_revision, recorded_to_revision, recorded_at_ms,
          source_observed_at_ms, source_id, actor, evidence_ref, lineage_ref, is_backfill)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        params![
            version.assertion_id,
            version.version,
            version.namespace,
            version.subject_id,
            version.predicate,
            version.object_ref,
            version.payload_json,
            version.valid_from.kind.as_str(),
            version.valid_from.ms,
            version.valid_to.kind.as_str(),
            version.valid_to.ms,
            version.recorded_from_revision,
            version.recorded_to_revision,
            version.recorded_at_ms,
            version.source_observed_at_ms,
            version.source_id,
            version.actor,
            version.evidence_ref,
            version.lineage_ref,
            version.is_backfill as i64,
        ],
    )
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE") || msg.contains("PRIMARY KEY") {
            "duplicate assertion version".into()
        } else {
            msg
        }
    })?;
    Ok(())
}

fn row_to_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<TemporalPolicy> {
    let kind_raw: String = row.get(1)?;
    let surface_kind = TemporalSurfaceKind::parse(&kind_raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            format!("unknown surface_kind {kind_raw}").into(),
        )
    })?;
    Ok(TemporalPolicy {
        namespace: row.get(0)?,
        surface_kind,
        surface_name: row.get(2)?,
        enabled: row.get::<_, i64>(3)? != 0,
        policy_version: row.get(4)?,
        preserve_conflicts: row.get::<_, i64>(5)? != 0,
        retention_days: row.get(6)?,
        classification_behavior: row.get(7)?,
        created_at_ms: row.get(8)?,
        updated_at_ms: row.get(9)?,
        enabled_at_revision: row.get(10)?,
    })
}

fn row_to_assertion(row: &rusqlite::Row<'_>) -> rusqlite::Result<TemporalAssertionVersion> {
    let from_kind_raw: String = row.get(7)?;
    let to_kind_raw: String = row.get(9)?;
    let from_kind = TemporalBoundKind::parse(&from_kind_raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            format!("unknown valid_from_kind {from_kind_raw}").into(),
        )
    })?;
    let to_kind = TemporalBoundKind::parse(&to_kind_raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            rusqlite::types::Type::Text,
            format!("unknown valid_to_kind {to_kind_raw}").into(),
        )
    })?;
    Ok(TemporalAssertionVersion {
        assertion_id: row.get(0)?,
        version: row.get(1)?,
        namespace: row.get(2)?,
        subject_id: row.get(3)?,
        predicate: row.get(4)?,
        object_ref: row.get(5)?,
        payload_json: row.get(6)?,
        valid_from: TemporalBound {
            kind: from_kind,
            ms: row.get(8)?,
        },
        valid_to: TemporalBound {
            kind: to_kind,
            ms: row.get(10)?,
        },
        recorded_from_revision: row.get(11)?,
        recorded_to_revision: row.get(12)?,
        recorded_at_ms: row.get(13)?,
        source_observed_at_ms: row.get(14)?,
        source_id: row.get(15)?,
        actor: row.get(16)?,
        evidence_ref: row.get(17)?,
        lineage_ref: row.get(18)?,
        is_backfill: row.get::<_, i64>(19)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use std::path::PathBuf;

    fn memory_db() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sekai-temporal-{}-{}-{}.db",
            name,
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        path
    }

    fn sample_append(assertion_id: &str, subject: &str) -> AppendAssertionRequest {
        AppendAssertionRequest {
            assertion_id: assertion_id.into(),
            namespace: "ns".into(),
            subject_id: subject.into(),
            predicate: "works_for".into(),
            object_ref: "org-1".into(),
            payload_json: r#"{"employer":"org-1"}"#.into(),
            valid_from: TemporalBound::known(1_700_000_000_000),
            valid_to: TemporalBound::unbounded(),
            source_observed_at_ms: Some(1_699_000_000_000),
            source_id: "src-1".into(),
            actor: "alice".into(),
            evidence_ref: "ev-1".into(),
            lineage_ref: String::new(),
        }
    }

    fn policy_write(
        namespace: &str,
        kind: TemporalSurfaceKind,
        name: &str,
        enabled: bool,
        preserve_conflicts: bool,
        retention_days: Option<i32>,
    ) -> TemporalPolicyWrite {
        TemporalPolicyWrite {
            namespace: namespace.into(),
            surface_kind: kind,
            surface_name: name.into(),
            enabled,
            preserve_conflicts,
            retention_days,
            classification_behavior: "inherit".into(),
        }
    }

    #[test]
    fn fresh_db_has_empty_temporal_structures_and_revision_counter() {
        let db = memory_db();
        let stats = db.temporal_storage_stats().unwrap();
        assert_eq!(stats.policy_count, 0);
        assert_eq!(stats.assertion_version_count, 0);
        assert_eq!(stats.next_revision, 1);
        assert!(db.list_temporal_policies().unwrap().is_empty());
    }

    #[test]
    fn reopen_and_upgrade_preserve_policies_versions_and_revision_order() {
        let path = temp_path("reopen");
        let path_str = path.to_str().unwrap();
        {
            let db = SekaiDb::new(path_str).unwrap();
            db.upsert_temporal_policy(&policy_write(
                "ns",
                TemporalSurfaceKind::Relation,
                "works_for",
                true,
                true,
                Some(90),
            ))
            .unwrap();
            let v1 = db
                .append_temporal_assertion(&sample_append("a1", "ada"))
                .unwrap();
            let v2 = db
                .append_temporal_assertion(&AppendAssertionRequest {
                    payload_json: r#"{"employer":"org-2"}"#.into(),
                    object_ref: "org-2".into(),
                    valid_from: TemporalBound::known(1_700_100_000_000),
                    ..sample_append("a1", "ada")
                })
                .unwrap();
            assert_eq!(v1.version, 1);
            assert_eq!(v2.version, 2);
            assert!(v1.recorded_from_revision < v2.recorded_from_revision);
            // Re-read v1 after the correction closed its recorded interval.
            let v1_closed = db.get_temporal_assertion("a1", 1).unwrap().unwrap();
            assert_eq!(
                v1_closed.recorded_to_revision,
                Some(v2.recorded_from_revision)
            );
        }
        {
            let db = SekaiDb::new(path_str).unwrap();
            let policy = db
                .get_temporal_policy("ns", TemporalSurfaceKind::Relation, "works_for")
                .unwrap()
                .unwrap();
            assert!(policy.enabled);
            assert_eq!(policy.retention_days, Some(90));
            let versions = db
                .list_temporal_assertions_for_subject("ns", "ada", "works_for")
                .unwrap();
            assert_eq!(versions.len(), 2);
            assert_eq!(versions[0].version, 1);
            assert_eq!(versions[1].version, 2);
            assert!(versions[0].recorded_from_revision < versions[1].recorded_from_revision);
            let stats = db.temporal_storage_stats().unwrap();
            assert_eq!(stats.assertion_version_count, 2);
            assert!(stats.next_revision > 2);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn non_temporal_mutations_create_no_history_rows() {
        let db = memory_db();
        let before = db.temporal_storage_stats().unwrap();
        let object = Object {
            id: "obj-1".into(),
            kind: "person".into(),
            name: "Ada".into(),
            namespace: "ns".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        };
        db.create_object_with_audit(&object, "alice").unwrap();
        let after = db.temporal_storage_stats().unwrap();
        assert_eq!(
            before.assertion_version_count,
            after.assertion_version_count
        );
        assert_eq!(after.assertion_version_count, 0);
        assert_eq!(before.next_revision, after.next_revision);
    }

    #[test]
    fn invalid_bounds_and_caller_revision_and_bad_payload_rejected() {
        let db = memory_db();
        assert!(
            SekaiDb::reject_caller_supplied_revision(Some(9))
                .unwrap_err()
                .contains("system-assigned")
        );
        let mut req = sample_append("a1", "ada");
        req.valid_from = TemporalBound::known(100);
        req.valid_to = TemporalBound::known(50);
        assert!(
            db.append_temporal_assertion(&req)
                .unwrap_err()
                .contains("valid_from_ms")
        );

        req.valid_from = TemporalBound {
            kind: TemporalBoundKind::Unknown,
            ms: Some(1),
        };
        req.valid_to = TemporalBound::unbounded();
        assert!(
            db.append_temporal_assertion(&req)
                .unwrap_err()
                .contains("unknown bound")
        );

        req.valid_from = TemporalBound::known(1);
        req.payload_json = "not-json".into();
        assert!(
            db.append_temporal_assertion(&req)
                .unwrap_err()
                .contains("JSON")
        );
    }

    #[test]
    fn prospective_enablement_does_not_invent_earlier_history() {
        let db = memory_db();
        // Existing current-state objects predate policy enablement.
        let object = Object {
            id: "obj-legacy".into(),
            kind: "person".into(),
            name: "Legacy".into(),
            namespace: "ns".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        };
        db.create_object_with_audit(&object, "alice").unwrap();
        let policy = db
            .upsert_temporal_policy(&policy_write(
                "ns",
                TemporalSurfaceKind::ObjectType,
                "person",
                true,
                false,
                None,
            ))
            .unwrap();
        assert!(policy.enabled_at_revision.is_some());
        assert_eq!(
            db.temporal_storage_stats().unwrap().assertion_version_count,
            0
        );
        // No automatic history for pre-existing subjects.
        assert!(
            db.list_temporal_assertions_for_subject("ns", "obj-legacy", "person")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn backfill_is_bounded_idempotent_and_marks_unknown_validity() {
        let db = memory_db();
        db.upsert_temporal_policy(&policy_write(
            "ns",
            TemporalSurfaceKind::Relation,
            "works_for",
            true,
            false,
            None,
        ))
        .unwrap();

        let empty = TemporalBackfillRequest {
            namespace: "ns".into(),
            surface_kind: TemporalSurfaceKind::Relation,
            surface_name: "works_for".into(),
            subject_ids: vec![],
            predicate: "works_for".into(),
            actor: "ops".into(),
            idempotency_key: "bf-1".into(),
        };
        assert!(
            db.backfill_temporal_baseline(&empty)
                .unwrap_err()
                .contains("non-empty")
        );

        let req = TemporalBackfillRequest {
            namespace: "ns".into(),
            surface_kind: TemporalSurfaceKind::Relation,
            surface_name: "works_for".into(),
            subject_ids: vec!["ada".into(), "grace".into()],
            predicate: "works_for".into(),
            actor: "ops".into(),
            idempotency_key: "bf-1".into(),
        };
        let first = db.backfill_temporal_baseline(&req).unwrap();
        assert_eq!(first.created, 2);
        assert!(!first.idempotent_replay);
        let versions = db
            .list_temporal_assertions_for_subject("ns", "ada", "works_for")
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions[0].is_backfill);
        assert_eq!(versions[0].valid_from.kind, TemporalBoundKind::Unknown);
        assert_eq!(versions[0].valid_to.kind, TemporalBoundKind::Unknown);

        let second = db.backfill_temporal_baseline(&req).unwrap();
        assert!(second.idempotent_replay);
        assert_eq!(second.created, first.created);
        assert_eq!(
            db.temporal_storage_stats().unwrap().assertion_version_count,
            2
        );
    }

    #[test]
    fn disable_stops_new_policy_enablement_flag_but_retains_versions() {
        let db = memory_db();
        db.upsert_temporal_policy(&policy_write(
            "ns",
            TemporalSurfaceKind::Relation,
            "works_for",
            true,
            false,
            None,
        ))
        .unwrap();
        db.append_temporal_assertion(&sample_append("a1", "ada"))
            .unwrap();
        let disabled = db
            .upsert_temporal_policy(&policy_write(
                "ns",
                TemporalSurfaceKind::Relation,
                "works_for",
                false,
                false,
                None,
            ))
            .unwrap();
        assert!(!disabled.enabled);
        assert_eq!(
            db.temporal_storage_stats().unwrap().assertion_version_count,
            1
        );
        // Storage still allows explicit append (mutation coupling is #226);
        // policy flag is what callers consult.
        assert!(
            !db.is_temporal_enabled("ns", TemporalSurfaceKind::Relation, "works_for")
                .unwrap()
        );
    }

    #[test]
    fn storage_cost_at_selective_coverage_stays_near_current_only() {
        // Small in-process check complementary to scripts/temporal_semantics_spike.sh.
        let path_current = temp_path("cost-current");
        let path_selective = temp_path("cost-selective");
        // Keep the fixture small enough for debug-unit runtime while still
        // exercising selective coverage vs current-only file size.
        let n = 400usize;
        let coverage = 40usize; // 10%

        {
            let db = SekaiDb::new(path_current.to_str().unwrap()).unwrap();
            for i in 0..n {
                let object = Object {
                    id: format!("obj-{i:05}"),
                    kind: "item".into(),
                    name: format!("item-{i}"),
                    namespace: "default".into(),
                    external_id: String::new(),
                    properties: Default::default(),
                    created: i as i64,
                    updated: i as i64,
                };
                db.create_object_with_audit(&object, "bench").unwrap();
            }
        }
        {
            let db = SekaiDb::new(path_selective.to_str().unwrap()).unwrap();
            db.upsert_temporal_policy(&policy_write(
                "default",
                TemporalSurfaceKind::Property,
                "item.value",
                true,
                false,
                None,
            ))
            .unwrap();
            for i in 0..n {
                let object = Object {
                    id: format!("obj-{i:05}"),
                    kind: "item".into(),
                    name: format!("item-{i}"),
                    namespace: "default".into(),
                    external_id: String::new(),
                    properties: Default::default(),
                    created: i as i64,
                    updated: i as i64,
                };
                db.create_object_with_audit(&object, "bench").unwrap();
                if i < coverage {
                    db.append_temporal_assertion(&AppendAssertionRequest {
                        assertion_id: format!("assert-{i:05}"),
                        namespace: "default".into(),
                        subject_id: format!("obj-{i:05}"),
                        predicate: "item.value".into(),
                        object_ref: String::new(),
                        payload_json: format!(r#"{{"value":{i}}}"#),
                        valid_from: TemporalBound::known(0),
                        valid_to: TemporalBound::unbounded(),
                        source_observed_at_ms: None,
                        source_id: "bench".into(),
                        actor: "bench".into(),
                        evidence_ref: String::new(),
                        lineage_ref: String::new(),
                    })
                    .unwrap();
                }
            }
        }

        // Checkpoint WAL into main file so sizes are comparable.
        for path in [&path_current, &path_selective] {
            let conn = rusqlite::Connection::open(path).unwrap();
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
        let current_bytes = std::fs::metadata(&path_current).unwrap().len() as f64;
        let selective_bytes = std::fs::metadata(&path_selective).unwrap().len() as f64;
        let ratio = selective_bytes / current_bytes;
        // Directional budget: 10% coverage should stay well under 2x current-only.
        assert!(
            ratio < 2.0,
            "selective/current ratio {ratio} (current={current_bytes}, selective={selective_bytes}) exceeds budget"
        );
        let _ = std::fs::remove_file(&path_current);
        let _ = std::fs::remove_file(&path_selective);
        let _ = std::fs::remove_file(format!("{}-wal", path_current.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path_current.display()));
        let _ = std::fs::remove_file(format!("{}-wal", path_selective.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path_selective.display()));
    }
}
