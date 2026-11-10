use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use crate::sekai::classification_lattice::ClassificationLattice;
use crate::sekai::dataset::Dataset;
use crate::sekai::markings::{
    MarkingDecision, deny_unmarked_enabled, env_deny_unmarked, is_trusted_service_principal,
    namespace_deny_unmarked, object_is_unmarked, object_marking_token, unmarked_access_decision,
};
use crate::sekai::search_index::{
    ANALYZER_VERSION, SEARCH_CHECKPOINT_CONFLICT, SEARCH_REBUILD_IN_PROGRESS, SearchCandidate,
    SearchCandidateQuery, SearchCatchUpReport, SearchCheckpoint, SearchDatasetDump, SearchDocument,
    SearchDocumentKey, SearchIndex, SearchIndexDump, SearchIndexError, SearchIndexStatus,
    SearchObjectDump, SearchQueryMode, SearchRebuildReport, SearchSourceKind, VectorCandidate,
    VectorCandidateQuery, acl_allows, dataset_catalog_digest, dataset_classification_allows,
    dataset_content_digest, exact_vector_candidates, fts_query, indexed_search_text,
    live_object_match_fields, object_content_digest, object_text_properties, policy_attributes,
    policy_marking_allows, purpose_allows, text_matches_query,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

/// The search index this plane reads and writes (#2250). Planes from before
/// the fenced catch-up keep the unsuffixed tables in [`LEGACY_SCHEMA`], so
/// the two never write each other's index; both follow the object-change
/// feed and the dataset catalog. The legacy tables are retired and dropped
/// in a later release. Mirrors PostgreSQL migration 0154.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sekai_search_checkpoint_v2 (
    namespace TEXT PRIMARY KEY,
    analyzer_version TEXT NOT NULL,
    last_change_rowid INTEGER NOT NULL DEFAULT 0,
    last_generation INTEGER NOT NULL DEFAULT 0,
    dataset_catalog_digest TEXT NOT NULL DEFAULT '',
    indexed_at_ms INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sekai_search_object_v2 (
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    access_marking TEXT NOT NULL DEFAULT '',
    policy_attributes TEXT NOT NULL DEFAULT '{}',
    content_digest TEXT NOT NULL,
    indexed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, object_id)
);
CREATE TABLE IF NOT EXISTS sekai_search_object_text_v2 (
    id INTEGER PRIMARY KEY,
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    property TEXT NOT NULL,
    text TEXT NOT NULL,
    UNIQUE (namespace, object_id, property)
);
CREATE TABLE IF NOT EXISTS sekai_search_dataset_v2 (
    namespace TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    name TEXT NOT NULL,
    bound_object_id TEXT NOT NULL DEFAULT '',
    bound_access_marking TEXT NOT NULL DEFAULT '',
    bound_policy_attributes TEXT NOT NULL DEFAULT '{}',
    columns TEXT NOT NULL DEFAULT '[]',
    content_digest TEXT NOT NULL,
    indexed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, dataset_id)
);
CREATE TABLE IF NOT EXISTS sekai_search_dataset_text_v2 (
    id INTEGER PRIMARY KEY,
    namespace TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    field TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    UNIQUE (namespace, dataset_id, field)
);
CREATE VIRTUAL TABLE IF NOT EXISTS sekai_search_object_v2_fts USING fts5(
    property UNINDEXED,
    text,
    content='sekai_search_object_text_v2',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE VIRTUAL TABLE IF NOT EXISTS sekai_search_dataset_v2_fts USING fts5(
    field UNINDEXED,
    text,
    content='sekai_search_dataset_text_v2',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
";

/// The index of planes from before #2250, unchanged: still created so an
/// older plane (during a rolling deploy or after a rollback) finds its
/// tables, and read once to seed [`SCHEMA`]. Never written by this plane.
const LEGACY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sekai_search_checkpoint (
    namespace TEXT PRIMARY KEY,
    analyzer_version TEXT NOT NULL,
    last_change_rowid INTEGER NOT NULL DEFAULT 0,
    last_generation INTEGER NOT NULL DEFAULT 0,
    dataset_catalog_digest TEXT NOT NULL DEFAULT '',
    indexed_at_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sekai_search_object (
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    access_marking TEXT NOT NULL DEFAULT '',
    policy_attributes TEXT NOT NULL DEFAULT '{}',
    content_digest TEXT NOT NULL,
    indexed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, object_id)
);
CREATE TABLE IF NOT EXISTS sekai_search_object_text (
    id INTEGER PRIMARY KEY,
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    property TEXT NOT NULL,
    text TEXT NOT NULL,
    UNIQUE (namespace, object_id, property)
);
CREATE TABLE IF NOT EXISTS sekai_search_dataset (
    namespace TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    name TEXT NOT NULL,
    bound_object_id TEXT NOT NULL DEFAULT '',
    bound_access_marking TEXT NOT NULL DEFAULT '',
    bound_policy_attributes TEXT NOT NULL DEFAULT '{}',
    columns TEXT NOT NULL DEFAULT '[]',
    content_digest TEXT NOT NULL,
    indexed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, dataset_id)
);
CREATE TABLE IF NOT EXISTS sekai_search_dataset_text (
    id INTEGER PRIMARY KEY,
    namespace TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    field TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    UNIQUE (namespace, dataset_id, field)
);
CREATE VIRTUAL TABLE IF NOT EXISTS sekai_search_object_fts USING fts5(
    property UNINDEXED,
    text,
    content='sekai_search_object_text',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE VIRTUAL TABLE IF NOT EXISTS sekai_search_dataset_fts USING fts5(
    field UNINDEXED,
    text,
    content='sekai_search_dataset_text',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
";

/// Copy the legacy index into the new tables, once, as they are created.
/// Text rows keep their ids, so the full-text index is refilled from them.
const SEED_FROM_LEGACY: &str = "
INSERT INTO sekai_search_checkpoint_v2
    (namespace, analyzer_version, last_change_rowid, last_generation,
     dataset_catalog_digest, indexed_at_ms)
SELECT namespace, analyzer_version, last_change_rowid, last_generation,
       dataset_catalog_digest, indexed_at_ms
FROM sekai_search_checkpoint;
INSERT INTO sekai_search_object_v2
    (namespace, object_id, kind, access_marking, policy_attributes,
     content_digest, indexed_at_ms)
SELECT namespace, object_id, kind, access_marking, policy_attributes,
       content_digest, indexed_at_ms
FROM sekai_search_object;
INSERT INTO sekai_search_object_text_v2 (id, namespace, object_id, property, text)
SELECT id, namespace, object_id, property, text FROM sekai_search_object_text;
INSERT INTO sekai_search_dataset_v2
    (namespace, dataset_id, name, bound_object_id, bound_access_marking,
     bound_policy_attributes, columns, content_digest, indexed_at_ms)
SELECT namespace, dataset_id, name, bound_object_id, bound_access_marking,
       bound_policy_attributes, columns, content_digest, indexed_at_ms
FROM sekai_search_dataset;
INSERT INTO sekai_search_dataset_text_v2
    (id, namespace, dataset_id, field, classification, text)
SELECT id, namespace, dataset_id, field, classification, text
FROM sekai_search_dataset_text;
";

fn lattice_marking_allows(
    marking: &str,
    query: &SearchCandidateQuery,
    lattice: Option<&ClassificationLattice>,
) -> bool {
    policy_marking_allows(marking, &query.policy, lattice)
}

impl SekaiDb {
    pub fn migrate_search_index(&self) -> Result<(), String> {
        let mut conn = self.conn();
        conn.execute_batch(LEGACY_SCHEMA)
            .map_err(|error| error.to_string())?;
        // Columns the legacy dataset table gained before it was retired.
        for column in [
            "bound_access_marking TEXT NOT NULL DEFAULT ''",
            "bound_policy_attributes TEXT NOT NULL DEFAULT '{}'",
            "bound_object_id TEXT NOT NULL DEFAULT ''",
        ] {
            let _ = conn.execute(
                &format!("ALTER TABLE sekai_search_dataset ADD COLUMN {column}"),
                [],
            );
        }
        // One writer creates and seeds the new index; a second plane opening
        // the same file waits, then finds it created.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let created: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'sekai_search_checkpoint_v2')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        tx.execute_batch(SCHEMA)
            .map_err(|error| error.to_string())?;
        if !created {
            tx.execute_batch(SEED_FROM_LEGACY)
                .map_err(|error| error.to_string())?;
            for (table, label) in [
                ("sekai_search_object", "property"),
                ("sekai_search_dataset", "field"),
            ] {
                let rows = {
                    let mut stmt = tx
                        .prepare(&format!("SELECT id, {label}, text FROM {table}_text_v2"))
                        .map_err(|error| error.to_string())?;
                    stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })
                    .map_err(|error| error.to_string())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?
                };
                for (id, field, text) in rows {
                    tx.execute(
                        &format!(
                            "INSERT INTO {table}_v2_fts(rowid, {label}, text) VALUES (?1, ?2, ?3)"
                        ),
                        params![id, field, indexed_search_text(&text)],
                    )
                    .map_err(|error| error.to_string())?;
                }
            }
        }
        tx.commit().map_err(|error| error.to_string())
    }

    fn subjects_include_team_principal(&self, subjects: &[String]) -> Result<bool, String> {
        if subjects.is_empty() {
            return Ok(false);
        }
        let conn = self.conn();
        for subject in subjects {
            let found: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sekai_team_principals WHERE principal = ?1)",
                    rusqlite::params![subject],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if found {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn compiled_object_security_allows(
        &self,
        namespace: &str,
        object_id: &str,
        _kind: &str,
        fields: &BTreeSet<String>,
        query: &SearchCandidateQuery,
    ) -> Result<Option<(String, BTreeSet<String>)>, String> {
        let Some(object) = self.get_object(object_id)? else {
            return Ok(None);
        };
        if object.namespace != namespace {
            return Ok(None);
        }
        if object_is_unmarked(&object) {
            let namespace_object = self.find_by_external_id(&format!("namespace:{namespace}"))?;
            let deny = deny_unmarked_enabled(
                env_deny_unmarked(),
                namespace_deny_unmarked(namespace_object.as_ref()),
            );
            let trusted = query
                .policy
                .subjects
                .iter()
                .any(|subject| is_trusted_service_principal(subject));
            let grants = self.list_grants(&object.id)?;
            let explicit = grants.iter().any(|grant| {
                query
                    .policy
                    .subjects
                    .iter()
                    .any(|subject| subject == &grant.principal)
            });
            if unmarked_access_decision(deny, trusted, explicit) == MarkingDecision::Deny {
                return Ok(None);
            }
        }
        if !fields.is_empty()
            && !query.policy.kinds.is_empty()
            && !query.policy.kinds.iter().any(|item| item == &object.kind)
        {
            return Ok(None);
        }
        let marking = object_marking_token(&object).unwrap_or_default();
        let lattice = self.get_classification_lattice(namespace)?;
        if !lattice_marking_allows(marking, query, lattice.as_ref()) {
            return Ok(None);
        }
        let attributes = policy_attributes(&object);
        if !acl_allows(&attributes, &query.policy.subjects) {
            return Ok(None);
        }
        if !purpose_allows(
            &attributes,
            query.policy.purpose.as_deref(),
            query.policy.purpose_authorized,
        ) {
            return Ok(None);
        }
        let mut visible = if fields.is_empty() {
            BTreeSet::new()
        } else {
            let live = live_object_match_fields(&object, &query.text);
            fields.intersection(&live).cloned().collect()
        };
        if let Some(allowed) = &query.policy.visible_property_names {
            if allowed.is_empty() {
                return Ok(None);
            }
            visible.retain(|field| allowed.iter().any(|item| item == field));
        }
        if !fields.is_empty() && visible.is_empty() {
            return Ok(None);
        }
        let live_kind = object.kind.clone();
        let policy = {
            let conn = self.conn();
            crate::db::object_security::load_active_policy_sqlite(&conn, namespace, &object.kind)?
        };
        if let Some(policy) = policy {
            let context = crate::sekai::object_security::PrincipalPolicyContext {
                subjects: query.policy.subjects.clone(),
                scopes: query.policy.scopes.clone(),
                delegated_subject: None,
            }
            .normalized();
            if let Some(required) = &policy.required_purpose
                && (!query.policy.purpose_authorized
                    || query.policy.purpose.as_deref() != Some(required.as_str()))
            {
                return Ok(None);
            }
            if !policy.allows(
                &context,
                &object,
                crate::sekai::object_security::ObjectSecurityOperation::Read,
            ) {
                return Ok(None);
            }
            if policy.property_grants_enforced() {
                visible.retain(|field| {
                    policy.allows_property_access(
                        field,
                        crate::sekai::object_security::PropertyGrantAccess::Read,
                    )
                });
            }
            if policy.value_instance_grants_enforced() {
                visible.retain(|field| {
                    let value = if field == "name" {
                        object.name.as_str()
                    } else {
                        object
                            .properties
                            .get(field)
                            .map(String::as_str)
                            .unwrap_or("")
                    };
                    policy.allows_value_instance_access(
                        &object.id,
                        field,
                        value,
                        crate::sekai::object_security::PropertyGrantAccess::Read,
                    )
                });
            }
        }
        if fields.is_empty() {
            return Ok(Some((live_kind, visible)));
        }
        if visible.is_empty() {
            return Ok(None);
        }
        Ok(Some((live_kind, visible)))
    }

    fn grant_allows(&self, object_id: &str, subjects: &[String]) -> Result<bool, String> {
        if subjects
            .iter()
            .any(|subject| subject == "root" || subject == "local")
        {
            return Ok(true);
        }
        if object_id.is_empty() {
            return Ok(false);
        }
        let grants = self.list_grants(object_id)?;
        if grants.is_empty() {
            return Ok(true);
        }
        let now_ms = crate::sekai::security::unix_now_ms();
        Ok(grants.iter().any(|grant| {
            grant.is_active(now_ms).is_ok()
                && subjects.iter().any(|subject| subject == &grant.principal)
        }))
    }

    fn bound_dataset_policy(&self, dataset: &Dataset) -> Result<(String, String), String> {
        match self.get_object(&dataset.object_id)? {
            Some(object) => Ok((
                object_marking_token(&object)
                    .unwrap_or_default()
                    .to_string(),
                serde_json::to_string(&policy_attributes(&object))
                    .map_err(|error| error.to_string())?,
            )),
            None => Ok((String::new(), "{}".into())),
        }
    }

    fn read_search_checkpoint(&self, namespace: &str) -> Result<Option<SearchCheckpoint>, String> {
        self.conn()
            .query_row(
                "SELECT analyzer_version, last_change_rowid, last_generation,
                        dataset_catalog_digest, indexed_at_ms, revision
                 FROM sekai_search_checkpoint_v2 WHERE namespace = ?1",
                params![namespace],
                |row| {
                    Ok(SearchCheckpoint {
                        analyzer_version: row.get(0)?,
                        last_change_rowid: row.get::<_, i64>(1)?.max(0) as u64,
                        last_generation: row.get::<_, i64>(2)?.max(0) as u64,
                        dataset_catalog_digest: row.get(3)?,
                        indexed_at_ms: row.get(4)?,
                        revision: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    /// Run `write` in an immediate transaction after a compare-and-bump of
    /// the namespace checkpoint revision that also sets `fields` and stamps
    /// `indexed_at_ms` (the rebuild lease). Returns the new revision.
    fn fenced_search_write(
        &self,
        namespace: &str,
        revision: i64,
        now_ms: i64,
        fields: &CheckpointFields<'_>,
        write: impl FnOnce(&Connection) -> Result<(), String>,
    ) -> Result<i64, SearchIndexError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let bumped = tx
            .execute(
                "UPDATE sekai_search_checkpoint_v2
                 SET revision = revision + 1, indexed_at_ms = ?3,
                     analyzer_version = COALESCE(?4, analyzer_version),
                     last_change_rowid = COALESCE(?5, last_change_rowid),
                     last_generation = COALESCE(?6, last_generation),
                     dataset_catalog_digest = COALESCE(?7, dataset_catalog_digest)
                 WHERE namespace = ?1 AND revision = ?2",
                params![
                    namespace,
                    revision,
                    now_ms,
                    fields.analyzer_version,
                    fields.last_change_rowid,
                    fields.last_generation,
                    fields.dataset_catalog_digest
                ],
            )
            .map_err(|error| error.to_string())?;
        let created = bumped == 0
            && revision == 0
            && tx
                .execute(
                    "INSERT INTO sekai_search_checkpoint_v2
                     (namespace, analyzer_version, last_change_rowid, last_generation,
                      dataset_catalog_digest, revision, indexed_at_ms)
                     VALUES (?1, COALESCE(?3, ''), COALESCE(?4, 0), COALESCE(?5, 0),
                             COALESCE(?6, ''), 1, ?2)
                     ON CONFLICT(namespace) DO NOTHING",
                    params![
                        namespace,
                        now_ms,
                        fields.analyzer_version,
                        fields.last_change_rowid,
                        fields.last_generation,
                        fields.dataset_catalog_digest
                    ],
                )
                .map_err(|error| error.to_string())?
                == 1;
        if bumped != 1 && !created {
            return Err(SearchIndexError::Unavailable(
                SEARCH_CHECKPOINT_CONFLICT.into(),
            ));
        }
        write(&tx)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(revision + 1)
    }

    fn replace_object_text_on(
        conn: &Connection,
        namespace: &str,
        object_id: &str,
        properties: &BTreeMap<String, String>,
    ) -> Result<(), String> {
        Self::clear_object_text_on(conn, namespace, object_id)?;
        for (property, text) in properties {
            conn.execute(
                "INSERT INTO sekai_search_object_text_v2 (namespace, object_id, property, text)
                 VALUES (?1, ?2, ?3, ?4)",
                params![namespace, object_id, property, text],
            )
            .map_err(|error| error.to_string())?;
            let id: i64 = conn
                .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            conn.execute(
                "INSERT INTO sekai_search_object_v2_fts(rowid, property, text) VALUES (?1, ?2, ?3)",
                params![id, property, indexed_search_text(text)],
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub(crate) fn clear_object_text_on(
        conn: &Connection,
        namespace: &str,
        object_id: &str,
    ) -> Result<(), String> {
        let mut stmt = conn
            .prepare(
                "SELECT id, property, text FROM sekai_search_object_text_v2
                 WHERE namespace = ?1 AND object_id = ?2",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, object_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(stmt);
        for (id, property, text) in rows {
            conn.execute(
                "INSERT INTO sekai_search_object_v2_fts(sekai_search_object_v2_fts, rowid, property, text)
                 VALUES('delete', ?1, ?2, ?3)",
                params![id, property, indexed_search_text(&text)],
            )
            .map_err(|error| error.to_string())?;
        }
        conn.execute(
            "DELETE FROM sekai_search_object_text_v2 WHERE namespace = ?1 AND object_id = ?2",
            params![namespace, object_id],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn replace_dataset_text_on(
        conn: &Connection,
        namespace: &str,
        dataset: &Dataset,
    ) -> Result<(), String> {
        Self::clear_dataset_text_on(conn, namespace, &dataset.id)?;
        let mut fields = vec![("name".to_string(), String::new(), dataset.name.clone())];
        for column in &dataset.columns {
            fields.push((
                format!("column:{}", column.name),
                column.classification.clone(),
                column.name.clone(),
            ));
        }
        for (field, classification, text) in fields {
            conn.execute(
                "INSERT INTO sekai_search_dataset_text_v2
                 (namespace, dataset_id, field, classification, text)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![namespace, dataset.id, field, classification, text],
            )
            .map_err(|error| error.to_string())?;
            let id: i64 = conn
                .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            conn.execute(
                "INSERT INTO sekai_search_dataset_v2_fts(rowid, field, text) VALUES (?1, ?2, ?3)",
                params![id, field, indexed_search_text(&text)],
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub(crate) fn clear_dataset_text_on(
        conn: &Connection,
        namespace: &str,
        dataset_id: &str,
    ) -> Result<(), String> {
        let mut stmt = conn
            .prepare(
                "SELECT id, field, text FROM sekai_search_dataset_text_v2
                 WHERE namespace = ?1 AND dataset_id = ?2",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, dataset_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(stmt);
        for (id, field, text) in rows {
            conn.execute(
                "INSERT INTO sekai_search_dataset_v2_fts(sekai_search_dataset_v2_fts, rowid, field, text)
                 VALUES('delete', ?1, ?2, ?3)",
                params![id, field, indexed_search_text(&text)],
            )
            .map_err(|error| error.to_string())?;
        }
        conn.execute(
            "DELETE FROM sekai_search_dataset_text_v2 WHERE namespace = ?1 AND dataset_id = ?2",
            params![namespace, dataset_id],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Upsert one object's index row and text; unchanged content is left.
    fn index_object_on(conn: &Connection, object: &Object, now_ms: i64) -> Result<(), String> {
        let digest = object_content_digest(object);
        let existing: Option<String> = conn
            .query_row(
                "SELECT content_digest FROM sekai_search_object_v2
                 WHERE namespace = ?1 AND object_id = ?2",
                params![object.namespace, object.id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing.as_deref() == Some(digest.as_str()) {
            return Ok(());
        }
        let attributes =
            serde_json::to_string(&policy_attributes(object)).map_err(|error| error.to_string())?;
        conn.execute(
            "INSERT INTO sekai_search_object_v2
             (namespace, object_id, kind, access_marking, policy_attributes, content_digest, indexed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(namespace, object_id) DO UPDATE SET
                kind = excluded.kind,
                access_marking = excluded.access_marking,
                policy_attributes = excluded.policy_attributes,
                content_digest = excluded.content_digest,
                indexed_at_ms = excluded.indexed_at_ms",
            params![
                object.namespace,
                object.id,
                object.kind,
                object_marking_token(object).unwrap_or_default(),
                attributes,
                digest,
                now_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        Self::replace_object_text_on(
            conn,
            &object.namespace,
            &object.id,
            &object_text_properties(object),
        )
    }

    /// Upsert one dataset's metadata row and text. `bound` is the bound
    /// object's marking and policy attributes, read before the transaction.
    fn index_dataset_on(
        conn: &Connection,
        namespace: &str,
        dataset: &Dataset,
        (bound_marking, bound_attributes): &(String, String),
        now_ms: i64,
    ) -> Result<(), String> {
        let digest = dataset_content_digest(dataset);
        let existing: Option<String> = conn
            .query_row(
                "SELECT content_digest FROM sekai_search_dataset_v2
                 WHERE namespace = ?1 AND dataset_id = ?2",
                params![namespace, dataset.id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing.as_deref() == Some(digest.as_str()) {
            conn.execute(
                "UPDATE sekai_search_dataset_v2
                 SET bound_access_marking = ?3, bound_policy_attributes = ?4, indexed_at_ms = ?5
                 WHERE namespace = ?1 AND dataset_id = ?2",
                params![
                    namespace,
                    dataset.id,
                    bound_marking,
                    bound_attributes,
                    now_ms
                ],
            )
            .map_err(|error| error.to_string())?;
            return Ok(());
        }
        let columns = serde_json::to_string(
            &dataset
                .columns
                .iter()
                .map(|column| (column.name.clone(), column.classification.clone()))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| error.to_string())?;
        conn.execute(
            "INSERT INTO sekai_search_dataset_v2
             (namespace, dataset_id, name, bound_object_id, bound_access_marking,
              bound_policy_attributes, columns, content_digest, indexed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(namespace, dataset_id) DO UPDATE SET
                name = excluded.name,
                bound_object_id = excluded.bound_object_id,
                bound_access_marking = excluded.bound_access_marking,
                bound_policy_attributes = excluded.bound_policy_attributes,
                columns = excluded.columns,
                content_digest = excluded.content_digest,
                indexed_at_ms = excluded.indexed_at_ms",
            params![
                namespace,
                dataset.id,
                dataset.name,
                dataset.object_id,
                bound_marking,
                bound_attributes,
                columns,
                digest,
                now_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        Self::replace_dataset_text_on(conn, namespace, dataset)
    }

    fn delete_object_on(conn: &Connection, namespace: &str, object_id: &str) -> Result<(), String> {
        Self::clear_object_text_on(conn, namespace, object_id)?;
        conn.execute(
            "DELETE FROM sekai_search_object_v2 WHERE namespace = ?1 AND object_id = ?2",
            params![namespace, object_id],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn delete_dataset_on(
        conn: &Connection,
        namespace: &str,
        dataset_id: &str,
    ) -> Result<(), String> {
        Self::clear_dataset_text_on(conn, namespace, dataset_id)?;
        conn.execute(
            "DELETE FROM sekai_search_dataset_v2 WHERE namespace = ?1 AND dataset_id = ?2",
            params![namespace, dataset_id],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Drop every index row of the namespace, keeping FTS in step.
    fn clear_namespace_on(conn: &Connection, namespace: &str) -> Result<(), String> {
        let ids = |sql: &str| -> Result<Vec<String>, String> {
            let mut stmt = conn.prepare(sql).map_err(|error| error.to_string())?;
            stmt.query_map(params![namespace], |row| row.get(0))
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())
        };
        for object_id in
            ids("SELECT DISTINCT object_id FROM sekai_search_object_text_v2 WHERE namespace = ?1")?
        {
            Self::clear_object_text_on(conn, namespace, &object_id)?;
        }
        for dataset_id in ids(
            "SELECT DISTINCT dataset_id FROM sekai_search_dataset_text_v2 WHERE namespace = ?1",
        )? {
            Self::clear_dataset_text_on(conn, namespace, &dataset_id)?;
        }
        for table in ["sekai_search_object_v2", "sekai_search_dataset_v2"] {
            conn.execute(
                &format!("DELETE FROM {table} WHERE namespace = ?1"),
                params![namespace],
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// An unfenced index write for the [`SearchIndex`] document methods.
    fn search_write(
        &self,
        write: impl FnOnce(&Connection) -> Result<(), String>,
    ) -> Result<(), SearchIndexError> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        write(&tx)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    /// See [`RuntimeDb::ensure_search_checkpoint`].
    pub fn ensure_search_checkpoint(&self, namespace: &str) -> Result<(), String> {
        let conn = self.conn();
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sekai_search_checkpoint_v2 WHERE namespace = ?1)",
                params![namespace],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !exists {
            conn.execute(
                "INSERT INTO sekai_search_checkpoint_v2 (namespace, analyzer_version)
                 VALUES (?1, '') ON CONFLICT(namespace) DO NOTHING",
                params![namespace],
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// See [`RuntimeDb::search_index_namespaces`].
    pub fn search_index_namespaces(
        &self,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT namespace FROM sekai_namespace_object_generation
                 WHERE namespace > ?1
                 UNION
                 SELECT namespace FROM sekai_search_checkpoint_v2 WHERE namespace > ?1
                 ORDER BY namespace LIMIT ?2",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(
            params![after, i64::try_from(limit).unwrap_or(i64::MAX)],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
    }

    pub fn search_index_dump(&self, namespace: &str) -> Result<SearchIndexDump, String> {
        let conn = self.conn();
        let mut objects = BTreeMap::new();
        let mut stmt = conn
            .prepare(
                "SELECT object_id, kind, access_marking, policy_attributes
                 FROM sekai_search_object_v2 WHERE namespace = ?1",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (object_id, kind, access_marking, attributes) =
                row.map_err(|error| error.to_string())?;
            let policy_attributes = serde_json::from_str(&attributes).unwrap_or_default();
            objects.insert(
                object_id,
                SearchObjectDump {
                    kind,
                    access_marking,
                    policy_attributes,
                    properties: BTreeMap::new(),
                },
            );
        }
        let mut text = conn
            .prepare(
                "SELECT object_id, property, text FROM sekai_search_object_text_v2
                 WHERE namespace = ?1 ORDER BY object_id, property",
            )
            .map_err(|error| error.to_string())?;
        let text_rows = text
            .query_map(params![namespace], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in text_rows {
            let (object_id, property, value) = row.map_err(|error| error.to_string())?;
            if let Some(object) = objects.get_mut(&object_id) {
                object.properties.insert(property, value);
            }
        }
        let mut datasets = BTreeMap::new();
        let mut dataset_stmt = conn
            .prepare(
                "SELECT dataset_id, name, bound_object_id, columns
                 FROM sekai_search_dataset_v2 WHERE namespace = ?1",
            )
            .map_err(|error| error.to_string())?;
        let dataset_rows = dataset_stmt
            .query_map(params![namespace], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in dataset_rows {
            let (dataset_id, name, bound_object_id, columns) =
                row.map_err(|error| error.to_string())?;
            datasets.insert(
                dataset_id,
                SearchDatasetDump {
                    name,
                    bound_object_id,
                    columns: serde_json::from_str(&columns).unwrap_or_default(),
                },
            );
        }
        Ok(SearchIndexDump {
            analyzer_version: ANALYZER_VERSION.into(),
            objects,
            datasets,
        })
    }

    #[cfg(any(test, feature = "gateway-test-support"))]
    pub fn purge_object_changes_for_test(&self) -> Result<(), String> {
        self.conn()
            .execute("DELETE FROM sekai_object_changes", [])
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    #[cfg(any(test, feature = "gateway-test-support"))]
    pub fn purge_object_changes_for_object_for_test(&self, object_id: &str) -> Result<(), String> {
        self.conn()
            .execute(
                "DELETE FROM sekai_object_changes WHERE object_id = ?1",
                params![object_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// One catch-up of the namespace; see [`catch_up_namespace`].
    pub fn catch_up_search_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchCatchUpReport, SearchIndexError> {
        catch_up_namespace(self, namespace, now_ms)
    }

    fn query_search_candidates(
        &self,
        query: &SearchCandidateQuery,
    ) -> Result<Vec<SearchCandidate>, SearchIndexError> {
        if query.mode != SearchQueryMode::Text {
            return Err(SearchIndexError::InvalidArgument(
                "only text search is implemented".into(),
            ));
        }
        if query.policy.namespace.trim().is_empty() {
            return Err(SearchIndexError::InvalidArgument(
                "namespace required".into(),
            ));
        }
        if !query.policy.namespace_authorized {
            return Ok(Vec::new());
        }
        let match_query = format!("text : ({})", fts_query(&query.text)?);
        let limit = if query.limit == 0 { 32 } else { query.limit };
        let mut hits = Vec::new();
        if query.source.unwrap_or(SearchSourceKind::Object) == SearchSourceKind::Object
            || query.source.is_none()
        {
            hits.extend(self.query_object_candidates(query, &match_query, limit)?);
        }
        if (query.source == Some(SearchSourceKind::Dataset) || query.source.is_none())
            && hits.len() < limit
        {
            hits.extend(self.query_dataset_candidates(query, &match_query, limit - hits.len())?);
        }
        Ok(hits)
    }

    fn query_object_candidates(
        &self,
        query: &SearchCandidateQuery,
        match_query: &str,
        limit: usize,
    ) -> Result<Vec<SearchCandidate>, SearchIndexError> {
        let lattice = self.get_classification_lattice(&query.policy.namespace)?;
        let conn = self.conn();
        let sql = "
            SELECT f.object_id, f.property, o.kind, o.access_marking, o.policy_attributes
            FROM sekai_search_object_v2_fts fts
            JOIN sekai_search_object_text_v2 f ON f.id = fts.rowid
            JOIN sekai_search_object_v2 o
              ON o.namespace = f.namespace AND o.object_id = f.object_id
            WHERE f.namespace = ?1 AND sekai_search_object_v2_fts MATCH ?2
            ORDER BY f.object_id, f.property";
        let mut stmt = conn.prepare(sql).map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![query.policy.namespace, match_query], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        type ObjectHit = (String, BTreeSet<String>, String, BTreeMap<String, String>);
        let mut grouped: BTreeMap<String, ObjectHit> = BTreeMap::new();
        for row in rows {
            let (object_id, property, kind, marking, attributes) =
                row.map_err(|error| error.to_string())?;
            if !query.policy.kinds.is_empty()
                && !query.policy.kinds.iter().any(|item| item == &kind)
            {
                continue;
            }
            match &query.policy.visible_property_names {
                Some(allowed) if allowed.is_empty() => continue,
                Some(allowed) if !allowed.iter().any(|item| item == &property) => continue,
                _ => {}
            }
            if !lattice_marking_allows(&marking, query, lattice.as_ref()) {
                continue;
            }
            let parsed: BTreeMap<String, String> =
                serde_json::from_str(&attributes).unwrap_or_default();
            if !acl_allows(&parsed, &query.policy.subjects) {
                continue;
            }
            if !purpose_allows(
                &parsed,
                query.policy.purpose.as_deref(),
                query.policy.purpose_authorized,
            ) {
                continue;
            }
            grouped
                .entry(object_id)
                .or_insert_with(|| (kind, BTreeSet::new(), marking, parsed))
                .1
                .insert(property);
        }
        drop(stmt);
        drop(conn);
        let mut hits = Vec::new();
        for (id, (kind, fields, _, _)) in grouped {
            if !self.grant_allows(&id, &query.policy.subjects)? {
                continue;
            }
            let Some((kind, fields)) = self.compiled_object_security_allows(
                &query.policy.namespace,
                &id,
                &kind,
                &fields,
                query,
            )?
            else {
                continue;
            };
            hits.push(SearchCandidate {
                source: SearchSourceKind::Object,
                id,
                kind,
                matched_fields: fields.into_iter().collect(),
                authority: false,
            });
            if hits.len() >= limit {
                break;
            }
        }
        Ok(hits)
    }

    fn query_dataset_candidates(
        &self,
        query: &SearchCandidateQuery,
        match_query: &str,
        limit: usize,
    ) -> Result<Vec<SearchCandidate>, SearchIndexError> {
        if !query.policy.kinds.is_empty()
            && !query.policy.kinds.iter().any(|kind| kind == "dataset")
        {
            return Ok(Vec::new());
        }
        let lattice = self.get_classification_lattice(&query.policy.namespace)?;
        let conn = self.conn();
        let sql = "
            SELECT f.dataset_id, f.field, f.classification, d.bound_access_marking,
                   d.bound_policy_attributes, d.bound_object_id
            FROM sekai_search_dataset_v2_fts fts
            JOIN sekai_search_dataset_text_v2 f ON f.id = fts.rowid
            JOIN sekai_search_dataset_v2 d
              ON d.namespace = f.namespace AND d.dataset_id = f.dataset_id
            WHERE f.namespace = ?1 AND sekai_search_dataset_v2_fts MATCH ?2
            ORDER BY f.dataset_id, f.field";
        let mut stmt = conn.prepare(sql).map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![query.policy.namespace, match_query], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        let mut grouped: BTreeMap<String, (BTreeSet<String>, String)> = BTreeMap::new();
        for row in rows {
            let (
                dataset_id,
                field,
                classification,
                bound_marking,
                bound_attributes,
                bound_object_id,
            ) = row.map_err(|error| error.to_string())?;
            if !lattice_marking_allows(&bound_marking, query, lattice.as_ref()) {
                continue;
            }
            let parsed: BTreeMap<String, String> =
                serde_json::from_str(&bound_attributes).unwrap_or_default();
            if !acl_allows(&parsed, &query.policy.subjects) {
                continue;
            }
            if !purpose_allows(
                &parsed,
                query.policy.purpose.as_deref(),
                query.policy.purpose_authorized,
            ) {
                continue;
            }
            if !dataset_classification_allows(&classification, query.policy.clearance.as_deref())
                && !classification.is_empty()
            {
                continue;
            }
            grouped
                .entry(dataset_id)
                .or_insert_with(|| (BTreeSet::new(), bound_object_id))
                .0
                .insert(field);
        }
        drop(stmt);
        drop(conn);
        let mut hits = Vec::new();
        for (id, _) in grouped {
            let Some(dataset) = self.get_dataset(&id)? else {
                continue;
            };
            if dataset.object_id.is_empty() {
                if self.subjects_include_team_principal(&query.policy.subjects)? {
                    continue;
                }
            } else {
                if !self.grant_allows(&dataset.object_id, &query.policy.subjects)? {
                    continue;
                }
                let Some(bound) = self.get_object(&dataset.object_id)? else {
                    continue;
                };
                if self
                    .compiled_object_security_allows(
                        &query.policy.namespace,
                        &dataset.object_id,
                        &bound.kind,
                        &BTreeSet::new(),
                        query,
                    )?
                    .is_none()
                {
                    continue;
                }
            }
            let mut fields = BTreeSet::new();
            if text_matches_query(&dataset.name, &query.text) {
                fields.insert("name".into());
            }
            for column in &dataset.columns {
                if !text_matches_query(&column.name, &query.text) {
                    continue;
                }
                if !dataset_classification_allows(
                    &column.classification,
                    query.policy.clearance.as_deref(),
                ) {
                    continue;
                }
                fields.insert(format!("column:{}", column.name));
            }
            if fields.is_empty() {
                continue;
            }
            hits.push(SearchCandidate {
                source: SearchSourceKind::Dataset,
                id,
                kind: "dataset".into(),
                matched_fields: fields.into_iter().collect(),
                authority: false,
            });
            if hits.len() >= limit {
                break;
            }
        }
        Ok(hits)
    }
}

impl SearchMaintenance for SekaiDb {
    fn search_maintenance(&self) -> &Mutex<()> {
        &self.search_maintenance
    }

    fn read_search_checkpoint(&self, namespace: &str) -> Result<Option<SearchCheckpoint>, String> {
        SekaiDb::read_search_checkpoint(self, namespace)
    }

    fn search_checkpoint_namespaces(&self) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT namespace FROM sekai_search_checkpoint_v2")
            .map_err(|error| error.to_string())?;
        stmt.query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    fn pending_search_changes(
        &self,
        namespace: &str,
        after_rowid: u64,
    ) -> Result<Vec<(String, u64, i64)>, String> {
        self.list_committed_object_mutations_after(namespace, after_rowid, PENDING_PAGE)
            .map(|rows| {
                rows.into_iter()
                    .map(|(change, seq, _, _)| (change.object_id, seq, change.timestamp))
                    .collect()
            })
    }

    fn namespace_object_generation(&self, namespace: &str) -> Result<u64, String> {
        SekaiDb::namespace_object_generation(self, namespace)
    }

    fn object_change_watermark(&self, namespace: &str) -> Result<u64, String> {
        SekaiDb::object_change_watermark(self, namespace)
    }

    fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        SekaiDb::get_object(self, id)
    }

    fn namespace_datasets(&self, namespace: &str) -> Result<Vec<Dataset>, String> {
        let mut datasets = Vec::new();
        for dataset in self.list_datasets()? {
            if dataset.object_id.is_empty() {
                datasets.push(dataset);
                continue;
            }
            let bound = SekaiDb::get_object(self, &dataset.object_id)?;
            if bound.is_some_and(|object| object.namespace == namespace) {
                datasets.push(dataset);
            }
        }
        datasets.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(datasets)
    }

    fn namespace_object_ids(&self, namespace: &str) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id FROM sekai_objects WHERE namespace = ?1 ORDER BY id")
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    fn search_dataset_ids(&self, namespace: &str) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT dataset_id FROM sekai_search_dataset_v2 WHERE namespace = ?1 ORDER BY dataset_id",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![namespace], |row| row.get(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    fn search_counts(&self, namespace: &str) -> Result<(i64, i64), String> {
        let conn = self.conn();
        let count = |table: &str| {
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE namespace = ?1"),
                params![namespace],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
        };
        Ok((
            count("sekai_search_object_v2")?,
            count("sekai_search_dataset_v2")?,
        ))
    }

    fn start_search_rebuild(
        &self,
        namespace: &str,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, SearchIndexError> {
        self.fenced_search_write(
            namespace,
            revision,
            now_ms,
            &CheckpointFields::REBUILD_START,
            |conn| Self::clear_namespace_on(conn, namespace),
        )
    }

    fn write_search_document(
        &self,
        namespace: &str,
        write: DocumentWrite<'_>,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, SearchIndexError> {
        match write {
            DocumentWrite::IndexObject(object) => self.fenced_search_write(
                namespace,
                revision,
                now_ms,
                &CheckpointFields::default(),
                |conn| Self::index_object_on(conn, object, now_ms),
            ),
            DocumentWrite::DeleteObject(object_id) => self.fenced_search_write(
                namespace,
                revision,
                now_ms,
                &CheckpointFields::default(),
                |conn| Self::delete_object_on(conn, namespace, object_id),
            ),
            DocumentWrite::IndexDataset(dataset) => {
                // Read before the transaction: one in-memory connection.
                let bound = self.bound_dataset_policy(dataset)?;
                self.fenced_search_write(
                    namespace,
                    revision,
                    now_ms,
                    &CheckpointFields::default(),
                    |conn| Self::index_dataset_on(conn, namespace, dataset, &bound, now_ms),
                )
            }
            DocumentWrite::DeleteDataset(dataset_id) => self.fenced_search_write(
                namespace,
                revision,
                now_ms,
                &CheckpointFields::default(),
                |conn| Self::delete_dataset_on(conn, namespace, dataset_id),
            ),
        }
    }

    fn advance_search_checkpoint(
        &self,
        namespace: &str,
        position: &SearchPosition,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, SearchIndexError> {
        let fields = CheckpointFields::published(position)?;
        self.fenced_search_write(namespace, revision, now_ms, &fields, |_| Ok(()))
    }
}

impl SearchIndex for SekaiDb {
    fn index(&self, document: &SearchDocument, now_ms: i64) -> Result<(), SearchIndexError> {
        let _guard = lock_search_maintenance(self)?;
        match document {
            SearchDocument::Object(object) => {
                self.search_write(|conn| Self::index_object_on(conn, object, now_ms))
            }
            SearchDocument::Dataset { namespace, dataset } => {
                let bound = self.bound_dataset_policy(dataset)?;
                self.search_write(|conn| {
                    Self::index_dataset_on(conn, namespace, dataset, &bound, now_ms)
                })
            }
        }
    }

    fn delete(&self, key: &SearchDocumentKey) -> Result<(), SearchIndexError> {
        let _guard = lock_search_maintenance(self)?;
        match key {
            SearchDocumentKey::Object {
                namespace,
                object_id,
            } => self.search_write(|conn| Self::delete_object_on(conn, namespace, object_id)),
            SearchDocumentKey::Dataset {
                namespace,
                dataset_id,
            } => self.search_write(|conn| Self::delete_dataset_on(conn, namespace, dataset_id)),
        }
    }

    fn query_candidates(
        &self,
        query: &SearchCandidateQuery,
    ) -> Result<Vec<SearchCandidate>, SearchIndexError> {
        self.query_search_candidates(query)
    }

    fn rebuild_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchRebuildReport, SearchIndexError> {
        rebuild_namespace_fenced(self, namespace, now_ms)
    }

    fn status(&self, namespace: &str, now_ms: i64) -> Result<SearchIndexStatus, SearchIndexError> {
        search_status(self, namespace, now_ms)
    }

    fn vector_candidates(
        &self,
        query: &VectorCandidateQuery,
        keep: &mut dyn FnMut(&VectorCandidate) -> Result<bool, SearchIndexError>,
    ) -> Result<Vec<VectorCandidate>, SearchIndexError> {
        use crate::sekai::embedding_index::EmbeddingStore;
        let namespace = &query.policy.namespace;
        let chunks = self.embedding_chunks(namespace, &query.spec_id)?;
        let lattice = self.get_classification_lattice(namespace)?;
        let policy = query.policy_query();
        exact_vector_candidates(chunks, query, lattice.as_ref(), |candidate| {
            let id = candidate.object_id.as_str();
            Ok(self.grant_allows(id, &query.policy.subjects)?
                && self
                    .compiled_object_security_allows(namespace, id, "", &BTreeSet::new(), &policy)?
                    .is_some()
                && keep(candidate)?)
        })
    }
}

impl SearchIndex for RuntimeDb {
    fn index(&self, document: &SearchDocument, now_ms: i64) -> Result<(), SearchIndexError> {
        match self {
            Self::Sqlite(db) => db.index(document, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.index(document, now_ms)),
        }
    }

    fn delete(&self, key: &SearchDocumentKey) -> Result<(), SearchIndexError> {
        match self {
            Self::Sqlite(db) => db.delete(key),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete(key)),
        }
    }

    fn query_candidates(
        &self,
        query: &SearchCandidateQuery,
    ) -> Result<Vec<SearchCandidate>, SearchIndexError> {
        match self {
            Self::Sqlite(db) => db.query_candidates(query),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.query_candidates(query)),
        }
    }

    fn rebuild_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchRebuildReport, SearchIndexError> {
        match self {
            Self::Sqlite(db) => db.rebuild_namespace(namespace, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.rebuild_namespace(namespace, now_ms))
            }
        }
    }

    fn status(&self, namespace: &str, now_ms: i64) -> Result<SearchIndexStatus, SearchIndexError> {
        match self {
            Self::Sqlite(db) => db.status(namespace, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.status(namespace, now_ms)),
        }
    }

    fn vector_candidates(
        &self,
        query: &VectorCandidateQuery,
        keep: &mut dyn FnMut(&VectorCandidate) -> Result<bool, SearchIndexError>,
    ) -> Result<Vec<VectorCandidate>, SearchIndexError> {
        match self {
            Self::Sqlite(db) => db.vector_candidates(query, keep),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.vector_candidates(query, keep))
            }
        }
    }
}

pub trait SearchIndexStore {
    fn catch_up_search_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchCatchUpReport, SearchIndexError>;
    fn search_index_dump(&self, namespace: &str) -> Result<SearchIndexDump, SearchIndexError>;
    #[cfg(any(test, feature = "gateway-test-support"))]
    fn purge_object_changes_for_test(&self) -> Result<(), SearchIndexError>;
    #[cfg(any(test, feature = "gateway-test-support"))]
    fn purge_object_changes_for_object_for_test(
        &self,
        object_id: &str,
    ) -> Result<(), SearchIndexError>;
}

impl SearchIndexStore for RuntimeDb {
    fn catch_up_search_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchCatchUpReport, SearchIndexError> {
        match self {
            Self::Sqlite(db) => db.catch_up_search_namespace(namespace, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.catch_up_search_namespace(namespace, now_ms))
            }
        }
    }

    fn search_index_dump(&self, namespace: &str) -> Result<SearchIndexDump, SearchIndexError> {
        match self {
            Self::Sqlite(db) => db
                .search_index_dump(namespace)
                .map_err(SearchIndexError::from),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.search_index_dump(namespace)
                    .map_err(SearchIndexError::from)
            }),
        }
    }

    #[cfg(any(test, feature = "gateway-test-support"))]
    fn purge_object_changes_for_test(&self) -> Result<(), SearchIndexError> {
        match self {
            Self::Sqlite(db) => db
                .purge_object_changes_for_test()
                .map_err(SearchIndexError::from),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.purge_object_changes_for_test()
                    .map_err(SearchIndexError::from)
            }),
        }
    }

    #[cfg(any(test, feature = "gateway-test-support"))]
    fn purge_object_changes_for_object_for_test(
        &self,
        object_id: &str,
    ) -> Result<(), SearchIndexError> {
        match self {
            Self::Sqlite(db) => db
                .purge_object_changes_for_object_for_test(object_id)
                .map_err(SearchIndexError::from),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.purge_object_changes_for_object_for_test(object_id)
                    .map_err(SearchIndexError::from)
            }),
        }
    }
}

/// One catch-up's outcome per namespace, from [`catch_up_search_pass`].
pub type SearchPassOutcome = (String, Result<SearchCatchUpReport, SearchIndexError>);

impl RuntimeDb {
    /// Record a placeholder checkpoint (revision 0, no analyzer, no lease)
    /// for a namespace the index does not follow yet, so the scheduled
    /// worker discovers and builds it. Call only after the caller is
    /// authorized for `namespace`. Reads first, so a followed namespace
    /// writes nothing.
    pub fn ensure_search_checkpoint(&self, namespace: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.ensure_search_checkpoint(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.ensure_search_checkpoint(namespace))
            }
        }
    }

    /// Namespaces the search index follows, in name order after `after`:
    /// every namespace with object history or a checkpoint.
    pub fn search_index_namespaces(
        &self,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, String> {
        match self {
            Self::Sqlite(db) => db.search_index_namespaces(after, limit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.search_index_namespaces(after, limit))
            }
        }
    }
}

/// One scheduled catch-up pass (#2250): up to `limit` namespaces after
/// `after`, in name order, one catch-up call each. Continue after the last
/// namespace returned, or from the start when fewer than `limit` came back.
/// Replicas may run passes at once: every write is fenced, so a namespace
/// another instance holds fails with [`SearchIndexError::is_conflict`] and
/// is retried on a later pass. A namespace that fails does not stop the
/// others.
pub fn catch_up_search_pass(
    db: &RuntimeDb,
    after: &str,
    limit: usize,
    now_ms: &dyn Fn() -> i64,
) -> Result<Vec<SearchPassOutcome>, String> {
    Ok(db
        .search_index_namespaces(after, limit)?
        .into_iter()
        .map(|namespace| {
            let outcome = db.catch_up_search_namespace(&namespace, now_ms());
            (namespace, outcome)
        })
        .collect())
}

/// Changes one catch-up call consumes at most; the next call continues.
pub(crate) const PENDING_PAGE: i32 = 10_000;

/// One fenced index document write.
pub(crate) enum DocumentWrite<'a> {
    IndexObject(&'a Object),
    DeleteObject(&'a str),
    IndexDataset(&'a Dataset),
    DeleteDataset(&'a str),
}

/// Where a finished catch-up or rebuild leaves the namespace.
pub(crate) struct SearchPosition {
    pub last_change_rowid: u64,
    pub last_generation: u64,
    pub dataset_catalog_digest: String,
}

/// Checkpoint columns a fenced write sets in the same statement as its
/// revision bump; `None` keeps the stored value.
#[derive(Default)]
pub(crate) struct CheckpointFields<'a> {
    pub analyzer_version: Option<&'a str>,
    pub last_change_rowid: Option<i64>,
    pub last_generation: Option<i64>,
    pub dataset_catalog_digest: Option<&'a str>,
}

impl<'a> CheckpointFields<'a> {
    /// A rebuild in progress: cleared analyzer and position.
    pub const REBUILD_START: Self = Self {
        analyzer_version: Some(""),
        last_change_rowid: Some(0),
        last_generation: Some(0),
        dataset_catalog_digest: Some(""),
    };

    /// The index is current for this analyzer up to `position`.
    pub fn published(position: &'a SearchPosition) -> Result<Self, String> {
        Ok(Self {
            analyzer_version: Some(ANALYZER_VERSION),
            last_change_rowid: Some(
                i64::try_from(position.last_change_rowid).map_err(|error| error.to_string())?,
            ),
            last_generation: Some(
                i64::try_from(position.last_generation).map_err(|error| error.to_string())?,
            ),
            dataset_catalog_digest: Some(&position.dataset_catalog_digest),
        })
    }
}

/// Backend primitives under the shared search catch-up (#2250, ADR 0108).
/// Every write is fenced: it takes the checkpoint revision the caller last
/// saw and returns the next one; a stale revision fails with
/// [`SEARCH_CHECKPOINT_CONFLICT`] and writes nothing.
pub(crate) trait SearchMaintenance {
    /// Serializes this plane's own index writers; replicas rely on the fence.
    fn search_maintenance(&self) -> &Mutex<()>;
    fn read_search_checkpoint(&self, namespace: &str) -> Result<Option<SearchCheckpoint>, String>;
    fn search_checkpoint_namespaces(&self) -> Result<Vec<String>, String>;
    /// `(object_id, seq, timestamp)` of committed changes after
    /// `after_rowid`, at most [`PENDING_PAGE`].
    fn pending_search_changes(
        &self,
        namespace: &str,
        after_rowid: u64,
    ) -> Result<Vec<(String, u64, i64)>, String>;
    fn namespace_object_generation(&self, namespace: &str) -> Result<u64, String>;
    fn object_change_watermark(&self, namespace: &str) -> Result<u64, String>;
    fn get_object(&self, id: &str) -> Result<Option<Object>, String>;
    /// The namespace's datasets (bound to its objects, or unbound), by id.
    fn namespace_datasets(&self, namespace: &str) -> Result<Vec<Dataset>, String>;
    fn namespace_object_ids(&self, namespace: &str) -> Result<Vec<String>, String>;
    fn search_dataset_ids(&self, namespace: &str) -> Result<Vec<String>, String>;
    /// Indexed `(objects, datasets)`.
    fn search_counts(&self, namespace: &str) -> Result<(i64, i64), String>;
    /// Mark a rebuild in progress (analyzer version cleared, `now_ms` as its
    /// lease) and empty the namespace's index, in one fenced write.
    fn start_search_rebuild(
        &self,
        namespace: &str,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, SearchIndexError>;
    fn write_search_document(
        &self,
        namespace: &str,
        write: DocumentWrite<'_>,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, SearchIndexError>;
    /// Publish `position` as current for this binary's analyzer.
    fn advance_search_checkpoint(
        &self,
        namespace: &str,
        position: &SearchPosition,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, SearchIndexError>;
}

pub(crate) fn lock_search_maintenance<S: SearchMaintenance + ?Sized>(
    store: &S,
) -> Result<MutexGuard<'_, ()>, SearchIndexError> {
    store
        .search_maintenance()
        .lock()
        .map_err(|_| SearchIndexError::Unavailable("search maintenance lock was poisoned".into()))
}

fn require_namespace(namespace: &str) -> Result<(), SearchIndexError> {
    if namespace.trim().is_empty() {
        return Err(SearchIndexError::InvalidArgument(
            "namespace required".into(),
        ));
    }
    Ok(())
}

fn rebuilt_report(rebuilt: SearchRebuildReport) -> SearchCatchUpReport {
    SearchCatchUpReport {
        namespace: rebuilt.namespace,
        objects: rebuilt.objects,
        datasets: rebuilt.datasets,
        rebuilt: true,
        consumed_changes: 0,
    }
}

/// Bring the namespace's index up to the object-change feed and dataset
/// catalog, one feed page per call. Rebuilds when the index is not current
/// for this analyzer or the feed lost mutations, unless another instance's
/// rebuild holds its lease ([`SEARCH_REBUILD_IN_PROGRESS`]). Every write is
/// fenced on the revision read here, so a concurrent writer for the
/// namespace stops this one with [`SEARCH_CHECKPOINT_CONFLICT`]; the
/// checkpoint is left where it was and the next call retries.
pub(crate) fn catch_up_namespace<S: SearchMaintenance + ?Sized>(
    store: &S,
    namespace: &str,
    now_ms: i64,
) -> Result<SearchCatchUpReport, SearchIndexError> {
    require_namespace(namespace)?;
    let _guard = lock_search_maintenance(store)?;
    let checkpoint = match store.read_search_checkpoint(namespace)? {
        Some(checkpoint) if checkpoint.current() => checkpoint,
        previous => return rebuild_after(store, namespace, previous, now_ms).map(rebuilt_report),
    };
    let pending = store.pending_search_changes(namespace, checkpoint.last_change_rowid)?;
    let generation = store.namespace_object_generation(namespace)?;
    if pending.is_empty()
        && !feed_covers_generation(checkpoint.last_generation, generation, &pending)
    {
        // Mutations were purged from the feed before we read them: only a
        // rebuild closes that gap.
        return rebuild(store, namespace, checkpoint.revision, now_ms).map(rebuilt_report);
    }
    let mut revision = checkpoint.revision;
    let mut object_ids = Vec::new();
    let mut seen = BTreeSet::new();
    let mut last_rowid = checkpoint.last_change_rowid;
    for (object_id, seq, _) in &pending {
        last_rowid = last_rowid.max(*seq);
        if seen.insert(object_id.as_str()) {
            object_ids.push(object_id.as_str());
        }
    }
    for object_id in &object_ids {
        let object = store
            .get_object(object_id)?
            .filter(|object| object.namespace == namespace);
        let write = match &object {
            Some(object) => DocumentWrite::IndexObject(object),
            None => DocumentWrite::DeleteObject(object_id),
        };
        revision = store.write_search_document(namespace, write, revision, now_ms)?;
    }
    let datasets = store.namespace_datasets(namespace)?;
    let digest = dataset_catalog_digest(&datasets);
    let reindexed: Vec<&Dataset> = if digest == checkpoint.dataset_catalog_digest {
        datasets
            .iter()
            .filter(|dataset| object_ids.contains(&dataset.object_id.as_str()))
            .collect()
    } else {
        let current: BTreeSet<&str> = datasets.iter().map(|dataset| dataset.id.as_str()).collect();
        for dataset_id in store.search_dataset_ids(namespace)? {
            if !current.contains(dataset_id.as_str()) {
                revision = store.write_search_document(
                    namespace,
                    DocumentWrite::DeleteDataset(&dataset_id),
                    revision,
                    now_ms,
                )?;
            }
        }
        datasets.iter().collect()
    };
    for dataset in reindexed {
        revision = store.write_search_document(
            namespace,
            DocumentWrite::IndexDataset(dataset),
            revision,
            now_ms,
        )?;
    }
    if last_rowid == 0 {
        last_rowid = store.object_change_watermark(namespace)?;
    }
    let acknowledged = if feed_covers_generation(checkpoint.last_generation, generation, &pending) {
        generation
    } else {
        checkpoint.last_generation
    };
    let position = SearchPosition {
        last_change_rowid: last_rowid,
        last_generation: acknowledged,
        dataset_catalog_digest: digest,
    };
    // An idle namespace writes nothing, so replicas do not contend on it.
    if revision != checkpoint.revision
        || position.last_change_rowid != checkpoint.last_change_rowid
        || position.last_generation != checkpoint.last_generation
        || position.dataset_catalog_digest != checkpoint.dataset_catalog_digest
    {
        store.advance_search_checkpoint(namespace, &position, revision, now_ms)?;
        publish_search_lag(store, namespace, now_ms)?;
    }
    let (objects, dataset_count) = store.search_counts(namespace)?;
    Ok(SearchCatchUpReport {
        namespace: namespace.into(),
        objects,
        datasets: dataset_count,
        rebuilt: false,
        consumed_changes: pending.len() as i64,
    })
}

/// A forced rebuild, under the same lease and fence as catch-up.
pub(crate) fn rebuild_namespace_fenced<S: SearchMaintenance + ?Sized>(
    store: &S,
    namespace: &str,
    now_ms: i64,
) -> Result<SearchRebuildReport, SearchIndexError> {
    require_namespace(namespace)?;
    let _guard = lock_search_maintenance(store)?;
    let previous = store.read_search_checkpoint(namespace)?;
    rebuild_after(store, namespace, previous, now_ms)
}

/// Rebuild from `previous`, unless it is another instance's rebuild whose
/// lease still holds. A lapsed one is taken over: its next write loses the
/// fence, so it can never publish.
fn rebuild_after<S: SearchMaintenance + ?Sized>(
    store: &S,
    namespace: &str,
    previous: Option<SearchCheckpoint>,
    now_ms: i64,
) -> Result<SearchRebuildReport, SearchIndexError> {
    if previous
        .as_ref()
        .is_some_and(|checkpoint| checkpoint.rebuild_lease_held(now_ms))
    {
        return Err(SearchIndexError::Unavailable(
            SEARCH_REBUILD_IN_PROGRESS.into(),
        ));
    }
    let revision = previous.map_or(0, |checkpoint| checkpoint.revision);
    rebuild(store, namespace, revision, now_ms)
}

fn rebuild<S: SearchMaintenance + ?Sized>(
    store: &S,
    namespace: &str,
    revision: i64,
    now_ms: i64,
) -> Result<SearchRebuildReport, SearchIndexError> {
    // Bind the checkpoint to the snapshot about to be read. Writes after
    // this point stay in the feed for the next catch-up.
    let watermark = store.object_change_watermark(namespace)?;
    let generation = store.namespace_object_generation(namespace)?;
    // Writes are stamped with elapsed time, so each one renews the lease.
    let started = std::time::Instant::now();
    let clock = || now_ms.saturating_add(started.elapsed().as_millis() as i64);
    // Marked in progress before anything is cleared: a rebuild that dies is
    // retried once its lease lapses instead of looking current.
    let mut revision = store.start_search_rebuild(namespace, revision, now_ms)?;
    let mut objects = 0;
    for id in store.namespace_object_ids(namespace)? {
        if let Some(object) = store
            .get_object(&id)?
            .filter(|object| object.namespace == namespace)
        {
            revision = store.write_search_document(
                namespace,
                DocumentWrite::IndexObject(&object),
                revision,
                clock(),
            )?;
            objects += 1;
        }
    }
    let datasets = store.namespace_datasets(namespace)?;
    for dataset in &datasets {
        revision = store.write_search_document(
            namespace,
            DocumentWrite::IndexDataset(dataset),
            revision,
            clock(),
        )?;
    }
    store.advance_search_checkpoint(
        namespace,
        &SearchPosition {
            last_change_rowid: watermark,
            last_generation: generation,
            dataset_catalog_digest: dataset_catalog_digest(&datasets),
        },
        revision,
        clock(),
    )?;
    publish_search_lag(store, namespace, now_ms)?;
    Ok(SearchRebuildReport {
        namespace: namespace.into(),
        objects,
        datasets: datasets.len() as i64,
        rebuilt: true,
    })
}

/// `(lag_ms, pending_changes, generation)` from durable state only.
fn search_lag<S: SearchMaintenance + ?Sized>(
    store: &S,
    namespace: &str,
    now_ms: i64,
) -> Result<(i64, i64, u64), String> {
    let checkpoint = store.read_search_checkpoint(namespace)?;
    let after = checkpoint
        .as_ref()
        .map_or(0, |checkpoint| checkpoint.last_change_rowid);
    let pending = store.pending_search_changes(namespace, after)?;
    let generation = store.namespace_object_generation(namespace)?;
    let checkpoint_generation = checkpoint
        .as_ref()
        .map_or(0, |checkpoint| checkpoint.last_generation);
    let oldest = pending.iter().map(|(_, _, timestamp)| *timestamp).min();
    let lag = if let Some(timestamp) = oldest {
        now_ms.saturating_sub(timestamp).max(0)
    } else if generation > checkpoint_generation {
        checkpoint.as_ref().map_or(now_ms.max(1), |checkpoint| {
            now_ms.saturating_sub(checkpoint.indexed_at_ms).max(1)
        })
    } else {
        0
    };
    Ok((lag, pending.len() as i64, generation))
}

/// Set the lag gauge to the maximum over every indexed namespace; returns
/// `namespace`'s lag.
fn publish_search_lag<S: SearchMaintenance + ?Sized>(
    store: &S,
    namespace: &str,
    now_ms: i64,
) -> Result<i64, String> {
    let (lag, _, _) = search_lag(store, namespace, now_ms)?;
    let mut maximum = lag.max(0) as u64;
    let mut seen = BTreeSet::from([namespace.to_string()]);
    for other in store.search_checkpoint_namespaces()? {
        if !seen.insert(other.clone()) {
            continue;
        }
        let (other_lag, _, _) = search_lag(store, &other, now_ms)?;
        maximum = maximum.max(other_lag.max(0) as u64);
    }
    crate::obs::metrics::set_search_index_lag_ms(maximum);
    Ok(lag)
}

/// Status from durable state; never catches up. The analyzer version is
/// empty before the first build and while a rebuild is in progress.
pub(crate) fn search_status<S: SearchMaintenance + ?Sized>(
    store: &S,
    namespace: &str,
    now_ms: i64,
) -> Result<SearchIndexStatus, SearchIndexError> {
    require_namespace(namespace)?;
    let checkpoint = store.read_search_checkpoint(namespace)?;
    let (objects, datasets) = store.search_counts(namespace)?;
    let (lag, pending, generation) = search_lag(store, namespace, now_ms)?;
    publish_search_lag(store, namespace, now_ms)?;
    let checkpoint = checkpoint.unwrap_or(SearchCheckpoint {
        last_generation: generation,
        ..SearchCheckpoint::default()
    });
    Ok(SearchIndexStatus {
        namespace: namespace.into(),
        analyzer_version: checkpoint.analyzer_version,
        last_change_rowid: checkpoint.last_change_rowid,
        last_generation: checkpoint.last_generation,
        dataset_catalog_digest: checkpoint.dataset_catalog_digest,
        indexed_at_ms: checkpoint.indexed_at_ms,
        object_count: objects,
        dataset_count: datasets,
        lag_ms: lag,
        pending_changes: pending,
    })
}

fn feed_covers_generation(
    last_generation: u64,
    generation: u64,
    pending: &[(String, u64, i64)],
) -> bool {
    if generation <= last_generation {
        return true;
    }
    let covered = pending
        .iter()
        .map(|(object_id, _, timestamp)| (object_id.as_str(), *timestamp))
        .collect::<BTreeSet<_>>()
        .len() as u64;
    covered >= generation.saturating_sub(last_generation)
}
