use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use crate::sekai::classification_lattice::{ClassificationLattice, evaluate_lattice_access};
use crate::sekai::dataset::Dataset;
use crate::sekai::markings::{
    MarkingDecision, PrincipalAuthority, deny_unmarked_enabled, env_deny_unmarked,
    is_trusted_service_principal, namespace_deny_unmarked, object_is_unmarked,
    object_marking_token, parse_optional_classification, trusted_service_authority,
    unmarked_access_decision,
};
use crate::sekai::search_index::{
    ANALYZER_VERSION, SearchCandidate, SearchCandidateQuery, SearchCatchUpReport,
    SearchDatasetDump, SearchDocument, SearchDocumentKey, SearchIndex, SearchIndexDump,
    SearchIndexError, SearchIndexStatus, SearchObjectDump, SearchQueryMode, SearchRebuildReport,
    SearchSourceKind, acl_allows, dataset_catalog_digest, dataset_classification_allows,
    dataset_content_digest, fts_query, indexed_search_text, live_object_match_fields,
    object_content_digest, object_text_properties, policy_attributes, purpose_allows,
    text_matches_query,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA: &str = "
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
";

fn search_authority(query: &SearchCandidateQuery) -> PrincipalAuthority {
    let subject = query
        .policy
        .subjects
        .iter()
        .find(|subject| is_trusted_service_principal(subject))
        .cloned()
        .or_else(|| query.policy.subjects.first().cloned())
        .unwrap_or_default();
    if let Some(trusted) = trusted_service_authority(&subject) {
        return trusted;
    }
    PrincipalAuthority {
        principal: subject,
        classification_ceiling: query
            .policy
            .clearance
            .as_deref()
            .and_then(|token| parse_optional_classification(token).ok().flatten()),
        classification_token: query.policy.clearance.clone(),
        allowed_purposes: BTreeSet::new(),
        declassify_markings: BTreeSet::new(),
    }
}

fn lattice_marking_allows(
    marking: &str,
    query: &SearchCandidateQuery,
    lattice: Option<&ClassificationLattice>,
) -> bool {
    let token = (!marking.is_empty()).then_some(marking);
    evaluate_lattice_access("search", token, &search_authority(query), lattice).decision
        != MarkingDecision::Deny
}

impl SekaiDb {
    pub(crate) fn migrate_search_index(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(SCHEMA)
            .map_err(|error| error.to_string())?;
        conn.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS sekai_search_object_fts USING fts5(
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
            );",
        )
        .map_err(|error| error.to_string())?;
        let _ = conn.execute(
            "ALTER TABLE sekai_search_dataset
             ADD COLUMN bound_access_marking TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE sekai_search_dataset
             ADD COLUMN bound_policy_attributes TEXT NOT NULL DEFAULT '{}'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE sekai_search_dataset
             ADD COLUMN bound_object_id TEXT NOT NULL DEFAULT ''",
            [],
        );
        Ok(())
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
        Ok(grants
            .iter()
            .any(|grant| subjects.iter().any(|subject| subject == &grant.principal)))
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

    fn search_checkpoint(
        &self,
        namespace: &str,
    ) -> Result<Option<(u64, u64, String, i64)>, String> {
        self.conn()
            .query_row(
                "SELECT last_change_rowid, last_generation, dataset_catalog_digest, indexed_at_ms
                 FROM sekai_search_checkpoint WHERE namespace = ?1",
                params![namespace],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u64,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get(2)?,
                        row.get(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn store_search_checkpoint(
        &self,
        namespace: &str,
        last_change_rowid: u64,
        last_generation: u64,
        dataset_catalog_digest: &str,
        indexed_at_ms: i64,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_search_checkpoint
                 (namespace, analyzer_version, last_change_rowid, last_generation,
                  dataset_catalog_digest, indexed_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(namespace) DO UPDATE SET
                    analyzer_version = excluded.analyzer_version,
                    last_change_rowid = excluded.last_change_rowid,
                    last_generation = excluded.last_generation,
                    dataset_catalog_digest = excluded.dataset_catalog_digest,
                    indexed_at_ms = excluded.indexed_at_ms",
                params![
                    namespace,
                    ANALYZER_VERSION,
                    last_change_rowid as i64,
                    last_generation as i64,
                    dataset_catalog_digest,
                    indexed_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
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
                "INSERT INTO sekai_search_object_text (namespace, object_id, property, text)
                 VALUES (?1, ?2, ?3, ?4)",
                params![namespace, object_id, property, text],
            )
            .map_err(|error| error.to_string())?;
            let id: i64 = conn
                .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            conn.execute(
                "INSERT INTO sekai_search_object_fts(rowid, property, text) VALUES (?1, ?2, ?3)",
                params![id, property, indexed_search_text(text)],
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn clear_object_text_on(
        conn: &Connection,
        namespace: &str,
        object_id: &str,
    ) -> Result<(), String> {
        let mut stmt = conn
            .prepare(
                "SELECT id, property, text FROM sekai_search_object_text
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
                "INSERT INTO sekai_search_object_fts(sekai_search_object_fts, rowid, property, text)
                 VALUES('delete', ?1, ?2, ?3)",
                params![id, property, indexed_search_text(&text)],
            )
            .map_err(|error| error.to_string())?;
        }
        conn.execute(
            "DELETE FROM sekai_search_object_text WHERE namespace = ?1 AND object_id = ?2",
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
                "INSERT INTO sekai_search_dataset_text
                 (namespace, dataset_id, field, classification, text)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![namespace, dataset.id, field, classification, text],
            )
            .map_err(|error| error.to_string())?;
            let id: i64 = conn
                .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            conn.execute(
                "INSERT INTO sekai_search_dataset_fts(rowid, field, text) VALUES (?1, ?2, ?3)",
                params![id, field, indexed_search_text(&text)],
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn clear_dataset_text_on(
        conn: &Connection,
        namespace: &str,
        dataset_id: &str,
    ) -> Result<(), String> {
        let mut stmt = conn
            .prepare(
                "SELECT id, field, text FROM sekai_search_dataset_text
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
                "INSERT INTO sekai_search_dataset_fts(sekai_search_dataset_fts, rowid, field, text)
                 VALUES('delete', ?1, ?2, ?3)",
                params![id, field, indexed_search_text(&text)],
            )
            .map_err(|error| error.to_string())?;
        }
        conn.execute(
            "DELETE FROM sekai_search_dataset_text WHERE namespace = ?1 AND dataset_id = ?2",
            params![namespace, dataset_id],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn index_object_document(&self, object: &Object, now_ms: i64) -> Result<(), SearchIndexError> {
        let digest = object_content_digest(object);
        let attributes =
            serde_json::to_string(&policy_attributes(object)).map_err(|error| error.to_string())?;
        let properties = object_text_properties(object);
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT content_digest FROM sekai_search_object
                 WHERE namespace = ?1 AND object_id = ?2",
                params![object.namespace, object.id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing.as_deref() == Some(digest.as_str()) {
            return Ok(());
        }
        tx.execute(
            "INSERT INTO sekai_search_object
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
        Self::replace_object_text_on(&tx, &object.namespace, &object.id, &properties)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn index_dataset_document(
        &self,
        namespace: &str,
        dataset: &Dataset,
        now_ms: i64,
    ) -> Result<(), SearchIndexError> {
        let digest = dataset_content_digest(dataset);
        let (bound_marking, bound_attributes) = self.bound_dataset_policy(dataset)?;
        let columns = serde_json::to_string(
            &dataset
                .columns
                .iter()
                .map(|column| (column.name.clone(), column.classification.clone()))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT content_digest FROM sekai_search_dataset
                 WHERE namespace = ?1 AND dataset_id = ?2",
                params![namespace, dataset.id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing.as_deref() == Some(digest.as_str()) {
            tx.execute(
                "UPDATE sekai_search_dataset
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
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(());
        }
        tx.execute(
            "INSERT INTO sekai_search_dataset
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
        Self::replace_dataset_text_on(&tx, namespace, dataset)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn delete_object_document(
        &self,
        namespace: &str,
        object_id: &str,
    ) -> Result<(), SearchIndexError> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        Self::clear_object_text_on(&tx, namespace, object_id)?;
        tx.execute(
            "DELETE FROM sekai_search_object WHERE namespace = ?1 AND object_id = ?2",
            params![namespace, object_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn delete_dataset_document(
        &self,
        namespace: &str,
        dataset_id: &str,
    ) -> Result<(), SearchIndexError> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        Self::clear_dataset_text_on(&tx, namespace, dataset_id)?;
        tx.execute(
            "DELETE FROM sekai_search_dataset WHERE namespace = ?1 AND dataset_id = ?2",
            params![namespace, dataset_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn clear_namespace_index(&self, namespace: &str) -> Result<(), SearchIndexError> {
        let object_ids = self.search_object_ids(namespace)?;
        for object_id in object_ids {
            self.delete_object_document(namespace, &object_id)?;
        }
        let dataset_ids = self.search_dataset_ids(namespace)?;
        for dataset_id in dataset_ids {
            self.delete_dataset_document(namespace, &dataset_id)?;
        }
        Ok(())
    }

    fn search_object_ids(&self, namespace: &str) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT object_id FROM sekai_search_object WHERE namespace = ?1 ORDER BY object_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    fn search_dataset_ids(&self, namespace: &str) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT dataset_id FROM sekai_search_dataset WHERE namespace = ?1 ORDER BY dataset_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    fn pending_search_changes(
        &self,
        namespace: &str,
        after_rowid: u64,
    ) -> Result<Vec<(String, u64, i64)>, String> {
        self.list_committed_object_mutations_after(namespace, after_rowid, 10_000)
            .map(|rows| {
                rows.into_iter()
                    .map(|(change, seq, _, _)| (change.object_id, seq, change.timestamp))
                    .collect()
            })
    }

    fn namespace_datasets(&self, namespace: &str) -> Result<Vec<Dataset>, String> {
        let mut datasets = Vec::new();
        for dataset in self.list_datasets()? {
            if dataset.object_id.is_empty() {
                datasets.push(dataset);
                continue;
            }
            let bound = self.get_object(&dataset.object_id)?;
            if bound.is_some_and(|object| object.namespace == namespace) {
                datasets.push(dataset);
            }
        }
        datasets.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(datasets)
    }

    fn list_namespace_objects(&self, namespace: &str) -> Result<Vec<Object>, String> {
        let ids = {
            let conn = self.conn();
            let mut stmt = conn
                .prepare("SELECT id FROM sekai_objects WHERE namespace = ?1 ORDER BY id")
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map(params![namespace], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        let mut objects = Vec::new();
        for id in ids {
            if let Some(object) = self.get_object(&id)?
                && object.namespace == namespace
            {
                objects.push(object);
            }
        }
        Ok(objects)
    }

    fn search_counts(&self, namespace: &str) -> Result<(i64, i64), String> {
        let objects = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_search_object WHERE namespace = ?1",
                params![namespace],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let datasets = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_search_dataset WHERE namespace = ?1",
                params![namespace],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        Ok((objects, datasets))
    }

    pub(crate) fn search_index_dump(&self, namespace: &str) -> Result<SearchIndexDump, String> {
        let conn = self.conn();
        let mut objects = BTreeMap::new();
        let mut stmt = conn
            .prepare(
                "SELECT object_id, kind, access_marking, policy_attributes
                 FROM sekai_search_object WHERE namespace = ?1",
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
                "SELECT object_id, property, text FROM sekai_search_object_text
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
                 FROM sekai_search_dataset WHERE namespace = ?1",
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

    fn search_lag_ms(&self, namespace: &str, now_ms: i64) -> Result<(i64, i64, u64), String> {
        let checkpoint = self.search_checkpoint(namespace)?;
        let after = checkpoint
            .as_ref()
            .map(|(rowid, _, _, _)| *rowid)
            .unwrap_or(0);
        let pending = self.pending_search_changes(namespace, after)?;
        let generation = self.namespace_object_generation(namespace)?;
        let checkpoint_generation = checkpoint
            .as_ref()
            .map(|(_, generation, _, _)| *generation)
            .unwrap_or(0);
        let oldest = pending.iter().map(|(_, _, timestamp)| *timestamp).min();
        let lag = if let Some(timestamp) = oldest {
            now_ms.saturating_sub(timestamp).max(0)
        } else if generation > checkpoint_generation {
            checkpoint
                .as_ref()
                .map(|(_, _, _, indexed_at)| now_ms.saturating_sub(*indexed_at).max(1))
                .unwrap_or(now_ms.max(1))
        } else {
            0
        };
        Ok((lag, pending.len() as i64, generation))
    }

    fn publish_search_lag(&self, namespace: &str, now_ms: i64) -> Result<i64, String> {
        let (lag, _, _) = self.search_lag_ms(namespace, now_ms)?;
        let mut maximum = lag.max(0) as u64;
        // Collect names first so this connection is released before
        // `search_lag_ms` checks out the single in-memory pool slot.
        let namespaces = {
            let conn = self.conn();
            let mut stmt = conn
                .prepare("SELECT namespace FROM sekai_search_checkpoint")
                .map_err(|error| error.to_string())?;
            stmt.query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        let mut seen = BTreeSet::from([namespace.to_string()]);
        for other in namespaces {
            if !seen.insert(other.clone()) {
                continue;
            }
            let (other_lag, _, _) = self.search_lag_ms(&other, now_ms)?;
            maximum = maximum.max(other_lag.max(0) as u64);
        }
        crate::obs::metrics::set_search_index_lag_ms(maximum);
        Ok(lag)
    }

    fn rebuild_search_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchRebuildReport, SearchIndexError> {
        if namespace.trim().is_empty() {
            return Err(SearchIndexError::InvalidArgument(
                "namespace required".into(),
            ));
        }
        // Bind the checkpoint to the snapshot we are about to read. Writes
        // after this point stay in the feed for the next catch-up. Invalidate
        // first so a failed rebuild is retried instead of looking current.
        let watermark = self.object_change_watermark(namespace)?;
        let generation = self.namespace_object_generation(namespace)?;
        self.store_search_checkpoint(namespace, 0, 0, "", 0)?;
        self.clear_namespace_index(namespace)?;
        let objects = self.list_namespace_objects(namespace)?;
        for object in &objects {
            self.index_object_document(object, now_ms)?;
        }
        let datasets = self.namespace_datasets(namespace)?;
        for dataset in &datasets {
            self.index_dataset_document(namespace, dataset, now_ms)?;
        }
        self.store_search_checkpoint(
            namespace,
            watermark,
            generation,
            &dataset_catalog_digest(&datasets),
            now_ms,
        )?;
        self.publish_search_lag(namespace, now_ms)?;
        Ok(SearchRebuildReport {
            namespace: namespace.into(),
            objects: objects.len() as i64,
            datasets: datasets.len() as i64,
            rebuilt: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn purge_object_changes_for_test(&self) -> Result<(), String> {
        self.conn()
            .execute("DELETE FROM sekai_object_changes", [])
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn purge_object_changes_for_object_for_test(
        &self,
        object_id: &str,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "DELETE FROM sekai_object_changes WHERE object_id = ?1",
                params![object_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub(crate) fn catch_up_search_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchCatchUpReport, SearchIndexError> {
        if namespace.trim().is_empty() {
            return Err(SearchIndexError::InvalidArgument(
                "namespace required".into(),
            ));
        }
        let _guard = self.lock_search_maintenance()?;
        let checkpoint = self.search_checkpoint(namespace)?;
        let after = checkpoint
            .as_ref()
            .map(|(rowid, _, _, _)| *rowid)
            .unwrap_or(0);
        let last_generation = checkpoint
            .as_ref()
            .map(|(_, generation, _, _)| *generation)
            .unwrap_or(0);
        let pending = self.pending_search_changes(namespace, after)?;
        let generation = self.namespace_object_generation(namespace)?;
        if pending.is_empty() && !feed_covers_generation(last_generation, generation, &pending) {
            let rebuilt = self.rebuild_search_namespace(namespace, now_ms)?;
            return Ok(SearchCatchUpReport {
                namespace: rebuilt.namespace,
                objects: rebuilt.objects,
                datasets: rebuilt.datasets,
                rebuilt: true,
                consumed_changes: 0,
            });
        }
        let mut object_ids = Vec::new();
        let mut seen = BTreeSet::new();
        let mut last_rowid = after;
        for (object_id, seq, _) in &pending {
            last_rowid = last_rowid.max(*seq);
            if seen.insert(object_id.clone()) {
                object_ids.push(object_id.clone());
            }
        }
        for object_id in &object_ids {
            match self.get_object(object_id)? {
                Some(object) if object.namespace == namespace => {
                    self.index_object_document(&object, now_ms)?;
                }
                _ => self.delete_object_document(namespace, object_id)?,
            }
        }
        let datasets = self.namespace_datasets(namespace)?;
        for dataset in &datasets {
            if object_ids.iter().any(|id| id == &dataset.object_id) {
                self.index_dataset_document(namespace, dataset, now_ms)?;
            }
        }
        let digest = dataset_catalog_digest(&datasets);
        let previous_digest = checkpoint
            .as_ref()
            .map(|(_, _, digest, _)| digest.clone())
            .unwrap_or_default();
        if digest != previous_digest {
            let current: BTreeSet<String> =
                datasets.iter().map(|dataset| dataset.id.clone()).collect();
            for dataset_id in self.search_dataset_ids(namespace)? {
                if !current.contains(&dataset_id) {
                    self.delete_dataset_document(namespace, &dataset_id)?;
                }
            }
            for dataset in &datasets {
                self.index_dataset_document(namespace, dataset, now_ms)?;
            }
        }
        if last_rowid == 0 {
            last_rowid = self.object_change_watermark(namespace)?;
        }
        let acknowledged_generation =
            if feed_covers_generation(last_generation, generation, &pending) {
                generation
            } else {
                last_generation
            };
        self.store_search_checkpoint(
            namespace,
            last_rowid,
            acknowledged_generation,
            &digest,
            now_ms,
        )?;
        self.publish_search_lag(namespace, now_ms)?;
        let (objects, dataset_count) = self.search_counts(namespace)?;
        Ok(SearchCatchUpReport {
            namespace: namespace.into(),
            objects,
            datasets: dataset_count,
            rebuilt: false,
            consumed_changes: pending.len() as i64,
        })
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
            FROM sekai_search_object_fts fts
            JOIN sekai_search_object_text f ON f.id = fts.rowid
            JOIN sekai_search_object o
              ON o.namespace = f.namespace AND o.object_id = f.object_id
            WHERE f.namespace = ?1 AND sekai_search_object_fts MATCH ?2
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
            FROM sekai_search_dataset_fts fts
            JOIN sekai_search_dataset_text f ON f.id = fts.rowid
            JOIN sekai_search_dataset d
              ON d.namespace = f.namespace AND d.dataset_id = f.dataset_id
            WHERE f.namespace = ?1 AND sekai_search_dataset_fts MATCH ?2
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

    fn search_status(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchIndexStatus, SearchIndexError> {
        let checkpoint = self.search_checkpoint(namespace)?;
        let (objects, datasets) = self.search_counts(namespace)?;
        let (lag, pending, generation) = self.search_lag_ms(namespace, now_ms)?;
        self.publish_search_lag(namespace, now_ms)?;
        Ok(SearchIndexStatus {
            namespace: namespace.into(),
            analyzer_version: ANALYZER_VERSION.into(),
            last_change_rowid: checkpoint
                .as_ref()
                .map(|(rowid, _, _, _)| *rowid)
                .unwrap_or(0),
            last_generation: checkpoint
                .as_ref()
                .map(|(_, stored, _, _)| *stored)
                .unwrap_or(generation),
            dataset_catalog_digest: checkpoint
                .as_ref()
                .map(|(_, _, digest, _)| digest.clone())
                .unwrap_or_default(),
            indexed_at_ms: checkpoint
                .as_ref()
                .map(|(_, _, _, indexed_at)| *indexed_at)
                .unwrap_or(0),
            object_count: objects,
            dataset_count: datasets,
            lag_ms: lag,
            pending_changes: pending,
        })
    }
}

impl SekaiDb {
    fn lock_search_maintenance(&self) -> Result<std::sync::MutexGuard<'_, ()>, SearchIndexError> {
        self.search_maintenance.lock().map_err(|_| {
            SearchIndexError::Unavailable("search maintenance lock was poisoned".into())
        })
    }
}

impl SearchIndex for SekaiDb {
    fn index(&self, document: &SearchDocument, now_ms: i64) -> Result<(), SearchIndexError> {
        let _guard = self.lock_search_maintenance()?;
        match document {
            SearchDocument::Object(object) => self.index_object_document(object, now_ms),
            SearchDocument::Dataset { namespace, dataset } => {
                self.index_dataset_document(namespace, dataset, now_ms)
            }
        }
    }

    fn delete(&self, key: &SearchDocumentKey) -> Result<(), SearchIndexError> {
        let _guard = self.lock_search_maintenance()?;
        match key {
            SearchDocumentKey::Object {
                namespace,
                object_id,
            } => self.delete_object_document(namespace, object_id),
            SearchDocumentKey::Dataset {
                namespace,
                dataset_id,
            } => self.delete_dataset_document(namespace, dataset_id),
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
        let _guard = self.lock_search_maintenance()?;
        self.rebuild_search_namespace(namespace, now_ms)
    }

    fn status(&self, namespace: &str, now_ms: i64) -> Result<SearchIndexStatus, SearchIndexError> {
        self.search_status(namespace, now_ms)
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
}

pub trait SearchIndexStore {
    fn catch_up_search_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchCatchUpReport, SearchIndexError>;
    fn search_index_dump(&self, namespace: &str) -> Result<SearchIndexDump, SearchIndexError>;
    #[cfg(test)]
    fn purge_object_changes_for_test(&self) -> Result<(), SearchIndexError>;
    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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
