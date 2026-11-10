use crate::db::postgres::PostgresDb;
use crate::db::postgres_object_security::load_active_policy_postgres;
use crate::db::search_index::{
    CheckpointFields, DocumentWrite, PENDING_PAGE, SearchMaintenance, SearchPosition,
    catch_up_namespace, lock_search_maintenance, rebuild_namespace_fenced, search_status,
};
use crate::domain::Object;
use crate::sekai::classification_lattice::ClassificationLattice;
use crate::sekai::dataset::Dataset;
use crate::sekai::markings::{
    MarkingDecision, deny_unmarked_enabled, env_deny_unmarked, is_trusted_service_principal,
    namespace_deny_unmarked, object_is_unmarked, object_marking_token, unmarked_access_decision,
};
use crate::sekai::search_index::{
    ANALYZER_VERSION, SEARCH_CHECKPOINT_CONFLICT, SearchCandidate, SearchCandidateQuery,
    SearchCatchUpReport, SearchCheckpoint, SearchDatasetDump, SearchDocument, SearchDocumentKey,
    SearchIndex, SearchIndexDump, SearchIndexError, SearchIndexStatus, SearchObjectDump,
    SearchQueryMode, SearchRebuildReport, SearchSourceKind, VectorCandidate, VectorCandidateQuery,
    acl_allows, dataset_classification_allows, dataset_content_digest, exact_vector_candidates,
    live_object_match_fields, object_content_digest, object_text_properties, policy_attributes,
    policy_marking_allows, purpose_allows, search_tokens, text_matches_query,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

const PG_MAX_LEXEME_BYTES: usize = 2047;

/// Index table, its text table, and key column per source.
const OBJECT_ROWS: [&str; 3] = [
    "sekai_search_object_v2",
    "sekai_search_object_text_v2",
    "object_id",
];
const DATASET_ROWS: [&str; 3] = [
    "sekai_search_dataset_v2",
    "sekai_search_dataset_text_v2",
    "dataset_id",
];

fn query_uses_oversize_lexeme(text: &str) -> bool {
    search_tokens(text)
        .iter()
        .any(|token| token.len() > PG_MAX_LEXEME_BYTES)
}

fn lattice_marking_allows(
    marking: &str,
    query: &SearchCandidateQuery,
    lattice: Option<&ClassificationLattice>,
) -> bool {
    policy_marking_allows(marking, &query.policy, lattice)
}

fn postgres_tsquery(text: &str) -> Result<String, SearchIndexError> {
    let tokens = search_tokens(text);
    if tokens.is_empty() {
        return Err(SearchIndexError::InvalidArgument(
            "search text required".into(),
        ));
    }
    // OR lets a token in any overflow chunk surface the property. Live
    // AND matching restores the same candidate set as a single tsvector.
    Ok(tokens.join(" | "))
}

const MAX_TSVECTOR_CHUNK_BYTES: usize = 32_000;

fn tsvector_chunks(text: &str) -> Vec<String> {
    let tokens = search_tokens(text);
    if tokens.is_empty() {
        return vec![String::new()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    for token in tokens {
        let extra = if current.is_empty() {
            token.len()
        } else {
            token.len() + 1
        };
        if !current.is_empty() && current.len() + extra > MAX_TSVECTOR_CHUNK_BYTES {
            chunks.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(&token);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn split_tsvector_source(source: &str) -> Option<(String, String)> {
    if source.len() < 32 {
        return None;
    }
    let mut mid = source.len() / 2;
    while mid > 0 && !source.is_char_boundary(mid) {
        mid -= 1;
    }
    let slice = &source[..mid];
    let cut = slice.rfind(char::is_whitespace).filter(|idx| *idx >= 16)?;
    let left = source[..cut].to_string();
    let right = source[cut..].trim_start().to_string();
    if left.is_empty() || right.is_empty() {
        return None;
    }
    Some((left, right))
}

fn tsvector_exceeds_program_limit(error: &postgres::Error) -> bool {
    error.code() == Some(&postgres::error::SqlState::PROGRAM_LIMIT_EXCEEDED)
}

fn execute_in_savepoint(
    tx: &mut postgres::Transaction<'_>,
    work: impl FnOnce(&mut postgres::Transaction<'_>) -> Result<(), postgres::Error>,
) -> Result<Result<(), postgres::Error>, String> {
    tx.execute("SAVEPOINT search_tsv", &[])
        .map_err(|error| error.to_string())?;
    match work(tx) {
        Ok(()) => {
            tx.execute("RELEASE SAVEPOINT search_tsv", &[])
                .map_err(|error| error.to_string())?;
            Ok(Ok(()))
        }
        Err(error) => {
            tx.execute("ROLLBACK TO SAVEPOINT search_tsv", &[])
                .map_err(|rollback| format!("{error}; rollback: {rollback}"))?;
            let _ = tx.execute("RELEASE SAVEPOINT search_tsv", &[]);
            Ok(Err(error))
        }
    }
}

fn insert_chunked_tsvector(
    tx: &mut postgres::Transaction<'_>,
    text: &str,
    mut insert_row: impl FnMut(
        &mut postgres::Transaction<'_>,
        i32,
        &str,
        &str,
    ) -> Result<(), postgres::Error>,
) -> Result<(), String> {
    let mut pending = tsvector_chunks(text)
        .into_iter()
        .enumerate()
        .map(|(index, source)| {
            (
                i32::try_from(index).expect("chunk fits i32"),
                if index == 0 {
                    text.to_string()
                } else {
                    String::new()
                },
                source,
            )
        })
        .collect::<Vec<_>>();
    let mut next_chunk = i32::try_from(pending.len()).map_err(|error| error.to_string())?;
    while let Some((chunk, stored, source)) = pending.pop() {
        match execute_in_savepoint(tx, |tx| insert_row(tx, chunk, &stored, &source))? {
            Ok(()) => {}
            Err(error) if tsvector_exceeds_program_limit(&error) => {
                let Some((left, right)) = split_tsvector_source(&source) else {
                    return Err(error.to_string());
                };
                pending.push((chunk, stored, left));
                pending.push((next_chunk, String::new(), right));
                next_chunk = next_chunk
                    .checked_add(1)
                    .ok_or_else(|| "search text produced too many tsvector chunks".to_string())?;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

impl PostgresDb {
    fn read_search_checkpoint(&self, namespace: &str) -> Result<Option<SearchCheckpoint>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT analyzer_version, last_change_rowid, last_generation,
                        dataset_catalog_digest, indexed_at_ms, revision
                 FROM sekai_search_checkpoint_v2 WHERE namespace = $1",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .map(|row| SearchCheckpoint {
                analyzer_version: row.get(0),
                last_change_rowid: row.get::<_, i64>(1).max(0) as u64,
                last_generation: row.get::<_, i64>(2).max(0) as u64,
                dataset_catalog_digest: row.get(3),
                indexed_at_ms: row.get(4),
                revision: row.get(5),
            }))
    }

    /// Run `write` in a transaction after a compare-and-bump of the
    /// namespace checkpoint revision (the row lock serializes writers) that
    /// also sets `fields` and stamps `indexed_at_ms` (the rebuild lease).
    /// Returns the new revision.
    fn fenced_search_write(
        &self,
        namespace: &str,
        revision: i64,
        now_ms: i64,
        fields: &CheckpointFields<'_>,
        write: impl FnOnce(&mut postgres::Transaction<'_>) -> Result<(), String>,
    ) -> Result<i64, SearchIndexError> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let bumped = tx
            .execute(
                "UPDATE sekai_search_checkpoint_v2
                 SET revision = revision + 1, indexed_at_ms = $3,
                     analyzer_version = COALESCE($4::TEXT, analyzer_version),
                     last_change_rowid = COALESCE($5::BIGINT, last_change_rowid),
                     last_generation = COALESCE($6::BIGINT, last_generation),
                     dataset_catalog_digest = COALESCE($7::TEXT, dataset_catalog_digest)
                 WHERE namespace = $1 AND revision = $2",
                &[
                    &namespace,
                    &revision,
                    &now_ms,
                    &fields.analyzer_version,
                    &fields.last_change_rowid,
                    &fields.last_generation,
                    &fields.dataset_catalog_digest,
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
                     VALUES ($1, COALESCE($3::TEXT, ''), COALESCE($4::BIGINT, 0),
                             COALESCE($5::BIGINT, 0), COALESCE($6::TEXT, ''), 1, $2)
                     ON CONFLICT (namespace) DO NOTHING",
                    &[
                        &namespace,
                        &now_ms,
                        &fields.analyzer_version,
                        &fields.last_change_rowid,
                        &fields.last_generation,
                        &fields.dataset_catalog_digest,
                    ],
                )
                .map_err(|error| error.to_string())?
                == 1;
        if bumped != 1 && !created {
            return Err(SearchIndexError::Unavailable(
                SEARCH_CHECKPOINT_CONFLICT.into(),
            ));
        }
        write(&mut tx)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(revision + 1)
    }

    /// An unfenced index write for the [`SearchIndex`] document methods.
    fn search_write(
        &self,
        write: impl FnOnce(&mut postgres::Transaction<'_>) -> Result<(), String>,
    ) -> Result<(), SearchIndexError> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        write(&mut tx)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    /// See [`crate::db::runtime_db::RuntimeDb::ensure_search_checkpoint`].
    pub fn ensure_search_checkpoint(&self, namespace: &str) -> Result<(), String> {
        let mut conn = self.connection()?;
        let exists: bool = conn
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM sekai_search_checkpoint_v2 WHERE namespace = $1)",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if !exists {
            conn.execute(
                "INSERT INTO sekai_search_checkpoint_v2 (namespace, analyzer_version)
                 VALUES ($1, '') ON CONFLICT (namespace) DO NOTHING",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// See [`crate::db::runtime_db::RuntimeDb::search_index_namespaces`].
    pub fn search_index_namespaces(
        &self,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, String> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        Ok(self
            .connection()?
            .query(
                "SELECT namespace FROM sekai_namespace_object_generation WHERE namespace > $1
                 UNION
                 SELECT namespace FROM sekai_search_checkpoint_v2 WHERE namespace > $1
                 ORDER BY namespace LIMIT $2",
                &[&after, &limit],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }

    fn replace_object_text(
        tx: &mut postgres::Transaction<'_>,
        namespace: &str,
        object_id: &str,
        properties: &BTreeMap<String, String>,
    ) -> Result<(), String> {
        tx.execute(
            "DELETE FROM sekai_search_object_text_v2 WHERE namespace = $1 AND object_id = $2",
            &[&namespace, &object_id],
        )
        .map_err(|error| error.to_string())?;
        for (property, text) in properties {
            insert_chunked_tsvector(tx, text, |tx, chunk, stored, source| {
                tx.execute(
                    "INSERT INTO sekai_search_object_text_v2
                     (namespace, object_id, property, chunk, text, tsv)
                     VALUES ($1, $2, $3, $4, $5, to_tsvector('simple', $6))",
                    &[&namespace, &object_id, &property, &chunk, &stored, &source],
                )
                .map(|_| ())
            })?;
        }
        Ok(())
    }

    fn replace_dataset_text(
        tx: &mut postgres::Transaction<'_>,
        namespace: &str,
        dataset: &Dataset,
    ) -> Result<(), String> {
        tx.execute(
            "DELETE FROM sekai_search_dataset_text_v2 WHERE namespace = $1 AND dataset_id = $2",
            &[&namespace, &dataset.id],
        )
        .map_err(|error| error.to_string())?;
        let mut fields = vec![("name".to_string(), String::new(), dataset.name.clone())];
        for column in &dataset.columns {
            fields.push((
                format!("column:{}", column.name),
                column.classification.clone(),
                column.name.clone(),
            ));
        }
        for (field, classification, text) in fields {
            insert_chunked_tsvector(tx, &text, |tx, chunk, stored, source| {
                tx.execute(
                    "INSERT INTO sekai_search_dataset_text_v2
                     (namespace, dataset_id, field, chunk, classification, text, tsv)
                     VALUES ($1, $2, $3, $4, $5, $6, to_tsvector('simple', $7))",
                    &[
                        &namespace,
                        &dataset.id,
                        &field,
                        &chunk,
                        &classification,
                        &stored,
                        &source,
                    ],
                )
                .map(|_| ())
            })?;
        }
        Ok(())
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

    /// Upsert one object's index row and text; unchanged content is left.
    fn index_object_on(
        tx: &mut postgres::Transaction<'_>,
        object: &Object,
        now_ms: i64,
    ) -> Result<(), String> {
        let digest = object_content_digest(object);
        let existing: Option<String> = tx
            .query_opt(
                "SELECT content_digest FROM sekai_search_object_v2
                 WHERE namespace = $1 AND object_id = $2",
                &[&object.namespace, &object.id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if existing.as_deref() == Some(digest.as_str()) {
            return Ok(());
        }
        let attributes =
            serde_json::to_string(&policy_attributes(object)).map_err(|error| error.to_string())?;
        let marking = object_marking_token(object).unwrap_or_default();
        tx.execute(
            "INSERT INTO sekai_search_object_v2
             (namespace, object_id, kind, access_marking, policy_attributes, content_digest, indexed_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (namespace, object_id) DO UPDATE SET
                kind = EXCLUDED.kind,
                access_marking = EXCLUDED.access_marking,
                policy_attributes = EXCLUDED.policy_attributes,
                content_digest = EXCLUDED.content_digest,
                indexed_at_ms = EXCLUDED.indexed_at_ms",
            &[
                &object.namespace,
                &object.id,
                &object.kind,
                &marking,
                &attributes,
                &digest,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        Self::replace_object_text(
            tx,
            &object.namespace,
            &object.id,
            &object_text_properties(object),
        )
    }

    /// Upsert one dataset's metadata row and text. `bound` is the bound
    /// object's marking and policy attributes, read before the transaction.
    fn index_dataset_on(
        tx: &mut postgres::Transaction<'_>,
        namespace: &str,
        dataset: &Dataset,
        (bound_marking, bound_attributes): &(String, String),
        now_ms: i64,
    ) -> Result<(), String> {
        let digest = dataset_content_digest(dataset);
        let existing: Option<String> = tx
            .query_opt(
                "SELECT content_digest FROM sekai_search_dataset_v2
                 WHERE namespace = $1 AND dataset_id = $2",
                &[&namespace, &dataset.id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if existing.as_deref() == Some(digest.as_str()) {
            tx.execute(
                "UPDATE sekai_search_dataset_v2
                 SET bound_access_marking = $3, bound_policy_attributes = $4, indexed_at_ms = $5
                 WHERE namespace = $1 AND dataset_id = $2",
                &[
                    &namespace,
                    &dataset.id,
                    bound_marking,
                    bound_attributes,
                    &now_ms,
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
        tx.execute(
            "INSERT INTO sekai_search_dataset_v2
             (namespace, dataset_id, name, bound_object_id, bound_access_marking,
              bound_policy_attributes, columns, content_digest, indexed_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (namespace, dataset_id) DO UPDATE SET
                name = EXCLUDED.name,
                bound_object_id = EXCLUDED.bound_object_id,
                bound_access_marking = EXCLUDED.bound_access_marking,
                bound_policy_attributes = EXCLUDED.bound_policy_attributes,
                columns = EXCLUDED.columns,
                content_digest = EXCLUDED.content_digest,
                indexed_at_ms = EXCLUDED.indexed_at_ms",
            &[
                &namespace,
                &dataset.id,
                &dataset.name,
                &dataset.object_id,
                bound_marking,
                bound_attributes,
                &columns,
                &digest,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        Self::replace_dataset_text(tx, namespace, dataset)
    }

    /// Delete index rows of `table` and its text table for one key, or for
    /// the whole namespace when `key` is none.
    fn delete_rows_on(
        tx: &mut postgres::Transaction<'_>,
        [table, text_table, column]: [&str; 3],
        namespace: &str,
        key: Option<&str>,
    ) -> Result<(), String> {
        for table in [text_table, table] {
            match key {
                Some(key) => tx.execute(
                    &format!("DELETE FROM {table} WHERE namespace = $1 AND {column} = $2"),
                    &[&namespace, &key],
                ),
                None => tx.execute(
                    &format!("DELETE FROM {table} WHERE namespace = $1"),
                    &[&namespace],
                ),
            }
            .map_err(|error| error.to_string())?;
        }
        Ok(())
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

    fn subjects_include_team_principal(&self, subjects: &[String]) -> Result<bool, String> {
        if subjects.is_empty() {
            return Ok(false);
        }
        let mut conn = self.connection()?;
        for subject in subjects {
            let found = match conn.query_one(
                "SELECT EXISTS(SELECT 1 FROM sekai_team_principals WHERE principal = $1)",
                &[&subject],
            ) {
                Ok(row) => row.get::<_, bool>(0),
                Err(error) if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE) => {
                    false
                }
                Err(error) => return Err(error.to_string()),
            };
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
        let mut conn = self.connection()?;
        let policy = load_active_policy_postgres(&mut *conn, namespace, &object.kind)?;
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

    /// One catch-up of the namespace; see [`catch_up_namespace`].
    pub fn catch_up_search_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchCatchUpReport, SearchIndexError> {
        catch_up_namespace(self, namespace, now_ms)
    }

    pub fn search_index_dump(&self, namespace: &str) -> Result<SearchIndexDump, String> {
        let mut conn = self.connection()?;
        let object_rows = conn
            .query(
                "SELECT object_id, kind, access_marking, policy_attributes
                 FROM sekai_search_object_v2 WHERE namespace = $1",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?;
        let mut objects = BTreeMap::new();
        for row in object_rows {
            let object_id: String = row.get(0);
            let kind: String = row.get(1);
            let access_marking: String = row.get(2);
            let attributes: String = row.get(3);
            let mut properties = BTreeMap::new();
            for text in conn
                .query(
                    "SELECT property, text FROM sekai_search_object_text_v2
                     WHERE namespace = $1 AND object_id = $2 AND chunk = 0",
                    &[&namespace, &object_id],
                )
                .map_err(|error| error.to_string())?
            {
                properties.insert(text.get(0), text.get(1));
            }
            objects.insert(
                object_id,
                SearchObjectDump {
                    kind,
                    access_marking,
                    policy_attributes: serde_json::from_str(&attributes).unwrap_or_default(),
                    properties,
                },
            );
        }
        let mut datasets = BTreeMap::new();
        for row in conn
            .query(
                "SELECT dataset_id, name, bound_object_id, columns
                 FROM sekai_search_dataset_v2 WHERE namespace = $1",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
        {
            datasets.insert(
                row.get(0),
                SearchDatasetDump {
                    name: row.get(1),
                    bound_object_id: row.get(2),
                    columns: serde_json::from_str(&row.get::<_, String>(3)).unwrap_or_default(),
                },
            );
        }
        Ok(SearchIndexDump {
            analyzer_version: ANALYZER_VERSION.into(),
            objects,
            datasets,
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
        let match_query = postgres_tsquery(&query.text)?;
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
        let rows = self
            .connection()?
            .query(
                "SELECT f.object_id, f.property, o.kind, o.access_marking, o.policy_attributes
                 FROM sekai_search_object_text_v2 f
                 JOIN sekai_search_object_v2 o
                   ON o.namespace = f.namespace AND o.object_id = f.object_id
                 WHERE f.namespace = $1 AND f.tsv @@ to_tsquery('simple', $2)
                 ORDER BY f.object_id, f.property",
                &[&query.policy.namespace, &match_query],
            )
            .map_err(|error| error.to_string())?;
        type ObjectHit = (String, BTreeSet<String>, String, BTreeMap<String, String>);
        let mut grouped: BTreeMap<String, ObjectHit> = BTreeMap::new();
        for row in rows {
            let object_id: String = row.get(0);
            let property: String = row.get(1);
            let kind: String = row.get(2);
            let marking: String = row.get(3);
            let attributes: String = row.get(4);
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
        if query_uses_oversize_lexeme(&query.text) {
            for row in self
                .connection()?
                .query(
                    "SELECT f.object_id, f.property, o.kind, o.access_marking,
                            o.policy_attributes, f.text
                     FROM sekai_search_object_text_v2 f
                     JOIN sekai_search_object_v2 o
                       ON o.namespace = f.namespace AND o.object_id = f.object_id
                     WHERE f.namespace = $1 AND f.chunk = 0",
                    &[&query.policy.namespace],
                )
                .map_err(|error| error.to_string())?
            {
                let object_id: String = row.get(0);
                let property: String = row.get(1);
                let kind: String = row.get(2);
                let marking: String = row.get(3);
                let attributes: String = row.get(4);
                let stored: String = row.get(5);
                if !text_matches_query(&stored, &query.text) {
                    continue;
                }
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
        }
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
        let lattice = self.get_classification_lattice(&query.policy.namespace)?;
        if !query.policy.kinds.is_empty()
            && !query.policy.kinds.iter().any(|kind| kind == "dataset")
        {
            return Ok(Vec::new());
        }
        let rows = self
            .connection()?
            .query(
                "SELECT f.dataset_id, f.field, f.classification, d.bound_access_marking,
                        d.bound_policy_attributes, d.bound_object_id
                 FROM sekai_search_dataset_text_v2 f
                 JOIN sekai_search_dataset_v2 d
                   ON d.namespace = f.namespace AND d.dataset_id = f.dataset_id
                 WHERE f.namespace = $1 AND f.tsv @@ to_tsquery('simple', $2)
                 ORDER BY f.dataset_id, f.field",
                &[&query.policy.namespace, &match_query],
            )
            .map_err(|error| error.to_string())?;
        let mut grouped: BTreeMap<String, (BTreeSet<String>, String)> = BTreeMap::new();
        for row in rows {
            let dataset_id: String = row.get(0);
            let field: String = row.get(1);
            let classification: String = row.get(2);
            let bound_marking: String = row.get(3);
            let bound_attributes: String = row.get(4);
            let bound_object_id: String = row.get(5);
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
        if query_uses_oversize_lexeme(&query.text) {
            for row in self
                .connection()?
                .query(
                    "SELECT f.dataset_id, f.field, f.classification, d.bound_access_marking,
                            d.bound_policy_attributes, d.bound_object_id, f.text
                     FROM sekai_search_dataset_text_v2 f
                     JOIN sekai_search_dataset_v2 d
                       ON d.namespace = f.namespace AND d.dataset_id = f.dataset_id
                     WHERE f.namespace = $1 AND f.chunk = 0",
                    &[&query.policy.namespace],
                )
                .map_err(|error| error.to_string())?
            {
                let dataset_id: String = row.get(0);
                let field: String = row.get(1);
                let classification: String = row.get(2);
                let bound_marking: String = row.get(3);
                let bound_attributes: String = row.get(4);
                let bound_object_id: String = row.get(5);
                let stored: String = row.get(6);
                if !text_matches_query(&stored, &query.text) {
                    continue;
                }
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
                if !dataset_classification_allows(
                    &classification,
                    query.policy.clearance.as_deref(),
                ) && !classification.is_empty()
                {
                    continue;
                }
                grouped
                    .entry(dataset_id)
                    .or_insert_with(|| (BTreeSet::new(), bound_object_id))
                    .0
                    .insert(field);
            }
        }
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

    #[cfg(any(test, feature = "gateway-test-support"))]
    pub fn purge_object_changes_for_test(&self) -> Result<(), String> {
        self.connection()?
            .execute("DELETE FROM sekai_object_changes", &[])
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    #[cfg(any(test, feature = "gateway-test-support"))]
    pub fn purge_object_changes_for_object_for_test(&self, object_id: &str) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM sekai_object_changes WHERE object_id = $1",
                &[&object_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

impl SearchMaintenance for PostgresDb {
    fn search_maintenance(&self) -> &Mutex<()> {
        &self.search_maintenance
    }

    fn read_search_checkpoint(&self, namespace: &str) -> Result<Option<SearchCheckpoint>, String> {
        PostgresDb::read_search_checkpoint(self, namespace)
    }

    fn search_checkpoint_namespaces(&self) -> Result<Vec<String>, String> {
        Ok(self
            .connection()?
            .query("SELECT namespace FROM sekai_search_checkpoint_v2", &[])
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
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
        PostgresDb::namespace_object_generation(self, namespace)
    }

    fn object_change_watermark(&self, namespace: &str) -> Result<u64, String> {
        PostgresDb::object_change_watermark(self, namespace)
    }

    fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        PostgresDb::get_object(self, id)
    }

    fn namespace_datasets(&self, namespace: &str) -> Result<Vec<Dataset>, String> {
        let mut datasets = Vec::new();
        for dataset in self.list_datasets()? {
            if dataset.object_id.is_empty() {
                datasets.push(dataset);
                continue;
            }
            let bound = PostgresDb::get_object(self, &dataset.object_id)?;
            if bound.is_some_and(|object| object.namespace == namespace) {
                datasets.push(dataset);
            }
        }
        datasets.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(datasets)
    }

    fn namespace_object_ids(&self, namespace: &str) -> Result<Vec<String>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT id FROM sekai_objects WHERE namespace = $1 ORDER BY id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }

    fn search_dataset_ids(&self, namespace: &str) -> Result<Vec<String>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT dataset_id FROM sekai_search_dataset_v2 WHERE namespace = $1 ORDER BY dataset_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }

    fn search_counts(&self, namespace: &str) -> Result<(i64, i64), String> {
        let row = self
            .connection()?
            .query_one(
                "SELECT (SELECT COUNT(*) FROM sekai_search_object_v2 WHERE namespace = $1),
                        (SELECT COUNT(*) FROM sekai_search_dataset_v2 WHERE namespace = $1)",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?;
        Ok((row.get(0), row.get(1)))
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
            |tx| {
                Self::delete_rows_on(tx, OBJECT_ROWS, namespace, None)?;
                Self::delete_rows_on(tx, DATASET_ROWS, namespace, None)
            },
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
                |tx| Self::index_object_on(tx, object, now_ms),
            ),
            DocumentWrite::DeleteObject(object_id) => self.fenced_search_write(
                namespace,
                revision,
                now_ms,
                &CheckpointFields::default(),
                |tx| Self::delete_rows_on(tx, OBJECT_ROWS, namespace, Some(object_id)),
            ),
            DocumentWrite::IndexDataset(dataset) => {
                let bound = self.bound_dataset_policy(dataset)?;
                self.fenced_search_write(
                    namespace,
                    revision,
                    now_ms,
                    &CheckpointFields::default(),
                    |tx| Self::index_dataset_on(tx, namespace, dataset, &bound, now_ms),
                )
            }
            DocumentWrite::DeleteDataset(dataset_id) => self.fenced_search_write(
                namespace,
                revision,
                now_ms,
                &CheckpointFields::default(),
                |tx| Self::delete_rows_on(tx, DATASET_ROWS, namespace, Some(dataset_id)),
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

impl SearchIndex for PostgresDb {
    fn index(&self, document: &SearchDocument, now_ms: i64) -> Result<(), SearchIndexError> {
        let _guard = lock_search_maintenance(self)?;
        match document {
            SearchDocument::Object(object) => {
                self.search_write(|tx| Self::index_object_on(tx, object, now_ms))
            }
            SearchDocument::Dataset { namespace, dataset } => {
                let bound = self.bound_dataset_policy(dataset)?;
                self.search_write(|tx| {
                    Self::index_dataset_on(tx, namespace, dataset, &bound, now_ms)
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
            } => self.search_write(|tx| {
                Self::delete_rows_on(tx, OBJECT_ROWS, namespace, Some(object_id))
            }),
            SearchDocumentKey::Dataset {
                namespace,
                dataset_id,
            } => self.search_write(|tx| {
                Self::delete_rows_on(tx, DATASET_ROWS, namespace, Some(dataset_id))
            }),
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
        // Exact over the chunk table, as on SQLite.
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

#[cfg(test)]
mod tests {
    use super::{MAX_TSVECTOR_CHUNK_BYTES, split_tsvector_source, tsvector_chunks};

    #[test]
    fn tsvector_chunks_keep_every_token() {
        let huge = (0..(MAX_TSVECTOR_CHUNK_BYTES / 2 + 40))
            .map(|index| format!("t{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let chunks = tsvector_chunks(&huge);
        assert!(chunks.len() > 1);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.len() <= MAX_TSVECTOR_CHUNK_BYTES)
        );
        let tokens = chunks
            .iter()
            .flat_map(|chunk| chunk.split_whitespace())
            .collect::<Vec<_>>();
        let expected = huge.split_whitespace().collect::<Vec<_>>();
        assert_eq!(tokens, expected);
    }

    #[test]
    fn split_tsvector_source_keeps_both_sides() {
        let source = "alpha beta gamma delta epsilon zeta eta theta iota kappa";
        let (left, right) = split_tsvector_source(source).unwrap();
        assert!(!left.is_empty());
        assert!(!right.is_empty());
        let joined = format!("{left} {right}");
        for token in source.split_whitespace() {
            assert!(joined.contains(token), "{token}");
        }
    }
}
