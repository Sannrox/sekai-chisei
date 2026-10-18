use crate::db::postgres::PostgresDb;
use crate::db::postgres_object_security::load_active_policy_postgres;
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
    dataset_content_digest, live_object_match_fields, object_content_digest,
    object_text_properties, policy_attributes, purpose_allows, search_tokens, text_matches_query,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::MutexGuard;

const PG_MAX_LEXEME_BYTES: usize = 2047;

fn query_uses_oversize_lexeme(text: &str) -> bool {
    search_tokens(text)
        .iter()
        .any(|token| token.len() > PG_MAX_LEXEME_BYTES)
}

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
    fn lock_search_maintenance(&self) -> Result<MutexGuard<'_, ()>, SearchIndexError> {
        self.search_maintenance.lock().map_err(|_| {
            SearchIndexError::Unavailable("search maintenance lock was poisoned".into())
        })
    }

    fn search_checkpoint(
        &self,
        namespace: &str,
    ) -> Result<Option<(u64, u64, String, i64)>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT last_change_rowid, last_generation, dataset_catalog_digest, indexed_at_ms
                 FROM sekai_search_checkpoint WHERE namespace = $1",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                (
                    row.get::<_, i64>(0).max(0) as u64,
                    row.get::<_, i64>(1).max(0) as u64,
                    row.get(2),
                    row.get(3),
                )
            }))
    }

    fn store_search_checkpoint(
        &self,
        namespace: &str,
        last_change_rowid: u64,
        last_generation: u64,
        dataset_catalog_digest: &str,
        indexed_at_ms: i64,
    ) -> Result<(), String> {
        let rowid = i64::try_from(last_change_rowid).map_err(|error| error.to_string())?;
        let generation = i64::try_from(last_generation).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_search_checkpoint
             (namespace, analyzer_version, last_change_rowid, last_generation,
              dataset_catalog_digest, indexed_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (namespace) DO UPDATE SET
                analyzer_version = EXCLUDED.analyzer_version,
                last_change_rowid = EXCLUDED.last_change_rowid,
                last_generation = EXCLUDED.last_generation,
                dataset_catalog_digest = EXCLUDED.dataset_catalog_digest,
                indexed_at_ms = EXCLUDED.indexed_at_ms",
                &[
                    &namespace,
                    &ANALYZER_VERSION,
                    &rowid,
                    &generation,
                    &dataset_catalog_digest,
                    &indexed_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn replace_object_text(
        tx: &mut postgres::Transaction<'_>,
        namespace: &str,
        object_id: &str,
        properties: &BTreeMap<String, String>,
    ) -> Result<(), String> {
        tx.execute(
            "DELETE FROM sekai_search_object_text WHERE namespace = $1 AND object_id = $2",
            &[&namespace, &object_id],
        )
        .map_err(|error| error.to_string())?;
        for (property, text) in properties {
            insert_chunked_tsvector(tx, text, |tx, chunk, stored, source| {
                tx.execute(
                    "INSERT INTO sekai_search_object_text
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
            "DELETE FROM sekai_search_dataset_text WHERE namespace = $1 AND dataset_id = $2",
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
                    "INSERT INTO sekai_search_dataset_text
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

    fn index_object_document(&self, object: &Object, now_ms: i64) -> Result<(), SearchIndexError> {
        let digest = object_content_digest(object);
        let attributes =
            serde_json::to_string(&policy_attributes(object)).map_err(|error| error.to_string())?;
        let properties = object_text_properties(object);
        let marking = object_marking_token(object).unwrap_or_default();
        let mut conn = self.connection().map_err(SearchIndexError::from)?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let existing: Option<String> = tx
            .query_opt(
                "SELECT content_digest FROM sekai_search_object
                 WHERE namespace = $1 AND object_id = $2",
                &[&object.namespace, &object.id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if existing.as_deref() == Some(digest.as_str()) {
            return Ok(());
        }
        tx.execute(
            "INSERT INTO sekai_search_object
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
        Self::replace_object_text(&mut tx, &object.namespace, &object.id, &properties)?;
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
        let mut conn = self.connection().map_err(SearchIndexError::from)?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let existing: Option<String> = tx
            .query_opt(
                "SELECT content_digest FROM sekai_search_dataset
                 WHERE namespace = $1 AND dataset_id = $2",
                &[&namespace, &dataset.id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if existing.as_deref() == Some(digest.as_str()) {
            tx.execute(
                "UPDATE sekai_search_dataset
                 SET bound_access_marking = $3, bound_policy_attributes = $4, indexed_at_ms = $5
                 WHERE namespace = $1 AND dataset_id = $2",
                &[
                    &namespace,
                    &dataset.id,
                    &bound_marking,
                    &bound_attributes,
                    &now_ms,
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
                &bound_marking,
                &bound_attributes,
                &columns,
                &digest,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        Self::replace_dataset_text(&mut tx, namespace, dataset)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn delete_object_document(
        &self,
        namespace: &str,
        object_id: &str,
    ) -> Result<(), SearchIndexError> {
        let mut conn = self.connection().map_err(SearchIndexError::from)?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_search_object_text WHERE namespace = $1 AND object_id = $2",
            &[&namespace, &object_id],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_search_object WHERE namespace = $1 AND object_id = $2",
            &[&namespace, &object_id],
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
        let mut conn = self.connection().map_err(SearchIndexError::from)?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_search_dataset_text WHERE namespace = $1 AND dataset_id = $2",
            &[&namespace, &dataset_id],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_search_dataset WHERE namespace = $1 AND dataset_id = $2",
            &[&namespace, &dataset_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn search_object_ids(&self, namespace: &str) -> Result<Vec<String>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT object_id FROM sekai_search_object WHERE namespace = $1 ORDER BY object_id",
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
                "SELECT dataset_id FROM sekai_search_dataset WHERE namespace = $1 ORDER BY dataset_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }

    fn clear_namespace_index(&self, namespace: &str) -> Result<(), SearchIndexError> {
        for object_id in self.search_object_ids(namespace)? {
            self.delete_object_document(namespace, &object_id)?;
        }
        for dataset_id in self.search_dataset_ids(namespace)? {
            self.delete_dataset_document(namespace, &dataset_id)?;
        }
        Ok(())
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
        let ids = self
            .connection()?
            .query(
                "SELECT id FROM sekai_objects WHERE namespace = $1 ORDER BY id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
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
            .connection()?
            .query_one(
                "SELECT COUNT(*) FROM sekai_search_object WHERE namespace = $1",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .get::<_, i64>(0);
        let datasets = self
            .connection()?
            .query_one(
                "SELECT COUNT(*) FROM sekai_search_dataset WHERE namespace = $1",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .get::<_, i64>(0);
        Ok((objects, datasets))
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
        let namespaces = self
            .connection()?
            .query("SELECT namespace FROM sekai_search_checkpoint", &[])
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
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
        if !lattice_marking_allows(marking, query, None) {
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

    pub(crate) fn search_index_dump(&self, namespace: &str) -> Result<SearchIndexDump, String> {
        let mut conn = self.connection()?;
        let object_rows = conn
            .query(
                "SELECT object_id, kind, access_marking, policy_attributes
                 FROM sekai_search_object WHERE namespace = $1",
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
                    "SELECT property, text FROM sekai_search_object_text
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
                 FROM sekai_search_dataset WHERE namespace = $1",
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
        let rows = self
            .connection()?
            .query(
                "SELECT f.object_id, f.property, o.kind, o.access_marking, o.policy_attributes
                 FROM sekai_search_object_text f
                 JOIN sekai_search_object o
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
            if !lattice_marking_allows(&marking, query, None) {
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
                     FROM sekai_search_object_text f
                     JOIN sekai_search_object o
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
                if !lattice_marking_allows(&marking, query, None) {
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
                 FROM sekai_search_dataset_text f
                 JOIN sekai_search_dataset d
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
            if !lattice_marking_allows(&bound_marking, query, None) {
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
                     FROM sekai_search_dataset_text f
                     JOIN sekai_search_dataset d
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
                if !lattice_marking_allows(&bound_marking, query, None) {
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

    fn search_status(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchIndexStatus, SearchIndexError> {
        if namespace.trim().is_empty() {
            return Err(SearchIndexError::InvalidArgument(
                "namespace required".into(),
            ));
        }
        let (lag, pending, generation) = self.search_lag_ms(namespace, now_ms)?;
        let (objects, datasets) = self.search_counts(namespace)?;
        let checkpoint = self.search_checkpoint(namespace)?;
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
                .map(|(_, _, _, indexed)| *indexed)
                .unwrap_or(0),
            object_count: objects,
            dataset_count: datasets,
            lag_ms: lag,
            pending_changes: pending,
        })
    }

    #[cfg(test)]
    pub(crate) fn purge_object_changes_for_test(&self) -> Result<(), String> {
        self.connection()?
            .execute("DELETE FROM sekai_object_changes", &[])
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    #[cfg(test)]
    pub(crate) fn purge_object_changes_for_object_for_test(
        &self,
        object_id: &str,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM sekai_object_changes WHERE object_id = $1",
                &[&object_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

impl SearchIndex for PostgresDb {
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
