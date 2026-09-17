use crate::db::sekai::SekaiDb;
use crate::sekai::dataset::RowQuery;
use crate::sekai::object_type_index::{
    HopProjectionAdmit, HopProjectionFence, ObjectTypeDatasource, ObjectTypeIndexEdit,
    ObjectTypeIndexError, ObjectTypeIndexMember, ObjectTypeIndexStatus, ReindexReport,
    admit_hop_projection_fence, member_from_edit, member_from_row, schema_drift,
};
use rusqlite::params;
use std::collections::{BTreeMap, HashMap};

impl SekaiDb {
    pub(crate) fn migrate_object_type_index(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS sekai_object_type_datasource (
                    namespace TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    definition_digest TEXT NOT NULL,
                    dataset_id TEXT NOT NULL,
                    key_column TEXT NOT NULL,
                    property_mapping TEXT NOT NULL,
                    hidden_column TEXT NOT NULL DEFAULT '',
                    edits_only INTEGER NOT NULL DEFAULT 0,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (namespace, kind)
                );
                CREATE TABLE IF NOT EXISTS sekai_object_type_index_status (
                    namespace TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    indexed_at_ms INTEGER NOT NULL,
                    last_dataset_row_id INTEGER NOT NULL DEFAULT 0,
                    member_count INTEGER NOT NULL DEFAULT 0,
                    stale INTEGER NOT NULL DEFAULT 0,
                    quarantine_reason TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (namespace, kind)
                );
                CREATE TABLE IF NOT EXISTS sekai_object_type_index_member (
                    namespace TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    source_key TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    properties TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    hidden INTEGER NOT NULL DEFAULT 0,
                    from_edit INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (namespace, kind, source_key)
                );
                CREATE TABLE IF NOT EXISTS sekai_object_type_index_edit (
                    namespace TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    source_key TEXT NOT NULL,
                    properties TEXT NOT NULL,
                    hidden INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (namespace, kind, source_key)
                );
                CREATE TABLE IF NOT EXISTS sekai_object_type_index_join (
                    namespace TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    property TEXT NOT NULL,
                    value_digest TEXT NOT NULL,
                    source_key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (namespace, kind, property, value_digest, source_key)
                );
                CREATE INDEX IF NOT EXISTS sekai_object_type_index_join_lookup
                    ON sekai_object_type_index_join (namespace, kind, property, value_digest);
                CREATE INDEX IF NOT EXISTS sekai_object_type_index_join_value
                    ON sekai_object_type_index_join (namespace, kind, property, value);
                CREATE INDEX IF NOT EXISTS sekai_object_type_index_join_member
                    ON sekai_object_type_index_join (namespace, kind, source_key);
                CREATE TABLE IF NOT EXISTS sekai_object_type_index_join_status (
                    namespace TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    ready INTEGER NOT NULL DEFAULT 0,
                    rebuilt_at_ms INTEGER NOT NULL DEFAULT 0,
                    generation TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (namespace, kind)
                );
                ",
            )
            .map_err(|error| error.to_string())?;
        let _ = self.conn().execute(
            "ALTER TABLE sekai_object_type_index_join_status
             ADD COLUMN generation TEXT NOT NULL DEFAULT ''",
            [],
        );
        Ok(())
    }

    pub fn register_object_type_datasource(
        &self,
        binding: &ObjectTypeDatasource,
        created_at_ms: i64,
    ) -> Result<(), String> {
        let existing = self.get_object_type_datasource(&binding.namespace, &binding.kind)?;
        let mapping =
            serde_json::to_string(&binding.property_mapping).map_err(|e| e.to_string())?;
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_object_type_datasource
                 (namespace, kind, definition_digest, dataset_id, key_column, property_mapping, hidden_column, edits_only, created_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    binding.namespace,
                    binding.kind,
                    binding.definition_digest,
                    binding.dataset_id,
                    binding.key_column,
                    mapping,
                    binding.hidden_column,
                    i64::from(binding.edits_only),
                    created_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        if existing
            .as_ref()
            .is_none_or(|previous| previous.changes_hop_generation(binding))
        {
            self.set_hop_projection_ready(&binding.namespace, &binding.kind, false, created_at_ms)?;
        }
        Ok(())
    }

    pub fn get_object_type_datasource(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Option<ObjectTypeDatasource>, String> {
        self.conn()
            .query_row(
                "SELECT definition_digest, dataset_id, key_column, property_mapping, hidden_column, edits_only
                 FROM sekai_object_type_datasource WHERE namespace = ?1 AND kind = ?2",
                params![namespace, kind],
                |row| {
                    let mapping: String = row.get(3)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        mapping,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional_row()
            .map_err(|error| error.to_string())?
            .map(
                |(definition_digest, dataset_id, key_column, mapping, hidden_column, edits_only)| {
                    let property_mapping: BTreeMap<String, String> =
                        serde_json::from_str(&mapping).map_err(|error| error.to_string())?;
                    Ok(ObjectTypeDatasource {
                        contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                        namespace: namespace.into(),
                        kind: kind.into(),
                        definition_digest,
                        dataset_id,
                        key_column,
                        property_mapping,
                        hidden_column,
                        edits_only: edits_only != 0,
                    })
                },
            )
            .transpose()
    }

    pub fn put_object_type_index_edit(&self, edit: &ObjectTypeIndexEdit) -> Result<(), String> {
        let properties = serde_json::to_string(&edit.properties).map_err(|e| e.to_string())?;
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_object_type_index_edit
                 (namespace, kind, source_key, properties, hidden) VALUES (?1,?2,?3,?4,?5)",
                params![
                    edit.namespace,
                    edit.kind,
                    edit.source_key,
                    properties,
                    i64::from(edit.hidden)
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn apply_object_type_index(
        &self,
        namespace: &str,
        kind: &str,
        full_rebuild: bool,
        now_ms: i64,
    ) -> Result<ReindexReport, String> {
        self.apply_object_type_index_staged(namespace, kind, full_rebuild, now_ms, true)
    }

    #[cfg(test)]
    pub(crate) fn apply_object_type_index_without_join_rebuild(
        &self,
        namespace: &str,
        kind: &str,
        full_rebuild: bool,
        now_ms: i64,
    ) -> Result<ReindexReport, String> {
        self.apply_object_type_index_staged(namespace, kind, full_rebuild, now_ms, false)
    }

    fn apply_object_type_index_staged(
        &self,
        namespace: &str,
        kind: &str,
        full_rebuild: bool,
        now_ms: i64,
        commit_joins: bool,
    ) -> Result<ReindexReport, String> {
        let binding = self
            .get_object_type_datasource(namespace, kind)?
            .ok_or("object type datasource not found")?;
        if !binding.edits_only {
            let dataset = self
                .get_dataset(&binding.dataset_id)?
                .ok_or("dataset not found")?;
            if let Some(reason) = schema_drift(&binding, &dataset.columns) {
                self.mark_index_quarantined(namespace, kind, now_ms, &reason)?;
                return Ok(ReindexReport {
                    quarantined: true,
                    quarantine_reason: reason,
                    ..ReindexReport::default()
                });
            }
        }
        let status = self.object_type_index_status(namespace, kind, now_ms)?;
        let after_id = if full_rebuild {
            0
        } else {
            status
                .as_ref()
                .map(|status| status.last_dataset_row_id)
                .unwrap_or(0)
        };
        self.set_hop_projection_ready(namespace, kind, false, now_ms)?;
        if full_rebuild {
            self.conn()
                .execute(
                    "DELETE FROM sekai_object_type_index_member WHERE namespace = ?1 AND kind = ?2 AND from_edit = 0",
                    params![namespace, kind],
                )
                .map_err(|error| error.to_string())?;
            self.conn()
                .execute(
                    "DELETE FROM sekai_object_type_index_join WHERE namespace = ?1 AND kind = ?2",
                    params![namespace, kind],
                )
                .map_err(|error| error.to_string())?;
        }
        let mut rewritten = 0i32;
        let mut skipped = 0i32;
        let mut last_row_id = after_id;
        if !binding.edits_only {
            let rows = self.list_dataset_row_records(&binding.dataset_id)?;
            for (row_id, data) in rows {
                if row_id <= after_id {
                    continue;
                }
                last_row_id = last_row_id.max(row_id);
                let member = match member_from_row(&binding, &data) {
                    Ok(member) => member,
                    Err(_) => continue,
                };
                if self.upsert_index_member(&member)? {
                    rewritten += 1;
                } else {
                    skipped += 1;
                }
            }
        }
        for edit in self.list_object_type_index_edits(namespace, kind)? {
            let member = member_from_edit(&binding, &edit);
            self.force_upsert_index_member(&member)?;
            rewritten += 1;
        }
        if !commit_joins {
            return Ok(ReindexReport {
                rewritten_keys: rewritten,
                skipped_unchanged: skipped,
                quarantined: false,
                quarantine_reason: String::new(),
            });
        }
        let member_count = self.count_visible_index_members(namespace, kind)?;
        self.rebuild_kind_join(namespace, kind, now_ms)?;
        self.stamp_datasource_to_published(namespace, kind)?;
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_object_type_index_status
                 (namespace, kind, indexed_at_ms, last_dataset_row_id, member_count, stale, quarantine_reason)
                 VALUES (?1,?2,?3,?4,?5,0,'')",
                params![namespace, kind, now_ms, last_row_id, member_count],
            )
            .map_err(|error| error.to_string())?;
        Ok(ReindexReport {
            rewritten_keys: rewritten,
            skipped_unchanged: skipped,
            quarantined: false,
            quarantine_reason: String::new(),
        })
    }

    pub fn object_type_index_status(
        &self,
        namespace: &str,
        kind: &str,
        now_ms: i64,
    ) -> Result<Option<ObjectTypeIndexStatus>, String> {
        self.conn()
            .query_row(
                "SELECT indexed_at_ms, last_dataset_row_id, member_count, stale, quarantine_reason
                 FROM sekai_object_type_index_status WHERE namespace = ?1 AND kind = ?2",
                params![namespace, kind],
                |row| {
                    Ok(ObjectTypeIndexStatus {
                        namespace: namespace.into(),
                        kind: kind.into(),
                        indexed_at_ms: row.get(0)?,
                        last_dataset_row_id: row.get(1)?,
                        member_count: row.get(2)?,
                        stale: row.get::<_, i64>(3)? != 0,
                        quarantine_reason: row.get(4)?,
                        lag_ms: 0,
                    })
                },
            )
            .optional_row()
            .map_err(|error| error.to_string())
            .map(|status| {
                status.map(|mut status| {
                    status.lag_ms = now_ms.saturating_sub(status.indexed_at_ms).max(0);
                    status
                })
            })
    }

    pub fn list_visible_index_members(
        &self,
        namespace: &str,
        kind: &str,
        query: &RowQuery,
    ) -> Result<Vec<ObjectTypeIndexMember>, String> {
        self.list_visible_index_members_projected(namespace, kind, query, None)
    }

    pub fn list_visible_index_members_projected(
        &self,
        namespace: &str,
        kind: &str,
        query: &RowQuery,
        needed: Option<&[String]>,
    ) -> Result<Vec<ObjectTypeIndexMember>, String> {
        let (filter_sql, filter_values) = crate::sekai::object_type_index::member_filter_sql(
            crate::sekai::object_type_index::IndexSqlDialect::Sqlite,
            &query.filters,
        )?;
        let sql = format!(
            "SELECT source_key, object_id, properties, content_hash, hidden, from_edit
             FROM sekai_object_type_index_member
             WHERE namespace = ?1 AND kind = ?2 AND hidden = 0{filter_sql}
             ORDER BY source_key"
        );
        let conn = self.conn();
        let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&namespace, &kind];
        for value in &filter_values {
            params.push(value);
        }
        let mut rows = stmt
            .query(params.as_slice())
            .map_err(|error| error.to_string())?;
        let mut members = Vec::new();
        let mut skipped = 0i32;
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let properties: String = row.get(2).map_err(|error| error.to_string())?;
            let properties =
                crate::sekai::object_type_index::project_member_properties(&properties, needed)?;
            if !index_member_matches(&properties, query) {
                continue;
            }
            if skipped < query.offset {
                skipped += 1;
                continue;
            }
            if query.limit > 0 && members.len() as i32 >= query.limit {
                continue;
            }
            members.push(ObjectTypeIndexMember {
                namespace: namespace.into(),
                kind: kind.into(),
                source_key: row.get(0).map_err(|error| error.to_string())?,
                object_id: row.get(1).map_err(|error| error.to_string())?,
                properties,
                content_hash: row.get(3).map_err(|error| error.to_string())?,
                hidden: false,
                from_edit: row.get::<_, i64>(5).map_err(|error| error.to_string())? != 0,
            });
        }
        Ok(members)
    }

    pub fn count_visible_index_members(&self, namespace: &str, kind: &str) -> Result<i32, String> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_object_type_index_member
                 WHERE namespace = ?1 AND kind = ?2 AND hidden = 0",
                params![namespace, kind],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }

    fn list_object_type_index_edits(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Vec<ObjectTypeIndexEdit>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT source_key, properties, hidden FROM sekai_object_type_index_edit
                 WHERE namespace = ?1 AND kind = ?2",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = stmt
            .query(params![namespace, kind])
            .map_err(|error| error.to_string())?;
        let mut edits = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let properties: String = row.get(1).map_err(|error| error.to_string())?;
            edits.push(ObjectTypeIndexEdit {
                namespace: namespace.into(),
                kind: kind.into(),
                source_key: row.get(0).map_err(|error| error.to_string())?,
                properties: serde_json::from_str(&properties).map_err(|error| error.to_string())?,
                hidden: row.get::<_, i64>(2).map_err(|error| error.to_string())? != 0,
            });
        }
        Ok(edits)
    }

    fn upsert_index_member(&self, member: &ObjectTypeIndexMember) -> Result<bool, String> {
        let existing: Option<String> = self
            .conn()
            .query_row(
                "SELECT content_hash FROM sekai_object_type_index_member
                 WHERE namespace = ?1 AND kind = ?2 AND source_key = ?3",
                params![member.namespace, member.kind, member.source_key],
                |row| row.get(0),
            )
            .optional_row()
            .map_err(|error| error.to_string())?;
        if existing.as_deref() == Some(member.content_hash.as_str()) {
            return Ok(false);
        }
        self.force_upsert_index_member(member)?;
        Ok(true)
    }

    fn force_upsert_index_member(&self, member: &ObjectTypeIndexMember) -> Result<(), String> {
        let properties = serde_json::to_string(&member.properties).map_err(|e| e.to_string())?;
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_object_type_index_member
                 (namespace, kind, source_key, object_id, properties, content_hash, hidden, from_edit)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    member.namespace,
                    member.kind,
                    member.source_key,
                    member.object_id,
                    properties,
                    member.content_hash,
                    i64::from(member.hidden),
                    i64::from(member.from_edit)
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub(crate) fn set_hop_projection_ready(
        &self,
        namespace: &str,
        kind: &str,
        ready: bool,
        now_ms: i64,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_object_type_index_join_status
                 (namespace, kind, ready, rebuilt_at_ms, generation) VALUES (?1,?2,?3,?4,?5)",
                params![namespace, kind, i64::from(ready), now_ms, ""],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn invalidate_namespace_hop_projection(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "UPDATE sekai_object_type_index_join_status
                 SET ready = 0, generation = '', rebuilt_at_ms = ?1 WHERE namespace = ?2",
                params![now_ms, namespace],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn stamp_datasource_to_published(&self, namespace: &str, kind: &str) -> Result<(), String> {
        let Some(published) = self.get_published_definition_revision(namespace)? else {
            return Ok(());
        };
        self.conn()
            .execute(
                "UPDATE sekai_object_type_datasource
                 SET definition_digest = ?1 WHERE namespace = ?2 AND kind = ?3",
                params![published.revision_digest, namespace, kind],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn hop_rebuild_generation(&self, namespace: &str, kind: &str) -> Result<String, String> {
        if let Some(published) = self.get_published_definition_revision(namespace)? {
            return Ok(published.revision_digest);
        }
        Ok(self
            .get_object_type_datasource(namespace, kind)?
            .map(|binding| binding.definition_digest)
            .unwrap_or_default())
    }

    fn rebuild_kind_join(&self, namespace: &str, kind: &str, now_ms: i64) -> Result<(), String> {
        let generation = self.hop_rebuild_generation(namespace, kind)?;
        let members = self.list_visible_index_members(
            namespace,
            kind,
            &crate::sekai::dataset::RowQuery::default(),
        )?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO sekai_object_type_index_join_status
             (namespace, kind, ready, rebuilt_at_ms, generation) VALUES (?1,?2,?3,?4,?5)",
            params![namespace, kind, 0i64, now_ms, ""],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_object_type_index_join WHERE namespace = ?1 AND kind = ?2",
            params![namespace, kind],
        )
        .map_err(|error| error.to_string())?;
        for member in &members {
            for (property, value) in &member.properties {
                let digest = crate::sekai::object_type_index::join_value_digest(value);
                tx.execute(
                    "INSERT OR REPLACE INTO sekai_object_type_index_join
                     (namespace, kind, property, value_digest, source_key, value)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![
                        member.namespace,
                        member.kind,
                        property,
                        digest,
                        member.source_key,
                        value
                    ],
                )
                .map_err(|error| error.to_string())?;
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO sekai_object_type_index_join_status
             (namespace, kind, ready, rebuilt_at_ms, generation) VALUES (?1,?2,?3,?4,?5)",
            params![namespace, kind, 1i64, now_ms, generation],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    fn hop_projection_count_witness(&self, namespace: &str, kind: &str) -> Result<bool, String> {
        if self.count_index_join_rows(namespace, kind)? > 0 {
            return Ok(true);
        }
        Ok(self.count_visible_index_members(namespace, kind)? == 0)
    }

    fn list_hop_projection_fences(
        &self,
        namespace: &str,
        kinds: &[&str],
    ) -> Result<HashMap<String, HopProjectionFence>, String> {
        if kinds.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = (0..kinds.len())
            .map(|index| format!("?{}", index + 2))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT s.kind, s.ready, COALESCE(s.generation, ''), COALESCE(d.definition_digest, '')
             FROM sekai_object_type_index_join_status s
             LEFT JOIN sekai_object_type_datasource d
               ON d.namespace = s.namespace AND d.kind = s.kind
             WHERE s.namespace = ?1 AND s.kind IN ({placeholders})"
        );
        let conn = self.conn();
        let mut statement = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let mut params: Vec<&dyn rusqlite::types::ToSql> = vec![&namespace];
        for kind in kinds {
            params.push(kind);
        }
        let rows = statement
            .query_map(params.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    HopProjectionFence {
                        ready: row.get::<_, i64>(1)? != 0,
                        generation: row.get(2)?,
                        definition_digest: row.get(3)?,
                    },
                ))
            })
            .map_err(|error| error.to_string())?;
        let mut fences = HashMap::new();
        for row in rows {
            let (kind, fence) = row.map_err(|error| error.to_string())?;
            fences.insert(kind, fence);
        }
        Ok(fences)
    }

    pub fn hop_projection_kinds_ready(
        &self,
        namespace: &str,
        kinds: &[&str],
        published: &str,
    ) -> Result<bool, String> {
        if kinds.is_empty() {
            return Ok(true);
        }
        let fences = self.list_hop_projection_fences(namespace, kinds)?;
        for kind in kinds {
            let Some(fence) = fences.get(*kind) else {
                return Ok(false);
            };
            match admit_hop_projection_fence(fence, published) {
                HopProjectionAdmit::Admit => {}
                HopProjectionAdmit::Reject => return Ok(false),
                HopProjectionAdmit::CountFallback => {
                    if !self.hop_projection_count_witness(namespace, kind)? {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    pub fn hop_projection_ready(&self, namespace: &str, kind: &str) -> Result<bool, String> {
        let published = self.hop_rebuild_generation(namespace, kind)?;
        self.hop_projection_kinds_ready(namespace, &[kind], &published)
    }

    pub fn count_index_join_rows(&self, namespace: &str, kind: &str) -> Result<i64, String> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_object_type_index_join
                 WHERE namespace = ?1 AND kind = ?2",
                params![namespace, kind],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }

    pub fn list_index_join_children(
        &self,
        namespace: &str,
        kind: &str,
        property: &str,
        values: &[String],
    ) -> Result<Vec<(String, String)>, String> {
        if values.is_empty() {
            return Ok(Vec::new());
        }
        if values.len() > 400 {
            let mut out = Vec::new();
            for chunk in values.chunks(400) {
                out.extend(self.list_index_join_children(namespace, kind, property, chunk)?);
            }
            return Ok(out);
        }
        let conn = self.conn();
        let placeholders = vec!["?"; values.len()].join(",");
        let sql = format!(
            "SELECT value, source_key FROM sekai_object_type_index_join
             WHERE namespace = ?1 AND kind = ?2 AND property = ?3 AND value IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&namespace, &kind, &property];
        for value in values {
            params.push(value);
        }
        let mut rows = stmt
            .query(params.as_slice())
            .map_err(|error| error.to_string())?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            out.push((
                row.get(0).map_err(|error| error.to_string())?,
                row.get(1).map_err(|error| error.to_string())?,
            ));
        }
        Ok(out)
    }

    pub fn list_index_members_by_keys(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
    ) -> Result<Vec<ObjectTypeIndexMember>, String> {
        self.list_index_members_by_keys_projected(namespace, kind, keys, None)
    }

    pub fn list_index_members_by_keys_projected(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
        needed: Option<&[String]>,
    ) -> Result<Vec<ObjectTypeIndexMember>, String> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        if keys.len() > 400 {
            let mut out = Vec::new();
            for chunk in keys.chunks(400) {
                out.extend(
                    self.list_index_members_by_keys_projected(namespace, kind, chunk, needed)?,
                );
            }
            return Ok(out);
        }
        if needed.is_some_and(|keys| keys.is_empty()) {
            return Ok(self
                .list_index_member_idents(namespace, kind, keys)?
                .into_iter()
                .map(|(source_key, object_id)| ObjectTypeIndexMember {
                    namespace: namespace.into(),
                    kind: kind.into(),
                    source_key,
                    object_id,
                    ..ObjectTypeIndexMember::default()
                })
                .collect());
        }
        let conn = self.conn();
        let placeholders = vec!["?"; keys.len()].join(",");
        let sql = format!(
            "SELECT source_key, object_id, properties, content_hash, hidden, from_edit
             FROM sekai_object_type_index_member
             WHERE namespace = ?1 AND kind = ?2 AND hidden = 0 AND source_key IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&namespace, &kind];
        for key in keys {
            params.push(key);
        }
        let mut rows = stmt
            .query(params.as_slice())
            .map_err(|error| error.to_string())?;
        let mut members = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let properties: String = row.get(2).map_err(|error| error.to_string())?;
            members.push(ObjectTypeIndexMember {
                namespace: namespace.into(),
                kind: kind.into(),
                source_key: row.get(0).map_err(|error| error.to_string())?,
                object_id: row.get(1).map_err(|error| error.to_string())?,
                properties: crate::sekai::object_type_index::project_member_properties(
                    &properties,
                    needed,
                )?,
                content_hash: row.get(3).map_err(|error| error.to_string())?,
                hidden: false,
                from_edit: row.get::<_, i64>(5).map_err(|error| error.to_string())? != 0,
            });
        }
        Ok(members)
    }

    pub fn list_index_member_idents(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
    ) -> Result<Vec<(String, String)>, String> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        if keys.len() > 400 {
            let mut out = Vec::new();
            for chunk in keys.chunks(400) {
                out.extend(self.list_index_member_idents(namespace, kind, chunk)?);
            }
            return Ok(out);
        }
        let conn = self.conn();
        let placeholders = vec!["?"; keys.len()].join(",");
        let sql = format!(
            "SELECT source_key, object_id
             FROM sekai_object_type_index_member
             WHERE namespace = ?1 AND kind = ?2 AND hidden = 0 AND source_key IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&namespace, &kind];
        for key in keys {
            params.push(key);
        }
        let mut rows = stmt
            .query(params.as_slice())
            .map_err(|error| error.to_string())?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            out.push((
                row.get(0).map_err(|error| error.to_string())?,
                row.get(1).map_err(|error| error.to_string())?,
            ));
        }
        Ok(out)
    }

    fn mark_index_quarantined(
        &self,
        namespace: &str,
        kind: &str,
        now_ms: i64,
        reason: &str,
    ) -> Result<(), String> {
        let existing = self.object_type_index_status(namespace, kind, now_ms)?;
        let (indexed_at_ms, last_row, count) = existing
            .map(|status| {
                (
                    status.indexed_at_ms,
                    status.last_dataset_row_id,
                    status.member_count,
                )
            })
            .unwrap_or((now_ms, 0, 0));
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_object_type_index_status
                 (namespace, kind, indexed_at_ms, last_dataset_row_id, member_count, stale, quarantine_reason)
                 VALUES (?1,?2,?3,?4,?5,1,?6)",
                params![namespace, kind, indexed_at_ms, last_row, count, reason],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

fn index_member_matches(properties: &BTreeMap<String, String>, query: &RowQuery) -> bool {
    query.filters.iter().all(|filter| {
        properties.get(&filter.column).is_some_and(|value| {
            crate::sekai::dataset::row_value_matches(value, &filter.op, &filter.value)
        })
    })
}

trait OptionalRow<T> {
    fn optional_row(self) -> rusqlite::Result<Option<T>>;
}

impl<T> OptionalRow<T> for rusqlite::Result<T> {
    fn optional_row(self) -> rusqlite::Result<Option<T>> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl From<ObjectTypeIndexError> for String {
    fn from(value: ObjectTypeIndexError) -> Self {
        value.message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::dataset::{ColumnDef, Dataset, RowFilter, RowQuery};
    use crate::sekai::object_type_index::CONTRACT_VERSION;
    use std::collections::HashMap;

    fn db() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    fn dataset(id: &str, columns: &[&str]) -> Dataset {
        Dataset {
            id: id.into(),
            name: id.into(),
            columns: columns
                .iter()
                .map(|name| ColumnDef {
                    name: (*name).into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                })
                .collect(),
            object_id: String::new(),
            created: 1,
        }
    }

    fn binding() -> ObjectTypeDatasource {
        ObjectTypeDatasource {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: "rev-1".into(),
            dataset_id: "ds-customers".into(),
            key_column: "customer_id".into(),
            property_mapping: BTreeMap::from([("region".into(), "region".into())]),
            hidden_column: "hidden".into(),
            edits_only: false,
        }
        .prepare()
        .unwrap()
    }

    #[test]
    fn incremental_reindex_skips_unchanged_keys_and_excludes_hidden() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[
                HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("hidden".into(), "0".into()),
                ]),
                HashMap::from([
                    ("customer_id".into(), "c2".into()),
                    ("region".into(), "us".into()),
                    ("hidden".into(), "true".into()),
                ]),
            ],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        let first = db
            .apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        assert_eq!(first.rewritten_keys, 2);
        assert_eq!(
            db.count_visible_index_members("sales", "Customer").unwrap(),
            1
        );
        let visible = db
            .list_visible_index_members("sales", "Customer", &RowQuery::default())
            .unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].source_key, "c1");

        let second = db
            .apply_object_type_index("sales", "Customer", false, 30)
            .unwrap();
        assert_eq!(second.rewritten_keys, 0);
        assert_eq!(second.skipped_unchanged, 0);

        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c3".into()),
                ("region".into(), "ap".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        let third = db
            .apply_object_type_index("sales", "Customer", false, 40)
            .unwrap();
        assert_eq!(third.rewritten_keys, 1);
        assert_eq!(
            db.count_visible_index_members("sales", "Customer").unwrap(),
            2
        );
    }

    #[test]
    fn schema_drift_quarantines_and_keeps_last_index() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        db.update_dataset(&dataset("ds-customers", &["customer_id", "hidden"]))
            .unwrap();
        let report = db
            .apply_object_type_index("sales", "Customer", false, 30)
            .unwrap();
        assert!(report.quarantined);
        assert!(report.quarantine_reason.contains("region"));
        let status = db
            .object_type_index_status("sales", "Customer", 40)
            .unwrap()
            .unwrap();
        assert!(status.stale);
        assert_eq!(status.member_count, 1);
        assert_eq!(
            db.count_visible_index_members("sales", "Customer").unwrap(),
            1
        );
    }

    #[test]
    fn action_edits_survive_full_rebuild() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        db.put_object_type_index_edit(&ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
        })
        .unwrap();
        db.apply_object_type_index("sales", "Customer", true, 30)
            .unwrap();
        let visible = db
            .list_visible_index_members("sales", "Customer", &RowQuery::default())
            .unwrap();
        assert_eq!(visible[0].properties.get("region").unwrap(), "edited");
        assert!(visible[0].from_edit);
    }

    #[test]
    fn hop_projection_ready_fails_closed_while_joins_wiped() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());
        assert!(db.count_index_join_rows("sales", "Customer").unwrap() > 0);

        db.conn()
            .execute(
                "DELETE FROM sekai_object_type_index_join WHERE namespace = 'sales' AND kind = 'Customer'",
                [],
            )
            .unwrap();
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());

        db.conn()
            .execute(
                "UPDATE sekai_object_type_index_join_status SET generation = ''
                 WHERE namespace = 'sales' AND kind = 'Customer'",
                [],
            )
            .unwrap();
        assert!(!db.hop_projection_ready("sales", "Customer").unwrap());

        db.set_hop_projection_ready("sales", "Customer", false, 30)
            .unwrap();
        assert!(!db.hop_projection_ready("sales", "Customer").unwrap());

        db.apply_object_type_index("sales", "Customer", true, 40)
            .unwrap();
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());
    }

    #[test]
    fn incremental_reindex_clears_hop_ready_before_member_upsert() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());
        let joins_before = db.count_index_join_rows("sales", "Customer").unwrap();
        assert!(joins_before > 0);

        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c3".into()),
                ("region".into(), "ap".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        let report = db
            .apply_object_type_index_without_join_rebuild("sales", "Customer", false, 30)
            .unwrap();
        assert_eq!(report.rewritten_keys, 1);
        assert!(!db.hop_projection_ready("sales", "Customer").unwrap());
        assert_eq!(
            db.count_visible_index_members("sales", "Customer").unwrap(),
            2
        );
        assert_eq!(
            db.count_index_join_rows("sales", "Customer").unwrap(),
            joins_before
        );

        db.apply_object_type_index("sales", "Customer", false, 40)
            .unwrap();
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());
        assert!(db.count_index_join_rows("sales", "Customer").unwrap() > joins_before);
    }

    #[test]
    fn hop_projection_fence_skips_count_when_generation_matches() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        assert!(
            db.hop_projection_kinds_ready("sales", &["Customer"], "rev-1")
                .unwrap()
        );
        db.conn()
            .execute(
                "DELETE FROM sekai_object_type_index_join WHERE namespace = 'sales' AND kind = 'Customer'",
                [],
            )
            .unwrap();
        assert!(
            db.hop_projection_kinds_ready("sales", &["Customer"], "rev-1")
                .unwrap()
        );
        assert!(
            !db.hop_projection_kinds_ready("sales", &["Customer"], "rev-2")
                .unwrap()
        );
    }

    #[test]
    fn hop_projection_clears_ready_until_reindex_stamps_published_digest() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());

        db.invalidate_namespace_hop_projection("sales", 30).unwrap();
        assert!(!db.hop_projection_ready("sales", "Customer").unwrap());

        db.apply_object_type_index("sales", "Customer", true, 40)
            .unwrap();
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());
        assert_eq!(
            db.get_object_type_datasource("sales", "Customer")
                .unwrap()
                .unwrap()
                .definition_digest,
            "rev-1"
        );
    }

    #[test]
    fn register_same_digest_join_change_clears_hop_projection_ready() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.create_dataset(&dataset(
            "ds-customers-v2",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());

        db.register_object_type_datasource(&binding(), 30).unwrap();
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());

        let mut rebound = binding();
        rebound.dataset_id = "ds-customers-v2".into();
        db.register_object_type_datasource(&rebound, 40).unwrap();
        assert!(!db.hop_projection_ready("sales", "Customer").unwrap());
        assert_eq!(
            db.get_object_type_datasource("sales", "Customer")
                .unwrap()
                .unwrap()
                .dataset_id,
            "ds-customers-v2"
        );
    }

    #[test]
    fn index_member_filters_honor_numeric_ops_and_fail_closed() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "tier", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[
                HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("tier".into(), "1".into()),
                    ("hidden".into(), "0".into()),
                ]),
                HashMap::from([
                    ("customer_id".into(), "c2".into()),
                    ("region".into(), "eu".into()),
                    ("tier".into(), "3".into()),
                    ("hidden".into(), "0".into()),
                ]),
            ],
        )
        .unwrap();
        let mut binding = binding();
        binding
            .property_mapping
            .insert("tier".into(), "tier".into());
        db.register_object_type_datasource(&binding, 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();

        let gte = db
            .list_visible_index_members(
                "sales",
                "Customer",
                &RowQuery {
                    filters: vec![RowFilter {
                        column: "tier".into(),
                        op: "gte".into(),
                        value: "2".into(),
                    }],
                    ..RowQuery::default()
                },
            )
            .unwrap();
        assert_eq!(
            gte.iter()
                .map(|m| m.source_key.as_str())
                .collect::<Vec<_>>(),
            ["c2"]
        );

        let non_numeric = db
            .list_visible_index_members(
                "sales",
                "Customer",
                &RowQuery {
                    filters: vec![RowFilter {
                        column: "region".into(),
                        op: "gt".into(),
                        value: "eu".into(),
                    }],
                    ..RowQuery::default()
                },
            )
            .unwrap();
        assert!(non_numeric.is_empty());
    }

    #[test]
    fn reindex_rebuilds_joins_once_from_visible_members() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[
                HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("hidden".into(), "0".into()),
                ]),
                HashMap::from([
                    ("customer_id".into(), "c2".into()),
                    ("region".into(), "us".into()),
                    ("hidden".into(), "true".into()),
                ]),
            ],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        let visible = db
            .list_visible_index_members("sales", "Customer", &RowQuery::default())
            .unwrap();
        let expected = visible
            .iter()
            .map(|member| member.properties.len() as i64)
            .sum::<i64>();
        assert_eq!(expected, 1);
        assert_eq!(
            db.count_index_join_rows("sales", "Customer").unwrap(),
            expected
        );
        assert!(db.hop_projection_ready("sales", "Customer").unwrap());
    }

    #[test]
    fn join_children_lookup_uses_raw_value_not_digest() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        let pairs = db
            .list_index_join_children("sales", "Customer", "region", &["eu".into()])
            .unwrap();
        assert_eq!(pairs, vec![("eu".into(), "c1".into())]);
        let digest = crate::sekai::object_type_index::join_value_digest("eu");
        assert!(
            db.list_index_join_children("sales", "Customer", "region", &[digest])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn list_index_members_by_keys_projects_only_needed_properties() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.register_object_type_datasource(&binding(), 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        let full = db
            .list_index_members_by_keys("sales", "Customer", &["c1".into()])
            .unwrap();
        assert!(full[0].properties.contains_key("region"));
        let projected = db
            .list_index_members_by_keys_projected("sales", "Customer", &["c1".into()], Some(&[]))
            .unwrap();
        assert!(projected[0].properties.is_empty());
        let region_only = db
            .list_index_members_by_keys_projected(
                "sales",
                "Customer",
                &["c1".into()],
                Some(&["region".into()]),
            )
            .unwrap();
        assert_eq!(
            region_only[0].properties,
            BTreeMap::from([("region".into(), "eu".into())])
        );
    }
}
