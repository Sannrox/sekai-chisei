use crate::db::postgres::PostgresDb;
use crate::sekai::dataset::RowQuery;
use crate::sekai::object_type_index::{
    HopProjectionAdmit, HopProjectionFence, ObjectTypeDatasource, ObjectTypeIndexEdit,
    ObjectTypeIndexMember, ObjectTypeIndexStatus, ReindexReport, admit_hop_projection_fence,
    member_from_edit, member_from_row, schema_drift,
};
use std::collections::HashMap;

impl PostgresDb {
    pub fn register_object_type_datasource(
        &self,
        binding: &ObjectTypeDatasource,
        created_at_ms: i64,
    ) -> Result<(), String> {
        let existing = self.get_object_type_datasource(&binding.namespace, &binding.kind)?;
        let mapping =
            serde_json::to_string(&binding.property_mapping).map_err(|e| e.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_type_datasource
                 (namespace, kind, definition_digest, dataset_id, key_column, property_mapping, hidden_column, edits_only, created_at_ms)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                 ON CONFLICT (namespace, kind) DO UPDATE SET
                   definition_digest = EXCLUDED.definition_digest,
                   dataset_id = EXCLUDED.dataset_id,
                   key_column = EXCLUDED.key_column,
                   property_mapping = EXCLUDED.property_mapping,
                   hidden_column = EXCLUDED.hidden_column,
                   edits_only = EXCLUDED.edits_only",
                &[
                    &binding.namespace,
                    &binding.kind,
                    &binding.definition_digest,
                    &binding.dataset_id,
                    &binding.key_column,
                    &mapping,
                    &binding.hidden_column,
                    &binding.edits_only,
                    &created_at_ms,
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
        self.connection()?
            .query_opt(
                "SELECT definition_digest, dataset_id, key_column, property_mapping, hidden_column, edits_only
                 FROM sekai_object_type_datasource WHERE namespace=$1 AND kind=$2",
                &[&namespace, &kind],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let mapping: String = row.get(3);
                Ok(ObjectTypeDatasource {
                    contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                    namespace: namespace.into(),
                    kind: kind.into(),
                    definition_digest: row.get(0),
                    dataset_id: row.get(1),
                    key_column: row.get(2),
                    property_mapping: serde_json::from_str(&mapping).map_err(|e| e.to_string())?,
                    hidden_column: row.get(4),
                    edits_only: row.get(5),
                })
            })
            .transpose()
    }

    pub fn put_object_type_index_edit(&self, edit: &ObjectTypeIndexEdit) -> Result<(), String> {
        let properties = serde_json::to_string(&edit.properties).map_err(|e| e.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_type_index_edit
                 (namespace, kind, source_key, properties, hidden) VALUES ($1,$2,$3,$4,$5)
                 ON CONFLICT (namespace, kind, source_key) DO UPDATE SET
                   properties = EXCLUDED.properties, hidden = EXCLUDED.hidden",
                &[
                    &edit.namespace,
                    &edit.kind,
                    &edit.source_key,
                    &properties,
                    &edit.hidden,
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
        if full_rebuild {
            self.set_hop_projection_ready(namespace, kind, false, now_ms)?;
            self.connection()?
                .execute(
                    "DELETE FROM sekai_object_type_index_member WHERE namespace=$1 AND kind=$2 AND from_edit=FALSE",
                    &[&namespace, &kind],
                )
                .map_err(|error| error.to_string())?;
            self.connection()?
                .execute(
                    "DELETE FROM sekai_object_type_index_join WHERE namespace=$1 AND kind=$2",
                    &[&namespace, &kind],
                )
                .map_err(|error| error.to_string())?;
        }
        let mut rewritten = 0i32;
        let mut skipped = 0i32;
        let mut last_row_id = after_id;
        if !binding.edits_only {
            for (row_id, data) in self.list_dataset_row_records(&binding.dataset_id)? {
                if row_id <= after_id {
                    continue;
                }
                last_row_id = last_row_id.max(row_id);
                let Ok(member) = member_from_row(&binding, &data) else {
                    continue;
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
        let member_count = self.count_visible_index_members(namespace, kind)?;
        self.rebuild_kind_join(namespace, kind, now_ms)?;
        self.stamp_datasource_to_published(namespace, kind)?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_type_index_status
                 (namespace, kind, indexed_at_ms, last_dataset_row_id, member_count, stale, quarantine_reason)
                 VALUES ($1,$2,$3,$4,$5,FALSE,'')
                 ON CONFLICT (namespace, kind) DO UPDATE SET
                   indexed_at_ms = EXCLUDED.indexed_at_ms,
                   last_dataset_row_id = EXCLUDED.last_dataset_row_id,
                   member_count = EXCLUDED.member_count,
                   stale = FALSE,
                   quarantine_reason = ''",
                &[&namespace, &kind, &now_ms, &last_row_id, &member_count],
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
        Ok(self
            .connection()?
            .query_opt(
                "SELECT indexed_at_ms, last_dataset_row_id, member_count, stale, quarantine_reason
                 FROM sekai_object_type_index_status WHERE namespace=$1 AND kind=$2",
                &[&namespace, &kind],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let indexed_at_ms: i64 = row.get(0);
                ObjectTypeIndexStatus {
                    namespace: namespace.into(),
                    kind: kind.into(),
                    indexed_at_ms,
                    last_dataset_row_id: row.get(1),
                    member_count: row.get(2),
                    stale: row.get(3),
                    quarantine_reason: row.get(4),
                    lag_ms: now_ms.saturating_sub(indexed_at_ms).max(0),
                }
            }))
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
            crate::sekai::object_type_index::IndexSqlDialect::Postgres,
            &query.filters,
        )?;
        let sql = format!(
            "SELECT source_key, object_id, properties, content_hash, from_edit
             FROM sekai_object_type_index_member
             WHERE namespace=$1 AND kind=$2 AND hidden=FALSE{filter_sql}
             ORDER BY source_key"
        );
        let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&namespace, &kind];
        for value in &filter_values {
            params.push(value);
        }
        let rows = self
            .connection()?
            .query(&sql, params.as_slice())
            .map_err(|error| error.to_string())?;
        let mut members = Vec::new();
        let mut skipped = 0i32;
        for row in rows {
            let properties: String = row.get(2);
            let properties =
                crate::sekai::object_type_index::project_member_properties(&properties, needed)?;
            if !query.filters.iter().all(|filter| {
                properties.get(&filter.column).is_some_and(|value| {
                    crate::sekai::dataset::row_value_matches(value, &filter.op, &filter.value)
                })
            }) {
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
                source_key: row.get(0),
                object_id: row.get(1),
                properties,
                content_hash: row.get(3),
                hidden: false,
                from_edit: row.get(4),
            });
        }
        Ok(members)
    }

    pub fn count_visible_index_members(&self, namespace: &str, kind: &str) -> Result<i32, String> {
        self.connection()?
            .query_one(
                "SELECT COUNT(*)::INT FROM sekai_object_type_index_member
                 WHERE namespace=$1 AND kind=$2 AND hidden=FALSE",
                &[&namespace, &kind],
            )
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
    }

    fn list_object_type_index_edits(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Vec<ObjectTypeIndexEdit>, String> {
        self.connection()?
            .query(
                "SELECT source_key, properties, hidden FROM sekai_object_type_index_edit
                 WHERE namespace=$1 AND kind=$2",
                &[&namespace, &kind],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let properties: String = row.get(1);
                Ok(ObjectTypeIndexEdit {
                    namespace: namespace.into(),
                    kind: kind.into(),
                    source_key: row.get(0),
                    properties: serde_json::from_str(&properties).map_err(|e| e.to_string())?,
                    hidden: row.get(2),
                })
            })
            .collect()
    }

    fn upsert_index_member(&self, member: &ObjectTypeIndexMember) -> Result<bool, String> {
        let existing = self
            .connection()?
            .query_opt(
                "SELECT content_hash FROM sekai_object_type_index_member
                 WHERE namespace=$1 AND kind=$2 AND source_key=$3",
                &[&member.namespace, &member.kind, &member.source_key],
            )
            .map_err(|error| error.to_string())?;
        if existing
            .as_ref()
            .is_some_and(|row| row.get::<_, String>(0) == member.content_hash)
        {
            return Ok(false);
        }
        self.force_upsert_index_member(member)?;
        Ok(true)
    }

    fn force_upsert_index_member(&self, member: &ObjectTypeIndexMember) -> Result<(), String> {
        let properties = serde_json::to_string(&member.properties).map_err(|e| e.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_type_index_member
                 (namespace, kind, source_key, object_id, properties, content_hash, hidden, from_edit)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (namespace, kind, source_key) DO UPDATE SET
                   object_id = EXCLUDED.object_id,
                   properties = EXCLUDED.properties,
                   content_hash = EXCLUDED.content_hash,
                   hidden = EXCLUDED.hidden,
                   from_edit = EXCLUDED.from_edit",
                &[
                    &member.namespace,
                    &member.kind,
                    &member.source_key,
                    &member.object_id,
                    &properties,
                    &member.content_hash,
                    &member.hidden,
                    &member.from_edit,
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
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_type_index_join_status
                 (namespace, kind, ready, rebuilt_at_ms, generation)
                 VALUES ($1,$2,$3,$4,$5)
                 ON CONFLICT (namespace, kind) DO UPDATE SET
                   ready = EXCLUDED.ready,
                   rebuilt_at_ms = EXCLUDED.rebuilt_at_ms,
                   generation = EXCLUDED.generation",
                &[&namespace, &kind, &ready, &now_ms, &""],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn invalidate_namespace_hop_projection(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "UPDATE sekai_object_type_index_join_status
                 SET ready = FALSE, generation = '', rebuilt_at_ms = $1 WHERE namespace = $2",
                &[&now_ms, &namespace],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn stamp_datasource_to_published(&self, namespace: &str, kind: &str) -> Result<(), String> {
        let Some(published) = self.get_published_definition_revision(namespace)? else {
            return Ok(());
        };
        self.connection()?
            .execute(
                "UPDATE sekai_object_type_datasource
                 SET definition_digest = $1 WHERE namespace = $2 AND kind = $3",
                &[&published.revision_digest, &namespace, &kind],
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
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_object_type_index_join_status
             (namespace, kind, ready, rebuilt_at_ms, generation)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (namespace, kind) DO UPDATE SET
               ready = EXCLUDED.ready,
               rebuilt_at_ms = EXCLUDED.rebuilt_at_ms,
               generation = EXCLUDED.generation",
            &[&namespace, &kind, &false, &now_ms, &""],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_object_type_index_join WHERE namespace=$1 AND kind=$2",
            &[&namespace, &kind],
        )
        .map_err(|error| error.to_string())?;
        for member in &members {
            for (property, value) in &member.properties {
                let digest = crate::sekai::object_type_index::join_value_digest(value);
                tx.execute(
                    "INSERT INTO sekai_object_type_index_join
                     (namespace, kind, property, value_digest, source_key, value)
                     VALUES ($1,$2,$3,$4,$5,$6)
                     ON CONFLICT (namespace, kind, property, value_digest, source_key) DO NOTHING",
                    &[
                        &member.namespace,
                        &member.kind,
                        property,
                        &digest,
                        &member.source_key,
                        value,
                    ],
                )
                .map_err(|error| error.to_string())?;
            }
        }
        tx.execute(
            "INSERT INTO sekai_object_type_index_join_status
             (namespace, kind, ready, rebuilt_at_ms, generation)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (namespace, kind) DO UPDATE SET
               ready = EXCLUDED.ready,
               rebuilt_at_ms = EXCLUDED.rebuilt_at_ms,
               generation = EXCLUDED.generation",
            &[&namespace, &kind, &true, &now_ms, &generation],
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
        let kind_list: Vec<String> = kinds.iter().map(|kind| (*kind).to_string()).collect();
        let rows = self
            .connection()?
            .query(
                "SELECT s.kind, s.ready, COALESCE(s.generation, ''), COALESCE(d.definition_digest, '')
                 FROM sekai_object_type_index_join_status s
                 LEFT JOIN sekai_object_type_datasource d
                   ON d.namespace = s.namespace AND d.kind = s.kind
                 WHERE s.namespace = $1 AND s.kind = ANY($2)",
                &[&namespace, &kind_list],
            )
            .map_err(|error| error.to_string())?;
        let mut fences = HashMap::new();
        for row in rows {
            fences.insert(
                row.get(0),
                HopProjectionFence {
                    ready: row.get(1),
                    generation: row.get(2),
                    definition_digest: row.get(3),
                },
            );
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
        self.connection()?
            .query_one(
                "SELECT COUNT(*) FROM sekai_object_type_index_join
                 WHERE namespace=$1 AND kind=$2",
                &[&namespace, &kind],
            )
            .map(|row| row.get(0))
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
        self.connection()?
            .query(
                "SELECT value, source_key FROM sekai_object_type_index_join
                 WHERE namespace=$1 AND kind=$2 AND property=$3 AND value = ANY($4)",
                &[&namespace, &kind, &property, &values],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| Ok((row.get(0), row.get(1))))
            .collect()
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
        let placeholders = (0..keys.len())
            .map(|index| format!("${}", index + 3))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT source_key, object_id, properties, content_hash, hidden, from_edit
             FROM sekai_object_type_index_member
             WHERE namespace=$1 AND kind=$2 AND hidden=FALSE AND source_key IN ({placeholders})"
        );
        let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&namespace, &kind];
        for key in keys {
            params.push(key);
        }
        self.connection()?
            .query(&sql, params.as_slice())
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let properties: String = row.get(2);
                Ok(ObjectTypeIndexMember {
                    namespace: namespace.into(),
                    kind: kind.into(),
                    source_key: row.get(0),
                    object_id: row.get(1),
                    properties: crate::sekai::object_type_index::project_member_properties(
                        &properties,
                        needed,
                    )?,
                    content_hash: row.get(3),
                    hidden: false,
                    from_edit: row.get(5),
                })
            })
            .collect()
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
        let placeholders = (0..keys.len())
            .map(|index| format!("${}", index + 3))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT source_key, object_id
             FROM sekai_object_type_index_member
             WHERE namespace=$1 AND kind=$2 AND hidden=FALSE AND source_key IN ({placeholders})"
        );
        let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&namespace, &kind];
        for key in keys {
            params.push(key);
        }
        self.connection()?
            .query(&sql, params.as_slice())
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| Ok((row.get(0), row.get(1))))
            .collect()
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
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_type_index_status
                 (namespace, kind, indexed_at_ms, last_dataset_row_id, member_count, stale, quarantine_reason)
                 VALUES ($1,$2,$3,$4,$5,TRUE,$6)
                 ON CONFLICT (namespace, kind) DO UPDATE SET
                   stale = TRUE, quarantine_reason = EXCLUDED.quarantine_reason",
                &[&namespace, &kind, &indexed_at_ms, &last_row, &count, &reason],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}
