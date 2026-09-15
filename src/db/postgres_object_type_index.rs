use crate::db::postgres::PostgresDb;
use crate::sekai::dataset::RowQuery;
use crate::sekai::object_type_index::{
    ObjectTypeDatasource, ObjectTypeIndexEdit, ObjectTypeIndexMember, ObjectTypeIndexStatus,
    ReindexReport, member_from_edit, member_from_row, schema_drift,
};
use std::collections::BTreeMap;

impl PostgresDb {
    pub fn register_object_type_datasource(
        &self,
        binding: &ObjectTypeDatasource,
        created_at_ms: i64,
    ) -> Result<(), String> {
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
            .map(|_| ())
            .map_err(|error| error.to_string())
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
        let rows = self
            .connection()?
            .query(
                "SELECT source_key, object_id, properties, content_hash, from_edit
                 FROM sekai_object_type_index_member
                 WHERE namespace=$1 AND kind=$2 AND hidden=FALSE
                 ORDER BY source_key",
                &[&namespace, &kind],
            )
            .map_err(|error| error.to_string())?;
        let mut members = Vec::new();
        let mut skipped = 0i32;
        for row in rows {
            let properties: String = row.get(2);
            let properties: BTreeMap<String, String> =
                serde_json::from_str(&properties).map_err(|error| error.to_string())?;
            if !query.filters.iter().all(|filter| {
                properties
                    .get(&filter.column)
                    .is_some_and(|value| value == &filter.value)
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
        self.replace_index_join(member)
    }

    fn replace_index_join(&self, member: &ObjectTypeIndexMember) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM sekai_object_type_index_join
                 WHERE namespace=$1 AND kind=$2 AND source_key=$3",
                &[&member.namespace, &member.kind, &member.source_key],
            )
            .map_err(|error| error.to_string())?;
        if member.hidden {
            return Ok(());
        }
        for (property, value) in &member.properties {
            let digest = crate::sekai::object_type_index::join_value_digest(value);
            self.connection()?
                .execute(
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
        Ok(())
    }

    fn rebuild_kind_join(&self, namespace: &str, kind: &str, now_ms: i64) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM sekai_object_type_index_join WHERE namespace=$1 AND kind=$2",
                &[&namespace, &kind],
            )
            .map_err(|error| error.to_string())?;
        let members = self.list_visible_index_members(
            namespace,
            kind,
            &crate::sekai::dataset::RowQuery::default(),
        )?;
        for member in members {
            self.replace_index_join(&member)?;
        }
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_type_index_join_status
                 (namespace, kind, ready, rebuilt_at_ms)
                 VALUES ($1,$2,TRUE,$3)
                 ON CONFLICT (namespace, kind) DO UPDATE SET
                   ready = TRUE,
                   rebuilt_at_ms = EXCLUDED.rebuilt_at_ms",
                &[&namespace, &kind, &now_ms],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn hop_projection_ready(&self, namespace: &str, kind: &str) -> Result<bool, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT ready FROM sekai_object_type_index_join_status
                 WHERE namespace=$1 AND kind=$2",
                &[&namespace, &kind],
            )
            .map_err(|error| error.to_string())?
            .is_some_and(|row| row.get(0)))
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
        if values.len() > 400 {
            let mut out = Vec::new();
            for chunk in values.chunks(400) {
                out.extend(self.list_index_join_children(namespace, kind, property, chunk)?);
            }
            return Ok(out);
        }
        let digests: Vec<String> = values
            .iter()
            .map(|value| crate::sekai::object_type_index::join_value_digest(value))
            .collect();
        let placeholders = (0..digests.len())
            .map(|index| format!("${}", index + 4))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT value, source_key FROM sekai_object_type_index_join
             WHERE namespace=$1 AND kind=$2 AND property=$3 AND value_digest IN ({placeholders})"
        );
        let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> =
            vec![&namespace, &kind, &property];
        for digest in &digests {
            params.push(digest);
        }
        let wanted: std::collections::HashSet<&str> = values.iter().map(String::as_str).collect();
        self.connection()?
            .query(&sql, params.as_slice())
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter_map(|row| {
                let value: String = row.get(0);
                wanted
                    .contains(value.as_str())
                    .then(|| Ok((value, row.get(1))))
            })
            .collect()
    }

    pub fn list_index_members_by_keys(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
    ) -> Result<Vec<ObjectTypeIndexMember>, String> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        if keys.len() > 400 {
            let mut out = Vec::new();
            for chunk in keys.chunks(400) {
                out.extend(self.list_index_members_by_keys(namespace, kind, chunk)?);
            }
            return Ok(out);
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
                    properties: serde_json::from_str(&properties).map_err(|e| e.to_string())?,
                    content_hash: row.get(3),
                    hidden: false,
                    from_edit: row.get(5),
                })
            })
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
