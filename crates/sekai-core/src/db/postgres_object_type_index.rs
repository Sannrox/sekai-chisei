use crate::db::postgres::PostgresDb;
use crate::sekai::dataset::RowQuery;
use crate::sekai::object_type_index::{
    HopProjectionAdmit, HopProjectionFence, ObjectTypeDatasource, ObjectTypeIndexEdit,
    ObjectTypeIndexMember, ObjectTypeIndexStatus, ReindexReport, admit_hop_projection_fence,
    coerce_index_edit, coerce_index_member, mapping_renames, member_from_row, overlay_member,
    parse_property_edit_times, schema_drift,
};
use std::collections::{BTreeMap, HashMap};

impl PostgresDb {
    pub fn register_object_type_datasource(
        &self,
        binding: &ObjectTypeDatasource,
        created_at_ms: i64,
    ) -> Result<(), String> {
        let existing = self.get_object_type_datasource(&binding.namespace, &binding.kind)?;
        let mapping =
            serde_json::to_string(&binding.property_mapping).map_err(|e| e.to_string())?;
        let rename = existing.as_ref().map_or(Vec::new(), |previous| {
            mapping_renames(&previous.property_mapping, &binding.property_mapping)
        });
        if !rename.is_empty() {
            let mut edits = self.list_object_type_index_edits(&binding.namespace, &binding.kind)?;
            // Rewrite overlays before the mapping INSERT so a failed rewrite
            // does not strand edits under old names. Retrying this register
            // recomputes the same rename from the still-old mapping and
            // replays. Holding the datasource lock across the log rewrite
            // deadlocks with put (log then SQL).
            crate::sekai::object_log::rewrite_index_edit_overlays(
                &mut edits,
                &rename,
                &binding.definition_digest,
            )?;
            self.replace_object_type_index_edits(&binding.namespace, &binding.kind, &edits)?;
        }
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        crate::db::postgres::lock_object_type_datasource(
            &mut transaction,
            &binding.namespace,
            &binding.kind,
        )?;
        transaction
            .execute(
                "INSERT INTO sekai_object_type_datasource
                 (namespace, kind, definition_digest, dataset_id, key_column, property_mapping, hidden_column, edits_only, conflict_rule, source_timestamp_property, created_at_ms)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                 ON CONFLICT (namespace, kind) DO UPDATE SET
                   definition_digest = EXCLUDED.definition_digest,
                   dataset_id = EXCLUDED.dataset_id,
                   key_column = EXCLUDED.key_column,
                   property_mapping = EXCLUDED.property_mapping,
                   hidden_column = EXCLUDED.hidden_column,
                   edits_only = EXCLUDED.edits_only,
                   conflict_rule = EXCLUDED.conflict_rule,
                   source_timestamp_property = EXCLUDED.source_timestamp_property",
                &[
                    &binding.namespace,
                    &binding.kind,
                    &binding.definition_digest,
                    &binding.dataset_id,
                    &binding.key_column,
                    &mapping,
                    &binding.hidden_column,
                    &binding.edits_only,
                    &binding.conflict_rule,
                    &binding.source_timestamp_property,
                    &created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        drop(connection);
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
                "SELECT definition_digest, dataset_id, key_column, property_mapping, hidden_column, edits_only, conflict_rule, source_timestamp_property
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
                    conflict_rule: row.get(6),
                    source_timestamp_property: row.get(7),
                })
            })
            .transpose()
    }

    pub fn get_object_type_index_edit(
        &self,
        namespace: &str,
        kind: &str,
        source_key: &str,
    ) -> Result<Option<ObjectTypeIndexEdit>, String> {
        self.connection()?
            .query_opt(
                "SELECT properties, hidden, action_id, edited_at_ms, property_edited_at_ms
                 FROM sekai_object_type_index_edit
                 WHERE namespace=$1 AND kind=$2 AND source_key=$3",
                &[&namespace, &kind, &source_key],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let properties: String = row.get(0);
                let property_times: String = row.get(4);
                Ok(ObjectTypeIndexEdit {
                    namespace: namespace.into(),
                    kind: kind.into(),
                    source_key: source_key.into(),
                    properties: serde_json::from_str(&properties).map_err(|e| e.to_string())?,
                    hidden: row.get(1),
                    action_id: row.get(2),
                    edited_at_ms: row.get(3),
                    property_edited_at_ms: parse_property_edit_times(&property_times)?,
                })
            })
            .transpose()
    }

    pub fn put_object_type_index_edit(&self, edit: &ObjectTypeIndexEdit) -> Result<(), String> {
        let edit = coerce_index_edit(self.get_object_type(&edit.kind)?.as_ref(), edit.clone())
            .map_err(|error| format!("invalid_property_value: {}", error.message()))?;
        self.reserve_index_edit_identity(&edit)?;
        let merged = crate::sekai::object_log::merge_and_apply_index_edit(
            self.get_object_type_index_edit(&edit.namespace, &edit.kind, &edit.source_key)?,
            edit,
        )?;
        let merged = coerce_index_edit(self.get_object_type(&merged.kind)?.as_ref(), merged)
            .map_err(|error| format!("invalid_property_value: {}", error.message()))?;
        self.store_index_edit_projection(&merged)
    }

    fn reserve_index_edit_identity(&self, edit: &ObjectTypeIndexEdit) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_type_index_edit
                 (namespace, kind, source_key, properties, hidden, action_id, edited_at_ms, property_edited_at_ms)
                 VALUES ($1,$2,$3,'{}',false,'',0,'{}')
                 ON CONFLICT (namespace, kind, source_key) DO NOTHING",
                &[&edit.namespace, &edit.kind, &edit.source_key],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn store_index_edit_projection(&self, edit: &ObjectTypeIndexEdit) -> Result<(), String> {
        let properties = serde_json::to_string(&edit.properties).map_err(|e| e.to_string())?;
        let property_times =
            serde_json::to_string(&edit.property_edited_at_ms).map_err(|e| e.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_type_index_edit
                 (namespace, kind, source_key, properties, hidden, action_id, edited_at_ms, property_edited_at_ms)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (namespace, kind, source_key) DO UPDATE SET
                   properties = EXCLUDED.properties,
                   hidden = EXCLUDED.hidden,
                   action_id = EXCLUDED.action_id,
                   edited_at_ms = EXCLUDED.edited_at_ms,
                   property_edited_at_ms = EXCLUDED.property_edited_at_ms",
                &[
                    &edit.namespace,
                    &edit.kind,
                    &edit.source_key,
                    &properties,
                    &edit.hidden,
                    &edit.action_id,
                    &edit.edited_at_ms,
                    &property_times,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn replace_object_type_index_edits(
        &self,
        _namespace: &str,
        _kind: &str,
        edits: &[ObjectTypeIndexEdit],
    ) -> Result<(), String> {
        // Upsert in place. A pre-delete would drop recovery keys for
        // identities the log still holds if the process crashed before the
        // following inserts.
        for edit in edits {
            self.store_index_edit_projection(edit)?;
        }
        Ok(())
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
        let mut full_rebuild = full_rebuild;
        let mut after_id = if full_rebuild {
            0
        } else {
            status
                .as_ref()
                .map(|status| status.last_dataset_row_id)
                .unwrap_or(0)
        };
        if !full_rebuild && after_id > 0 && !binding.edits_only {
            let source_members: i64 = self
                .connection()?
                .query_one(
                    "SELECT COUNT(*) FROM sekai_object_type_index_member
                     WHERE namespace=$1 AND kind=$2 AND from_edit=FALSE",
                    &[&namespace, &kind],
                )
                .map(|row| row.get(0))
                .map_err(|error| error.to_string())?;
            if source_members == 0 {
                // Interrupted full rebuild deleted source members before the
                // status cursor advanced. Incremental would skip those rows.
                full_rebuild = true;
                after_id = 0;
            }
        }
        self.set_hop_projection_ready(namespace, kind, false, now_ms)?;
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
            self.connection()?
                .execute(
                    "UPDATE sekai_object_type_index_status
                     SET last_dataset_row_id = 0
                     WHERE namespace=$1 AND kind=$2",
                    &[&namespace, &kind],
                )
                .map_err(|error| error.to_string())?;
        }
        let mut rewritten = 0i32;
        let mut skipped = 0i32;
        let mut touched_source_keys = Vec::new();
        let mut last_row_id = after_id;
        self.project_log_overlays_into_edits(namespace, kind)?;
        let edits: BTreeMap<String, ObjectTypeIndexEdit> = self
            .list_object_type_index_edits(namespace, kind)?
            .into_iter()
            .map(|edit| (edit.source_key.clone(), edit))
            .collect();
        let object_type = self.get_object_type(kind)?;
        let mut members: BTreeMap<String, ObjectTypeIndexMember> = BTreeMap::new();
        if !binding.edits_only {
            for (row_id, data) in self.list_dataset_row_records(&binding.dataset_id)? {
                if row_id <= after_id {
                    continue;
                }
                last_row_id = last_row_id.max(row_id);
                let mut member = match member_from_row(&binding, &data) {
                    Ok(member) => {
                        coerce_index_member(member.clone(), object_type.as_ref()).unwrap_or(member)
                    }
                    Err(_) => continue,
                };
                self.bind_index_member_object_id(namespace, &mut member)?;
                members.insert(member.source_key.clone(), member);
            }
        }
        let processed: BTreeMap<String, ()> =
            members.keys().cloned().map(|key| (key, ())).collect();
        for (source_key, mut member) in members {
            touched_source_keys.push(source_key.clone());
            if let Some(edit) = edits.get(&source_key) {
                member = overlay_member(&binding, Some(member), edit)?;
            }
            if self.upsert_index_member(&member)? {
                rewritten += 1;
            } else {
                skipped += 1;
            }
        }
        let leftover_keys: BTreeMap<String, ()> = edits
            .keys()
            .filter(|key| !processed.contains_key(*key))
            .cloned()
            .map(|key| (key, ()))
            .collect();
        let mut sources = self.leftover_source_members(&binding, &leftover_keys)?;
        for (source_key, edit) in &edits {
            if processed.contains_key(source_key) {
                continue;
            }
            // Reservation stub: key exists for log recovery, not a committed edit.
            if edit.properties.is_empty() && edit.action_id.is_empty() && !edit.hidden {
                continue;
            }
            let source = sources.remove(source_key);
            let mut member = overlay_member(&binding, source, edit)?;
            self.bind_index_member_object_id(namespace, &mut member)?;
            self.force_upsert_index_member(&member)?;
            rewritten += 1;
            touched_source_keys.push(source_key.clone());
        }
        let rematerialize_keys = if full_rebuild {
            None
        } else {
            Some(touched_source_keys.as_slice())
        };
        self.rematerialize_source_objects_from_index(namespace, kind, now_ms, rematerialize_keys)?;
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

    fn bind_index_member_object_id(
        &self,
        namespace: &str,
        member: &mut ObjectTypeIndexMember,
    ) -> Result<(), String> {
        let object_id = self
            .connection()?
            .query_opt(
                "SELECT object_id FROM sekai_source_identities
                 WHERE namespace=$1 AND source_id=$2 AND type_name=$3",
                &[&namespace, &member.source_key, &member.kind],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0));
        if let Some(object_id) = object_id {
            member.object_id = object_id;
        }
        Ok(())
    }

    fn rematerialize_source_objects_from_index(
        &self,
        namespace: &str,
        kind: &str,
        now_ms: i64,
        source_keys: Option<&[String]>,
    ) -> Result<(), String> {
        if source_keys.is_some_and(|keys| keys.is_empty()) {
            return Ok(());
        }
        let source_ids: Vec<String> = if let Some(keys) = source_keys {
            keys.to_vec()
        } else {
            self.connection()?
                .query(
                    "SELECT source_key FROM sekai_object_type_index_member
                     WHERE namespace = $1 AND kind = $2",
                    &[&namespace, &kind],
                )
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| row.get(0))
                .collect()
        };
        for source_id in source_ids {
            let mut connection = self.connection()?;
            let mut tx = connection
                .transaction()
                .map_err(|error| error.to_string())?;
            let Some(locked_object_id) = tx
                .query_opt(
                    "SELECT object_id FROM sekai_source_identities
                     WHERE namespace=$1 AND source_id=$2 AND type_name=$3",
                    &[&namespace, &source_id, &kind],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, String>(0))
            else {
                continue;
            };
            crate::db::postgres_audit::lock_object_lifecycle(&mut tx, &locked_object_id)?;
            let Some(identity) = tx
                .query_opt(
                    "SELECT binding_id, type_digest, type_name, object_id, source_version,
                            payload_digest, tombstoned, synced_object_json, lineage_json,
                            last_transaction_id, updated_at_ms
                     FROM sekai_source_identities
                     WHERE namespace=$1 AND source_id=$2 AND type_name=$3 FOR UPDATE",
                    &[&namespace, &source_id, &kind],
                )
                .map_err(|error| error.to_string())?
            else {
                continue;
            };
            let binding_id: String = identity.get(0);
            let type_digest: String = identity.get(1);
            let type_name: String = identity.get(2);
            let object_id: String = identity.get(3);
            let source_version: String = identity.get(4);
            let payload_digest: String = identity.get(5);
            let tombstoned: bool = identity.get(6);
            let synced_object_json: String = identity.get(7);
            let lineage_json: String = identity.get(8);
            let last_transaction_id: String = identity.get(9);
            let identity_updated_at_ms: i64 = identity.get(10);
            if object_id != locked_object_id {
                continue;
            }
            let Some(member_row) = tx
                .query_opt(
                    "SELECT properties, hidden FROM sekai_object_type_index_member
                     WHERE namespace=$1 AND kind=$2 AND source_key=$3",
                    &[&namespace, &kind, &source_id],
                )
                .map_err(|error| error.to_string())?
            else {
                continue;
            };
            let member_properties: String = member_row.get(0);
            let hidden: bool = member_row.get(1);
            let mapped: BTreeMap<String, crate::sekai::object_schema::PropertyValue> =
                serde_json::from_str(&member_properties).map_err(|error| error.to_string())?;
            let mapped = crate::sekai::object_schema::properties_as_cells(&mapped);
            let Some(existing) = tx
                .query_opt(
                    "SELECT id, kind, name, namespace, external_id, properties, created, updated
                     FROM sekai_objects WHERE id=$1 FOR UPDATE",
                    &[&object_id],
                )
                .map_err(|error| error.to_string())?
                .map(crate::db::postgres_audit::row_to_object)
                .transpose()?
            else {
                continue;
            };
            if existing.kind != kind {
                continue;
            }
            let mut object = existing.clone();
            object.properties = crate::db::source_batch_dataset::merge_mapped_properties(
                &existing.properties,
                &mapped,
                hidden,
                crate::db::object_sync::RESERVED_SYNC_PROPERTIES,
            );
            if let Some(policy) = super::postgres_object_security::load_active_policy_postgres(
                &mut tx, namespace, kind,
            )? {
                policy.coerce_granted_mutation(&existing, &mut object);
            }
            let properties_json = crate::domain::storage_properties_json(&object.properties)?;
            object.updated = now_ms;
            let changes = crate::sekai::audit::ChangeAttribution::source(&last_transaction_id)
                .stamp(crate::sekai::audit::object_diff_changes(
                    "",
                    Some(&existing),
                    Some(&object),
                    now_ms,
                ));
            if !changes.is_empty() {
                crate::db::postgres_audit::insert_changes(&mut tx, &changes)?;
            }
            tx.execute(
                "DELETE FROM sekai_source_identities WHERE namespace=$1 AND source_id=$2",
                &[&namespace, &source_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "UPDATE sekai_objects SET properties=$1, updated=$2 WHERE id=$3",
                &[&properties_json, &now_ms, &object_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_source_identities (
                    namespace, source_id, binding_id, type_digest, type_name, object_id,
                    source_version, payload_digest, tombstoned, synced_object_json,
                    lineage_json, last_transaction_id, updated_at_ms
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
                &[
                    &namespace,
                    &source_id,
                    &binding_id,
                    &type_digest,
                    &type_name,
                    &object_id,
                    &source_version,
                    &payload_digest,
                    &tombstoned,
                    &synced_object_json,
                    &lineage_json,
                    &last_transaction_id,
                    &identity_updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
        }
        Ok(())
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
        let dialect = crate::sekai::object_type_index::IndexSqlDialect::Postgres;
        let project = match needed {
            Some(keys) => Some(keys),
            None if !query.columns.is_empty() => Some(query.columns.as_slice()),
            None => None,
        };
        let properties_sql =
            crate::sekai::object_type_index::member_properties_sql(dialect, project)?;
        let (filter_sql, filter_values) =
            crate::sekai::object_type_index::member_filter_sql(dialect, &query.filters)?;
        let (page_sql, page_values, _) = crate::sekai::object_type_index::member_page_sql(
            dialect,
            query.limit,
            query.offset,
            3 + filter_values.len(),
        );
        let sql = format!(
            "SELECT source_key, object_id, {properties_sql}, content_hash, from_edit
             FROM sekai_object_type_index_member
             WHERE namespace=$1 AND kind=$2 AND hidden=FALSE{filter_sql}
             ORDER BY source_key{page_sql}"
        );
        let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&namespace, &kind];
        for value in &filter_values {
            params.push(value);
        }
        for value in &page_values {
            params.push(value);
        }
        let rows = self
            .connection()?
            .query(&sql, params.as_slice())
            .map_err(|error| error.to_string())?;
        let mut members = Vec::new();
        for row in rows {
            let properties: String = row.get(2);
            members.push(ObjectTypeIndexMember {
                namespace: namespace.into(),
                kind: kind.into(),
                source_key: row.get(0),
                object_id: row.get(1),
                properties: crate::sekai::object_type_index::project_member_properties(
                    &properties,
                    project,
                )?,
                content_hash: row.get(3),
                hidden: false,
                from_edit: row.get(4),
            });
        }
        Ok(members)
    }

    pub fn object_log_migration_identities(&self) -> Result<Vec<(String, String, String)>, String> {
        self.connection()?
            .query(
                "SELECT namespace, kind, source_key
                 FROM sekai_object_type_index_member
                 UNION
                 SELECT namespace, kind, id
                 FROM sekai_objects
                 ORDER BY 1, 2, 3",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| Ok((row.get(0), row.get(1), row.get(2))))
            .collect()
    }

    pub fn list_kind_objects_outside_index(
        &self,
        namespace: &str,
        kind: &str,
        offset: i32,
        limit: i32,
    ) -> Result<Vec<crate::domain::Object>, String> {
        let offset = i64::from(offset.max(0));
        let limit = i64::from(limit.max(0));
        self.connection()?
            .query(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects o
                 WHERE o.namespace = $1 AND o.kind = $2
                   AND NOT EXISTS (
                     SELECT 1 FROM sekai_object_type_index_member m
                     WHERE m.namespace = o.namespace AND m.kind = o.kind AND m.object_id = o.id
                   )
                 ORDER BY o.id
                 LIMIT $3 OFFSET $4",
                &[&namespace, &kind, &limit, &offset],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(crate::db::postgres_audit::row_to_object)
            .collect()
    }

    pub fn list_index_member_object_ids(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Vec<String>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT object_id FROM sekai_object_type_index_member
                 WHERE namespace=$1 AND kind=$2",
                &[&namespace, &kind],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }

    pub fn count_visible_index_members(&self, namespace: &str, kind: &str) -> Result<i32, String> {
        self.count_visible_index_members_matching(namespace, kind, &[])
    }

    pub fn count_visible_index_members_matching(
        &self,
        namespace: &str,
        kind: &str,
        filters: &[crate::sekai::dataset::RowFilter],
    ) -> Result<i32, String> {
        let dialect = crate::sekai::object_type_index::IndexSqlDialect::Postgres;
        let (filter_sql, filter_values) =
            crate::sekai::object_type_index::member_filter_sql(dialect, filters)?;
        let sql = format!(
            "SELECT COUNT(*)::INT FROM sekai_object_type_index_member
             WHERE namespace=$1 AND kind=$2 AND hidden=FALSE{filter_sql}"
        );
        let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&namespace, &kind];
        for value in &filter_values {
            params.push(value);
        }
        self.connection()?
            .query_one(&sql, params.as_slice())
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
    }

    pub fn list_object_type_index_edits(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Vec<ObjectTypeIndexEdit>, String> {
        self.connection()?
            .query(
                "SELECT source_key, properties, hidden, action_id, edited_at_ms, property_edited_at_ms
                 FROM sekai_object_type_index_edit
                 WHERE namespace=$1 AND kind=$2",
                &[&namespace, &kind],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let properties: String = row.get(1);
                let property_times: String = row.get(5);
                Ok(ObjectTypeIndexEdit {
                    namespace: namespace.into(),
                    kind: kind.into(),
                    source_key: row.get(0),
                    properties: serde_json::from_str(&properties).map_err(|e| e.to_string())?,
                    hidden: row.get(2),
                    action_id: row.get(3),
                    edited_at_ms: row.get(4),
                    property_edited_at_ms: parse_property_edit_times(&property_times)?,
                })
            })
            .collect()
    }

    fn leftover_source_members(
        &self,
        binding: &ObjectTypeDatasource,
        keys: &BTreeMap<String, ()>,
    ) -> Result<BTreeMap<String, ObjectTypeIndexMember>, String> {
        let mut sources = BTreeMap::new();
        if binding.edits_only || keys.is_empty() {
            return Ok(sources);
        }
        let object_type = self.get_object_type(&binding.kind)?;
        for (_row_id, data) in self.list_dataset_row_records(&binding.dataset_id)? {
            let member = match member_from_row(binding, &data) {
                Ok(member) => {
                    coerce_index_member(member.clone(), object_type.as_ref()).unwrap_or(member)
                }
                Err(_) => continue,
            };
            if keys.contains_key(&member.source_key) {
                sources.insert(member.source_key.clone(), member);
            }
        }
        Ok(sources)
    }

    fn project_log_overlays_into_edits(&self, namespace: &str, kind: &str) -> Result<(), String> {
        let keys = self.index_overlay_keys(namespace, kind)?;
        let object_type = self.get_object_type(kind)?;
        for edit in crate::sekai::object_log::load_index_overlays(namespace, kind, &keys)? {
            let edit = coerce_index_edit(object_type.as_ref(), edit)
                .map_err(|error| format!("invalid_property_value: {}", error.message()))?;
            self.store_index_edit_projection(&edit)?;
        }
        Ok(())
    }

    fn index_overlay_keys(&self, namespace: &str, kind: &str) -> Result<Vec<String>, String> {
        let mut keys = BTreeMap::new();
        for edit in self.list_object_type_index_edits(namespace, kind)? {
            keys.insert(edit.source_key, ());
        }
        // Pinned Store has no overlay identity scan. SQL edit keys include the
        // stub reserved before overlay apply, so a crash after the log commit
        // still names the identity. Hidden members and dataset keys remain
        // recovery keys when that stub is gone.
        for key in self.list_index_member_keys(namespace, kind)? {
            keys.insert(key, ());
        }
        if let Some(binding) = self.get_object_type_datasource(namespace, kind)?
            && !binding.edits_only
        {
            for (_row_id, data) in self.list_dataset_row_records(&binding.dataset_id)? {
                if let Some(key) = data.get(&binding.key_column) {
                    let key = key.trim();
                    if !key.is_empty() {
                        keys.insert(key.to_string(), ());
                    }
                }
            }
        }
        Ok(keys.into_keys().collect())
    }

    fn list_index_member_keys(&self, namespace: &str, kind: &str) -> Result<Vec<String>, String> {
        self.connection()?
            .query(
                "SELECT source_key FROM sekai_object_type_index_member
                 WHERE namespace=$1 AND kind=$2",
                &[&namespace, &kind],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| Ok(row.get(0)))
            .collect()
    }

    fn upsert_index_member(&self, member: &ObjectTypeIndexMember) -> Result<bool, String> {
        let existing = self
            .connection()?
            .query_opt(
                "SELECT object_id, content_hash FROM sekai_object_type_index_member
                 WHERE namespace=$1 AND kind=$2 AND source_key=$3",
                &[&member.namespace, &member.kind, &member.source_key],
            )
            .map_err(|error| error.to_string())?;
        if existing.as_ref().is_some_and(|row| {
            row.get::<_, String>(0) == member.object_id
                && row.get::<_, String>(1) == member.content_hash
        }) {
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

    pub fn set_hop_projection_ready(
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

    pub fn invalidate_namespace_hop_projection(
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
                let cell = value.as_cell();
                let digest = crate::sekai::object_type_index::join_value_digest(&cell);
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
                        &cell,
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
