use crate::db::sekai::SekaiDb;
use crate::sekai::dataset::RowQuery;
use crate::sekai::object_type_index::{
    HopProjectionAdmit, HopProjectionFence, ObjectTypeDatasource, ObjectTypeIndexEdit,
    ObjectTypeIndexMember, ObjectTypeIndexStatus, ReindexReport, admit_hop_projection_fence,
    mapping_renames, member_from_row, overlay_member, parse_property_edit_times, schema_drift,
};
use rusqlite::{TransactionBehavior, params};
use std::collections::{BTreeMap, HashMap};

impl SekaiDb {
    pub fn migrate_object_type_index(&self) -> Result<(), String> {
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
                    conflict_rule TEXT NOT NULL DEFAULT '',
                    source_timestamp_property TEXT NOT NULL DEFAULT '',
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
                    action_id TEXT NOT NULL DEFAULT '',
                    edited_at_ms INTEGER NOT NULL DEFAULT 0,
                    property_edited_at_ms TEXT NOT NULL DEFAULT '{}',
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
        let _ = self.conn().execute(
            "ALTER TABLE sekai_object_type_datasource
             ADD COLUMN conflict_rule TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = self.conn().execute(
            "ALTER TABLE sekai_object_type_datasource
             ADD COLUMN source_timestamp_property TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = self.conn().execute(
            "ALTER TABLE sekai_object_type_index_edit
             ADD COLUMN action_id TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = self.conn().execute(
            "ALTER TABLE sekai_object_type_index_edit
             ADD COLUMN edited_at_ms INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = self.conn().execute(
            "ALTER TABLE sekai_object_type_index_edit
             ADD COLUMN property_edited_at_ms TEXT NOT NULL DEFAULT '{}'",
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
        let rename = existing.as_ref().map_or(Vec::new(), |previous| {
            mapping_renames(&previous.property_mapping, &binding.property_mapping)
        });
        if !rename.is_empty() {
            let mut edits = self.list_object_type_index_edits(&binding.namespace, &binding.kind)?;
            // Rewrite overlays before the mapping INSERT so a failed rewrite
            // does not strand edits under old names. Retrying this register
            // recomputes the same rename from the still-old mapping and
            // replays. Holding the SQL lock across the log rewrite deadlocks
            // with put (log then SQL).
            crate::sekai::object_log::rewrite_index_edit_overlays(
                &mut edits,
                &rename,
                &binding.definition_digest,
            )?;
            self.replace_object_type_index_edits(&binding.namespace, &binding.kind, &edits)?;
        }
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_object_type_datasource
                 (namespace, kind, definition_digest, dataset_id, key_column, property_mapping, hidden_column, edits_only, conflict_rule, source_timestamp_property, created_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    binding.namespace,
                    binding.kind,
                    binding.definition_digest,
                    binding.dataset_id,
                    binding.key_column,
                    mapping,
                    binding.hidden_column,
                    i64::from(binding.edits_only),
                    binding.conflict_rule,
                    binding.source_timestamp_property,
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
                "SELECT definition_digest, dataset_id, key_column, property_mapping, hidden_column, edits_only, conflict_rule, source_timestamp_property
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
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional_row()
            .map_err(|error| error.to_string())?
            .map(
                |(
                    definition_digest,
                    dataset_id,
                    key_column,
                    mapping,
                    hidden_column,
                    edits_only,
                    conflict_rule,
                    source_timestamp_property,
                )| {
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
                        conflict_rule,
                        source_timestamp_property,
                    })
                },
            )
            .transpose()
    }

    pub fn get_object_type_index_edit(
        &self,
        namespace: &str,
        kind: &str,
        source_key: &str,
    ) -> Result<Option<ObjectTypeIndexEdit>, String> {
        self.conn()
            .query_row(
                "SELECT properties, hidden, action_id, edited_at_ms, property_edited_at_ms
                 FROM sekai_object_type_index_edit
                 WHERE namespace = ?1 AND kind = ?2 AND source_key = ?3",
                params![namespace, kind, source_key],
                |row| {
                    let properties: String = row.get(0)?;
                    Ok((
                        properties,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional_row()
            .map_err(|error| error.to_string())?
            .map(
                |(properties, hidden, action_id, edited_at_ms, property_edited_at_ms)| {
                    Ok(ObjectTypeIndexEdit {
                        namespace: namespace.into(),
                        kind: kind.into(),
                        source_key: source_key.into(),
                        properties: serde_json::from_str(&properties).map_err(|e| e.to_string())?,
                        hidden: hidden != 0,
                        action_id,
                        edited_at_ms,
                        property_edited_at_ms: parse_property_edit_times(&property_edited_at_ms)?,
                    })
                },
            )
            .transpose()
    }

    pub fn put_object_type_index_edit(&self, edit: &ObjectTypeIndexEdit) -> Result<(), String> {
        self.reserve_index_edit_identity(edit)?;
        let merged = crate::sekai::object_log::merge_and_apply_index_edit(
            self.get_object_type_index_edit(&edit.namespace, &edit.kind, &edit.source_key)?,
            edit.clone(),
        )?;
        self.store_index_edit_projection(&merged)
    }

    fn reserve_index_edit_identity(&self, edit: &ObjectTypeIndexEdit) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT OR IGNORE INTO sekai_object_type_index_edit
                 (namespace, kind, source_key, properties, hidden, action_id, edited_at_ms, property_edited_at_ms)
                 VALUES (?1,?2,?3,'{}',0,'',0,'{}')",
                params![edit.namespace, edit.kind, edit.source_key],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn store_index_edit_projection(&self, edit: &ObjectTypeIndexEdit) -> Result<(), String> {
        let properties = serde_json::to_string(&edit.properties).map_err(|e| e.to_string())?;
        let property_times =
            serde_json::to_string(&edit.property_edited_at_ms).map_err(|e| e.to_string())?;
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_object_type_index_edit
                 (namespace, kind, source_key, properties, hidden, action_id, edited_at_ms, property_edited_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    edit.namespace,
                    edit.kind,
                    edit.source_key,
                    properties,
                    i64::from(edit.hidden),
                    edit.action_id,
                    edit.edited_at_ms,
                    property_times
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
        self.apply_object_type_index_staged(namespace, kind, full_rebuild, now_ms, true)
    }

    #[cfg(test)]
    pub fn apply_object_type_index_without_join_rebuild(
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
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sekai_object_type_index_member
                     WHERE namespace = ?1 AND kind = ?2 AND from_edit = 0",
                    params![namespace, kind],
                    |row| row.get(0),
                )
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
            // Cursor 0 before recreate: a crash that left some members cannot
            // resume from the previous high-water mark and skip deleted rows.
            self.conn()
                .execute(
                    "UPDATE sekai_object_type_index_status
                     SET last_dataset_row_id = 0
                     WHERE namespace = ?1 AND kind = ?2",
                    params![namespace, kind],
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
        let mut members: BTreeMap<String, ObjectTypeIndexMember> = BTreeMap::new();
        if !binding.edits_only {
            let rows = self.list_dataset_row_records(&binding.dataset_id)?;
            for (row_id, data) in rows {
                if row_id <= after_id {
                    continue;
                }
                last_row_id = last_row_id.max(row_id);
                let Ok(mut member) = member_from_row(&binding, &data) else {
                    continue;
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
        if !commit_joins {
            return Ok(ReindexReport {
                rewritten_keys: rewritten,
                skipped_unchanged: skipped,
                quarantined: false,
                quarantine_reason: String::new(),
            });
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

    fn bind_index_member_object_id(
        &self,
        namespace: &str,
        member: &mut ObjectTypeIndexMember,
    ) -> Result<(), String> {
        let object_id = self
            .conn()
            .query_row(
                "SELECT object_id FROM sekai_source_identities
                 WHERE namespace=?1 AND source_id=?2 AND type_name=?3",
                params![namespace, member.source_key, member.kind],
                |row| row.get::<_, String>(0),
            )
            .optional_row()
            .map_err(|error| error.to_string())?;
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
            let conn = self.conn();
            let mut stmt = conn
                .prepare(
                    "SELECT source_key FROM sekai_object_type_index_member
                     WHERE namespace = ?1 AND kind = ?2",
                )
                .map_err(|error| error.to_string())?;
            let mapped = stmt
                .query_map(params![namespace, kind], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?;
            mapped
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        for source_id in source_ids {
            let mut conn = self.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            let Some((
                binding_id,
                type_digest,
                type_name,
                object_id,
                source_version,
                payload_digest,
                tombstoned,
                synced_object_json,
                lineage_json,
                last_transaction_id,
                identity_updated_at_ms,
            )) = tx
                .query_row(
                    "SELECT binding_id, type_digest, type_name, object_id, source_version,
                            payload_digest, tombstoned, synced_object_json, lineage_json,
                            last_transaction_id, updated_at_ms
                     FROM sekai_source_identities
                     WHERE namespace=?1 AND source_id=?2 AND type_name=?3",
                    params![namespace, source_id, kind],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, String>(7)?,
                            row.get::<_, String>(8)?,
                            row.get::<_, String>(9)?,
                            row.get::<_, i64>(10)?,
                        ))
                    },
                )
                .optional_row()
                .map_err(|error| error.to_string())?
            else {
                continue;
            };
            let Some((member_properties, hidden)) = tx
                .query_row(
                    "SELECT properties, hidden FROM sekai_object_type_index_member
                     WHERE namespace=?1 AND kind=?2 AND source_key=?3",
                    params![namespace, kind, source_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional_row()
                .map_err(|error| error.to_string())?
            else {
                continue;
            };
            let mapped: BTreeMap<String, String> =
                serde_json::from_str(&member_properties).map_err(|error| error.to_string())?;
            let Some(existing) = tx
                .query_row(
                    "SELECT id, kind, name, namespace, external_id, properties, created, updated
                     FROM sekai_objects WHERE id=?1",
                    params![object_id],
                    crate::db::sekai::row_to_object,
                )
                .optional_row()
                .map_err(|error| error.to_string())?
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
                hidden != 0,
                crate::db::object_sync::RESERVED_SYNC_PROPERTIES,
            );
            if let Some(policy) =
                crate::db::object_security::load_active_policy_sqlite(&tx, namespace, kind)?
            {
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
                crate::sekai::audit::insert_object_changes(&tx, &changes)?;
            }
            tx.execute(
                "DELETE FROM sekai_source_identities WHERE namespace=?1 AND source_id=?2",
                params![namespace, source_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "UPDATE sekai_objects SET properties=?1, updated=?2 WHERE id=?3",
                params![properties_json, now_ms, object_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_source_identities (
                    namespace, source_id, binding_id, type_digest, type_name, object_id,
                    source_version, payload_digest, tombstoned, synced_object_json,
                    lineage_json, last_transaction_id, updated_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    namespace,
                    source_id,
                    binding_id,
                    type_digest,
                    type_name,
                    object_id,
                    source_version,
                    payload_digest,
                    tombstoned,
                    synced_object_json,
                    lineage_json,
                    last_transaction_id,
                    identity_updated_at_ms
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
        let dialect = crate::sekai::object_type_index::IndexSqlDialect::Sqlite;
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
            "SELECT source_key, object_id, {properties_sql}, content_hash, hidden, from_edit
             FROM sekai_object_type_index_member
             WHERE namespace = ?1 AND kind = ?2 AND hidden = 0{filter_sql}
             ORDER BY source_key{page_sql}"
        );
        let conn = self.conn();
        let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&namespace, &kind];
        for value in &filter_values {
            params.push(value);
        }
        for value in &page_values {
            params.push(value);
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
                    project,
                )?,
                content_hash: row.get(3).map_err(|error| error.to_string())?,
                hidden: false,
                from_edit: row.get::<_, i64>(5).map_err(|error| error.to_string())? != 0,
            });
        }
        Ok(members)
    }

    pub fn object_log_migration_identities(&self) -> Result<Vec<(String, String, String)>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT namespace, kind, source_key
                 FROM sekai_object_type_index_member
                 UNION
                 SELECT namespace, kind, id
                 FROM sekai_objects
                 ORDER BY 1, 2, 3",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = stmt.query([]).map_err(|error| error.to_string())?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            out.push((
                row.get(0).map_err(|error| error.to_string())?,
                row.get(1).map_err(|error| error.to_string())?,
                row.get(2).map_err(|error| error.to_string())?,
            ));
        }
        Ok(out)
    }

    pub fn list_kind_objects_outside_index(
        &self,
        namespace: &str,
        kind: &str,
        offset: i32,
        limit: i32,
    ) -> Result<Vec<crate::domain::Object>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects o
                 WHERE o.namespace = ?1 AND o.kind = ?2
                   AND NOT EXISTS (
                     SELECT 1 FROM sekai_object_type_index_member m
                     WHERE m.namespace = o.namespace AND m.kind = o.kind AND m.object_id = o.id
                   )
                 ORDER BY o.id
                 LIMIT ?3 OFFSET ?4",
            )
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map(
                params![namespace, kind, limit.max(0), offset.max(0)],
                crate::db::sekai::row_to_object,
            )
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    pub fn list_index_member_object_ids(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT object_id FROM sekai_object_type_index_member
                 WHERE namespace = ?1 AND kind = ?2",
            )
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map(params![namespace, kind], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
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
        let dialect = crate::sekai::object_type_index::IndexSqlDialect::Sqlite;
        let (filter_sql, filter_values) =
            crate::sekai::object_type_index::member_filter_sql(dialect, filters)?;
        let sql = format!(
            "SELECT COUNT(*) FROM sekai_object_type_index_member
             WHERE namespace = ?1 AND kind = ?2 AND hidden = 0{filter_sql}"
        );
        let conn = self.conn();
        let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&namespace, &kind];
        for value in &filter_values {
            params.push(value);
        }
        stmt.query_row(params.as_slice(), |row| row.get(0))
            .map_err(|error| error.to_string())
    }

    pub fn list_object_type_index_edits(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Vec<ObjectTypeIndexEdit>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT source_key, properties, hidden, action_id, edited_at_ms, property_edited_at_ms
                 FROM sekai_object_type_index_edit
                 WHERE namespace = ?1 AND kind = ?2",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = stmt
            .query(params![namespace, kind])
            .map_err(|error| error.to_string())?;
        let mut edits = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let properties: String = row.get(1).map_err(|error| error.to_string())?;
            let property_times: String = row.get(5).map_err(|error| error.to_string())?;
            edits.push(ObjectTypeIndexEdit {
                namespace: namespace.into(),
                kind: kind.into(),
                source_key: row.get(0).map_err(|error| error.to_string())?,
                properties: serde_json::from_str(&properties).map_err(|error| error.to_string())?,
                hidden: row.get::<_, i64>(2).map_err(|error| error.to_string())? != 0,
                action_id: row.get(3).map_err(|error| error.to_string())?,
                edited_at_ms: row.get(4).map_err(|error| error.to_string())?,
                property_edited_at_ms: parse_property_edit_times(&property_times)?,
            });
        }
        Ok(edits)
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
        for (_row_id, data) in self.list_dataset_row_records(&binding.dataset_id)? {
            let Ok(member) = member_from_row(binding, &data) else {
                continue;
            };
            if keys.contains_key(&member.source_key) {
                sources.insert(member.source_key.clone(), member);
            }
        }
        Ok(sources)
    }

    fn project_log_overlays_into_edits(&self, namespace: &str, kind: &str) -> Result<(), String> {
        let keys = self.index_overlay_keys(namespace, kind)?;
        for edit in crate::sekai::object_log::load_index_overlays(namespace, kind, &keys)? {
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
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT source_key FROM sekai_object_type_index_member
                 WHERE namespace = ?1 AND kind = ?2",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = stmt
            .query(params![namespace, kind])
            .map_err(|error| error.to_string())?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            keys.push(row.get(0).map_err(|error| error.to_string())?);
        }
        Ok(keys)
    }

    fn upsert_index_member(&self, member: &ObjectTypeIndexMember) -> Result<bool, String> {
        let existing: Option<(String, String)> = self
            .conn()
            .query_row(
                "SELECT object_id, content_hash FROM sekai_object_type_index_member
                 WHERE namespace = ?1 AND kind = ?2 AND source_key = ?3",
                params![member.namespace, member.kind, member.source_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional_row()
            .map_err(|error| error.to_string())?;
        if existing.as_ref().is_some_and(|(object_id, content_hash)| {
            object_id == &member.object_id && content_hash == &member.content_hash
        }) {
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

    pub fn set_hop_projection_ready(
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

    pub fn invalidate_namespace_hop_projection(
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
            partition_keys: Vec::new(),
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
            conflict_rule: String::new(),
            source_timestamp_property: String::new(),
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
        assert_eq!(
            db.count_visible_index_members_matching(
                "sales",
                "Customer",
                &[RowFilter {
                    column: "region".into(),
                    op: "eq".into(),
                    value: "eu".into(),
                }],
            )
            .unwrap(),
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
            action_id: "act-region".into(),
            edited_at_ms: 25,
            property_edited_at_ms: Default::default(),
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
    fn property_edit_keeps_unedited_source_values_after_rebuild() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "name", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("name".into(), "Ada".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        let mut binding = binding();
        binding
            .property_mapping
            .insert("name".into(), "name".into());
        db.register_object_type_datasource(&binding, 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        db.put_object_type_index_edit(&ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
            action_id: "act-region".into(),
            edited_at_ms: 25,
            property_edited_at_ms: Default::default(),
        })
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "us".into()),
                ("name".into(), "Ada L.".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.apply_object_type_index("sales", "Customer", true, 40)
            .unwrap();
        let visible = db
            .list_visible_index_members("sales", "Customer", &RowQuery::default())
            .unwrap();
        assert_eq!(visible[0].properties.get("region").unwrap(), "edited");
        assert_eq!(visible[0].properties.get("name").unwrap(), "Ada L.");
    }

    #[test]
    fn newest_wins_rebuild_keeps_later_source_value() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "updated_at", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "eu".into()),
                ("updated_at".into(), "10".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        let mut binding = binding();
        binding
            .property_mapping
            .insert("updated_at".into(), "updated_at".into());
        binding.conflict_rule = "newest_wins".into();
        binding.source_timestamp_property = "updated_at".into();
        db.register_object_type_datasource(&binding, 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        db.put_object_type_index_edit(&ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
            action_id: "act-region".into(),
            edited_at_ms: 20,
            property_edited_at_ms: Default::default(),
        })
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[HashMap::from([
                ("customer_id".into(), "c1".into()),
                ("region".into(), "us".into()),
                ("updated_at".into(), "50".into()),
                ("hidden".into(), "0".into()),
            ])],
        )
        .unwrap();
        db.apply_object_type_index("sales", "Customer", true, 40)
            .unwrap();
        let visible = db
            .list_visible_index_members("sales", "Customer", &RowQuery::default())
            .unwrap();
        assert_eq!(visible[0].properties.get("region").unwrap(), "us");
    }

    #[test]
    fn type_revision_rename_carries_property_edits() {
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
        db.put_object_type_index_edit(&ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::from([("region".into(), "edited".into())]),
            hidden: false,
            action_id: "act-region".into(),
            edited_at_ms: 25,
            property_edited_at_ms: Default::default(),
        })
        .unwrap();
        let mut next = binding();
        next.property_mapping = BTreeMap::from([("area".into(), "region".into())]);
        db.register_object_type_datasource(&next, 30).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 40)
            .unwrap();
        let visible = db
            .list_visible_index_members("sales", "Customer", &RowQuery::default())
            .unwrap();
        assert_eq!(visible[0].properties.get("area").unwrap(), "edited");
        assert!(!visible[0].properties.contains_key("region"));
    }

    #[test]
    fn deleted_sql_edits_rebuild_from_the_object_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("objects-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
            let db = db();
            db.create_dataset(&dataset(
                "ds-customers",
                &["customer_id", "region", "name", "hidden"],
            ))
            .unwrap();
            db.append_rows(
                "ds-customers",
                &[HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("name".into(), "Ada".into()),
                    ("hidden".into(), "0".into()),
                ])],
            )
            .unwrap();
            let mut binding = binding();
            binding
                .property_mapping
                .insert("name".into(), "name".into());
            db.register_object_type_datasource(&binding, 10).unwrap();
            db.apply_object_type_index("sales", "Customer", true, 20)
                .unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region".into(),
                edited_at_ms: 25,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 30)
                .unwrap();
            let before = db
                .list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap();
            db.conn()
                .execute("DELETE FROM sekai_object_type_index_edit", [])
                .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 40)
                .unwrap();
            let after = db
                .list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap();
            assert_eq!(after[0].properties, before[0].properties);
            assert_eq!(after[0].properties.get("region").unwrap(), "edited");
            assert_eq!(after[0].properties.get("name").unwrap(), "Ada");
        });
        crate::sekai::object_log::release_process_object_log_cache();
    }

    #[test]
    fn property_history_reads_edits_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("history-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
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
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region-1".into(),
                edited_at_ms: 25,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "later".into())]),
                hidden: false,
                action_id: "act-region-2".into(),
                edited_at_ms: 40,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            let history =
                crate::sekai::object_log::property_history("sales", "Customer", "c1", "region")
                    .unwrap();
            let edits: Vec<_> = history
                .iter()
                .filter(|version| version.origin == "edit")
                .map(|version| version.value.clone())
                .collect();
            assert_eq!(edits, vec![Some("edited".into()), Some("later".into())]);
        });
        crate::sekai::object_log::release_process_object_log_cache();
    }

    #[test]
    fn incremental_reindex_applies_edit_without_new_dataset_rows() {
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
            action_id: "act-region".into(),
            edited_at_ms: 25,
            property_edited_at_ms: Default::default(),
        })
        .unwrap();
        db.apply_object_type_index("sales", "Customer", false, 30)
            .unwrap();
        let visible = db
            .list_visible_index_members("sales", "Customer", &RowQuery::default())
            .unwrap();
        assert_eq!(visible[0].properties.get("region").unwrap(), "edited");
    }

    #[test]
    fn incremental_reindex_unhides_when_edit_clears_hidden() {
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
            properties: BTreeMap::new(),
            hidden: true,
            action_id: "act-hide".into(),
            edited_at_ms: 25,
            property_edited_at_ms: Default::default(),
        })
        .unwrap();
        db.apply_object_type_index("sales", "Customer", false, 30)
            .unwrap();
        assert!(
            db.list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap()
                .is_empty()
        );
        db.put_object_type_index_edit(&ObjectTypeIndexEdit {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            properties: BTreeMap::new(),
            hidden: false,
            action_id: "act-show".into(),
            edited_at_ms: 35,
            property_edited_at_ms: Default::default(),
        })
        .unwrap();
        db.apply_object_type_index("sales", "Customer", false, 40)
            .unwrap();
        let visible = db
            .list_visible_index_members("sales", "Customer", &RowQuery::default())
            .unwrap();
        assert_eq!(visible.len(), 1);
        assert!(!visible[0].hidden);
    }

    #[test]
    fn hidden_edit_rebuilds_from_the_object_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("hidden-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
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
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::new(),
                hidden: true,
                action_id: "act-hide".into(),
                edited_at_ms: 25,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 30)
                .unwrap();
            assert!(
                db.list_visible_index_members("sales", "Customer", &RowQuery::default())
                    .unwrap()
                    .is_empty()
            );
            db.conn()
                .execute("DELETE FROM sekai_object_type_index_edit", [])
                .unwrap();
            db.conn()
                .execute("DELETE FROM sekai_object_type_index_member", [])
                .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 40)
                .unwrap();
            assert!(
                db.list_visible_index_members("sales", "Customer", &RowQuery::default())
                    .unwrap()
                    .is_empty()
            );
            let hidden: i64 = db
                .conn()
                .query_row(
                    "SELECT hidden FROM sekai_object_type_index_member
                     WHERE namespace = 'sales' AND kind = 'Customer' AND source_key = 'c1'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(hidden, 1);
        });
        crate::sekai::object_log::release_process_object_log_cache();
    }

    #[test]
    fn type_revision_rename_rewrites_object_log_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("rename-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
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
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region".into(),
                edited_at_ms: 25,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            let mut next = binding();
            next.property_mapping = BTreeMap::from([("area".into(), "region".into())]);
            db.register_object_type_datasource(&next, 30).unwrap();
            db.conn()
                .execute("DELETE FROM sekai_object_type_index_edit", [])
                .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 40)
                .unwrap();
            let visible = db
                .list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap();
            assert_eq!(visible[0].properties.get("area").unwrap(), "edited");
            assert!(!visible[0].properties.contains_key("region"));
            let region_history =
                crate::sekai::object_log::property_history("sales", "Customer", "c1", "region")
                    .unwrap();
            assert!(
                region_history
                    .last()
                    .is_some_and(|version| version.value.is_none()),
                "{region_history:?}"
            );
        });
        crate::sekai::object_log::release_process_object_log_cache();
    }

    #[test]
    fn newest_wins_rebuild_from_log_uses_per_property_times() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("times-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
            let db = db();
            db.create_dataset(&dataset(
                "ds-customers",
                &["customer_id", "region", "name", "updated_at", "hidden"],
            ))
            .unwrap();
            db.append_rows(
                "ds-customers",
                &[HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("name".into(), "Ada".into()),
                    ("updated_at".into(), "20".into()),
                    ("hidden".into(), "0".into()),
                ])],
            )
            .unwrap();
            let mut binding = binding();
            binding
                .property_mapping
                .insert("name".into(), "name".into());
            binding
                .property_mapping
                .insert("updated_at".into(), "updated_at".into());
            binding.conflict_rule = "newest_wins".into();
            binding.source_timestamp_property = "updated_at".into();
            db.register_object_type_datasource(&binding, 10).unwrap();
            db.apply_object_type_index("sales", "Customer", true, 20)
                .unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region".into(),
                edited_at_ms: 10,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("name".into(), "Edited".into())]),
                hidden: false,
                action_id: "act-name".into(),
                edited_at_ms: 30,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.append_rows(
                "ds-customers",
                &[HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "us".into()),
                    ("name".into(), "Ada L.".into()),
                    ("updated_at".into(), "20".into()),
                    ("hidden".into(), "0".into()),
                ])],
            )
            .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 40)
                .unwrap();
            let before = db
                .list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap();
            assert_eq!(before[0].properties.get("region").unwrap(), "us");
            assert_eq!(before[0].properties.get("name").unwrap(), "Edited");
            db.conn()
                .execute("DELETE FROM sekai_object_type_index_edit", [])
                .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 50)
                .unwrap();
            let after = db
                .list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap();
            assert_eq!(after[0].properties.get("region").unwrap(), "us");
            assert_eq!(after[0].properties.get("name").unwrap(), "Edited");
        });
        crate::sekai::object_log::release_process_object_log_cache();
    }

    #[test]
    fn delayed_retry_of_an_earlier_action_keeps_later_edits() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("retry-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
            let db = db();
            db.create_dataset(&dataset(
                "ds-customers",
                &["customer_id", "region", "name", "hidden"],
            ))
            .unwrap();
            db.append_rows(
                "ds-customers",
                &[HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("name".into(), "Ada".into()),
                    ("hidden".into(), "0".into()),
                ])],
            )
            .unwrap();
            let mut binding = binding();
            binding
                .property_mapping
                .insert("name".into(), "name".into());
            db.register_object_type_datasource(&binding, 10).unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region".into(),
                edited_at_ms: 25,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("name".into(), "Ada L.".into())]),
                hidden: false,
                action_id: "act-name".into(),
                edited_at_ms: 40,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region".into(),
                edited_at_ms: 55,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 60)
                .unwrap();
            let visible = db
                .list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap();
            assert_eq!(visible[0].properties.get("region").unwrap(), "edited");
            assert_eq!(visible[0].properties.get("name").unwrap(), "Ada L.");
        });
        crate::sekai::object_log::release_process_object_log_cache();
    }

    #[test]
    fn generated_action_ids_distinguish_hide_and_show() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("hide-show-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
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
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::new(),
                hidden: true,
                action_id: String::new(),
                edited_at_ms: 25,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::new(),
                hidden: false,
                action_id: String::new(),
                edited_at_ms: 40,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 50)
                .unwrap();
            let visible = db
                .list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap();
            assert_eq!(visible.len(), 1);
            assert!(!visible[0].hidden);
        });
        crate::sekai::object_log::release_process_object_log_cache();
    }

    #[test]
    fn reserved_edit_identity_rebuilds_after_stub_projection() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("stub-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
            let db = db();
            let mut binding = binding();
            binding.edits_only = true;
            db.register_object_type_datasource(&binding, 10).unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region".into(),
                edited_at_ms: 25,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.conn()
                .execute(
                    "UPDATE sekai_object_type_index_edit
                     SET properties = '{}', action_id = '', edited_at_ms = 0, property_edited_at_ms = '{}'
                     WHERE namespace = 'sales' AND kind = 'Customer' AND source_key = 'c1'",
                    [],
                )
                .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 40)
                .unwrap();
            let stored = db
                .get_object_type_index_edit("sales", "Customer", "c1")
                .unwrap()
                .unwrap();
            assert_eq!(stored.properties.get("region").unwrap(), "edited");
        });
        crate::sekai::object_log::release_process_object_log_cache();
    }

    #[test]
    fn reservation_stub_without_overlay_does_not_create_a_member() {
        let db = db();
        let mut binding = binding();
        binding.edits_only = true;
        db.register_object_type_datasource(&binding, 10).unwrap();
        db.conn()
            .execute(
                "INSERT INTO sekai_object_type_index_edit
                 (namespace, kind, source_key, properties, hidden, action_id, edited_at_ms, property_edited_at_ms)
                 VALUES ('sales', 'Customer', 'c1', '{}', 0, '', 0, '{}')",
                [],
            )
            .unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        assert!(
            db.list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn mutated_retry_of_an_earlier_action_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("mutated-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
            let db = db();
            db.create_dataset(&dataset(
                "ds-customers",
                &["customer_id", "region", "name", "hidden"],
            ))
            .unwrap();
            db.append_rows(
                "ds-customers",
                &[HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("name".into(), "Ada".into()),
                    ("hidden".into(), "0".into()),
                ])],
            )
            .unwrap();
            let mut binding = binding();
            binding
                .property_mapping
                .insert("name".into(), "name".into());
            db.register_object_type_datasource(&binding, 10).unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region".into(),
                edited_at_ms: 25,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("name".into(), "Ada L.".into())]),
                hidden: false,
                action_id: "act-name".into(),
                edited_at_ms: 40,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            let error = db
                .put_object_type_index_edit(&ObjectTypeIndexEdit {
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    source_key: "c1".into(),
                    properties: BTreeMap::from([("region".into(), "asia".into())]),
                    hidden: false,
                    action_id: "act-region".into(),
                    edited_at_ms: 55,
                    property_edited_at_ms: Default::default(),
                })
                .unwrap_err();
            assert!(error.contains("body conflict"), "{error}");
            db.apply_object_type_index("sales", "Customer", true, 60)
                .unwrap();
            let visible = db
                .list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap();
            assert_eq!(visible[0].properties.get("region").unwrap(), "edited");
            assert_eq!(visible[0].properties.get("name").unwrap(), "Ada L.");
        });
        crate::sekai::object_log::release_process_object_log_cache();
    }

    #[test]
    fn type_revision_rename_keeps_a_newer_live_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(format!("rename-live-{}.mikura", std::process::id()));
        crate::sekai::object_log::with_test_log_path(&log, || {
            let db = db();
            db.create_dataset(&dataset(
                "ds-customers",
                &["customer_id", "region", "name", "hidden"],
            ))
            .unwrap();
            db.append_rows(
                "ds-customers",
                &[HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("name".into(), "Ada".into()),
                    ("hidden".into(), "0".into()),
                ])],
            )
            .unwrap();
            let mut binding = binding();
            binding
                .property_mapping
                .insert("name".into(), "name".into());
            db.register_object_type_datasource(&binding, 10).unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("region".into(), "edited".into())]),
                hidden: false,
                action_id: "act-region".into(),
                edited_at_ms: 25,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            let mut snapshot = db
                .list_object_type_index_edits("sales", "Customer")
                .unwrap();
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: "sales".into(),
                kind: "Customer".into(),
                source_key: "c1".into(),
                properties: BTreeMap::from([("name".into(), "Ada L.".into())]),
                hidden: false,
                action_id: "act-name".into(),
                edited_at_ms: 40,
                property_edited_at_ms: Default::default(),
            })
            .unwrap();
            crate::sekai::object_log::rewrite_index_edit_overlays(
                &mut snapshot,
                &[("region".into(), "area".into())],
                "rev-area",
            )
            .unwrap();
            db.replace_object_type_index_edits("sales", "Customer", &snapshot)
                .unwrap();
            db.apply_object_type_index("sales", "Customer", true, 50)
                .unwrap();
            let visible = db
                .list_visible_index_members("sales", "Customer", &RowQuery::default())
                .unwrap();
            assert_eq!(visible[0].properties.get("area").unwrap(), "edited");
            assert_eq!(visible[0].properties.get("name").unwrap(), "Ada L.");
        });
        crate::sekai::object_log::release_process_object_log_cache();
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
    fn projected_index_members_use_sql_keys_and_page_bounds() {
        let db = db();
        db.create_dataset(&dataset(
            "ds-customers",
            &["customer_id", "region", "notes", "hidden"],
        ))
        .unwrap();
        db.append_rows(
            "ds-customers",
            &[
                HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("notes".into(), "wide-1".into()),
                    ("hidden".into(), "0".into()),
                ]),
                HashMap::from([
                    ("customer_id".into(), "c2".into()),
                    ("region".into(), "eu".into()),
                    ("notes".into(), "wide-2".into()),
                    ("hidden".into(), "0".into()),
                ]),
                HashMap::from([
                    ("customer_id".into(), "c3".into()),
                    ("region".into(), "us".into()),
                    ("notes".into(), "wide-3".into()),
                    ("hidden".into(), "0".into()),
                ]),
            ],
        )
        .unwrap();
        let mut binding = binding();
        binding
            .property_mapping
            .insert("notes".into(), "notes".into());
        db.register_object_type_datasource(&binding, 10).unwrap();
        db.apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();

        let page = db
            .list_visible_index_members_projected(
                "sales",
                "Customer",
                &RowQuery {
                    filters: vec![RowFilter {
                        column: "region".into(),
                        op: "eq".into(),
                        value: "eu".into(),
                    }],
                    columns: vec!["region".into()],
                    limit: 1,
                    offset: 1,
                },
                Some(&["region".into()]),
            )
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].source_key, "c2");
        assert_eq!(
            page[0].properties,
            BTreeMap::from([("region".into(), "eu".into())])
        );
        assert!(!page[0].properties.contains_key("notes"));

        let unfiltered = db
            .list_visible_index_members("sales", "Customer", &RowQuery::default())
            .unwrap();
        assert!(unfiltered[0].properties.contains_key("notes"));
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

    #[test]
    fn object_log_migration_identities_lists_each_projection_row() {
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
        db.create_object(&crate::domain::Object {
            id: "rec-log".into(),
            kind: "customer_record".into(),
            name: "rec-log".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        assert_eq!(
            db.object_log_migration_identities().unwrap(),
            vec![
                ("acme".into(), "customer_record".into(), "rec-log".into()),
                ("sales".into(), "Customer".into(), "c1".into()),
            ]
        );
    }
}
