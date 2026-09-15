use crate::db::sekai::SekaiDb;
use crate::sekai::dataset::RowQuery;
use crate::sekai::object_type_index::{
    ObjectTypeDatasource, ObjectTypeIndexEdit, ObjectTypeIndexError, ObjectTypeIndexMember,
    ObjectTypeIndexStatus, ReindexReport, member_from_edit, member_from_row, schema_drift,
};
use rusqlite::params;
use std::collections::BTreeMap;

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
                ",
            )
            .map_err(|error| error.to_string())
    }

    pub fn register_object_type_datasource(
        &self,
        binding: &ObjectTypeDatasource,
        created_at_ms: i64,
    ) -> Result<(), String> {
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
            .map(|_| ())
            .map_err(|error| error.to_string())
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
            self.conn()
                .execute(
                    "DELETE FROM sekai_object_type_index_member WHERE namespace = ?1 AND kind = ?2 AND from_edit = 0",
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
        let member_count = self.count_visible_index_members(namespace, kind)?;
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
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT source_key, object_id, properties, content_hash, hidden, from_edit
                 FROM sekai_object_type_index_member
                 WHERE namespace = ?1 AND kind = ?2 AND hidden = 0
                 ORDER BY source_key",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = stmt
            .query(params![namespace, kind])
            .map_err(|error| error.to_string())?;
        let mut members = Vec::new();
        let mut skipped = 0i32;
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let properties: String = row.get(2).map_err(|error| error.to_string())?;
            let properties: BTreeMap<String, String> =
                serde_json::from_str(&properties).map_err(|error| error.to_string())?;
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
            .map(|_| ())
            .map_err(|error| error.to_string())
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
        properties
            .get(&filter.column)
            .is_some_and(|value| match filter.op.as_str() {
                "eq" | "" => value == &filter.value,
                _ => false,
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
    use crate::sekai::dataset::{ColumnDef, Dataset};
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
}
