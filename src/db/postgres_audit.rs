use crate::db::postgres::PostgresDb;
use crate::domain::Object;
use crate::sekai::audit::{ObjectChange, object_diff_changes};

const OBJECT_COLUMNS: &str = "id, kind, name, namespace, external_id, properties, created, updated";

impl PostgresDb {
    pub fn create_object_with_audit(&self, object: &Object, actor: &str) -> Result<(), String> {
        validate_namespace_identity(object)?;
        let properties = crate::domain::storage_properties_json(&object.properties)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_object_lifecycle(&mut transaction, &object.id)?;
        let historical: i64 = transaction
            .query_one(
                "SELECT COUNT(*) FROM sekai_object_changes WHERE object_id = $1",
                &[&object.id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if historical > 0 {
            return Err("object IDs with audit history cannot be reused".into());
        }
        transaction
            .execute(
                "INSERT INTO sekai_objects
                    (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &object.id,
                    &object.kind,
                    &object.name,
                    &object.namespace,
                    &object.external_id,
                    &properties,
                    &object.created,
                    &object.updated,
                ],
            )
            .map_err(|error| error.to_string())?;
        insert_changes(
            &mut transaction,
            &object_diff_changes(
                actor,
                None,
                Some(object),
                chrono::Utc::now().timestamp_millis(),
            ),
        )?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn update_object_with_audit_if_revision(
        &self,
        object: &Object,
        actor: &str,
        expected_updated: i64,
    ) -> Result<Option<Object>, String> {
        validate_namespace_identity(object)?;
        let properties = crate::domain::storage_properties_json(&object.properties)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_object_lifecycle(&mut transaction, &object.id)?;
        let before = transaction
            .query_opt(
                &format!("SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE id = $1 FOR UPDATE"),
                &[&object.id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object)
            .transpose()?;
        let Some(before) = before else {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        if before.namespace != object.namespace {
            return Err("object namespace is immutable".into());
        }
        if before.created != object.created {
            return Err("object created timestamp is immutable".into());
        }
        if before.kind != object.kind {
            return Err(
                "object kind changes require ontology validation unavailable on PostgreSQL".into(),
            );
        }
        if before.updated != expected_updated || object.updated <= expected_updated {
            return Err("object revision conflict".into());
        }
        // The updated timestamp is the optimistic revision token shared by the
        // current public Object contract. A stale writer cannot overwrite a
        // newer committed revision.
        let updated = transaction
            .execute(
                "UPDATE sekai_objects SET
                    kind = $2, name = $3, namespace = $4, external_id = $5,
                    properties = $6, updated = $7
                 WHERE id = $1 AND updated = $8",
                &[
                    &object.id,
                    &object.kind,
                    &object.name,
                    &object.namespace,
                    &object.external_id,
                    &properties,
                    &object.updated,
                    &expected_updated,
                ],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("object revision conflict".into());
        }
        insert_changes(
            &mut transaction,
            &object_diff_changes(
                actor,
                Some(&before),
                Some(object),
                chrono::Utc::now().timestamp_millis(),
            ),
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(Some(before))
    }

    pub fn abort_unreceipted_object_create(&self, id: &str) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .execute("DELETE FROM sekai_objects WHERE id = $1", &[&id])
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "DELETE FROM sekai_object_changes WHERE object_id = $1",
                &[&id],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn delete_object_with_audit(
        &self,
        id: &str,
        actor: &str,
    ) -> Result<Option<Object>, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_object_lifecycle(&mut transaction, id)?;
        let before = transaction
            .query_opt(
                &format!("SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE id = $1 FOR UPDATE"),
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object)
            .transpose()?;
        transaction
            .execute(
                "DELETE FROM sekai_links WHERE from_id = $1 OR to_id = $1",
                &[&id],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute("DELETE FROM sekai_objects WHERE id = $1", &[&id])
            .map_err(|error| error.to_string())?;
        if let Some(before) = &before {
            insert_changes(
                &mut transaction,
                &object_diff_changes(
                    actor,
                    Some(before),
                    None,
                    chrono::Utc::now().timestamp_millis(),
                ),
            )?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(before)
    }

    pub fn list_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        let limit = if limit > 0 { limit } else { 100 };
        self.connection()?
            .query(
                "SELECT id, object_id, field, old_value, new_value, changed_by, timestamp
                 FROM sekai_object_changes WHERE object_id = $1
                 ORDER BY timestamp DESC, audit_seq DESC LIMIT $2 OFFSET $3",
                &[&object_id, &limit, &offset.max(0)],
            )
            .map(|rows| rows.into_iter().map(row_to_change).collect())
            .map_err(|error| error.to_string())
    }
}

pub(crate) fn lock_object_lifecycle(
    transaction: &mut postgres::Transaction<'_>,
    object_id: &str,
) -> Result<(), String> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 235))",
            &[&object_id],
        )
        .map(|_| ())
        .map_err(|error| format!("lock object lifecycle: {error}"))
}

fn validate_namespace_identity(object: &Object) -> Result<(), String> {
    if (object.id.starts_with("namespace:") || object.external_id.starts_with("namespace:"))
        && object.kind != "namespace"
    {
        return Err("namespace:* identities are reserved for namespace boundaries".into());
    }
    Ok(())
}

pub(crate) fn insert_changes(
    transaction: &mut postgres::Transaction<'_>,
    changes: &[ObjectChange],
) -> Result<(), String> {
    for change in changes {
        transaction
            .execute(
                "INSERT INTO sekai_object_changes
                    (id, object_id, field, old_value, new_value, changed_by, timestamp)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &change.id,
                    &change.object_id,
                    &change.field,
                    &change.old_value,
                    &change.new_value,
                    &change.changed_by,
                    &change.timestamp,
                ],
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn row_to_object(row: postgres::Row) -> Result<Object, String> {
    let properties_json: String = row.get(5);
    Ok(Object {
        id: row.get(0),
        kind: row.get(1),
        name: row.get(2),
        namespace: row.get(3),
        external_id: row.get(4),
        properties: serde_json::from_str(&properties_json)
            .map_err(|error| format!("invalid object properties: {error}"))?,
        created: row.get(6),
        updated: row.get(7),
    })
}

fn row_to_change(row: postgres::Row) -> ObjectChange {
    ObjectChange {
        id: row.get(0),
        object_id: row.get(1),
        field: row.get(2),
        old_value: row.get(3),
        new_value: row.get(4),
        changed_by: row.get(5),
        timestamp: row.get(6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn namespace_identities_are_reserved_before_connecting() {
        let object = Object {
            id: "namespace:x".into(),
            kind: "component".into(),
            name: "x".into(),
            namespace: "x".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        assert!(validate_namespace_identity(&object).is_err());
    }
}
