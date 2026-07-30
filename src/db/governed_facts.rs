//! Atomic graph insertion boundary for immutable governed-fact histories.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use crate::sekai::audit::{ObjectChange, object_diff_changes};
use rusqlite::{TransactionBehavior, params};

impl SekaiDb {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_governed_object_with_audit(
        &self,
        object: &Object,
        actor: &str,
        history_identity_property: &str,
        history_identity: &str,
        predecessor_property: &str,
        predecessor_id: &str,
        max_objects: usize,
    ) -> Result<(), String> {
        validate_governed_insert(
            object,
            history_identity_property,
            history_identity,
            predecessor_property,
            predecessor_id,
            max_objects,
        )?;
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let history_path = format!("$.{history_identity_property}");
        let predecessor_path = format!("$.{predecessor_property}");
        let kind_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM sekai_objects WHERE namespace=?1 AND kind=?2",
                params![object.namespace, object.kind],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if kind_count >= max_objects as i64 {
            return Err(format!(
                "governed namespace exceeds the limit of {max_objects} {} objects",
                object.kind
            ));
        }
        let identity_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM sekai_objects
                 WHERE namespace=?1 AND kind=?2
                   AND json_extract(properties, ?3)=?4",
                params![
                    object.namespace,
                    object.kind,
                    history_path,
                    history_identity
                ],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        validate_history_precondition_sqlite(
            &transaction,
            object,
            history_path.as_str(),
            history_identity,
            predecessor_path.as_str(),
            predecessor_id,
            identity_count,
        )?;
        let historical_changes: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM sekai_object_changes WHERE object_id=?1",
                params![object.id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if historical_changes > 0 {
            return Err("object IDs with audit history cannot be reused".into());
        }
        let properties = serde_json::to_string(&object.properties).map_err(|e| e.to_string())?;
        transaction
            .execute(
                "INSERT INTO sekai_objects
                    (id,kind,name,namespace,external_id,properties,created,updated)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    object.id,
                    object.kind,
                    object.name,
                    object.namespace,
                    object.external_id,
                    properties,
                    object.created,
                    object.updated
                ],
            )
            .map_err(|error| error.to_string())?;
        let now = chrono::Utc::now().timestamp_millis();
        crate::sekai::audit::insert_object_changes(
            &transaction,
            &object_diff_changes(actor, None, Some(object), now),
        )?;
        crate::sekai::temporal::retain_object_history_in_tx(
            &transaction,
            None,
            Some(object),
            actor,
            now,
        )?;
        transaction.commit().map_err(|error| error.to_string())
    }
}

fn validate_history_precondition_sqlite(
    transaction: &rusqlite::Transaction<'_>,
    object: &Object,
    history_path: &str,
    history_identity: &str,
    predecessor_path: &str,
    predecessor_id: &str,
    identity_count: i64,
) -> Result<(), String> {
    if predecessor_id.is_empty() {
        return if identity_count == 0 {
            Ok(())
        } else {
            Err("new governed versions must supersede the exact current version".into())
        };
    }
    let compatible_predecessor: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM sekai_objects
             WHERE id=?1 AND namespace=?2 AND kind=?3
               AND json_extract(properties, ?4)=?5",
            params![
                predecessor_id,
                object.namespace,
                object.kind,
                history_path,
                history_identity
            ],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if compatible_predecessor != 1 {
        return Err("superseded governed version is incompatible".into());
    }
    let successor_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM sekai_objects
             WHERE namespace=?1 AND kind=?2
               AND json_extract(properties, ?3)=?4",
            params![
                object.namespace,
                object.kind,
                predecessor_path,
                predecessor_id
            ],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if successor_count != 0 {
        return Err("governed version already has a superseding successor".into());
    }
    Ok(())
}

impl PostgresDb {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_governed_object_with_audit(
        &self,
        object: &Object,
        actor: &str,
        history_identity_property: &str,
        history_identity: &str,
        predecessor_property: &str,
        predecessor_id: &str,
        max_objects: usize,
    ) -> Result<(), String> {
        validate_governed_insert(
            object,
            history_identity_property,
            history_identity,
            predecessor_property,
            predecessor_id,
            max_objects,
        )?;
        let properties = serde_json::to_string(&object.properties).map_err(|e| e.to_string())?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key = format!(
            "sekai.governed-facts\u{1f}{}\u{1f}{}",
            object.namespace, object.kind
        );
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 266))",
                &[&lock_key],
            )
            .map_err(|error| format!("lock governed-fact history: {error}"))?;
        let kind_count: i64 = transaction
            .query_one(
                "SELECT COUNT(*) FROM sekai_objects WHERE namespace=$1 AND kind=$2",
                &[&object.namespace, &object.kind],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if kind_count >= max_objects as i64 {
            return Err(format!(
                "governed namespace exceeds the limit of {max_objects} {} objects",
                object.kind
            ));
        }
        let identity_count: i64 = transaction
            .query_one(
                "SELECT COUNT(*) FROM sekai_objects
                 WHERE namespace=$1 AND kind=$2
                   AND properties::jsonb ->> $3 = $4",
                &[
                    &object.namespace,
                    &object.kind,
                    &history_identity_property,
                    &history_identity,
                ],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        validate_history_precondition_postgres(
            &mut transaction,
            object,
            history_identity_property,
            history_identity,
            predecessor_property,
            predecessor_id,
            identity_count,
        )?;
        let historical_changes: i64 = transaction
            .query_one(
                "SELECT COUNT(*) FROM sekai_object_changes WHERE object_id=$1",
                &[&object.id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if historical_changes > 0 {
            return Err("object IDs with audit history cannot be reused".into());
        }
        transaction
            .execute(
                "INSERT INTO sekai_objects
                    (id,kind,name,namespace,external_id,properties,created,updated)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
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
        insert_postgres_changes(
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
}

fn validate_history_precondition_postgres(
    transaction: &mut postgres::Transaction<'_>,
    object: &Object,
    history_identity_property: &str,
    history_identity: &str,
    predecessor_property: &str,
    predecessor_id: &str,
    identity_count: i64,
) -> Result<(), String> {
    if predecessor_id.is_empty() {
        return if identity_count == 0 {
            Ok(())
        } else {
            Err("new governed versions must supersede the exact current version".into())
        };
    }
    let compatible_predecessor: i64 = transaction
        .query_one(
            "SELECT COUNT(*) FROM sekai_objects
             WHERE id=$1 AND namespace=$2 AND kind=$3
               AND properties::jsonb ->> $4 = $5",
            &[
                &predecessor_id,
                &object.namespace,
                &object.kind,
                &history_identity_property,
                &history_identity,
            ],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    if compatible_predecessor != 1 {
        return Err("superseded governed version is incompatible".into());
    }
    let successor_count: i64 = transaction
        .query_one(
            "SELECT COUNT(*) FROM sekai_objects
             WHERE namespace=$1 AND kind=$2
               AND properties::jsonb ->> $3 = $4",
            &[
                &object.namespace,
                &object.kind,
                &predecessor_property,
                &predecessor_id,
            ],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    if successor_count != 0 {
        return Err("governed version already has a superseding successor".into());
    }
    Ok(())
}

fn insert_postgres_changes(
    transaction: &mut postgres::Transaction<'_>,
    changes: &[ObjectChange],
) -> Result<(), String> {
    for change in changes {
        transaction
            .execute(
                "INSERT INTO sekai_object_changes
                    (id,object_id,field,old_value,new_value,changed_by,timestamp)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
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

fn validate_governed_insert(
    object: &Object,
    history_identity_property: &str,
    history_identity: &str,
    predecessor_property: &str,
    predecessor_id: &str,
    max_objects: usize,
) -> Result<(), String> {
    if max_objects == 0
        || history_identity_property.is_empty()
        || predecessor_property.is_empty()
        || object
            .properties
            .get(history_identity_property)
            .map(String::as_str)
            != Some(history_identity)
        || object
            .properties
            .get(predecessor_property)
            .map(String::as_str)
            != Some(predecessor_id)
    {
        return Err("invalid governed history insertion contract".into());
    }
    Ok(())
}
