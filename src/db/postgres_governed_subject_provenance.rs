//! PostgreSQL persistence for immutable governed-subject provenance exports.

use crate::chisei::governed_subject_provenance::ExportRecord;
use crate::db::postgres::PostgresDb;
use postgres::GenericClient;

impl PostgresDb {
    pub fn put_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
        record: &ExportRecord,
    ) -> Result<(ExportRecord, bool), String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 473))",
                &[&format!("{}:{actor}{export_id}", actor.len())],
            )
            .map_err(|error| error.to_string())?;
        if let Some(existing) = get_export(&mut transaction, actor, export_id)? {
            return immutable_replay(existing, record).map(|record| (record, false));
        }
        let record_json = record.to_json()?;
        transaction
            .execute(
                "INSERT INTO chisei_governed_subject_provenance_exports
                 (actor, export_id, binding_digest, namespace, record_json, created_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &actor,
                    &export_id,
                    &record.binding_digest,
                    &record.namespace,
                    &record_json,
                    &record.created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok((record.clone(), true))
    }

    pub fn get_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
    ) -> Result<Option<ExportRecord>, String> {
        let mut connection = self.connection()?;
        get_export(&mut *connection, actor, export_id)
    }
}

fn get_export(
    client: &mut impl GenericClient,
    actor: &str,
    export_id: &str,
) -> Result<Option<ExportRecord>, String> {
    client
        .query_opt(
            "SELECT record_json
             FROM chisei_governed_subject_provenance_exports
             WHERE actor=$1 AND export_id=$2",
            &[&actor, &export_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get::<_, String>(0))
        .map(|value| ExportRecord::from_json(&value))
        .transpose()
}

fn immutable_replay(
    existing: ExportRecord,
    requested: &ExportRecord,
) -> Result<ExportRecord, String> {
    if existing.binding_digest == requested.binding_digest {
        Ok(existing)
    } else {
        Err("export_id is already bound to different governed-subject evidence".into())
    }
}
