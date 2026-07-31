//! SQLite persistence for immutable governed-subject provenance exports.

use crate::chisei::governed_subject_provenance::ExportRecord;
use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

impl SekaiDb {
    pub(crate) fn migrate_governed_subject_provenance(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_governed_subject_provenance_exports (
                    actor TEXT NOT NULL,
                    export_id TEXT NOT NULL,
                    binding_digest TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(actor, export_id)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_governed_subject_provenance_namespace
                    ON chisei_governed_subject_provenance_exports(namespace, created_at_ms);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn put_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
        record: &ExportRecord,
    ) -> Result<(ExportRecord, bool), String> {
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(existing) = get_export_tx(&transaction, actor, export_id)? {
            return immutable_replay(existing, record).map(|record| (record, false));
        }
        let record_json = record.to_json()?;
        transaction
            .execute(
                "INSERT INTO chisei_governed_subject_provenance_exports
                 (actor, export_id, binding_digest, namespace, record_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    actor,
                    export_id,
                    record.binding_digest,
                    record.namespace,
                    record_json,
                    record.created_at_ms,
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
        let connection = self.conn();
        get_export_connection(&connection, actor, export_id)
    }
}

fn get_export_connection(
    connection: &rusqlite::Connection,
    actor: &str,
    export_id: &str,
) -> Result<Option<ExportRecord>, String> {
    connection
        .query_row(
            "SELECT record_json
             FROM chisei_governed_subject_provenance_exports
             WHERE actor=?1 AND export_id=?2",
            params![actor, export_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|value| ExportRecord::from_json(&value))
        .transpose()
}

fn get_export_tx(
    transaction: &Transaction<'_>,
    actor: &str,
    export_id: &str,
) -> Result<Option<ExportRecord>, String> {
    transaction
        .query_row(
            "SELECT record_json
             FROM chisei_governed_subject_provenance_exports
             WHERE actor=?1 AND export_id=?2",
            params![actor, export_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::governed_subject_provenance::{ProvenanceEnvelope, signing_key_from_hex};
    use base64::Engine as _;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn record(binding: char) -> ExportRecord {
        let key = signing_key_from_hex(&"09".repeat(32)).unwrap();
        ExportRecord {
            binding_digest: digest(binding),
            namespace: "test".into(),
            envelope: ProvenanceEnvelope::issue(
                &key,
                "subject-1".into(),
                digest('1'),
                digest('2'),
                "operation-1".into(),
                1_000,
                2_000,
            )
            .unwrap(),
            public_key: base64::engine::general_purpose::STANDARD
                .encode(key.verifying_key().to_bytes()),
            created_at_ms: 1_000,
        }
    }

    #[test]
    fn export_is_append_only_replay_or_conflict() {
        let db = SekaiDb::new(":memory:").unwrap();
        let first = record('a');
        assert_eq!(
            db.put_governed_subject_provenance_export("root", "export-1", &first)
                .unwrap(),
            (first.clone(), true)
        );
        assert_eq!(
            db.put_governed_subject_provenance_export("root", "export-1", &first)
                .unwrap(),
            (first.clone(), false)
        );
        assert!(
            db.put_governed_subject_provenance_export("root", "export-1", &record('b'))
                .is_err()
        );
        assert_eq!(
            db.get_governed_subject_provenance_export("root", "export-1")
                .unwrap(),
            Some(first)
        );
    }
}
