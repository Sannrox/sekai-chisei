//! SQLite persistence for signed namespace snapshots and peer grants (#697).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::namespace_snapshot::{
    PeerNamespaceGrant, SnapshotExportRecord, SnapshotFact, SnapshotImportRecord,
};

impl SekaiDb {
    pub fn put_federation_namespace_grant(&self, grant: &PeerNamespaceGrant) -> Result<(), String> {
        let json = serde_json::to_string(grant)
            .map_err(|error| format!("encode namespace grant: {error}"))?;
        self.conn()
            .execute(
                "INSERT INTO sekai_federation_namespace_grants
                    (grant_id, peer_site_id, namespace, record_json, revoked, granted_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(grant_id) DO UPDATE SET
                    peer_site_id = excluded.peer_site_id,
                    namespace = excluded.namespace,
                    record_json = excluded.record_json,
                    revoked = excluded.revoked,
                    granted_at_ms = excluded.granted_at_ms",
                params![
                    grant.grant_id,
                    grant.peer_site_id,
                    grant.namespace,
                    json,
                    i64::from(grant.revoked),
                    grant.granted_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_federation_namespace_grant(
        &self,
        grant_id: &str,
    ) -> Result<Option<PeerNamespaceGrant>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_federation_namespace_grants WHERE grant_id = ?1",
                params![grant_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode namespace grant: {error}"))
        })
        .transpose()
    }

    pub fn list_federation_namespace_grants(
        &self,
        namespace: Option<&str>,
        peer_site_id: Option<&str>,
    ) -> Result<Vec<PeerNamespaceGrant>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_federation_namespace_grants
                 WHERE (?1 IS NULL OR namespace = ?1)
                   AND (?2 IS NULL OR peer_site_id = ?2)
                 ORDER BY granted_at_ms ASC, grant_id ASC",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, peer_site_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        let mut grants = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            grants.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode namespace grant: {error}"))?,
            );
        }
        Ok(grants)
    }

    pub fn reserve_federation_snapshot_sequence(&self, namespace: &str) -> Result<u64, String> {
        let sequence: i64 = self
            .conn()
            .query_row(
                "INSERT INTO sekai_federation_snapshot_sequences (namespace, next_sequence)
                 VALUES (?1, 1)
                 ON CONFLICT(namespace) DO UPDATE SET next_sequence = next_sequence + 1
                 RETURNING next_sequence",
                params![namespace],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        Ok(sequence as u64)
    }

    pub fn put_federation_snapshot_export(
        &self,
        export: &SnapshotExportRecord,
    ) -> Result<(), String> {
        let json = serde_json::to_string(export)
            .map_err(|error| format!("encode snapshot export: {error}"))?;
        self.conn()
            .execute(
                "INSERT INTO sekai_federation_snapshot_exports
                    (snapshot_digest, namespace, sequence, record_json, exported_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(snapshot_digest) DO UPDATE SET
                    namespace = excluded.namespace,
                    sequence = excluded.sequence,
                    record_json = excluded.record_json,
                    exported_at_ms = excluded.exported_at_ms",
                params![
                    export.snapshot_digest,
                    export.namespace,
                    export.sequence as i64,
                    json,
                    export.exported_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn put_federation_snapshot_import(
        &self,
        record: &SnapshotImportRecord,
        facts: &[SnapshotFact],
    ) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode snapshot import: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction()
            .map_err(|error| format!("begin snapshot import: {error}"))?;
        tx.execute(
            "INSERT INTO sekai_federation_snapshot_imports
                (import_id, namespace, peer_site_id, snapshot_digest, sequence, record_json, imported_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.import_id,
                record.namespace,
                record.peer_site_id,
                record.snapshot_digest,
                record.sequence as i64,
                json,
                record.imported_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        for fact in facts {
            let fact_json = serde_json::to_string(fact)
                .map_err(|error| format!("encode snapshot fact: {error}"))?;
            tx.execute(
                "INSERT INTO sekai_federation_snapshot_facts (import_id, object_id, fact_json)
                 VALUES (?1, ?2, ?3)",
                params![record.import_id, fact.object_id, fact_json],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit()
            .map_err(|error| format!("commit snapshot import: {error}"))?;
        Ok(())
    }

    pub fn get_federation_snapshot_import(
        &self,
        import_id: &str,
    ) -> Result<Option<SnapshotImportRecord>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_federation_snapshot_imports WHERE import_id = ?1",
                params![import_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode snapshot import: {error}"))
        })
        .transpose()
    }

    pub fn latest_federation_snapshot_import(
        &self,
        peer_site_id: &str,
        namespace: &str,
    ) -> Result<Option<SnapshotImportRecord>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_federation_snapshot_imports
                 WHERE peer_site_id = ?1 AND namespace = ?2
                 ORDER BY sequence DESC, imported_at_ms DESC
                 LIMIT 1",
                params![peer_site_id, namespace],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode snapshot import: {error}"))
        })
        .transpose()
    }

    pub fn list_federation_snapshot_imports(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<SnapshotImportRecord>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_federation_snapshot_imports
                 WHERE (?1 IS NULL OR namespace = ?1)
                 ORDER BY imported_at_ms ASC, import_id ASC",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut records = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            records.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode snapshot import: {error}"))?,
            );
        }
        Ok(records)
    }

    pub fn list_federation_snapshot_facts(
        &self,
        import_id: &str,
    ) -> Result<Vec<SnapshotFact>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT fact_json FROM sekai_federation_snapshot_facts
                 WHERE import_id = ?1
                 ORDER BY object_id ASC",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![import_id], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut facts = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            facts.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode snapshot fact: {error}"))?,
            );
        }
        Ok(facts)
    }
}
