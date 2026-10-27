//! SQLite persistence for peer trust roots and compliance import records (#290).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::peer_import::{PeerImportRecord, PeerTrustRoot};

impl SekaiDb {
    pub fn put_peer_trust_root(&self, root: &PeerTrustRoot) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_peer_trust_roots
                (namespace, site_identity, key_id, public_key_hex, enabled, created_by, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(namespace, site_identity, key_id) DO UPDATE SET
                public_key_hex = excluded.public_key_hex,
                enabled = excluded.enabled,
                created_by = excluded.created_by,
                created_at_ms = excluded.created_at_ms",
            params![
                root.namespace,
                root.site_identity,
                root.key_id,
                root.public_key_hex,
                i64::from(root.enabled),
                root.created_by,
                root.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn list_peer_trust_roots(&self, namespace: &str) -> Result<Vec<PeerTrustRoot>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT namespace, site_identity, key_id, public_key_hex, enabled, created_by, created_at_ms
                 FROM sekai_peer_trust_roots
                 WHERE namespace = ?1
                 ORDER BY site_identity, key_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| {
                Ok(PeerTrustRoot {
                    namespace: row.get(0)?,
                    site_identity: row.get(1)?,
                    key_id: row.get(2)?,
                    public_key_hex: row.get(3)?,
                    enabled: row.get::<_, i64>(4)? != 0,
                    created_by: row.get(5)?,
                    created_at_ms: row.get(6)?,
                })
            })
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    pub fn put_peer_import(&self, record: &PeerImportRecord) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode peer import: {error}"))?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_peer_imports (import_id, namespace, record_json, imported_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                record.import_id,
                record.namespace,
                json,
                record.imported_at_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_peer_import(&self, import_id: &str) -> Result<Option<PeerImportRecord>, String> {
        let conn = self.conn();
        let json: Option<String> = conn
            .query_row(
                "SELECT record_json FROM sekai_peer_imports WHERE import_id = ?1",
                params![import_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode peer import: {error}"))
        })
        .transpose()
    }
}
