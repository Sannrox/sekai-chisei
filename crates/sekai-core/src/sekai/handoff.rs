//! Handoff persistence host.
//!
//! Value types live in `sekai-types`.

pub use sekai_types::handoff::*;

use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, params};

impl SekaiDb {
    pub fn migrate_handoffs(&self) -> Result<(), String> {
        self.conn().execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_handoffs (
               id TEXT PRIMARY KEY, namespace TEXT NOT NULL, intended_principal TEXT NOT NULL,
               creator_principal TEXT NOT NULL, request_id TEXT NOT NULL, request_digest TEXT NOT NULL, manifest_json TEXT NOT NULL,
               supersedes_manifest_id TEXT NOT NULL,
               created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, revoked_at_ms INTEGER,
               UNIQUE(creator_principal, request_id)
             );
             CREATE INDEX IF NOT EXISTS idx_sekai_handoffs_receiver
               ON sekai_handoffs(namespace, intended_principal, created_at_ms);
             CREATE TABLE IF NOT EXISTS sekai_handoff_events (
               id INTEGER PRIMARY KEY AUTOINCREMENT, manifest_id TEXT NOT NULL, event_type TEXT NOT NULL,
               actor TEXT NOT NULL, request_id TEXT NOT NULL, reason TEXT NOT NULL, recorded_at_ms INTEGER NOT NULL,
               UNIQUE(manifest_id, event_type, actor, request_id)
             );"
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn create_handoff(
        &self,
        manifest: &HandoffManifest,
        request_id: &str,
    ) -> Result<HandoffManifest, String> {
        if request_id.trim().is_empty() {
            return Err("request_id is required".into());
        }
        manifest.validate()?;
        let request_digest = manifest.canonical_digest()?;
        let mut stored = manifest.clone();
        stored.digest = request_digest.clone();
        let json = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let replay = tx.query_row(
            "SELECT request_digest, manifest_json FROM sekai_handoffs WHERE creator_principal=?1 AND request_id=?2",
            params![stored.creator_principal, request_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        ).optional().map_err(|e| e.to_string())?;
        if let Some((existing_digest, existing_json)) = replay {
            if existing_digest != request_digest {
                return Err("request_id is already bound to different handoff input".into());
            }
            return serde_json::from_str(&existing_json).map_err(|e| e.to_string());
        }
        tx.execute(
            "INSERT INTO sekai_handoffs(id, namespace, intended_principal, request_id, request_digest, manifest_json, created_at_ms, expires_at_ms, creator_principal, supersedes_manifest_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![stored.id, stored.namespace, stored.intended_principal, request_id, request_digest, json, stored.created_at_ms, stored.expires_at_ms, stored.creator_principal, stored.supersedes_manifest_id]
        ).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO sekai_handoff_events(manifest_id,event_type,actor,request_id,reason,recorded_at_ms) VALUES(?1,'created',?2,?3,?4,?5)",
            params![stored.id, stored.creator_principal, request_id, stored.purpose, stored.created_at_ms]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(stored)
    }

    pub fn get_handoff_by_request(
        &self,
        creator_principal: &str,
        request_id: &str,
    ) -> Result<Option<(String, HandoffManifest)>, String> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT request_digest, manifest_json, revoked_at_ms FROM sekai_handoffs WHERE creator_principal=?1 AND request_id=?2",
                params![creator_principal, request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<i64>>(2)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        row.map(|(digest, json, revoked_at)| {
            serde_json::from_str(&json)
                .map(|mut manifest: HandoffManifest| {
                    manifest.revoked = revoked_at.is_some();
                    (digest, manifest)
                })
                .map_err(|e| e.to_string())
        })
        .transpose()
    }

    pub fn get_handoff(&self, id: &str) -> Result<Option<HandoffManifest>, String> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT manifest_json, revoked_at_ms FROM sekai_handoffs WHERE id=?1",
                [id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        row.map(|(json, revoked)| {
            let mut manifest: HandoffManifest =
                serde_json::from_str(&json).map_err(|e| e.to_string())?;
            manifest.revoked = revoked.is_some();
            Ok(manifest)
        })
        .transpose()
    }

    pub fn handoff_is_superseded(&self, id: &str) -> Result<bool, String> {
        let conn = self.conn();
        conn.query_row("SELECT EXISTS(SELECT 1 FROM sekai_handoffs WHERE supersedes_manifest_id=?1 AND revoked_at_ms IS NULL)", [id], |row| row.get(0)).map_err(|e| e.to_string())
    }

    pub fn revoke_handoff(
        &self,
        id: &str,
        actor: &str,
        reason: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<HandoffManifest, String> {
        if reason.trim().is_empty() || request_id.trim().is_empty() {
            return Err("revocation reason and request_id are required".into());
        }
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let changed = tx
            .execute(
                "UPDATE sekai_handoffs SET revoked_at_ms=COALESCE(revoked_at_ms,?1) WHERE id=?2",
                params![now_ms, id],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("handoff not found".into());
        }
        let existing_reason = tx.query_row(
            "SELECT reason FROM sekai_handoff_events WHERE manifest_id=?1 AND event_type='revoked' AND actor=?2 AND request_id=?3",
            params![id, actor, request_id], |row| row.get::<_, String>(0)
        ).optional().map_err(|e| e.to_string())?;
        if existing_reason
            .as_deref()
            .is_some_and(|existing| existing != reason)
        {
            return Err("request_id is already bound to a different revocation".into());
        }
        tx.execute("INSERT OR IGNORE INTO sekai_handoff_events(manifest_id,event_type,actor,request_id,reason,recorded_at_ms) VALUES(?1,'revoked',?2,?3,?4,?5)", params![id,actor,request_id,reason,now_ms]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        drop(conn);
        self.get_handoff(id)?
            .ok_or_else(|| "handoff not found".into())
    }
}
