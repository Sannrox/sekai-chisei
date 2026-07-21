use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HANDOFF_VERSION: &str = "sekai.handoff/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffReference {
    pub kind: String,
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub omitted: bool,
    #[serde(default)]
    pub omission_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffManifest {
    pub schema_version: String,
    pub id: String,
    pub namespace: String,
    pub parent_operation_id: String,
    pub parent_attempt_id: String,
    pub parent_work_unit_id: String,
    pub references: Vec<HandoffReference>,
    pub creator_principal: String,
    pub intended_principal: String,
    pub intended_scope: String,
    pub purpose: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub digest: String,
    pub supersedes_manifest_id: String,
    pub revoked: bool,
}

impl HandoffManifest {
    pub fn canonical_digest(&self) -> Result<String, String> {
        let mut canonical = self.clone();
        canonical.digest.clear();
        // Revocation is live control state, not part of the immutable manifest.
        canonical.revoked = false;
        let bytes = serde_json::to_vec(&canonical).map_err(|e| e.to_string())?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != HANDOFF_VERSION {
            return Err("unsupported handoff schema version".into());
        }
        for (name, value) in [
            ("id", self.id.as_str()),
            ("namespace", self.namespace.as_str()),
            ("creator_principal", self.creator_principal.as_str()),
            ("intended_principal", self.intended_principal.as_str()),
            ("intended_scope", self.intended_scope.as_str()),
            ("purpose", self.purpose.as_str()),
        ] {
            if value.trim().is_empty() || value.trim() != value {
                return Err(format!("{name} is required and must be canonical"));
            }
        }
        if self.created_at_ms <= 0 || self.expires_at_ms <= self.created_at_ms {
            return Err("handoff expiry must be after creation".into());
        }
        if self.references.is_empty() {
            return Err("at least one handoff reference is required".into());
        }
        for reference in &self.references {
            if reference.kind.trim().is_empty() || reference.id.trim().is_empty() {
                return Err("handoff reference kind and id are required".into());
            }
            if reference.omitted {
                if !matches!(
                    reference.omission_reason.as_str(),
                    "policy" | "retention" | "unavailable"
                ) {
                    return Err("omission reason must be policy, retention, or unavailable".into());
                }
            } else if reference.version.trim().is_empty() || !reference.omission_reason.is_empty() {
                return Err("included references require a version and no omission reason".into());
            }
        }
        if !self.digest.is_empty() && self.digest != self.canonical_digest()? {
            return Err("handoff digest does not match canonical manifest".into());
        }
        Ok(())
    }
}

impl SekaiDb {
    pub(crate) fn migrate_handoffs(&self) -> Result<(), String> {
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
