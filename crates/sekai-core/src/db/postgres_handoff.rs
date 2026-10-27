use crate::db::postgres::PostgresDb;
use crate::sekai::handoff::HandoffManifest;

impl PostgresDb {
    pub fn create_handoff(
        &self,
        manifest: &HandoffManifest,
        request_id: &str,
    ) -> Result<HandoffManifest, String> {
        if request_id.trim().is_empty() {
            return Err("request_id is required".into());
        }
        manifest.validate()?;
        let digest = manifest.canonical_digest()?;
        let mut stored = manifest.clone();
        stored.digest = digest.clone();
        let json = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 250))",
            &[&format!("{}:{request_id}", stored.creator_principal)],
        )
        .map_err(|error| error.to_string())?;
        if let Some(row) = tx
            .query_opt(
                "SELECT request_digest, manifest_json, revoked_at_ms FROM sekai_handoffs
                 WHERE creator_principal=$1 AND request_id=$2",
                &[&stored.creator_principal, &request_id],
            )
            .map_err(|error| error.to_string())?
        {
            let existing_digest: String = row.get(0);
            if existing_digest != digest {
                return Err("request_id is already bound to different handoff input".into());
            }
            let mut replay: HandoffManifest =
                serde_json::from_str(row.get::<_, String>(1).as_str())
                    .map_err(|error| error.to_string())?;
            replay.revoked = row.get::<_, Option<i64>>(2).is_some();
            return Ok(replay);
        }
        tx.execute(
            "INSERT INTO sekai_handoffs
             (id,namespace,intended_principal,creator_principal,request_id,request_digest,
              manifest_json,supersedes_manifest_id,created_at_ms,expires_at_ms)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[
                &stored.id,
                &stored.namespace,
                &stored.intended_principal,
                &stored.creator_principal,
                &request_id,
                &digest,
                &json,
                &stored.supersedes_manifest_id,
                &stored.created_at_ms,
                &stored.expires_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_handoff_events
             (manifest_id,event_type,actor,request_id,reason,recorded_at_ms)
             VALUES($1,'created',$2,$3,$4,$5)",
            &[
                &stored.id,
                &stored.creator_principal,
                &request_id,
                &stored.purpose,
                &stored.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }

    pub fn get_handoff_by_request(
        &self,
        creator: &str,
        request_id: &str,
    ) -> Result<Option<(String, HandoffManifest)>, String> {
        self.connection()?
            .query_opt(
                "SELECT request_digest,manifest_json,revoked_at_ms FROM sekai_handoffs
                 WHERE creator_principal=$1 AND request_id=$2",
                &[&creator, &request_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let mut manifest: HandoffManifest =
                    serde_json::from_str(row.get::<_, String>(1).as_str())
                        .map_err(|error| error.to_string())?;
                manifest.revoked = row.get::<_, Option<i64>>(2).is_some();
                Ok((row.get(0), manifest))
            })
            .transpose()
    }

    pub fn get_handoff(&self, id: &str) -> Result<Option<HandoffManifest>, String> {
        self.connection()?
            .query_opt(
                "SELECT manifest_json,revoked_at_ms FROM sekai_handoffs WHERE id=$1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let mut manifest: HandoffManifest =
                    serde_json::from_str(row.get::<_, String>(0).as_str())
                        .map_err(|error| error.to_string())?;
                manifest.revoked = row.get::<_, Option<i64>>(1).is_some();
                Ok(manifest)
            })
            .transpose()
    }

    pub fn handoff_is_superseded(&self, id: &str) -> Result<bool, String> {
        self.connection()?
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM sekai_handoffs
                 WHERE supersedes_manifest_id=$1 AND revoked_at_ms IS NULL)",
                &[&id],
            )
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let row = tx
            .query_opt(
                "SELECT revoked_at_ms FROM sekai_handoffs WHERE id=$1 FOR UPDATE",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "handoff not found".to_string())?;
        if let Some(existing) = tx
            .query_opt(
                "SELECT reason FROM sekai_handoff_events
                 WHERE manifest_id=$1 AND event_type='revoked' AND actor=$2 AND request_id=$3",
                &[&id, &actor, &request_id],
            )
            .map_err(|error| error.to_string())?
        {
            if existing.get::<_, String>(0) != reason {
                return Err("request_id is already bound to a different revocation".into());
            }
        } else {
            tx.execute(
                "INSERT INTO sekai_handoff_events
                 (manifest_id,event_type,actor,request_id,reason,recorded_at_ms)
                 VALUES($1,'revoked',$2,$3,$4,$5)",
                &[&id, &actor, &request_id, &reason, &now_ms],
            )
            .map_err(|error| error.to_string())?;
        }
        if row.get::<_, Option<i64>>(0).is_none() {
            tx.execute(
                "UPDATE sekai_handoffs SET revoked_at_ms=$2 WHERE id=$1",
                &[&id, &now_ms],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        self.get_handoff(id)?
            .ok_or_else(|| "handoff not found".into())
    }
}
