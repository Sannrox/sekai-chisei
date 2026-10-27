//! SQLite persistence for multi-control-plane federation profile v1 (#291).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::federation_profile::{FederationPeer, LocalSiteIdentity};

impl SekaiDb {
    pub fn put_federation_local_site(&self, site: &LocalSiteIdentity) -> Result<(), String> {
        let classes = serde_json::to_string(&site.residency_data_classes)
            .map_err(|error| format!("encode residency data classes: {error}"))?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_federation_local_site
                (site_id, key_id, public_key_hex, region, residency_data_classes_json,
                 registered_by, registered_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(site_id) DO UPDATE SET
                key_id = excluded.key_id,
                public_key_hex = excluded.public_key_hex,
                region = excluded.region,
                residency_data_classes_json = excluded.residency_data_classes_json,
                registered_by = excluded.registered_by,
                registered_at_ms = excluded.registered_at_ms",
            params![
                site.site_id,
                site.key_id,
                site.public_key_hex,
                site.region,
                classes,
                site.registered_by,
                site.registered_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_federation_local_site(&self) -> Result<Option<LocalSiteIdentity>, String> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT site_id, key_id, public_key_hex, region, residency_data_classes_json,
                        registered_by, registered_at_ms
                 FROM sekai_federation_local_site
                 ORDER BY registered_at_ms ASC
                 LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;

        row.map(
            |(
                site_id,
                key_id,
                public_key_hex,
                region,
                classes_json,
                registered_by,
                registered_at_ms,
            )| {
                let residency_data_classes: Vec<String> = serde_json::from_str(&classes_json)
                    .map_err(|error| format!("decode residency data classes: {error}"))?;
                Ok(LocalSiteIdentity {
                    site_id,
                    key_id,
                    public_key_hex,
                    region,
                    residency_data_classes,
                    registered_by,
                    registered_at_ms,
                })
            },
        )
        .transpose()
    }

    pub fn put_federation_peer(&self, peer: &FederationPeer) -> Result<(), String> {
        let json = serde_json::to_string(peer)
            .map_err(|error| format!("encode federation peer: {error}"))?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_federation_peers
                (local_site_id, peer_site_id, record_json, membership, health, joined_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(local_site_id, peer_site_id) DO UPDATE SET
                record_json = excluded.record_json,
                membership = excluded.membership,
                health = excluded.health,
                joined_at_ms = excluded.joined_at_ms",
            params![
                peer.local_site_id,
                peer.peer_site_id,
                json,
                peer.membership.as_str(),
                peer.health.as_str(),
                peer.joined_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_federation_peer(
        &self,
        peer_site_id: &str,
    ) -> Result<Option<FederationPeer>, String> {
        let conn = self.conn();
        let json: Option<String> = conn
            .query_row(
                "SELECT record_json FROM sekai_federation_peers WHERE peer_site_id = ?1 LIMIT 1",
                params![peer_site_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode federation peer: {error}"))
        })
        .transpose()
    }

    pub fn list_federation_peers(&self) -> Result<Vec<FederationPeer>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_federation_peers
                 ORDER BY peer_site_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut peers = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            let peer: FederationPeer = serde_json::from_str(&json)
                .map_err(|error| format!("decode federation peer: {error}"))?;
            peers.push(peer);
        }
        Ok(peers)
    }
}
