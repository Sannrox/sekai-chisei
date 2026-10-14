//! PostgreSQL persistence for federation network, profile, conflict, and
//! revocation stores (#1475).

use crate::db::postgres::PostgresDb;
use crate::sekai::federation_conflict::FederationConflict;
use crate::sekai::federation_network::{
    NETWORK_UNAVAILABLE, NetworkContract, NetworkExchange, PEER_LOST, STATUS_ACCEPTED,
    STATUS_DISCONNECTED,
};
use crate::sekai::federation_profile::{FederationPeer, LocalSiteIdentity};
use crate::sekai::federation_revocation::FederationRevocation;

impl PostgresDb {
    pub fn put_federation_local_site(&self, site: &LocalSiteIdentity) -> Result<(), String> {
        let classes = serde_json::to_string(&site.residency_data_classes)
            .map_err(|error| format!("encode residency data classes: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_local_site
                    (site_id, key_id, public_key_hex, region, residency_data_classes_json,
                     registered_by, registered_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (site_id) DO UPDATE SET
                    key_id = EXCLUDED.key_id,
                    public_key_hex = EXCLUDED.public_key_hex,
                    region = EXCLUDED.region,
                    residency_data_classes_json = EXCLUDED.residency_data_classes_json,
                    registered_by = EXCLUDED.registered_by,
                    registered_at_ms = EXCLUDED.registered_at_ms",
                &[
                    &site.site_id,
                    &site.key_id,
                    &site.public_key_hex,
                    &site.region,
                    &classes,
                    &site.registered_by,
                    &site.registered_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_federation_local_site(&self) -> Result<Option<LocalSiteIdentity>, String> {
        self.connection()?
            .query_opt(
                "SELECT site_id, key_id, public_key_hex, region, residency_data_classes_json,
                        registered_by, registered_at_ms
                 FROM sekai_federation_local_site
                 ORDER BY registered_at_ms ASC
                 LIMIT 1",
                &[],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let classes_json: String = row.get(4);
                let residency_data_classes: Vec<String> = serde_json::from_str(&classes_json)
                    .map_err(|error| format!("decode residency data classes: {error}"))?;
                Ok(LocalSiteIdentity {
                    site_id: row.get(0),
                    key_id: row.get(1),
                    public_key_hex: row.get(2),
                    region: row.get(3),
                    residency_data_classes,
                    registered_by: row.get(5),
                    registered_at_ms: row.get(6),
                })
            })
            .transpose()
    }

    pub fn put_federation_peer(&self, peer: &FederationPeer) -> Result<(), String> {
        let json = serde_json::to_string(peer)
            .map_err(|error| format!("encode federation peer: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_peers
                    (local_site_id, peer_site_id, record_json, membership, health, joined_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (local_site_id, peer_site_id) DO UPDATE SET
                    record_json = EXCLUDED.record_json,
                    membership = EXCLUDED.membership,
                    health = EXCLUDED.health,
                    joined_at_ms = EXCLUDED.joined_at_ms",
                &[
                    &peer.local_site_id,
                    &peer.peer_site_id,
                    &json,
                    &peer.membership.as_str(),
                    &peer.health.as_str(),
                    &peer.joined_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_federation_peer(
        &self,
        peer_site_id: &str,
    ) -> Result<Option<FederationPeer>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_peers WHERE peer_site_id = $1 LIMIT 1",
                &[&peer_site_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_peer(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_federation_peers(&self) -> Result<Vec<FederationPeer>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_federation_peers ORDER BY peer_site_id",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_peer(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn put_federation_conflict(&self, record: &FederationConflict) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode federation conflict: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_conflicts
                    (conflict_id, namespace, object_id, status, record_json, updated_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (conflict_id) DO UPDATE SET
                    namespace = EXCLUDED.namespace,
                    object_id = EXCLUDED.object_id,
                    status = EXCLUDED.status,
                    record_json = EXCLUDED.record_json,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[
                    &record.conflict_id,
                    &record.namespace,
                    &record.object_id,
                    &record.status,
                    &json,
                    &record.updated_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_federation_conflict(
        &self,
        conflict_id: &str,
    ) -> Result<Option<FederationConflict>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_conflicts WHERE conflict_id = $1",
                &[&conflict_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_conflict(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_federation_conflicts(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<FederationConflict>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_federation_conflicts
                 WHERE ($1::text IS NULL OR namespace = $1)
                 ORDER BY updated_at_ms ASC, object_id ASC",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_conflict(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn put_federation_revocation(&self, record: &FederationRevocation) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode federation revocation: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_revocations
                    (revocation_id, subject_kind, subject_id, status, record_json, updated_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (revocation_id) DO UPDATE SET
                    subject_kind = EXCLUDED.subject_kind,
                    subject_id = EXCLUDED.subject_id,
                    status = EXCLUDED.status,
                    record_json = EXCLUDED.record_json,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[
                    &record.revocation_id,
                    &record.subject_kind.as_str(),
                    &record.subject_id,
                    &record.status,
                    &json,
                    &record.updated_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_federation_revocation(
        &self,
        revocation_id: &str,
    ) -> Result<Option<FederationRevocation>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_revocations WHERE revocation_id = $1",
                &[&revocation_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_revocation(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_federation_revocations(
        &self,
        subject_kind: Option<&str>,
    ) -> Result<Vec<FederationRevocation>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_federation_revocations
                 WHERE ($1::text IS NULL OR subject_kind = $1)
                 ORDER BY updated_at_ms ASC, subject_id ASC",
                &[&subject_kind],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_revocation(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn get_network_contract(
        &self,
        namespace: &str,
        contract_id: &str,
    ) -> Result<Option<NetworkContract>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_network_contracts
                 WHERE namespace = $1 AND contract_id = $2",
                &[&namespace, &contract_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_contract(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn put_network_contract(&self, contract: &NetworkContract) -> Result<(), String> {
        let json = serde_json::to_string(contract)
            .map_err(|error| format!("encode federation network: {error}"))?;
        let changed = self
            .connection()?
            .execute(
                "INSERT INTO sekai_federation_network_contracts
                    (namespace, contract_id, owner, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, contract_id) DO NOTHING",
                &[
                    &contract.namespace,
                    &contract.contract_id,
                    &contract.owner,
                    &json,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        Ok(())
    }

    pub fn cas_network_contract(
        &self,
        expected: &NetworkContract,
        next: &NetworkContract,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.contract_id != next.contract_id
            || expected.owner != next.owner
        {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode federation network: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_opt(
                "SELECT record_json FROM sekai_federation_network_contracts
                 WHERE namespace = $1 AND contract_id = $2 FOR UPDATE",
                &[&expected.namespace, &expected.contract_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_contract(&row.get::<_, String>(0)))
            .transpose()?
            .ok_or(NETWORK_UNAVAILABLE)?;
        if current != *expected {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_federation_network_contracts
                 SET record_json = $1
                 WHERE namespace = $2 AND contract_id = $3 AND owner = $4",
                &[&next_json, &next.namespace, &next.contract_id, &next.owner],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_network_exchange(
        &self,
        namespace: &str,
        contract_id: &str,
        exchange_id: &str,
    ) -> Result<Option<NetworkExchange>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_network_exchanges
                 WHERE namespace = $1 AND contract_id = $2 AND exchange_id = $3",
                &[&namespace, &contract_id, &exchange_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_exchange(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn put_network_exchange(&self, item: &NetworkExchange) -> Result<(), String> {
        let json = serde_json::to_string(item)
            .map_err(|error| format!("encode federation exchange: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let parent = tx
            .query_opt(
                "SELECT record_json FROM sekai_federation_network_contracts
                 WHERE namespace = $1 AND contract_id = $2 FOR UPDATE",
                &[&item.namespace, &item.contract_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_contract(&row.get::<_, String>(0)))
            .transpose()?
            .ok_or(NETWORK_UNAVAILABLE)?;
        if parent.status != STATUS_ACCEPTED {
            return Err(if parent.status == STATUS_DISCONNECTED {
                PEER_LOST.into()
            } else {
                NETWORK_UNAVAILABLE.into()
            });
        }
        let changed = tx
            .execute(
                "INSERT INTO sekai_federation_network_exchanges
                    (namespace, contract_id, exchange_id, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, contract_id, exchange_id) DO NOTHING",
                &[&item.namespace, &item.contract_id, &item.exchange_id, &json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn decode_peer(json: &str) -> Result<FederationPeer, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation peer: {error}"))
}

fn decode_conflict(json: &str) -> Result<FederationConflict, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation conflict: {error}"))
}

fn decode_revocation(json: &str) -> Result<FederationRevocation, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation revocation: {error}"))
}

fn decode_contract(json: &str) -> Result<NetworkContract, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation network: {error}"))
}

fn decode_exchange(json: &str) -> Result<NetworkExchange, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation exchange: {error}"))
}
