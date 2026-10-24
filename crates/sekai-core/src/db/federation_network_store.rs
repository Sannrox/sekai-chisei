//! SQLite persistence for bilateral federation network contracts (#708).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::federation_network::{NETWORK_UNAVAILABLE, NetworkContract, NetworkExchange};

impl SekaiDb {
    pub fn get_network_contract(
        &self,
        namespace: &str,
        contract_id: &str,
    ) -> Result<Option<NetworkContract>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_federation_network_contracts
                 WHERE namespace = ?1 AND contract_id = ?2",
                params![namespace, contract_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode federation network: {error}"))
        })
        .transpose()
    }

    pub fn put_network_contract(&self, contract: &NetworkContract) -> Result<(), String> {
        let json = serde_json::to_string(contract)
            .map_err(|error| format!("encode federation network: {error}"))?;
        let changed = self
            .conn()
            .execute(
                "INSERT INTO sekai_federation_network_contracts
                    (namespace, contract_id, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, contract_id) DO NOTHING",
                params![
                    contract.namespace,
                    contract.contract_id,
                    contract.owner,
                    json
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
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT record_json FROM sekai_federation_network_contracts
                 WHERE namespace = ?1 AND contract_id = ?2",
                params![expected.namespace, expected.contract_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let current: NetworkContract =
            serde_json::from_str(&current.ok_or(NETWORK_UNAVAILABLE)?)
                .map_err(|error| format!("decode federation network: {error}"))?;
        if current != *expected {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_federation_network_contracts
                 SET record_json = ?1
                 WHERE namespace = ?2 AND contract_id = ?3 AND owner = ?4",
                params![next_json, next.namespace, next.contract_id, next.owner],
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
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_federation_network_exchanges
                 WHERE namespace = ?1 AND contract_id = ?2 AND exchange_id = ?3",
                params![namespace, contract_id, exchange_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode federation exchange: {error}"))
        })
        .transpose()
    }

    pub fn put_network_exchange(&self, item: &NetworkExchange) -> Result<(), String> {
        let json = serde_json::to_string(item)
            .map_err(|error| format!("encode federation exchange: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let parent = tx
            .query_row(
                "SELECT record_json FROM sekai_federation_network_contracts
                 WHERE namespace = ?1 AND contract_id = ?2",
                params![item.namespace, item.contract_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let parent: crate::sekai::federation_network::NetworkContract =
            serde_json::from_str(&parent.ok_or(NETWORK_UNAVAILABLE)?)
                .map_err(|error| format!("decode federation network: {error}"))?;
        if parent.status != crate::sekai::federation_network::STATUS_ACCEPTED {
            return Err(
                if parent.status == crate::sekai::federation_network::STATUS_DISCONNECTED {
                    crate::sekai::federation_network::PEER_LOST.into()
                } else {
                    NETWORK_UNAVAILABLE.into()
                },
            );
        }
        let changed = tx
            .execute(
                "INSERT INTO sekai_federation_network_exchanges
                    (namespace, contract_id, exchange_id, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, contract_id, exchange_id) DO NOTHING",
                params![item.namespace, item.contract_id, item.exchange_id, json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}
