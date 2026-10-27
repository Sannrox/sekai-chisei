//! Bilateral federation network contracts (#708).
//!
//! Two planes exchange governed requests, evidence, and outcomes through an
//! explicit contract. Each plane keeps local write and governance authority.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::shomei;

pub const NETWORK_CONTRACT: &str = "sekai.federation-network-contract/v1";
pub const KIND_REQUEST: &str = "request";
pub const KIND_EVIDENCE: &str = "evidence";
pub const KIND_OUTCOME: &str = "outcome";
pub const STATUS_ACCEPTED: &str = "accepted";
pub const STATUS_DISCONNECTED: &str = "disconnected";
pub const STATUS_REVOKED: &str = "revoked";
pub const NETWORK_UNAVAILABLE: &str = "federation network is unavailable";
pub const LOCAL_AUTHORITY: &str = "federation network cannot grant local authority";
pub const PEER_LOST: &str = "federation peer is disconnected";
pub const PROTOCOL_UNSUPPORTED: &str = "federation network revision is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "federation networks are unavailable on the PostgreSQL community runtime";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkContract {
    pub contract_version: String,
    pub contract_id: String,
    pub namespace: String,
    pub owner: String,
    pub local_site_id: String,
    pub peer_site_id: String,
    pub allowed_kinds: Vec<String>,
    pub residency_class: String,
    pub status: String,
    pub contract_digest: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkExchange {
    pub exchange_id: String,
    pub contract_id: String,
    pub namespace: String,
    pub kind: String,
    pub origin_site_id: String,
    pub payload_digest: String,
    pub residency_class: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
}

#[derive(Serialize)]
struct ContractPin<'a> {
    contract_version: &'a str,
    contract_id: &'a str,
    namespace: &'a str,
    local_site_id: &'a str,
    peer_site_id: &'a str,
    allowed_kinds: &'a [String],
    residency_class: &'a str,
}

pub fn contract_digest_for(contract: &NetworkContract) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&ContractPin {
            contract_version: &contract.contract_version,
            contract_id: &contract.contract_id,
            namespace: &contract.namespace,
            local_site_id: &contract.local_site_id,
            peer_site_id: &contract.peer_site_id,
            allowed_kinds: &contract.allowed_kinds,
            residency_class: &contract.residency_class,
        })?
    ))
}

pub fn accept_contract(
    db: &RuntimeDb,
    actor: &str,
    contract: &NetworkContract,
    now_ms: i64,
) -> Result<NetworkContract, String> {
    required("actor", actor)?;
    require_positive_timestamp("accept", now_ms)?;
    let validated = validate_contract(contract, actor, now_ms)?;
    if let Some(existing) = db.get_network_contract(&validated.namespace, &validated.contract_id)? {
        return replay_contract(&existing, &validated);
    }
    match db.put_network_contract(&validated) {
        Ok(()) => Ok(validated),
        Err(error) if error == NETWORK_UNAVAILABLE => {
            let existing = db
                .get_network_contract(&validated.namespace, &validated.contract_id)?
                .ok_or(NETWORK_UNAVAILABLE)?;
            replay_contract(&existing, &validated)
        }
        Err(error) => Err(error),
    }
}

pub fn exchange(
    db: &RuntimeDb,
    actor: &str,
    item: &NetworkExchange,
    now_ms: i64,
) -> Result<NetworkExchange, String> {
    required("actor", actor)?;
    require_positive_timestamp("exchange", now_ms)?;
    let contract = live_contract(db, &item.namespace, &item.contract_id, actor)?;
    let validated = validate_exchange(&contract, item, actor, now_ms)?;
    if let Some(existing) = db.get_network_exchange(
        &validated.namespace,
        &validated.contract_id,
        &validated.exchange_id,
    )? {
        if same_exchange(&existing, &validated) {
            return Ok(existing);
        }
        return Err(NETWORK_UNAVAILABLE.into());
    }
    match db.put_network_exchange(&validated) {
        Ok(()) => Ok(validated),
        Err(error) if error == NETWORK_UNAVAILABLE => {
            let existing = db
                .get_network_exchange(
                    &validated.namespace,
                    &validated.contract_id,
                    &validated.exchange_id,
                )?
                .ok_or(NETWORK_UNAVAILABLE)?;
            if same_exchange(&existing, &validated) {
                Ok(existing)
            } else {
                Err(NETWORK_UNAVAILABLE.into())
            }
        }
        Err(error) => Err(error),
    }
}

pub fn mark_peer_lost(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    contract_id: &str,
    now_ms: i64,
) -> Result<NetworkContract, String> {
    required("actor", actor)?;
    require_positive_timestamp("peer-loss", now_ms)?;
    let current = owned_contract(db, namespace, contract_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    if current.status == STATUS_DISCONNECTED {
        return Ok(current);
    }
    let mut next = current.clone();
    next.status = STATUS_DISCONNECTED.into();
    db.cas_network_contract(&current, &next)?;
    Ok(next)
}

pub fn reconnect(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    contract_id: &str,
    now_ms: i64,
) -> Result<NetworkContract, String> {
    required("actor", actor)?;
    require_positive_timestamp("reconnect", now_ms)?;
    let current = owned_contract(db, namespace, contract_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    if current.status == STATUS_ACCEPTED {
        return Ok(current);
    }
    let mut next = current.clone();
    next.status = STATUS_ACCEPTED.into();
    db.cas_network_contract(&current, &next)?;
    Ok(next)
}

pub fn revoke_contract(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    contract_id: &str,
    now_ms: i64,
) -> Result<NetworkContract, String> {
    required("actor", actor)?;
    require_positive_timestamp("revoke", now_ms)?;
    let current = owned_contract(db, namespace, contract_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Ok(current);
    }
    let mut next = current.clone();
    next.status = STATUS_REVOKED.into();
    db.cas_network_contract(&current, &next)?;
    Ok(next)
}

pub fn get_contract(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    contract_id: &str,
) -> Result<NetworkContract, String> {
    required("actor", actor)?;
    owned_contract(db, namespace, contract_id, actor)
}

fn validate_contract(
    contract: &NetworkContract,
    actor: &str,
    now_ms: i64,
) -> Result<NetworkContract, String> {
    if contract.contract_version != NETWORK_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    required("contract id", &contract.contract_id)?;
    required("namespace", &contract.namespace)?;
    required("local site", &contract.local_site_id)?;
    required("peer site", &contract.peer_site_id)?;
    required("residency class", &contract.residency_class)?;
    if contract.owner != actor || contract.local_site_id == contract.peer_site_id {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    if contract.allowed_kinds.is_empty() {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    let mut seen = BTreeSet::new();
    for kind in &contract.allowed_kinds {
        if !supported_kind(kind) || !seen.insert(kind.as_str()) {
            return Err(NETWORK_UNAVAILABLE.into());
        }
    }
    if !contract.status.is_empty() && contract.status != STATUS_ACCEPTED {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    let digest = contract_digest_for(contract)?;
    if !contract.contract_digest.is_empty() && contract.contract_digest != digest {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    Ok(NetworkContract {
        status: STATUS_ACCEPTED.into(),
        contract_digest: digest,
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
        ..contract.clone()
    })
}

fn validate_exchange(
    contract: &NetworkContract,
    item: &NetworkExchange,
    actor: &str,
    now_ms: i64,
) -> Result<NetworkExchange, String> {
    required("exchange id", &item.exchange_id)?;
    required("origin site", &item.origin_site_id)?;
    if item.namespace != contract.namespace || item.contract_id != contract.contract_id {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    if contract.status == STATUS_DISCONNECTED {
        return Err(PEER_LOST.into());
    }
    if contract.status != STATUS_ACCEPTED {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    if !supported_kind(&item.kind) || !contract.allowed_kinds.iter().any(|kind| kind == &item.kind)
    {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    if item.origin_site_id != contract.local_site_id && item.origin_site_id != contract.peer_site_id
    {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    if item.residency_class != contract.residency_class {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    if !digest_token(&item.payload_digest) {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    Ok(NetworkExchange {
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
        ..item.clone()
    })
}

fn same_exchange(existing: &NetworkExchange, incoming: &NetworkExchange) -> bool {
    existing.exchange_id == incoming.exchange_id
        && existing.contract_id == incoming.contract_id
        && existing.namespace == incoming.namespace
        && existing.kind == incoming.kind
        && existing.origin_site_id == incoming.origin_site_id
        && existing.payload_digest == incoming.payload_digest
        && existing.residency_class == incoming.residency_class
}

fn replay_contract(
    existing: &NetworkContract,
    incoming: &NetworkContract,
) -> Result<NetworkContract, String> {
    if existing.owner != incoming.owner
        || existing.local_site_id != incoming.local_site_id
        || existing.peer_site_id != incoming.peer_site_id
        || existing.allowed_kinds != incoming.allowed_kinds
        || existing.residency_class != incoming.residency_class
        || existing.contract_digest != incoming.contract_digest
        || existing.status == STATUS_REVOKED
    {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    Ok(existing.clone())
}

fn live_contract(
    db: &RuntimeDb,
    namespace: &str,
    contract_id: &str,
    actor: &str,
) -> Result<NetworkContract, String> {
    let contract = owned_contract(db, namespace, contract_id, actor)?;
    if contract.status == STATUS_REVOKED {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    Ok(contract)
}

fn owned_contract(
    db: &RuntimeDb,
    namespace: &str,
    contract_id: &str,
    actor: &str,
) -> Result<NetworkContract, String> {
    required("namespace", namespace)?;
    required("contract id", contract_id)?;
    let contract = db
        .get_network_contract(namespace, contract_id)?
        .ok_or(NETWORK_UNAVAILABLE)?;
    if contract.owner != actor {
        return Err(NETWORK_UNAVAILABLE.into());
    }
    if contract.contract_version != NETWORK_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    Ok(contract)
}

fn supported_kind(kind: &str) -> bool {
    matches!(kind, KIND_REQUEST | KIND_EVIDENCE | KIND_OUTCOME)
}

fn digest_token(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn require_positive_timestamp(action: &str, now_ms: i64) -> Result<(), String> {
    if now_ms <= 0 {
        Err(format!("{action} timestamp must be positive"))
    } else {
        Ok(())
    }
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn digest(tag: u8) -> String {
        format!("sha256:{tag:02x}{}", "ab".repeat(31))
    }

    fn contract() -> NetworkContract {
        let mut contract = NetworkContract {
            contract_version: NETWORK_CONTRACT.into(),
            contract_id: "net:alpha-beta".into(),
            namespace: "shared".into(),
            owner: "operator".into(),
            local_site_id: "site:alpha".into(),
            peer_site_id: "site:beta".into(),
            allowed_kinds: vec![
                KIND_REQUEST.into(),
                KIND_EVIDENCE.into(),
                KIND_OUTCOME.into(),
            ],
            residency_class: "eu".into(),
            status: String::new(),
            contract_digest: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        };
        contract.contract_digest = contract_digest_for(&contract).unwrap();
        contract
    }

    fn item(kind: &str) -> NetworkExchange {
        NetworkExchange {
            exchange_id: format!("ex:{kind}"),
            contract_id: "net:alpha-beta".into(),
            namespace: "shared".into(),
            kind: kind.into(),
            origin_site_id: "site:beta".into(),
            payload_digest: digest(1),
            residency_class: "eu".into(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        }
    }

    fn accept(runtime: &RuntimeDb) -> NetworkContract {
        accept_contract(runtime, "operator", &contract(), 1_000).unwrap()
    }

    #[test]
    fn authorized_exchange_and_replay_preserve_local_authority() {
        let runtime = db();
        let accepted = accept(&runtime);
        assert_eq!(accepted.status, STATUS_ACCEPTED);
        let request = exchange(&runtime, "operator", &item(KIND_REQUEST), 1_200).unwrap();
        let evidence = exchange(&runtime, "operator", &item(KIND_EVIDENCE), 1_300).unwrap();
        let outcome = exchange(&runtime, "operator", &item(KIND_OUTCOME), 1_400).unwrap();
        assert_eq!(request.kind, KIND_REQUEST);
        assert_eq!(evidence.kind, KIND_EVIDENCE);
        assert_eq!(outcome.kind, KIND_OUTCOME);
        assert_eq!(
            exchange(&runtime, "operator", &item(KIND_REQUEST), 1_500).unwrap(),
            request
        );
        assert_eq!(
            LOCAL_AUTHORITY,
            "federation network cannot grant local authority"
        );
    }

    #[test]
    fn peer_loss_revocation_conflict_residency_and_recovery_fail_closed() {
        let runtime = db();
        accept(&runtime);
        let lost = mark_peer_lost(&runtime, "operator", "shared", "net:alpha-beta", 2_000).unwrap();
        assert_eq!(lost.status, STATUS_DISCONNECTED);
        assert_eq!(
            exchange(&runtime, "operator", &item(KIND_REQUEST), 2_100).unwrap_err(),
            PEER_LOST
        );
        reconnect(&runtime, "operator", "shared", "net:alpha-beta", 2_200).unwrap();
        exchange(&runtime, "operator", &item(KIND_REQUEST), 2_300).unwrap();

        let mut residency = item(KIND_EVIDENCE);
        residency.exchange_id = "ex:residency".into();
        residency.residency_class = "us".into();
        assert_eq!(
            exchange(&runtime, "operator", &residency, 2_400).unwrap_err(),
            NETWORK_UNAVAILABLE
        );
        let mut tampered = item(KIND_OUTCOME);
        tampered.exchange_id = "ex:tamper".into();
        tampered.payload_digest = "sha256:nope".into();
        assert_eq!(
            exchange(&runtime, "operator", &tampered, 2_500).unwrap_err(),
            NETWORK_UNAVAILABLE
        );
        let mut foreign = item(KIND_REQUEST);
        foreign.exchange_id = "ex:foreign".into();
        foreign.origin_site_id = "site:gamma".into();
        assert_eq!(
            exchange(&runtime, "operator", &foreign, 2_600).unwrap_err(),
            NETWORK_UNAVAILABLE
        );
        revoke_contract(&runtime, "operator", "shared", "net:alpha-beta", 3_000).unwrap();
        assert_eq!(
            exchange(&runtime, "operator", &item(KIND_EVIDENCE), 3_100).unwrap_err(),
            NETWORK_UNAVAILABLE
        );
        assert_eq!(
            reconnect(&runtime, "operator", "shared", "net:alpha-beta", 3_200).unwrap_err(),
            NETWORK_UNAVAILABLE
        );
        let history = get_contract(&runtime, "operator", "shared", "net:alpha-beta").unwrap();
        assert_eq!(history.status, STATUS_REVOKED);
        assert_eq!(
            get_contract(&runtime, "intruder", "shared", "net:alpha-beta").unwrap_err(),
            NETWORK_UNAVAILABLE
        );
    }

    #[test]
    fn postgres_surface_is_explicitly_unavailable() {
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "federation networks are unavailable on the PostgreSQL community runtime"
        );
    }
}
