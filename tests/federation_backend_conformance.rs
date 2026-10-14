//! Shared SQLite/PostgreSQL conformance for federation network, site/peer,
//! conflict, and revocation stores (#1475).

use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::federation_conflict::{CONFLICT_CONTRACT, FederationConflict};
use sekai_chisei::sekai::federation_network::{
    KIND_EVIDENCE, KIND_OUTCOME, KIND_REQUEST, NETWORK_CONTRACT, NETWORK_UNAVAILABLE,
    NetworkContract, NetworkExchange, PEER_LOST, STATUS_ACCEPTED, STATUS_DISCONNECTED,
    STATUS_REVOKED, accept_contract, contract_digest_for, exchange, get_contract, mark_peer_lost,
    reconnect, revoke_contract,
};
use sekai_chisei::sekai::federation_profile::{
    FEDERATION_PROFILE_CONTRACT, FederationPeer, LocalSiteIdentity, MembershipStatus, PeerHealth,
    PolicyPackPin, get_local_site, register_local_site,
};
use sekai_chisei::sekai::federation_revocation::{
    FederationRevocation, REVOCATION_CONTRACT, RevocationPropagation, SubjectKind,
};

use crate::postgres_scratch::ScratchDatabase;

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

fn exercise_network(db: &RuntimeDb) {
    let accepted = accept_contract(db, "operator", &contract(), 1_000).unwrap();
    assert_eq!(accepted.status, STATUS_ACCEPTED);
    let request = exchange(db, "operator", &item(KIND_REQUEST), 1_200).unwrap();
    assert_eq!(
        exchange(db, "operator", &item(KIND_REQUEST), 1_500).unwrap(),
        request
    );

    let lost = mark_peer_lost(db, "operator", "shared", "net:alpha-beta", 2_000).unwrap();
    assert_eq!(lost.status, STATUS_DISCONNECTED);
    assert_eq!(
        exchange(db, "operator", &item(KIND_REQUEST), 2_100).unwrap_err(),
        PEER_LOST
    );
    reconnect(db, "operator", "shared", "net:alpha-beta", 2_200).unwrap();
    exchange(db, "operator", &item(KIND_REQUEST), 2_300).unwrap();

    revoke_contract(db, "operator", "shared", "net:alpha-beta", 3_000).unwrap();
    assert_eq!(
        exchange(db, "operator", &item(KIND_EVIDENCE), 3_100).unwrap_err(),
        NETWORK_UNAVAILABLE
    );
    assert_eq!(
        reconnect(db, "operator", "shared", "net:alpha-beta", 3_200).unwrap_err(),
        NETWORK_UNAVAILABLE
    );
    let history = get_contract(db, "operator", "shared", "net:alpha-beta").unwrap();
    assert_eq!(history.status, STATUS_REVOKED);
    assert_eq!(
        get_contract(db, "intruder", "shared", "net:alpha-beta").unwrap_err(),
        NETWORK_UNAVAILABLE
    );
}

fn site(id: &str) -> LocalSiteIdentity {
    LocalSiteIdentity {
        site_id: id.into(),
        key_id: "key:local".into(),
        public_key_hex: "aa".repeat(32),
        region: Some("eu".into()),
        residency_data_classes: vec!["internal".into()],
        registered_by: "operator".into(),
        registered_at_ms: 10,
    }
}

fn peer(local: &str, remote: &str) -> FederationPeer {
    FederationPeer {
        contract_version: FEDERATION_PROFILE_CONTRACT.into(),
        local_site_id: local.into(),
        peer_site_id: remote.into(),
        peer_key_id: "key:peer".into(),
        peer_public_key_hex: "bb".repeat(32),
        policy_pack: PolicyPackPin {
            pack_id: "pack".into(),
            version: "1".into(),
            content_digest: digest(2),
        },
        residency_region: Some("eu".into()),
        residency_data_classes: vec!["internal".into()],
        health: PeerHealth::Unknown,
        membership: MembershipStatus::Joined,
        joined_by: "operator".into(),
        joined_at_ms: 20,
        left_by: None,
        left_at_ms: None,
    }
}

fn exercise_profile(db: &RuntimeDb) {
    let local = site("site:alpha");
    register_local_site(db, &local).unwrap();
    assert_eq!(get_local_site(db).unwrap().unwrap().site_id, "site:alpha");
    register_local_site(db, &local).unwrap();
    let other = site("site:gamma");
    assert!(
        register_local_site(db, &other)
            .unwrap_err()
            .contains("already registered")
    );

    let first = peer("site:alpha", "site:beta");
    db.put_federation_peer(&first).unwrap();
    let foreign = peer("site:alpha", "site:delta");
    db.put_federation_peer(&foreign).unwrap();
    assert_eq!(
        db.get_federation_peer("site:beta")
            .unwrap()
            .unwrap()
            .peer_site_id,
        "site:beta"
    );
    let listed = db.list_federation_peers().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|peer| peer.peer_site_id.as_str())
            .collect::<Vec<_>>(),
        ["site:beta", "site:delta"]
    );
}

fn exercise_conflict(db: &RuntimeDb) {
    let sales = FederationConflict {
        contract_version: CONFLICT_CONTRACT.into(),
        conflict_id: "conflict:sales".into(),
        namespace: "sales".into(),
        object_id: "obj:1".into(),
        claims: Vec::new(),
        status: "open".into(),
        resolution: None,
        resolution_history: Vec::new(),
        write_authority: true,
        permit_authority: false,
        admitted_by: "operator".into(),
        admitted_at_ms: 1,
        updated_at_ms: 1,
    };
    db.put_federation_conflict(&sales).unwrap();
    let mut ops = sales.clone();
    ops.conflict_id = "conflict:ops".into();
    ops.namespace = "ops".into();
    ops.object_id = "obj:2".into();
    db.put_federation_conflict(&ops).unwrap();
    assert_eq!(
        db.get_federation_conflict("conflict:sales")
            .unwrap()
            .unwrap()
            .namespace,
        "sales"
    );
    assert_eq!(
        db.list_federation_conflicts(Some("sales")).unwrap().len(),
        1
    );
    assert_eq!(db.list_federation_conflicts(None).unwrap().len(), 2);
}

fn exercise_revocation(db: &RuntimeDb) {
    let peer = FederationRevocation {
        contract_version: REVOCATION_CONTRACT.into(),
        revocation_id: "rev:peer".into(),
        subject_kind: SubjectKind::Peer,
        subject_id: "site:beta".into(),
        peer_site_id: "site:beta".into(),
        reason: "left".into(),
        status: "active".into(),
        write_authority: false,
        permit_authority: false,
        propagation: RevocationPropagation {
            local_applied_at_ms: 5,
            acknowledgement: "unknown".into(),
            last_peer_assertion_at_ms: None,
            last_reconciled_at_ms: None,
        },
        revoked_by: "operator".into(),
        revoked_at_ms: 5,
        updated_at_ms: 5,
    };
    db.put_federation_revocation(&peer).unwrap();
    let mut signer = peer.clone();
    signer.revocation_id = "rev:signer".into();
    signer.subject_kind = SubjectKind::Signer;
    signer.subject_id = "signer:ops".into();
    db.put_federation_revocation(&signer).unwrap();
    assert_eq!(
        db.get_federation_revocation("rev:peer")
            .unwrap()
            .unwrap()
            .subject_id,
        "site:beta"
    );
    assert_eq!(
        db.list_federation_revocations(Some("peer")).unwrap().len(),
        1
    );
    assert_eq!(db.list_federation_revocations(None).unwrap().len(), 2);
}

fn exercise(db: &RuntimeDb) {
    exercise_network(db);
    exercise_profile(db);
    exercise_conflict(db);
    exercise_revocation(db);
}

#[test]
fn sqlite_federation_backend_conformance() {
    exercise(&RuntimeDb::memory());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_federation_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise(&db);
}
