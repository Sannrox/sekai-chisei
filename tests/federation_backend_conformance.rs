//! Shared SQLite/PostgreSQL conformance for federation network, site/peer,
//! conflict, revocation, snapshot, grant, and peer-import stores (#1475, #1476).

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
use sekai_chisei::sekai::namespace_snapshot::{
    NAMESPACE_SNAPSHOT_CONTRACT, PeerNamespaceGrant, SnapshotExportRecord, SnapshotFact,
    SnapshotImportRecord,
};
use sekai_chisei::sekai::peer_import::{PEER_IMPORT_CONTRACT, PeerImportRecord, PeerTrustRoot};

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

fn exercise_grant(db: &RuntimeDb) {
    let sales = PeerNamespaceGrant {
        grant_id: "grant:sales".into(),
        peer_site_id: "site:beta".into(),
        namespace: "sales".into(),
        object_kinds: vec!["task".into()],
        max_classification: None,
        not_before_ms: 1,
        not_after_ms: None,
        revoked: false,
        revoked_at_ms: None,
        granted_by: "operator".into(),
        granted_at_ms: 10,
    };
    db.put_federation_namespace_grant(&sales).unwrap();
    let mut ops = sales.clone();
    ops.grant_id = "grant:ops".into();
    ops.namespace = "ops".into();
    ops.granted_at_ms = 11;
    db.put_federation_namespace_grant(&ops).unwrap();
    assert_eq!(
        db.get_federation_namespace_grant("grant:sales")
            .unwrap()
            .unwrap()
            .namespace,
        "sales"
    );
    assert_eq!(
        db.list_federation_namespace_grants(Some("sales"), None)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.list_federation_namespace_grants(None, Some("site:beta"))
            .unwrap()
            .len(),
        2
    );
}

fn exercise_snapshot(db: &RuntimeDb) {
    assert_eq!(db.reserve_federation_snapshot_sequence("sales").unwrap(), 1);
    assert_eq!(db.reserve_federation_snapshot_sequence("sales").unwrap(), 2);
    assert_eq!(db.reserve_federation_snapshot_sequence("ops").unwrap(), 1);

    let export = SnapshotExportRecord {
        snapshot_id: "snap:sales:1".into(),
        snapshot_digest: digest(9),
        namespace: "sales".into(),
        sequence: 1,
        fact_count: 1,
        hidden_omitted: false,
        exported_by: "operator".into(),
        exported_at_ms: 20,
    };
    db.put_federation_snapshot_export(&export).unwrap();
    let mut again = export.clone();
    again.fact_count = 2;
    db.put_federation_snapshot_export(&again).unwrap();

    let fact = SnapshotFact {
        object_id: "obj:sales:1".into(),
        kind: "task".into(),
        name: "one".into(),
        namespace: "sales".into(),
        external_id: "ext:1".into(),
        properties: Default::default(),
        created: 1,
        updated: 1,
        source_site_id: "site:beta".into(),
        write_authority: true,
        provenance: Vec::new(),
    };
    let import = SnapshotImportRecord {
        contract_version: NAMESPACE_SNAPSHOT_CONTRACT.into(),
        import_id: "import:sales:1".into(),
        namespace: "sales".into(),
        peer_site_id: "site:beta".into(),
        peer_key_id: "key:beta".into(),
        peer_public_key_hex: "aa".repeat(32),
        residency_data_classes: vec!["eu".into()],
        not_before_ms: 0,
        not_after_ms: None,
        snapshot_id: "snap:sales:1".into(),
        snapshot_digest: digest(9),
        sequence: 1,
        fact_count: 1,
        conflict_count: 1,
        conflict_object_ids: vec!["obj:sales:1".into()],
        write_authority: true,
        permit_authority: false,
        status: "admitted".into(),
        imported_by: "operator".into(),
        imported_at_ms: 30,
    };
    let conflict = FederationConflict {
        contract_version: CONFLICT_CONTRACT.into(),
        conflict_id: "conflict:snap".into(),
        namespace: "sales".into(),
        object_id: "obj:sales:1".into(),
        claims: Vec::new(),
        status: "open".into(),
        resolution: None,
        resolution_history: Vec::new(),
        write_authority: true,
        permit_authority: false,
        admitted_by: "operator".into(),
        admitted_at_ms: 30,
        updated_at_ms: 30,
    };
    let facts = [fact];
    let conflicts = [conflict];
    db.put_federation_snapshot_import(&import, &facts, &conflicts)
        .unwrap();
    let later = SnapshotImportRecord {
        import_id: "import:sales:2".into(),
        snapshot_digest: digest(10),
        sequence: 2,
        imported_at_ms: 40,
        fact_count: 0,
        conflict_count: 0,
        conflict_object_ids: Vec::new(),
        ..import.clone()
    };
    db.put_federation_snapshot_import(&later, &[], &[]).unwrap();
    assert_eq!(
        db.get_federation_snapshot_import("import:sales:1")
            .unwrap()
            .unwrap()
            .fact_count,
        1
    );
    assert_eq!(
        db.latest_federation_snapshot_import("site:beta", "sales")
            .unwrap()
            .unwrap()
            .import_id,
        "import:sales:2"
    );
    assert_eq!(
        db.list_federation_snapshot_imports(Some("sales"))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        db.list_federation_snapshot_facts("import:sales:1")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.get_federation_conflict("conflict:snap")
            .unwrap()
            .unwrap()
            .object_id,
        "obj:sales:1"
    );
}

fn exercise_peer_import(db: &RuntimeDb) {
    let root = PeerTrustRoot {
        namespace: "sales".into(),
        site_identity: "site:beta".into(),
        key_id: "key:beta".into(),
        public_key_hex: "aa".repeat(32),
        enabled: true,
        created_by: "operator".into(),
        created_at_ms: 5,
    };
    db.put_peer_trust_root(&root).unwrap();
    let mut other = root.clone();
    other.site_identity = "site:gamma".into();
    other.key_id = "key:gamma".into();
    db.put_peer_trust_root(&other).unwrap();
    let listed = db.list_peer_trust_roots("sales").unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|item| item.site_identity.as_str())
            .collect::<Vec<_>>(),
        ["site:beta", "site:gamma"]
    );

    let record = PeerImportRecord {
        contract_version: PEER_IMPORT_CONTRACT.into(),
        import_id: "peer-import:1".into(),
        namespace: "sales".into(),
        peer_site_identity: "site:beta".into(),
        peer_key_id: "key:beta".into(),
        bundle_content_digest: digest(3),
        verified: true,
        receipt_count: 1,
        decision_count: 0,
        permit_authority: false,
        verification_errors: Vec::new(),
        imported_by: "operator".into(),
        imported_at_ms: 50,
    };
    db.put_peer_import(&record).unwrap();
    assert_eq!(
        db.get_peer_import("peer-import:1")
            .unwrap()
            .unwrap()
            .namespace,
        "sales"
    );
}

fn exercise(db: &RuntimeDb) {
    exercise_network(db);
    exercise_profile(db);
    exercise_conflict(db);
    exercise_revocation(db);
    exercise_grant(db);
    exercise_snapshot(db);
    exercise_peer_import(db);
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
