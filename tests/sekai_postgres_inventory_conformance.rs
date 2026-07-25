//! Fail-closed inventory and complete-Sekai capability evidence for #252.

use sekai_chisei::db::decision::DecisionBackend;
use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::reusable::postgres_reusable_capabilities;
use sekai_chisei::db::sekai_rpc_inventory::{
    SEKAI_SERVICE_PROTO, SekaiRpcInventory, parse_sekai_service_rpcs,
    postgres_complete_sekai_capabilities,
};
use sekai_chisei::db::team_namespace::TeamNamespaceBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::audit::{Decision, DecisionFilter};
use sekai_chisei::sekai::security::Role;
use std::collections::HashMap;
use std::path::Path;

#[test]
fn inventory_covers_every_sekai_service_rpc_exactly_once() {
    let inventory = SekaiRpcInventory::load().expect("inventory must load");
    let proto = parse_sekai_service_rpcs(SEKAI_SERVICE_PROTO).unwrap();
    assert_eq!(inventory.entries.len(), proto.len());
    for rpc in &proto {
        let entry = inventory.entry(rpc).expect(rpc);
        assert!(!entry.evidence.is_empty(), "{rpc} missing evidence");
        for path in &entry.evidence {
            assert!(
                Path::new(path).exists(),
                "missing evidence path {path} for {rpc}"
            );
        }
    }
}

#[test]
fn inventory_fails_when_rpc_is_removed_from_classification() {
    let mut inventory = SekaiRpcInventory::load().unwrap();
    let removed = inventory.entries.pop().unwrap().rpc;
    let err = inventory.validate().unwrap_err();
    assert!(
        err.contains("missing") && err.contains(&removed),
        "expected missing {removed}, got {err}"
    );
}

#[test]
fn complete_sekai_capability_requires_all_foundation_surfaces() {
    let complete = postgres_complete_sekai_capabilities().unwrap();
    let foundations = postgres_reusable_capabilities();
    assert!(
        complete
            .validate_required(
                &foundations
                    .reusable_surfaces
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            )
            .is_ok()
    );
    // Complete Sekai is still not a full community runtime (no Chisei/gateway).
    assert!(
        complete
            .validate_required(sekai_chisei::runtime_backend::COMMUNITY_REQUIRED_SURFACES)
            .is_err()
    );
}

#[test]
fn tenant_oidc_oauth_surfaces_and_rpcs_remain_absent() {
    let inventory = SekaiRpcInventory::load().unwrap();
    let complete = postgres_complete_sekai_capabilities().unwrap();
    for surface in complete
        .reusable_surfaces
        .iter()
        .chain(inventory.complete_sekai_surfaces.iter())
    {
        let lower = surface.to_ascii_lowercase();
        assert!(!lower.contains("tenant"), "{surface}");
        assert!(!lower.contains("oidc"), "{surface}");
        assert!(!lower.contains("oauth"), "{surface}");
    }
    let proto = parse_sekai_service_rpcs(SEKAI_SERVICE_PROTO).unwrap();
    for rpc in proto {
        let lower = rpc.to_ascii_lowercase();
        assert!(
            !lower.contains("tenant"),
            "tenant RPC leaked into SekaiService: {rpc}"
        );
        assert!(
            !lower.contains("oidc"),
            "oidc RPC leaked into SekaiService: {rpc}"
        );
        assert!(
            !lower.contains("oauth"),
            "oauth RPC leaked into SekaiService: {rpc}"
        );
    }
    let full_proto = SEKAI_SERVICE_PROTO.to_ascii_lowercase();
    // Messages may mention tenants for enterprise extension types, but the
    // public service must not expose tenant RPCs (validated above).
    assert!(!full_proto.contains("rpc createtenant"));
    assert!(!full_proto.contains("rpc gettenant"));
}

/// Cross-surface fixture: team-namespace bootstrap, grant check, object write,
/// and decision audit share one authorization boundary.
fn exercise_cross_surface(
    db: &(impl TeamNamespaceBackend + GraphBackend + DecisionBackend),
    prefix: &str,
) {
    let namespace = format!("{prefix}-ns");
    let principal = format!("{prefix}-alice");
    let (boundary, grants) = db
        .ensure_team_namespace(&namespace, &principal, Role::Editor, "local")
        .unwrap();
    assert!(grants.iter().any(|grant| grant.principal == principal));
    assert!(db.can_admin(&boundary.id, &["local"]).unwrap());

    let object = Object {
        id: format!("{prefix}-obj"),
        kind: "component".into(),
        name: "cross".into(),
        namespace: namespace.clone(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 10,
        updated: 10,
    };
    GraphBackend::create_object(db, &object, "local").unwrap();
    assert_eq!(
        GraphBackend::get_object(db, &object.id)
            .unwrap()
            .unwrap()
            .namespace,
        namespace
    );
    let changes = db.list_object_changes(&object.id, 10, 0).unwrap();
    assert!(changes.iter().any(|change| change.field == "_created"));

    let decision = Decision {
        id: format!("{prefix}-decision"),
        timestamp: 20,
        actor: "local".into(),
        action: "create_object".into(),
        reason: "cross-surface".into(),
        evidence: HashMap::from([("namespace".into(), namespace.clone())]),
        target_id: object.id.clone(),
        outcome: "succeeded".into(),
    };
    db.record_decision(&decision).unwrap();
    let listed = db
        .list_decisions(&DecisionFilter {
            target_id: Some(object.id.clone()),
            ..DecisionFilter::default()
        })
        .unwrap();
    assert!(listed.iter().any(|item| item.id == decision.id));

    // Corrupt / secret evidence still fails closed on the decision surface.
    assert!(
        db.record_decision(&Decision {
            id: format!("{prefix}-secret"),
            evidence: HashMap::from([("token".into(), "sk-live-example".into())]),
            ..decision.clone()
        })
        .is_err()
    );
}

#[test]
fn sqlite_cross_surface_authorization_audit_and_idempotency() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise_cross_surface(&db, "sqlite");
    // exact retry of team-namespace bootstrap remains idempotent
    let _ = db
        .ensure_team_namespace("sqlite-ns", "sqlite-alice", Role::Editor, "local")
        .unwrap();
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_cross_surface_and_complete_capability_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise_cross_surface(&postgres(), &prefix);
    let restarted = postgres();
    assert!(
        restarted
            .find_namespace_boundary(&format!("{prefix}-ns"))
            .unwrap()
            .is_some()
    );
    let complete = postgres_complete_sekai_capabilities().unwrap();
    assert!(!complete.reusable_surfaces.is_empty());
}
