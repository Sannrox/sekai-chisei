//! Inventory fail-closed checks for Chisei PostgreSQL parity.

use sekai_chisei::db::chisei_rpc_inventory::{
    ChiseiRpcInventory, postgres_partial_chisei_capabilities,
};
use sekai_chisei::runtime_backend::COMMUNITY_REQUIRED_SURFACES;

#[test]
fn chisei_inventory_covers_every_proto_rpc() {
    let inventory = ChiseiRpcInventory::load().expect("inventory must validate");
    assert_eq!(inventory.entries.len(), 66);
    assert!(inventory.entry("GetOperationReceipt").is_some());
    assert!(inventory.entry("ReserveGatewayRequestAlias").is_some());
    assert!(inventory.entry("Chat").is_some());
    assert!(
        inventory
            .complete_chisei_surfaces
            .contains(&"chisei.execution".into())
    );
    assert!(
        inventory
            .remaining_surfaces
            .iter()
            .any(|surface| surface == "chisei.learning")
    );
    for path in inventory.all_evidence_paths() {
        assert!(
            std::path::Path::new(path).exists(),
            "missing evidence path {path}"
        );
    }
}

#[test]
fn partial_chisei_capabilities_are_not_community_complete() {
    let partial = postgres_partial_chisei_capabilities().unwrap();
    assert!(
        partial
            .validate_required(COMMUNITY_REQUIRED_SURFACES)
            .is_err()
    );
    for surface in ["chisei.budget", "chisei.execution"] {
        assert!(
            partial.reusable_surfaces.iter().any(|item| item == surface),
            "missing proven surface {surface}"
        );
    }
    // Fail closed: community still needs policy, gateway, operations, and Sekai.
    for required in COMMUNITY_REQUIRED_SURFACES {
        if matches!(*required, "chisei.budget" | "chisei.execution") {
            continue;
        }
        assert!(
            !partial
                .reusable_surfaces
                .iter()
                .any(|item| item == required),
            "partial must not advertise unproven community surface {required}"
        );
    }
}
