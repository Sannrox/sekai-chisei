#[path = "../adapters/warehouse_inventory.rs"]
mod warehouse_inventory;
#[path = "../adapters/warehouse_orders.rs"]
mod warehouse_orders;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::warehouse_projection::{
    MODE_INCREMENTAL, MODE_SNAPSHOT, OUTCOME_EXPORTED, OUTCOME_REPLAYED, PROFILE_INVENTORY,
    PROFILE_ORDERS, STATUS_REVOKED, WAREHOUSE_UNAVAILABLE, WarehousePage, WarehouseRow,
    export_page, page_digest_for, register_projection, revoke_projection,
};

fn snapshot_page(projection_id: &str, rows: Vec<WarehouseRow>) -> WarehousePage {
    let mut page = WarehousePage {
        projection_id: projection_id.into(),
        namespace: "ops".into(),
        mode: MODE_SNAPSHOT.into(),
        generation: 0,
        offset_start: 0,
        offset_end: rows.len() as u64,
        rows,
        page_digest: String::new(),
        lineage_digest: String::new(),
    };
    page.page_digest = page_digest_for(&page).unwrap();
    page
}

fn adapter_lifecycle(adapter_id: &str, projection_id: &str, rows: Vec<WarehouseRow>) {
    let db = RuntimeDb::memory();
    let projection = if adapter_id == PROFILE_ORDERS {
        let document =
            warehouse_orders::parse(include_bytes!("../adapters/fixtures/warehouse_orders.json"))
                .unwrap();
        warehouse_orders::translate_projection(&document).unwrap()
    } else {
        let document = warehouse_inventory::parse(include_bytes!(
            "../adapters/fixtures/warehouse_inventory.json"
        ))
        .unwrap();
        warehouse_inventory::translate_projection(&document).unwrap()
    };
    assert_eq!(projection.adapter_id, adapter_id);
    register_projection(&db, "integrator", &projection, 1_000).unwrap();
    let snapshot = export_page(
        &db,
        "integrator",
        &snapshot_page(projection_id, rows.clone()),
        2_000,
    )
    .unwrap();
    assert_eq!(snapshot.outcome, OUTCOME_EXPORTED);
    assert_eq!(
        export_page(&db, "integrator", &snapshot.page, 2_100)
            .unwrap()
            .outcome,
        OUTCOME_REPLAYED
    );
    let mut deleted = rows[0].clone();
    deleted.values.clear();
    deleted.deleted = true;
    let mut incremental = snapshot_page(projection_id, vec![deleted]);
    incremental.mode = MODE_INCREMENTAL.into();
    incremental.offset_start = 1;
    incremental.offset_end = 2;
    incremental.page_digest.clear();
    incremental.page_digest = page_digest_for(&incremental).unwrap();
    let exported = export_page(&db, "integrator", &incremental, 3_000).unwrap();
    assert_eq!(exported.outcome, OUTCOME_EXPORTED);
    assert_eq!(
        export_page(&db, "intruder", &exported.page, 3_100).unwrap_err(),
        WAREHOUSE_UNAVAILABLE
    );
    let revoked = revoke_projection(&db, "integrator", "ops", projection_id, 4_000).unwrap();
    assert_eq!(revoked.status, STATUS_REVOKED);
    assert_eq!(
        export_page(&db, "integrator", &exported.page, 4_100).unwrap_err(),
        WAREHOUSE_UNAVAILABLE
    );
}

#[test]
fn two_adapter_fixtures_pass_snapshot_incremental_replay_revocation_and_scope() {
    let orders = warehouse_orders::translate_rows(
        &warehouse_orders::parse(include_bytes!("../adapters/fixtures/warehouse_orders.json"))
            .unwrap(),
    )
    .unwrap();
    adapter_lifecycle(PROFILE_ORDERS, "wh:orders", orders);
    let inventory = warehouse_inventory::translate_rows(
        &warehouse_inventory::parse(include_bytes!(
            "../adapters/fixtures/warehouse_inventory.json"
        ))
        .unwrap(),
    )
    .unwrap();
    adapter_lifecycle(PROFILE_INVENTORY, "wh:inventory", inventory);
}

#[test]
fn hidden_fields_fail_closed() {
    let mut orders: serde_json::Value =
        serde_json::from_slice(include_bytes!("../adapters/fixtures/warehouse_orders.json"))
            .unwrap();
    orders
        .as_object_mut()
        .unwrap()
        .insert("token".into(), serde_json::json!("ghp_nope"));
    assert!(warehouse_orders::parse(&serde_json::to_vec(&orders).unwrap()).is_err());
    assert_eq!(warehouse_orders::ADAPTER_ID, PROFILE_ORDERS);
    assert_eq!(warehouse_inventory::ADAPTER_ID, PROFILE_INVENTORY);
}
