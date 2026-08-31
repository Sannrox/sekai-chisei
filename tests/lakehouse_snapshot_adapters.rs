#[path = "../adapters/lakehouse_events.rs"]
mod lakehouse_events;
#[path = "../adapters/lakehouse_metrics.rs"]
mod lakehouse_metrics;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::lakehouse_snapshot::{
    LAKEHOUSE_UNAVAILABLE, OUTCOME_EXPORTED, OUTCOME_REPLAYED, PROFILE_EVENTS, PROFILE_METRICS,
    STATUS_REVOKED, delete_partitions, redact_columns, register_snapshot, reimport_snapshot,
    revoke_snapshot, upgrade_schema,
};

fn adapter_lifecycle(adapter_id: &str) {
    let db = RuntimeDb::memory();
    let snapshot = if adapter_id == PROFILE_EVENTS {
        lakehouse_events::translate_snapshot(
            &lakehouse_events::parse(include_bytes!("../adapters/fixtures/lakehouse_events.json"))
                .unwrap(),
        )
        .unwrap()
    } else {
        lakehouse_metrics::translate_snapshot(
            &lakehouse_metrics::parse(include_bytes!(
                "../adapters/fixtures/lakehouse_metrics.json"
            ))
            .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(snapshot.adapter_id, adapter_id);
    let registered = register_snapshot(&db, "integrator", &snapshot, 1_000).unwrap();
    assert_eq!(registered.outcome, OUTCOME_EXPORTED);
    assert_eq!(registered.snapshot.partitions.len(), 2);
    assert_eq!(
        reimport_snapshot(&db, "integrator", &registered.snapshot, 1_100)
            .unwrap()
            .outcome,
        OUTCOME_REPLAYED
    );
    let mut upgraded = registered.snapshot.clone();
    upgraded.schema_version = 2;
    upgraded
        .columns
        .push(sekai_chisei::sekai::lakehouse_snapshot::LakehouseColumn {
            name: "note".into(),
            col_type: "string".into(),
            classification: "internal".into(),
        });
    for partition in &mut upgraded.partitions {
        for row in &mut partition.rows {
            row.values.insert("note".into(), "ok".into());
        }
        partition.partition_digest.clear();
    }
    upgraded.snapshot_digest.clear();
    let upgraded = upgrade_schema(&db, "integrator", &upgraded, 2_000).unwrap();
    assert_eq!(upgraded.outcome, OUTCOME_EXPORTED);
    let redacted = redact_columns(
        &db,
        "integrator",
        "ops",
        &snapshot.snapshot_id,
        &["note".into()],
        3_000,
    )
    .unwrap();
    assert!(redacted.redacted_columns.contains(&"note".into()));
    let deleted = delete_partitions(
        &db,
        "integrator",
        "ops",
        &snapshot.snapshot_id,
        &["2026-08-30".into()],
        4_000,
    )
    .unwrap();
    assert_eq!(deleted.partitions.len(), 1);
    assert_eq!(
        reimport_snapshot(&db, "intruder", &deleted, 4_100).unwrap_err(),
        LAKEHOUSE_UNAVAILABLE
    );
    let revoked = revoke_snapshot(&db, "integrator", "ops", &snapshot.snapshot_id, 5_000).unwrap();
    assert_eq!(revoked.status, STATUS_REVOKED);
    assert_eq!(
        reimport_snapshot(&db, "integrator", &deleted, 5_100).unwrap_err(),
        LAKEHOUSE_UNAVAILABLE
    );
}

#[test]
fn two_adapter_fixtures_pass_partitions_upgrade_redaction_deletion_reimport_and_provenance() {
    adapter_lifecycle(PROFILE_EVENTS);
    adapter_lifecycle(PROFILE_METRICS);
}

#[test]
fn hidden_fields_fail_closed() {
    let mut events: serde_json::Value =
        serde_json::from_slice(include_bytes!("../adapters/fixtures/lakehouse_events.json"))
            .unwrap();
    events
        .as_object_mut()
        .unwrap()
        .insert("token".into(), serde_json::json!("ghp_nope"));
    assert!(lakehouse_events::parse(&serde_json::to_vec(&events).unwrap()).is_err());
    assert_eq!(lakehouse_events::ADAPTER_ID, PROFILE_EVENTS);
    assert_eq!(lakehouse_metrics::ADAPTER_ID, PROFILE_METRICS);
}
