//! ApplySourceBatch for live registered source-type descriptors (#819).

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::pb::sekai::GetSourceSyncStateRequest;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::object_sync::{
    ADAPTER_REGISTERED_OBJECT_SYNC, ADAPTER_REGISTERED_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_V2_VERSION, SOURCE_BATCH_VERSION, SOURCE_GITHUB,
    SourceBatch, SourceBatchStatus, SourceDeliveryMode, SourceDeliveryWindow, SourceRecord,
    SyncDecision,
};
use sekai_chisei::sekai::security::Role;
use sekai_chisei::sekai::source_type_descriptor::{
    register_source_type_descriptor, retire_source_type_descriptor, synthetic_pager_alert_v1,
    synthetic_pager_alert_v2,
};
use sekai_chisei::source_adapter_catalog::built_in_source_adapters;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use tonic::metadata::MetadataValue;
use tonic::{Code, Request};

const PRODUCER: &str = "connector/pager";
const PAYLOAD_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PAYLOAD_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn alert(key: &str, version: &str, payload: &str, deleted: bool) -> SourceRecord {
    SourceRecord {
        source: "synthetic.pager".into(),
        source_instance: "ops-local".into(),
        external_id: key.into(),
        source_version: version.into(),
        type_name: "Alert".into(),
        display_name: "checkout latency".into(),
        payload_digest: payload.into(),
        properties: BTreeMap::from([("title".into(), "checkout latency".into())]),
        deleted,
        observed_at_ms: 10,
        source_sequence: None,
    }
}

fn pager_batch(
    descriptor_digest: &str,
    current: &str,
    next: &str,
    key: &str,
    record: SourceRecord,
) -> SourceBatch {
    let mut batch = SourceBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: "ops".into(),
        producer_identity: PRODUCER.into(),
        source: "synthetic.pager".into(),
        source_instance: "ops-local".into(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_REGISTERED_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_REGISTERED_OBJECT_SYNC_VERSION.into(),
        type_digest: descriptor_digest.into(),
        current_cursor: current.into(),
        proposed_next_cursor: next.into(),
        idempotency_key: key.into(),
        batch_digest: String::new(),
        collected_at_ms: 20,
        records: vec![record],
        delivery: None,
    };
    batch.batch_digest = batch.canonical_digest().unwrap();
    batch
}

fn upsert_id(decision: &SyncDecision) -> String {
    match decision {
        SyncDecision::Upsert(object) | SyncDecision::Tombstone(object) => object.object_id.clone(),
        other => panic!("expected upsert or tombstone, got {other:?}"),
    }
}

#[test]
fn registered_alert_refreshes_tombstones_and_restores_the_same_object() {
    let db = RuntimeDb::memory();
    let pager = synthetic_pager_alert_v1();
    register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();

    let first = pager_batch(
        &pager.digest,
        "",
        "cursor:1",
        "batch-1",
        alert("42", "alert-v1", PAYLOAD_A, false),
    );
    let admitted = db.apply_source_batch(&first, PRODUCER, 100).unwrap();
    assert_eq!(admitted.transaction.status, SourceBatchStatus::Committed);
    let object_id = upsert_id(&admitted.records[0].decision);
    match &admitted.records[0].decision {
        SyncDecision::Upsert(object) => {
            assert_eq!(object.source_id, "synthetic.pager:ops-local#Alert/42");
            assert_ne!(object.source_id, format!("{SOURCE_GITHUB}:ops-local#42"));
        }
        other => panic!("expected upsert, got {other:?}"),
    }

    let mut refresh = pager_batch(
        &pager.digest,
        "cursor:1",
        "cursor:2",
        "batch-2",
        alert("42", "alert-v2", PAYLOAD_B, false),
    );
    refresh.records[0].display_name = "checkout latency mitigated".into();
    refresh.batch_digest = refresh.canonical_digest().unwrap();
    let refreshed = db.apply_source_batch(&refresh, PRODUCER, 200).unwrap();
    assert_eq!(upsert_id(&refreshed.records[0].decision), object_id);

    let tombstone = pager_batch(
        &pager.digest,
        "cursor:2",
        "cursor:3",
        "batch-3",
        alert("42", "alert-v3", PAYLOAD_B, true),
    );
    let deleted = db.apply_source_batch(&tombstone, PRODUCER, 300).unwrap();
    match &deleted.records[0].decision {
        SyncDecision::Tombstone(object) => {
            assert_eq!(object.object_id, object_id);
            assert!(object.tombstoned);
        }
        other => panic!("expected tombstone, got {other:?}"),
    }

    let restore = pager_batch(
        &pager.digest,
        "cursor:3",
        "cursor:4",
        "batch-4",
        alert("42", "alert-v4", PAYLOAD_A, false),
    );
    let restored = db.apply_source_batch(&restore, PRODUCER, 400).unwrap();
    match &restored.records[0].decision {
        SyncDecision::Upsert(object) => {
            assert_eq!(object.object_id, object_id);
            assert!(!object.tombstoned);
        }
        other => panic!("expected upsert, got {other:?}"),
    }

    let github_id = format!(
        "sync-{:x}",
        Sha256::digest(format!("{GITHUB_OBJECT_SYNC_TYPE_DIGEST}\ngithub:acme/ops#42").as_bytes())
    );
    assert_ne!(object_id, github_id);
    assert_eq!(built_in_source_adapters().len(), 1);
    assert_eq!(built_in_source_adapters()[0].source, SOURCE_GITHUB);
}

#[test]
fn unadmitted_retired_and_duplicate_identities_leave_state_unchanged() {
    let db = RuntimeDb::memory();
    let pager = synthetic_pager_alert_v1();
    let unregistered = pager_batch(
        &pager.digest,
        "",
        "cursor:1",
        "batch-1",
        alert("42", "alert-v1", PAYLOAD_A, false),
    );
    let err = db
        .apply_source_batch(&unregistered, PRODUCER, 100)
        .unwrap_err();
    assert!(err.starts_with("unbound_type_revision:"), "{err}");
    assert!(
        db.get_source_sync_state("ops", "ops-local", &pager.digest)
            .unwrap()
            .is_none()
    );

    register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
    db.apply_source_batch(
        &pager_batch(
            &pager.digest,
            "",
            "cursor:1",
            "live-1",
            alert("7", "alert-v1", PAYLOAD_A, false),
        ),
        PRODUCER,
        200,
    )
    .unwrap();
    retire_source_type_descriptor(&db, "local", "ops", &pager.digest, 20).unwrap();
    let retired = db
        .apply_source_batch(
            &pager_batch(
                &pager.digest,
                "cursor:1",
                "cursor:2",
                "live-2",
                alert("7", "alert-v2", PAYLOAD_B, false),
            ),
            PRODUCER,
            300,
        )
        .unwrap_err();
    assert!(retired.starts_with("unbound_type_revision:"), "{retired}");
    assert_eq!(
        db.get_source_sync_state("ops", "ops-local", &pager.digest)
            .unwrap()
            .unwrap()
            .checkpoint
            .unwrap()
            .cursor,
        "cursor:1"
    );

    let pager = synthetic_pager_alert_v1();
    let db = RuntimeDb::memory();
    register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
    let mut duplicate = pager_batch(
        &pager.digest,
        "",
        "cursor:1",
        "dup",
        alert("42", "alert-v1", PAYLOAD_A, false),
    );
    duplicate
        .records
        .push(alert("42", "alert-v1b", PAYLOAD_B, false));
    duplicate.batch_digest = duplicate.canonical_digest().unwrap();
    let dup_err = db
        .apply_source_batch(&duplicate, PRODUCER, 100)
        .unwrap_err();
    assert!(
        dup_err.starts_with("ambiguous_record_identity:"),
        "{dup_err}"
    );
    assert!(
        db.get_source_sync_state("ops", "ops-local", &pager.digest)
            .unwrap()
            .is_none()
    );
}

#[test]
fn schema_revision_and_payload_drift_do_not_mutate_the_live_object() {
    let db = RuntimeDb::memory();
    let v1 = synthetic_pager_alert_v1();
    let v2 = synthetic_pager_alert_v2();
    register_source_type_descriptor(&db, "local", "ops", &v1, 10).unwrap();
    register_source_type_descriptor(&db, "local", "ops", &v2, 11).unwrap();
    let first = pager_batch(
        &v1.digest,
        "",
        "cursor:1",
        "v1",
        alert("9", "rev-1", PAYLOAD_A, false),
    );
    let admitted = db.apply_source_batch(&first, PRODUCER, 100).unwrap();
    let object_id = upsert_id(&admitted.records[0].decision);

    let drift = pager_batch(
        &v1.digest,
        "cursor:1",
        "cursor:2",
        "drift",
        alert("9", "rev-1", PAYLOAD_B, false),
    );
    let quarantined = db.apply_source_batch(&drift, PRODUCER, 200).unwrap();
    assert_eq!(
        quarantined.transaction.status,
        SourceBatchStatus::Quarantined
    );
    assert_eq!(
        db.get_source_sync_state("ops", "ops-local", &v1.digest)
            .unwrap()
            .unwrap()
            .checkpoint
            .unwrap()
            .cursor,
        "cursor:1"
    );

    let next_revision = pager_batch(
        &v2.digest,
        "cursor:1",
        "cursor:v2",
        "v2",
        alert("9", "rev-2", PAYLOAD_A, false),
    );
    let conflict = db
        .apply_source_batch(&next_revision, PRODUCER, 300)
        .unwrap();
    assert_eq!(conflict.transaction.status, SourceBatchStatus::Quarantined);
    assert!(
        conflict
            .transaction
            .reason
            .contains("binding_type_conflict")
            || conflict
                .transaction
                .reason
                .contains("type_identity_conflict"),
        "{}",
        conflict.transaction.reason
    );
    let live = db.get_object(&object_id).unwrap().unwrap();
    assert_eq!(live.id, object_id);
}

#[test]
fn github_discovery_and_github_batches_remain_unchanged() {
    assert_eq!(
        built_in_source_adapters()[0].type_digest,
        GITHUB_OBJECT_SYNC_TYPE_DIGEST
    );
    let mut github = SourceBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: "ops".into(),
        producer_identity: PRODUCER.into(),
        source: SOURCE_GITHUB.into(),
        source_instance: "acme/ops".into(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: "adapter.github.object_sync".into(),
        adapter_version: "1.0.0".into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        current_cursor: String::new(),
        proposed_next_cursor: "cursor:1".into(),
        idempotency_key: "gh-1".into(),
        batch_digest: String::new(),
        collected_at_ms: 20,
        records: vec![SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            external_id: "12".into(),
            source_version: "issue-v1".into(),
            type_name: "Issue".into(),
            display_name: "Bounded sync".into(),
            payload_digest: PAYLOAD_A.into(),
            properties: BTreeMap::from([("state".into(), "open".into())]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        }],
        delivery: None,
    };
    github.batch_digest = github.canonical_digest().unwrap();
    let db = RuntimeDb::memory();
    let result = db.apply_source_batch(&github, PRODUCER, 100).unwrap();
    match &result.records[0].decision {
        SyncDecision::Upsert(object) => {
            assert_eq!(object.source_id, "github:acme/ops#12");
        }
        other => panic!("expected github upsert, got {other:?}"),
    }
}

#[test]
fn generation_mismatch_and_partial_admission_leave_registered_state_unchanged() {
    let db = RuntimeDb::memory();
    let pager = synthetic_pager_alert_v1();
    register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
    db.apply_source_batch(
        &pager_batch(
            &pager.digest,
            "",
            "cursor:1",
            "live-1",
            alert("7", "alert-v1", PAYLOAD_A, false),
        ),
        PRODUCER,
        100,
    )
    .unwrap();

    let mut generation = pager_batch(
        &pager.digest,
        "cursor:1",
        "cursor:2",
        "gen-2",
        alert("7", "alert-v2", PAYLOAD_B, false),
    );
    generation.contract_version = SOURCE_BATCH_V2_VERSION.into();
    generation.delivery = Some(SourceDeliveryWindow {
        mode: SourceDeliveryMode::Snapshot,
        sync_generation: 2,
        source_feed_epoch: Some("pager-epoch".into()),
        offset_start: None,
        offset_end: Some(1),
        snapshot_complete: true,
    });
    generation.batch_digest = generation.canonical_digest().unwrap();
    let generation_err = db
        .apply_source_batch(&generation, PRODUCER, 200)
        .unwrap_err();
    assert!(
        generation_err.starts_with("legacy_batch_after_v2:")
            || generation_err.starts_with("generation_conflict:")
            || generation_err.starts_with("phase_conflict:"),
        "{generation_err}"
    );
    assert_eq!(
        db.get_source_sync_state("ops", "ops-local", &pager.digest)
            .unwrap()
            .unwrap()
            .checkpoint
            .unwrap()
            .cursor,
        "cursor:1"
    );

    let db = RuntimeDb::memory();
    register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
    let mut partial = pager_batch(
        &pager.digest,
        "",
        "cursor:1",
        "partial",
        alert("42", "alert-v1", PAYLOAD_A, false),
    );
    let mut second = alert("43", "alert-v1", PAYLOAD_A, false);
    second.type_name = "Issue".into();
    partial.records.push(second);
    partial.batch_digest = partial.canonical_digest().unwrap();
    let partial_err = db.apply_source_batch(&partial, PRODUCER, 100).unwrap_err();
    assert!(
        partial_err.starts_with("unsupported_record_type:")
            || partial_err.starts_with("mixed_record_type:"),
        "{partial_err}"
    );
    assert!(
        db.get_source_sync_state("ops", "ops-local", &pager.digest)
            .unwrap()
            .is_none()
    );
    let objects: i64 = db
        .conn()
        .query_row("SELECT COUNT(*) FROM sekai_objects", [], |row| row.get(0))
        .unwrap();
    assert_eq!(objects, 0);
}

#[tokio::test]
async fn get_source_sync_state_authorizes_before_catalog_lookup() {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    db.ensure_team_namespace("ops", "alice", Role::Admin, "local")
        .unwrap();
    let pager = synthetic_pager_alert_v1();
    register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
    let svc = SekaiServiceImpl::new(db);
    let mut live = Request::new(GetSourceSyncStateRequest {
        namespace: "ops".into(),
        source_instance: "ops-local".into(),
        type_digest: pager.digest.clone(),
    });
    live.metadata_mut()
        .insert("x-principal", MetadataValue::try_from("mallory").unwrap());
    let live_err = svc.get_source_sync_state(live).await.unwrap_err();
    assert_eq!(live_err.code(), Code::PermissionDenied);

    let mut unknown = Request::new(GetSourceSyncStateRequest {
        namespace: "ops".into(),
        source_instance: "ops-local".into(),
        type_digest: format!("sha256:{}", "c".repeat(64)),
    });
    unknown
        .metadata_mut()
        .insert("x-principal", MetadataValue::try_from("mallory").unwrap());
    let unknown_err = svc.get_source_sync_state(unknown).await.unwrap_err();
    assert_eq!(unknown_err.code(), Code::PermissionDenied);
    assert_eq!(unknown_err.message(), live_err.message());
}
