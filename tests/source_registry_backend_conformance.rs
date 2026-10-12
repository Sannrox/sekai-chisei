//! Source-webhook key pins and registered source-type descriptors behave the
//! same on SQLite and PostgreSQL (#1322): an unpinned delivery is refused, a
//! pinned one commits, and a registered descriptor admits batches only while
//! it is live.

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::object_sync::{
    ADAPTER_REGISTERED_OBJECT_SYNC, ADAPTER_REGISTERED_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_VERSION, SOURCE_GITHUB, SourceBatch,
    SourceBatchStatus, SourceRecord, SyncDecision,
};
use sekai_chisei::sekai::source_type_descriptor::{
    DESCRIPTOR_UNAVAILABLE, STATUS_LIVE, STATUS_RETIRED, inspect_source_type_descriptor,
    register_source_type_descriptor, retire_source_type_descriptor, synthetic_pager_alert_v1,
};
use sekai_chisei::sekai::source_webhook::{
    ADMIT_UNAVAILABLE, SourceWebhookDelivery, WEBHOOK_DELIVERY_CONTRACT, admit_source_webhook,
    list_source_webhook_keys, pin_source_webhook_key, sign_source_webhook,
};

use crate::postgres_scratch::ScratchDatabase;

const ADMIN: &str = "local";
const REPOSITORY: &str = "sekai-project/sekai-chisei";
const PAYLOAD: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn delivery(namespace: &str, id: &str, seed: u8, key_id: &str) -> SourceWebhookDelivery {
    let mut delivery = SourceWebhookDelivery {
        contract_version: WEBHOOK_DELIVERY_CONTRACT.into(),
        delivery_id: id.into(),
        namespace: namespace.into(),
        producer_identity: format!("connector/{namespace}"),
        source: SOURCE_GITHUB.into(),
        source_instance: REPOSITORY.into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        current_cursor: String::new(),
        proposed_next_cursor: format!("push:{id}"),
        signed_at_ms: 5_000,
        not_after_ms: 65_000,
        records: vec![SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: REPOSITORY.into(),
            external_id: "12".into(),
            source_version: "node-v1".into(),
            type_name: "Issue".into(),
            display_name: "Webhook issue".into(),
            payload_digest: PAYLOAD.into(),
            properties: BTreeMap::from([("state".into(), "open".into())]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        }],
        content_digest: String::new(),
        signature: None,
    };
    sign_source_webhook(&mut delivery, &signing_key(seed), key_id).unwrap();
    delivery
}

fn pager_batch(namespace: &str, digest: &str, current: &str, next: &str) -> SourceBatch {
    let mut batch = SourceBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: namespace.into(),
        producer_identity: "connector/pager".into(),
        source: "synthetic.pager".into(),
        source_instance: "ops-local".into(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_REGISTERED_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_REGISTERED_OBJECT_SYNC_VERSION.into(),
        type_digest: digest.into(),
        current_cursor: current.into(),
        proposed_next_cursor: next.into(),
        idempotency_key: format!("batch-{next}"),
        batch_digest: String::new(),
        collected_at_ms: 20,
        records: vec![SourceRecord {
            source: "synthetic.pager".into(),
            source_instance: "ops-local".into(),
            external_id: "42".into(),
            source_version: format!("alert-{next}"),
            type_name: "Alert".into(),
            display_name: "checkout latency".into(),
            payload_digest: PAYLOAD.into(),
            properties: BTreeMap::from([("title".into(), "checkout latency".into())]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        }],
        delivery: None,
    };
    batch.batch_digest = batch.canonical_digest().unwrap();
    batch
}

fn exercise_webhook_pins(db: &RuntimeDb, namespace: &str) {
    let producer = format!("connector/{namespace}");
    let unpinned = admit_source_webhook(db, &producer, &delivery(namespace, "d0", 1, "k1"), 5_100);
    assert_eq!(unpinned.unwrap_err(), ADMIT_UNAVAILABLE);

    let public_key = hex(signing_key(1).verifying_key().as_bytes());
    pin_source_webhook_key(db, ADMIN, namespace, REPOSITORY, "k1", &public_key, 1_000).unwrap();
    // Re-pinning the same key id replaces the pin instead of adding one.
    pin_source_webhook_key(db, ADMIN, namespace, REPOSITORY, "k1", &public_key, 2_000).unwrap();
    let pins = list_source_webhook_keys(db, Some(namespace), Some(REPOSITORY)).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].created_at_ms, 2_000);
    assert!(
        list_source_webhook_keys(db, Some("other-namespace"), None)
            .unwrap()
            .is_empty()
    );

    let admitted =
        admit_source_webhook(db, &producer, &delivery(namespace, "d1", 1, "k1"), 5_100).unwrap();
    assert_eq!(admitted.outcome, "accepted");
    assert!(admitted.batch.checkpoint_advanced);

    let foreign_key =
        admit_source_webhook(db, &producer, &delivery(namespace, "d2", 2, "k2"), 5_100);
    assert_eq!(foreign_key.unwrap_err(), ADMIT_UNAVAILABLE);
}

fn exercise_registered_descriptor(db: &RuntimeDb, namespace: &str) {
    let pager = synthetic_pager_alert_v1();
    let registered = register_source_type_descriptor(db, ADMIN, namespace, &pager, 10).unwrap();
    assert_eq!(registered.status, STATUS_LIVE);
    assert_eq!(
        register_source_type_descriptor(db, ADMIN, namespace, &pager, 11).unwrap(),
        registered,
        "exact re-registration is idempotent"
    );
    assert_eq!(
        inspect_source_type_descriptor(db, ADMIN, namespace, &pager.digest).unwrap(),
        registered
    );

    let first = db
        .apply_source_batch(
            &pager_batch(namespace, &pager.digest, "", "cursor-1"),
            "connector/pager",
            100,
        )
        .unwrap();
    assert_eq!(first.transaction.status, SourceBatchStatus::Committed);
    assert!(first.checkpoint_advanced);
    let SyncDecision::Upsert(object) = &first.records[0].decision else {
        panic!("registered record did not upsert: {first:?}");
    };
    assert_eq!(object.source_id, "synthetic.pager:ops-local#Alert/42");
    assert_eq!(object.type_digest, pager.digest);

    let retired = retire_source_type_descriptor(db, ADMIN, namespace, &pager.digest, 200).unwrap();
    assert_eq!(retired.status, STATUS_RETIRED);
    assert_eq!(
        retire_source_type_descriptor(db, ADMIN, namespace, &pager.digest, 201).unwrap_err(),
        DESCRIPTOR_UNAVAILABLE
    );
    let after_retire = db.apply_source_batch(
        &pager_batch(namespace, &pager.digest, "cursor-1", "cursor-2"),
        "connector/pager",
        300,
    );
    assert!(
        after_retire
            .unwrap_err()
            .starts_with("unbound_type_revision"),
        "a retired descriptor admits no batch"
    );
}

#[test]
fn sqlite_source_registry_backend_conformance() {
    let db = RuntimeDb::memory();
    exercise_webhook_pins(&db, "pins");
    exercise_registered_descriptor(&db, "descriptors");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_source_registry_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise_webhook_pins(&db, "pins");
    exercise_registered_descriptor(&db, "descriptors");
}

/// The descriptor RPCs run on the server's multi-threaded runtime, where the
/// blocking PostgreSQL client must be called off the runtime.
#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_descriptor_rpcs_run_on_the_server_runtime() {
    use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
    use sekai_chisei::grpc::pb::sekai::{
        InspectSourceTypeDescriptorRequest, RegisterSourceTypeDescriptorRequest,
    };
    use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
    use sekai_chisei::sekai::security::Role;
    use tonic::metadata::MetadataValue;

    let scratch = ScratchDatabase::create();
    let db = Arc::new(RuntimeDb::Postgres(Arc::new(scratch.connect(8))));
    db.ensure_team_namespace("ops", "alice", Role::Admin, ADMIN)
        .unwrap();
    let service =
        SekaiServiceImpl::new(sekai_chisei::db::store::SekaiStore::from_shared_runtime(db));
    fn request<T>(payload: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(payload);
        request
            .metadata_mut()
            .insert("x-principal", MetadataValue::from_static("alice"));
        request
    }
    let pager = synthetic_pager_alert_v1();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let registered = service
            .register_source_type_descriptor(request(RegisterSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                source: pager.source.clone(),
                record_kind: pager.record_kind.clone(),
                schema_revision: pager.schema_revision.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .descriptor
            .unwrap();
        assert_eq!(registered.digest, pager.digest);
        let inspected = service
            .inspect_source_type_descriptor(request(InspectSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                digest: pager.digest.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .descriptor
            .unwrap();
        assert_eq!(inspected.status, STATUS_LIVE);
    });
}
