use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

use sekai_chisei::db::object_sync::ObjectSyncBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, OperationOutcome, SOURCE_BATCH_VERSION, SOURCE_GITHUB,
    SourceBatch, SourceBatchStatus, SourceRecord, SyncDecision,
};

const TYPE_DIGEST: &str = GITHUB_OBJECT_SYNC_TYPE_DIGEST;
const PAYLOAD_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn batch(prefix: &str, current_cursor: &str, next_cursor: &str, key: &str) -> SourceBatch {
    let source_instance = format!("{prefix}/ops");
    let mut batch = SourceBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: format!("{prefix}-namespace"),
        producer_identity: format!("connector/{prefix}"),
        source: SOURCE_GITHUB.into(),
        source_instance: source_instance.clone(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        type_digest: TYPE_DIGEST.into(),
        current_cursor: current_cursor.into(),
        proposed_next_cursor: next_cursor.into(),
        idempotency_key: format!("{prefix}-{key}"),
        batch_digest: String::new(),
        collected_at_ms: 20,
        records: vec![SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance,
            external_id: "12".into(),
            source_version: "node-v1".into(),
            type_name: "Issue".into(),
            display_name: "Bounded sync".into(),
            payload_digest: PAYLOAD_DIGEST.into(),
            properties: BTreeMap::from([
                ("state".into(), "open".into()),
                ("title".into(), "Bounded sync".into()),
            ]),
            deleted: false,
            observed_at_ms: 10,
        }],
    };
    redigest(&mut batch);
    batch
}

fn redigest(batch: &mut SourceBatch) {
    batch.batch_digest = batch.canonical_digest().unwrap();
}

fn checkpoint(db: &dyn ObjectSyncBackend, prefix: &str) -> Option<String> {
    db.get_source_sync_state(
        &format!("{prefix}-namespace"),
        &format!("{prefix}/ops"),
        TYPE_DIGEST,
    )
    .unwrap()
    .and_then(|state| state.checkpoint.map(|checkpoint| checkpoint.cursor))
}

fn exercise_object_sync(db: &dyn ObjectSyncBackend, prefix: &str) {
    let producer = format!("connector/{prefix}");
    let first_batch = batch(prefix, "", "cursor:1", "batch-1");
    let first = db.apply_source_batch(&first_batch, &producer, 100).unwrap();
    assert_eq!(first.transaction.status, SourceBatchStatus::Committed);
    assert_eq!(first.transaction.outcome, OperationOutcome::Success);
    assert!(first.checkpoint_advanced);
    let object_id = match &first.records[0].decision {
        SyncDecision::Upsert(object) => object.object_id.clone(),
        other => panic!("expected upsert, got {other:?}"),
    };

    let mut replay = first_batch.clone();
    replay.collected_at_ms += 1_000;
    assert_eq!(
        db.apply_source_batch(&replay, &producer, 200).unwrap(),
        first
    );

    let mut revision_conflict = batch(
        prefix,
        "cursor:1",
        "cursor:blocked",
        "batch-revision-conflict",
    );
    revision_conflict.records[0].payload_digest =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
    redigest(&mut revision_conflict);
    assert!(
        db.apply_source_batch(&revision_conflict, &producer, 300)
            .unwrap_err()
            .starts_with("source_revision_conflict:")
    );
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:1"));

    let same_revision = batch(prefix, "cursor:1", "cursor:2", "batch-same-revision");
    let same_revision_result = db
        .apply_source_batch(&same_revision, &producer, 400)
        .unwrap();
    assert_eq!(
        same_revision_result.records[0].source_version,
        first.records[0].source_version
    );
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:2"));

    let stale = batch(prefix, "cursor:foreign", "cursor:3", "batch-stale");
    assert!(
        db.apply_source_batch(&stale, &producer, 500)
            .unwrap_err()
            .starts_with("stale_cursor:")
    );
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:2"));

    let mut tombstone = batch(prefix, "cursor:2", "cursor:3", "batch-2");
    tombstone.records[0].deleted = true;
    tombstone.records[0].source_version = "node-v2".into();
    redigest(&mut tombstone);
    let tombstone_result = db.apply_source_batch(&tombstone, &producer, 600).unwrap();
    let tombstoned = match &tombstone_result.records[0].decision {
        SyncDecision::Tombstone(object) => object,
        other => panic!("expected tombstone, got {other:?}"),
    };
    assert_eq!(tombstoned.object_id, object_id);
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:3"));

    let mut conflict = batch(prefix, "cursor:3", "cursor:4", "batch-3");
    conflict.records[0].type_name = "PullRequest".into();
    conflict.records[0].source_version = "node-v3".into();
    redigest(&mut conflict);
    assert!(
        db.apply_source_batch(&conflict, &producer, 700)
            .unwrap_err()
            .starts_with("type_identity_conflict:")
    );
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:3"));

    let state = db
        .get_source_sync_state(
            &format!("{prefix}-namespace"),
            &format!("{prefix}/ops"),
            TYPE_DIGEST,
        )
        .unwrap()
        .unwrap();
    assert_eq!(state.binding.producer_identity, producer);
    assert_eq!(state.binding.type_digest, TYPE_DIGEST);
    assert!(state.open_transaction.is_none());
    assert_eq!(state.checkpoint.unwrap().cursor, "cursor:3");
    assert_eq!(
        state.last_result.unwrap().transaction,
        tombstone_result.transaction
    );
}

#[test]
fn sqlite_object_sync_backend_conformance() {
    exercise_object_sync(&SekaiDb::new(":memory:").unwrap(), "sqlite");
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
fn postgres_object_sync_backend_conformance() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise_object_sync(&postgres(), &prefix);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_exact_replay_has_one_committed_result() {
    let db = Arc::new(postgres());
    let prefix = format!("race-{}", uuid::Uuid::new_v4().simple());
    let producer = format!("connector/{prefix}");
    let source_batch = batch(&prefix, "", "cursor:1", "batch-1");
    let barrier = Arc::new(Barrier::new(3));
    let handles = [100, 200].map(|now_ms| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let producer = producer.clone();
        let source_batch = source_batch.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.apply_source_batch(&source_batch, &producer, now_ms)
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap().unwrap());
    assert_eq!(results[0], results[1]);
    assert_eq!(results[0].transaction.status, SourceBatchStatus::Committed);
    assert_eq!(
        checkpoint(db.as_ref(), &prefix).as_deref(),
        Some("cursor:1")
    );
}
