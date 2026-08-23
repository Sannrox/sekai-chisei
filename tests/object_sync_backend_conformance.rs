use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

use sekai_chisei::db::object_sync::ObjectSyncBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, OperationOutcome, SOURCE_BATCH_VERSION, SOURCE_GITHUB,
    SourceBatch, SourceBatchStatus, SourceRecord, SourceSyncState, SyncDecision,
};

const TYPE_DIGEST: &str = GITHUB_OBJECT_SYNC_TYPE_DIGEST;
const SOURCE_INSTANCE: &str = "sekai-project/sekai-chisei";
const PAYLOAD_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const REFRESHED_PAYLOAD_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn batch(prefix: &str, current_cursor: &str, next_cursor: &str, key: &str) -> SourceBatch {
    let source_instance = SOURCE_INSTANCE.to_string();
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
    source_sync_state(db, prefix)
        .and_then(|state| state.checkpoint.map(|checkpoint| checkpoint.cursor))
}

fn source_sync_state(db: &dyn ObjectSyncBackend, prefix: &str) -> Option<SourceSyncState> {
    db.get_source_sync_state(&format!("{prefix}-namespace"), SOURCE_INSTANCE, TYPE_DIGEST)
        .unwrap()
}

fn exercise_object_sync(db: &dyn ObjectSyncBackend, prefix: &str) {
    let producer = format!("connector/{prefix}");
    let page_one_batch = batch(prefix, "", "cursor:1", "snapshot-page-1");
    let page_one = db
        .apply_source_batch(&page_one_batch, &producer, 100)
        .unwrap();
    assert_eq!(page_one.transaction.status, SourceBatchStatus::Committed);
    assert_eq!(page_one.transaction.outcome, OperationOutcome::Success);
    assert!(page_one.checkpoint_advanced);
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:1"));
    let object_id = match &page_one.records[0].decision {
        SyncDecision::Upsert(object) => object.object_id.clone(),
        other => panic!("expected upsert, got {other:?}"),
    };

    let mut revision_conflict = batch(
        prefix,
        "cursor:1",
        "cursor:blocked",
        "batch-revision-conflict",
    );
    revision_conflict.records[0].payload_digest = REFRESHED_PAYLOAD_DIGEST.into();
    redigest(&mut revision_conflict);
    assert!(
        db.apply_source_batch(&revision_conflict, &producer, 300)
            .unwrap_err()
            .starts_with("source_revision_conflict:")
    );
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:1"));

    let mut page_two_batch = batch(prefix, "cursor:1", "cursor:2", "snapshot-page-2");
    page_two_batch.records[0].source_version = "node-v2".into();
    page_two_batch.records[0].display_name = "Bounded sync refreshed".into();
    page_two_batch.records[0].payload_digest = REFRESHED_PAYLOAD_DIGEST.into();
    page_two_batch.records[0]
        .properties
        .insert("state".into(), "closed".into());
    page_two_batch.records[0]
        .properties
        .insert("title".into(), "Bounded sync refreshed".into());
    redigest(&mut page_two_batch);
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:1"));
    let page_two = db
        .apply_source_batch(&page_two_batch, &producer, 400)
        .unwrap();
    assert_eq!(page_two.transaction.status, SourceBatchStatus::Committed);
    assert_eq!(page_two.transaction.outcome, OperationOutcome::Success);
    assert!(page_two.checkpoint_advanced);
    let refreshed = match &page_two.records[0].decision {
        SyncDecision::Upsert(object) => object,
        other => panic!("expected refreshed upsert, got {other:?}"),
    };
    assert_eq!(refreshed.object_id, object_id);
    assert_eq!(refreshed.source_id, "github:sekai-project/sekai-chisei#12");
    assert_eq!(refreshed.source_version, "node-v2");
    assert_eq!(refreshed.payload_digest, REFRESHED_PAYLOAD_DIGEST);
    assert_eq!(refreshed.properties["state"], "closed");
    assert_eq!(refreshed.properties["title"], "Bounded sync refreshed");
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:2"));
    let page_two_state = source_sync_state(db, prefix).unwrap();
    assert_eq!(
        page_two_state
            .checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.committed_batch_digest.as_str()),
        Some(page_two_batch.batch_digest.as_str())
    );
    assert_eq!(page_two_state.last_result.as_ref(), Some(&page_two));

    let mut page_one_replay = page_one_batch.clone();
    page_one_replay.collected_at_ms += 1_000;
    assert_eq!(
        db.apply_source_batch(&page_one_replay, &producer, 500)
            .unwrap(),
        page_one
    );
    assert_eq!(source_sync_state(db, prefix).unwrap(), page_two_state);

    let stale = batch(prefix, "cursor:1", "cursor:3", "stale-page");
    assert!(
        db.apply_source_batch(&stale, &producer, 600)
            .unwrap_err()
            .starts_with("stale_cursor:")
    );
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:2"));
    assert_eq!(source_sync_state(db, prefix).unwrap(), page_two_state);

    let empty_prefix = format!("{prefix}-empty-binding");
    let empty_producer = format!("connector/{empty_prefix}");
    let copied_cursor = page_two_state.checkpoint.as_ref().unwrap().cursor.clone();
    let foreign = batch(
        &empty_prefix,
        &copied_cursor,
        "cursor:foreign-next",
        "foreign-cursor",
    );
    assert!(
        db.apply_source_batch(&foreign, &empty_producer, 700)
            .unwrap_err()
            .starts_with("foreign_cursor:")
    );
    assert!(source_sync_state(db, &empty_prefix).is_none());

    let mut tombstone = batch(prefix, "cursor:2", "cursor:3", "batch-tombstone");
    tombstone.records[0].deleted = true;
    tombstone.records[0].source_version = "node-v3".into();
    redigest(&mut tombstone);
    let tombstone_result = db.apply_source_batch(&tombstone, &producer, 800).unwrap();
    let tombstoned = match &tombstone_result.records[0].decision {
        SyncDecision::Tombstone(object) => object,
        other => panic!("expected tombstone, got {other:?}"),
    };
    assert_eq!(tombstoned.object_id, object_id);
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:3"));

    let mut conflict = batch(prefix, "cursor:3", "cursor:4", "batch-type-conflict");
    conflict.records[0].type_name = "PullRequest".into();
    conflict.records[0].source_version = "node-v4".into();
    redigest(&mut conflict);
    assert!(
        db.apply_source_batch(&conflict, &producer, 900)
            .unwrap_err()
            .starts_with("type_identity_conflict:")
    );
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:3"));

    let state = db
        .get_source_sync_state(&format!("{prefix}-namespace"), SOURCE_INSTANCE, TYPE_DIGEST)
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
