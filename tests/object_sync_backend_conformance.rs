use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

use rusqlite::params;
use sekai_chisei::db::object_sync::ObjectSyncBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, OperationOutcome, SOURCE_BATCH_V2_VERSION,
    SOURCE_BATCH_VERSION, SOURCE_GITHUB, SourceBatch, SourceBatchStatus, SourceDeliveryMode,
    SourceDeliveryWindow, SourceRecord, SourceSyncGenerationStatus, SourceSyncState, SyncDecision,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

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
            source_sequence: None,
        }],
        delivery: None,
    };
    redigest(&mut batch);
    batch
}

fn redigest(batch: &mut SourceBatch) {
    batch.batch_digest = batch.canonical_digest().unwrap();
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update(b"\n");
    }
    format!("{prefix}-{:x}", digest.finalize())
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

fn exercise_ordered_feed(db: &dyn ObjectSyncBackend, prefix: &str) {
    let producer = format!("connector/{prefix}");
    let mut snapshot = batch(prefix, "", "cursor:snapshot", "snapshot-1");
    snapshot.contract_version = SOURCE_BATCH_V2_VERSION.into();
    snapshot.delivery = Some(SourceDeliveryWindow {
        mode: SourceDeliveryMode::Snapshot,
        sync_generation: 1,
        source_feed_epoch: Some("epoch-1".into()),
        offset_start: None,
        offset_end: Some(40),
        snapshot_complete: true,
    });
    redigest(&mut snapshot);
    let snapshot_result = db.apply_source_batch(&snapshot, &producer, 1_000).unwrap();
    let handoff = source_sync_state(db, prefix).unwrap();
    assert_eq!(
        handoff.current_generation.as_ref().unwrap().status,
        SourceSyncGenerationStatus::Active
    );
    assert_eq!(
        handoff.current_generation.as_ref().unwrap().delivery_mode,
        SourceDeliveryMode::ChangeFeed
    );
    assert_eq!(
        handoff
            .current_generation
            .as_ref()
            .unwrap()
            .committed_offset,
        Some(40)
    );

    let mut feed = batch(prefix, "cursor:snapshot", "cursor:41", "feed-41");
    feed.contract_version = SOURCE_BATCH_V2_VERSION.into();
    feed.records[0].source_sequence = Some(41);
    feed.delivery = Some(SourceDeliveryWindow {
        mode: SourceDeliveryMode::ChangeFeed,
        sync_generation: 1,
        source_feed_epoch: Some("epoch-1".into()),
        offset_start: Some(40),
        offset_end: Some(41),
        snapshot_complete: false,
    });
    redigest(&mut feed);
    db.apply_source_batch(&feed, &producer, 1_100).unwrap();
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:41"));

    assert_eq!(
        db.apply_source_batch(&snapshot, &producer, 1_200).unwrap(),
        snapshot_result
    );
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:41"));

    let mut overlap = feed.clone();
    overlap.idempotency_key = format!("{prefix}-overlap");
    overlap.current_cursor = "cursor:41".into();
    overlap.proposed_next_cursor = "cursor:overlap".into();
    redigest(&mut overlap);
    assert!(
        db.apply_source_batch(&overlap, &producer, 1_300)
            .unwrap_err()
            .starts_with("overlapping_range:")
    );

    let mut missing = feed.clone();
    missing.idempotency_key = format!("{prefix}-missing");
    missing.current_cursor = "cursor:41".into();
    missing.proposed_next_cursor = "cursor:missing".into();
    missing.records[0].source_sequence = Some(51);
    missing.delivery.as_mut().unwrap().offset_start = Some(50);
    missing.delivery.as_mut().unwrap().offset_end = Some(51);
    redigest(&mut missing);
    assert!(
        db.apply_source_batch(&missing, &producer, 1_400)
            .unwrap_err()
            .starts_with("missing_range:")
    );
    let recovery_state = source_sync_state(db, prefix).unwrap();
    assert_eq!(
        recovery_state.current_generation.as_ref().unwrap().status,
        SourceSyncGenerationStatus::RecoveryRequired
    );
    assert_eq!(
        recovery_state.latest_transaction.as_ref().unwrap().status,
        SourceBatchStatus::Aborted
    );

    let mut recovery = batch(prefix, "cursor:41", "cursor:recovered", "snapshot-2");
    recovery.contract_version = SOURCE_BATCH_V2_VERSION.into();
    recovery.delivery = Some(SourceDeliveryWindow {
        mode: SourceDeliveryMode::Snapshot,
        sync_generation: 2,
        source_feed_epoch: Some("epoch-1".into()),
        offset_start: None,
        offset_end: Some(80),
        snapshot_complete: true,
    });
    redigest(&mut recovery);
    db.apply_source_batch(&recovery, &producer, 1_500).unwrap();
    let recovered = source_sync_state(db, prefix).unwrap();
    assert_eq!(
        recovered.current_generation.as_ref().unwrap().status,
        SourceSyncGenerationStatus::Active
    );
    assert_eq!(
        recovered
            .current_generation
            .as_ref()
            .unwrap()
            .sync_generation,
        2
    );
    assert_eq!(checkpoint(db, prefix).as_deref(), Some("cursor:recovered"));
}

#[test]
fn sqlite_object_sync_backend_conformance() {
    exercise_object_sync(&SekaiDb::new(":memory:").unwrap(), "sqlite");
    exercise_ordered_feed(&SekaiDb::new(":memory:").unwrap(), "sqlite-ordered");
}

#[test]
fn sqlite_ordered_open_resumes_after_restart() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("ordered-open.sqlite");
    let prefix = "sqlite-open-restart";
    let producer = format!("connector/{prefix}");
    let mut snapshot = batch(prefix, "", "cursor:snapshot", "snapshot-1");
    snapshot.contract_version = SOURCE_BATCH_V2_VERSION.into();
    snapshot.delivery = Some(SourceDeliveryWindow {
        mode: SourceDeliveryMode::Snapshot,
        sync_generation: 1,
        source_feed_epoch: Some("epoch-1".into()),
        offset_start: None,
        offset_end: Some(40),
        snapshot_complete: true,
    });
    redigest(&mut snapshot);
    SekaiDb::new(path.to_str().unwrap()).unwrap();

    let binding_id = stable_id(
        "source-binding",
        &[
            &snapshot.namespace,
            &snapshot.source,
            &snapshot.source_instance,
        ],
    );
    let transaction_id = stable_id(
        "source-batch",
        &[
            &snapshot.namespace,
            &snapshot.producer_identity,
            &snapshot.idempotency_key,
        ],
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO sekai_source_bindings (
                binding_id, namespace, producer_identity, source, source_instance,
                family, adapter_id, adapter_version, type_digest, created_at_ms,
                active, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 100, 1, 100)",
            params![
                binding_id,
                snapshot.namespace,
                snapshot.producer_identity,
                snapshot.source,
                snapshot.source_instance,
                snapshot.family,
                snapshot.adapter_id,
                snapshot.adapter_version,
                snapshot.type_digest,
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO sekai_source_batch_transactions (
                transaction_id, binding_id, namespace, producer_identity, idempotency_key,
                batch_digest, batch_json, current_cursor, proposed_next_cursor, status,
                outcome, opened_at_ms, reason, contract_version, delivery_mode,
                sync_generation, feed_epoch, offset_end, snapshot_complete
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'OPEN',
                'unavailable', 100, 'awaiting atomic commit', ?10, 'snapshot',
                1, 'epoch-1', 40, 1
             )",
            params![
                transaction_id,
                binding_id,
                snapshot.namespace,
                snapshot.producer_identity,
                snapshot.idempotency_key,
                snapshot.batch_digest,
                serde_json::to_string(&snapshot).unwrap(),
                snapshot.current_cursor,
                snapshot.proposed_next_cursor,
                snapshot.contract_version,
            ],
        )
        .unwrap();
    drop(connection);

    let reopened = SekaiDb::new(path.to_str().unwrap()).unwrap();
    let result = reopened
        .apply_source_batch(&snapshot, &producer, 200)
        .unwrap();
    assert_eq!(result.transaction.opened_at_ms, 100);
    assert_eq!(result.transaction.status, SourceBatchStatus::Committed);
    assert_eq!(
        source_sync_state(&reopened, prefix)
            .unwrap()
            .current_generation
            .unwrap()
            .status,
        SourceSyncGenerationStatus::Active
    );
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
    let db = postgres();
    exercise_object_sync(&db, &prefix);
    exercise_ordered_feed(&db, &format!("{prefix}-ordered"));
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
