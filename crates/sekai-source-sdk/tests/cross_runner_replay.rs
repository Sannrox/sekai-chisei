//! #2742: a pending batch is accepted by the other runner when the committed
//! state matches that batch's own delivery mode.

use sekai_source_sdk::{
    ApplySourceBatchReply, ChangeFeedPage, ChangeFeedSource, ChangeFeedSourceFailure,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, GenerationSnapshotRead, GenerationSnapshotSource,
    GetSourceSyncStateInput, OutboxLimits, SnapshotRunLimits, SnapshotSourceFailure,
    SourceAdapterConfig, SourceBatch, SourceDeliveryMode, SourceDeliveryWindow,
    SourceGenerationStatus, SourceOutbox, SourceRecord, SourceRunDisposition, SourceSyncStateView,
    SourceSyncTransport, TransportFailure, build_source_batch_v2, parse_github_fixture,
    run_change_feed, run_generation_snapshot_v2, translate_github_fixture,
};

const REPO: &str = "sannrox/sekai-chisei";

fn config() -> SourceAdapterConfig {
    SourceAdapterConfig {
        namespace: "acme".into(),
        producer_identity: "connector/github-primary".into(),
        source_instance: REPO.into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
    }
}

fn record(number: u64, sequence: Option<u64>) -> SourceRecord {
    let mut record = translate_github_fixture(
        parse_github_fixture(
            format!(
                r#"{{
                    "repository": "{REPO}",
                    "kind": "Issue",
                    "number": {number},
                    "revision": "rev-{number}",
                    "title": "Issue {number}",
                    "state": "open",
                    "observed_at_ms": 1
                }}"#
            )
            .as_bytes(),
        )
        .unwrap(),
        REPO,
    )
    .unwrap();
    record.source_sequence = sequence;
    record
}

fn matching_state(batch: &SourceBatch) -> SourceSyncStateView {
    let delivery = batch.delivery.as_ref().unwrap();
    SourceSyncStateView {
        found: true,
        current_cursor: Some(batch.proposed_next_cursor.clone()),
        last_committed_batch_digest: Some(batch.batch_digest.clone()),
        generation_status: Some(SourceGenerationStatus::Active),
        delivery_mode: Some(SourceDeliveryMode::ChangeFeed),
        sync_generation: Some(delivery.sync_generation),
        source_feed_epoch: delivery.source_feed_epoch.clone(),
        committed_offset: delivery.offset_end,
        latest_transaction_idempotency_key: Some(batch.idempotency_key.clone()),
        ..Default::default()
    }
}

struct CommitTransport {
    state: SourceSyncStateView,
}

impl SourceSyncTransport for CommitTransport {
    fn apply_source_batch(
        &mut self,
        batch: &SourceBatch,
    ) -> Result<ApplySourceBatchReply, TransportFailure> {
        Ok(ApplySourceBatchReply::Committed {
            idempotency_key: batch.idempotency_key.clone(),
            batch_digest: batch.batch_digest.clone(),
            committed_cursor: batch.proposed_next_cursor.clone(),
        })
    }

    fn get_source_sync_state(
        &mut self,
        _input: &GetSourceSyncStateInput,
    ) -> Result<SourceSyncStateView, TransportFailure> {
        Ok(self.state.clone())
    }
}

struct ScriptedFeed {
    pages: Vec<Result<ChangeFeedPage, ChangeFeedSourceFailure>>,
    reads: Vec<(String, u64)>,
}

impl ChangeFeedSource for ScriptedFeed {
    fn read_change_feed(
        &mut self,
        source_feed_epoch: &str,
        committed_offset: u64,
        _max_records: usize,
    ) -> Result<ChangeFeedPage, ChangeFeedSourceFailure> {
        self.reads
            .push((source_feed_epoch.to_owned(), committed_offset));
        self.pages
            .pop()
            .unwrap_or(Err(ChangeFeedSourceFailure::Invalid))
    }
}

struct UnreadSnapshot;

impl GenerationSnapshotSource for UnreadSnapshot {
    fn read_generation_page(
        &mut self,
        _committed_cursor: Option<&str>,
        _max_records: usize,
    ) -> Result<GenerationSnapshotRead, SnapshotSourceFailure> {
        Err(SnapshotSourceFailure::Invalid)
    }
}

#[test]
fn change_feed_accepts_a_replayed_complete_snapshot_batch() {
    let root = tempfile::tempdir().unwrap();
    let outbox = SourceOutbox::open(root.path(), OutboxLimits::default()).unwrap();
    let batch = build_source_batch_v2(
        &config(),
        "",
        "snapshot:complete",
        1,
        vec![record(1, None)],
        SourceDeliveryWindow {
            mode: SourceDeliveryMode::Snapshot,
            sync_generation: 1,
            source_feed_epoch: Some("feed-epoch-a".into()),
            offset_start: None,
            offset_end: Some(40),
            snapshot_complete: true,
        },
    )
    .unwrap();
    outbox.enqueue(&batch).unwrap();
    let mut transport = CommitTransport {
        state: matching_state(&batch),
    };
    let mut feed = ScriptedFeed {
        pages: vec![Ok(ChangeFeedPage {
            offset_start: 40,
            records: Vec::new(),
            proposed_next_cursor: String::new(),
            collected_at_ms: 1,
            caught_up: true,
        })],
        reads: Vec::new(),
    };

    let outcome = run_change_feed(&config(), &outbox, &mut transport, &mut feed, 10).unwrap();

    assert_eq!(outcome.disposition, SourceRunDisposition::CaughtUp);
    assert_eq!(feed.reads, [("feed-epoch-a".into(), 40)]);
}

#[test]
fn generation_snapshot_accepts_a_replayed_change_feed_batch() {
    let root = tempfile::tempdir().unwrap();
    let outbox = SourceOutbox::open(root.path(), OutboxLimits::default()).unwrap();
    let batch = build_source_batch_v2(
        &config(),
        "snapshot:complete",
        "feed:41",
        1,
        vec![record(2, Some(41))],
        SourceDeliveryWindow {
            mode: SourceDeliveryMode::ChangeFeed,
            sync_generation: 1,
            source_feed_epoch: Some("feed-epoch-a".into()),
            offset_start: Some(40),
            offset_end: Some(41),
            snapshot_complete: false,
        },
    )
    .unwrap();
    outbox.enqueue(&batch).unwrap();
    let mut transport = CommitTransport {
        state: matching_state(&batch),
    };

    let outcome = run_generation_snapshot_v2(
        &config(),
        &outbox,
        &mut transport,
        &mut UnreadSnapshot,
        SnapshotRunLimits::default(),
    )
    .unwrap();

    assert_eq!(outcome.disposition, SourceRunDisposition::CaughtUp);
    assert_eq!(outcome.batches_committed, 1);
}

#[test]
fn replayed_batch_whose_committed_state_does_not_match_requires_recovery() {
    let root = tempfile::tempdir().unwrap();
    let outbox = SourceOutbox::open(root.path(), OutboxLimits::default()).unwrap();
    let batch = build_source_batch_v2(
        &config(),
        "",
        "snapshot:complete",
        1,
        vec![record(1, None)],
        SourceDeliveryWindow {
            mode: SourceDeliveryMode::Snapshot,
            sync_generation: 1,
            source_feed_epoch: Some("feed-epoch-a".into()),
            offset_start: None,
            offset_end: Some(40),
            snapshot_complete: true,
        },
    )
    .unwrap();
    outbox.enqueue(&batch).unwrap();
    let mut state = matching_state(&batch);
    state.last_committed_batch_digest = Some(format!("sha256:{}", "e".repeat(64)));
    let mut transport = CommitTransport { state };
    let mut feed = ScriptedFeed {
        pages: Vec::new(),
        reads: Vec::new(),
    };

    let outcome = run_change_feed(&config(), &outbox, &mut transport, &mut feed, 10).unwrap();

    assert_eq!(outcome.disposition, SourceRunDisposition::RecoveryRequired);
    assert!(feed.reads.is_empty());
}
