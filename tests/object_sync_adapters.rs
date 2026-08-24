#[path = "../adapters/github_object_sync.rs"]
mod github_object_sync;
#[path = "../adapters/object_sync_conformance.rs"]
mod object_sync_conformance;
#[path = "../adapters/object_sync_feed.rs"]
mod object_sync_feed;
#[path = "../adapters/object_sync_sdk.rs"]
mod object_sync_sdk;
#[path = "../adapters/object_sync_snapshot.rs"]
mod object_sync_snapshot;

use object_sync_feed::{
    ChangeFeedPage, ChangeFeedSource, ChangeFeedSourceFailure, run_change_feed,
};
use object_sync_sdk::{
    ApplySourceBatchReply, GetSourceSyncStateInput, OutboxLimits, SourceAdapterConfig,
    SourceGenerationStatus, SourceOutbox, SourceRunDisposition, SourceSyncStateView,
    SourceSyncTransport, TransportFailure, build_source_batch, build_source_batch_v2,
    serialize_source_batch,
};
use object_sync_snapshot::{
    GenerationSnapshotPage, GenerationSnapshotRead, GenerationSnapshotSource, SnapshotPage,
    SnapshotPageSource, SnapshotRead, SnapshotRunError, SnapshotRunLimits, SnapshotRunOutcome,
    SnapshotSourceFailure, run_generation_snapshot_v2, run_snapshot,
};
use sekai_chisei::sekai::object_sync::{
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SourceBatch, SourceDeliveryMode, SourceDeliveryWindow,
    SourceRecord,
};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

const TYPE_DIGEST: &str = GITHUB_OBJECT_SYNC_TYPE_DIGEST;

fn temporary_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sekai-object-sync-adapter-{name}-{}",
        uuid::Uuid::new_v4()
    ))
}

fn config() -> SourceAdapterConfig {
    SourceAdapterConfig {
        namespace: "acme".into(),
        producer_identity: "connector/github-primary".into(),
        source_instance: "sannrox/sekai-chisei".into(),
        type_digest: TYPE_DIGEST.into(),
    }
}

fn issue() -> SourceRecord {
    github_object_sync::translate(
        github_object_sync::parse(include_bytes!(
            "../adapters/fixtures/github_object_sync.issue.json"
        ))
        .unwrap(),
        "sannrox/sekai-chisei",
    )
    .unwrap()
}

fn snapshot_record(input: &[u8]) -> SourceRecord {
    github_object_sync::translate(
        github_object_sync::parse(input).unwrap(),
        "sannrox/sekai-chisei",
    )
    .unwrap()
}

fn snapshot_page_one() -> Vec<SourceRecord> {
    vec![
        snapshot_record(include_bytes!(
            "../adapters/fixtures/github_object_sync.snapshot.page1.issue-671.json"
        )),
        snapshot_record(include_bytes!(
            "../adapters/fixtures/github_object_sync.snapshot.page1.issue-672.json"
        )),
    ]
}

fn snapshot_page_two() -> Vec<SourceRecord> {
    vec![
        snapshot_record(include_bytes!(
            "../adapters/fixtures/github_object_sync.snapshot.page2.issue-671.json"
        )),
        snapshot_record(include_bytes!(
            "../adapters/fixtures/github_object_sync.snapshot.page2.pull-request-673.json"
        )),
    ]
}

fn batch(records: Vec<SourceRecord>) -> SourceBatch {
    build_source_batch(
        &config(),
        "cursor:664",
        "cursor:665",
        1_787_510_500_000,
        records,
    )
    .unwrap()
}

#[derive(Default)]
struct ScriptedTransport {
    replies: VecDeque<Result<ApplySourceBatchReply, TransportFailure>>,
    applied: Vec<String>,
    state: Option<SourceSyncStateView>,
}

impl SourceSyncTransport for ScriptedTransport {
    fn apply_source_batch(
        &mut self,
        batch: &SourceBatch,
    ) -> Result<ApplySourceBatchReply, TransportFailure> {
        self.applied.push(batch.idempotency_key.clone());
        self.replies
            .pop_front()
            .unwrap_or(Err(TransportFailure::Unavailable))
    }

    fn get_source_sync_state(
        &mut self,
        _input: &GetSourceSyncStateInput,
    ) -> Result<SourceSyncStateView, TransportFailure> {
        self.state.clone().ok_or(TransportFailure::Unavailable)
    }
}

struct ScriptedPageSource {
    reads: VecDeque<(Option<String>, Result<SnapshotRead, SnapshotSourceFailure>)>,
    observed: Vec<Option<String>>,
}

impl Default for ScriptedPageSource {
    fn default() -> Self {
        Self::new(std::iter::empty())
    }
}

impl ScriptedPageSource {
    fn new(
        reads: impl IntoIterator<
            Item = (
                Option<&'static str>,
                Result<SnapshotRead, SnapshotSourceFailure>,
            ),
        >,
    ) -> Self {
        Self {
            reads: reads
                .into_iter()
                .map(|(cursor, result)| (cursor.map(str::to_string), result))
                .collect(),
            observed: Vec::new(),
        }
    }
}

impl SnapshotPageSource for ScriptedPageSource {
    fn read_page(
        &mut self,
        committed_cursor: Option<&str>,
        _max_records: usize,
    ) -> Result<SnapshotRead, SnapshotSourceFailure> {
        self.observed.push(committed_cursor.map(ToOwned::to_owned));
        let (expected_cursor, result) = self
            .reads
            .pop_front()
            .expect("unexpected snapshot page read");
        assert_eq!(committed_cursor, expected_cursor.as_deref());
        result
    }
}

struct CheckpointTransport {
    state: SourceSyncStateView,
    failures: VecDeque<TransportFailure>,
    applied: Vec<SourceBatch>,
    committed: HashMap<String, (String, ApplySourceBatchReply)>,
    state_reads: usize,
}

impl Default for CheckpointTransport {
    fn default() -> Self {
        Self {
            state: SourceSyncStateView {
                found: false,
                current_cursor: None,
                open_transaction: false,
                last_committed_batch_digest: None,
                ..Default::default()
            },
            failures: VecDeque::new(),
            applied: Vec::new(),
            committed: HashMap::new(),
            state_reads: 0,
        }
    }
}

impl SourceSyncTransport for CheckpointTransport {
    fn apply_source_batch(
        &mut self,
        batch: &SourceBatch,
    ) -> Result<ApplySourceBatchReply, TransportFailure> {
        self.applied.push(batch.clone());
        if let Some(failure) = self.failures.pop_front() {
            return Err(failure);
        }
        if let Some((batch_digest, reply)) = self.committed.get(&batch.idempotency_key) {
            return if batch_digest == &batch.batch_digest {
                Ok(reply.clone())
            } else {
                Ok(ApplySourceBatchReply::Rejected {
                    reason_code: "idempotency_conflict".into(),
                })
            };
        }
        let expected_cursor = self.state.current_cursor.as_deref().unwrap_or_default();
        if (!self.state.found && !batch.current_cursor.is_empty())
            || (self.state.found && batch.current_cursor != expected_cursor)
        {
            return Ok(ApplySourceBatchReply::Rejected {
                reason_code: if self.state.found {
                    "stale_cursor".into()
                } else {
                    "foreign_cursor".into()
                },
            });
        }
        self.state = SourceSyncStateView {
            found: true,
            current_cursor: Some(batch.proposed_next_cursor.clone()),
            open_transaction: false,
            last_committed_batch_digest: Some(batch.batch_digest.clone()),
            ..Default::default()
        };
        let reply = ApplySourceBatchReply::Committed {
            idempotency_key: batch.idempotency_key.clone(),
            batch_digest: batch.batch_digest.clone(),
            committed_cursor: batch.proposed_next_cursor.clone(),
        };
        self.committed.insert(
            batch.idempotency_key.clone(),
            (batch.batch_digest.clone(), reply.clone()),
        );
        Ok(reply)
    }

    fn get_source_sync_state(
        &mut self,
        _input: &GetSourceSyncStateInput,
    ) -> Result<SourceSyncStateView, TransportFailure> {
        self.state_reads += 1;
        Ok(self.state.clone())
    }
}

struct ScriptedGenerationSnapshot {
    pages: VecDeque<GenerationSnapshotPage>,
    observed: Vec<Option<String>>,
}

impl GenerationSnapshotSource for ScriptedGenerationSnapshot {
    fn read_generation_page(
        &mut self,
        committed_cursor: Option<&str>,
        _max_records: usize,
    ) -> Result<GenerationSnapshotRead, SnapshotSourceFailure> {
        self.observed.push(committed_cursor.map(ToOwned::to_owned));
        self.pages
            .pop_front()
            .map(GenerationSnapshotRead::Page)
            .ok_or(SnapshotSourceFailure::Invalid)
    }
}

struct ScriptedFeed {
    pages: VecDeque<Result<ChangeFeedPage, ChangeFeedSourceFailure>>,
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
            .pop_front()
            .unwrap_or(Err(ChangeFeedSourceFailure::Invalid))
    }
}

#[derive(Default)]
struct GenerationTransport {
    state: SourceSyncStateView,
    applied: Vec<SourceBatch>,
    failures: VecDeque<TransportFailure>,
}

impl SourceSyncTransport for GenerationTransport {
    fn apply_source_batch(
        &mut self,
        batch: &SourceBatch,
    ) -> Result<ApplySourceBatchReply, TransportFailure> {
        self.applied.push(batch.clone());
        if let Some(failure) = self.failures.pop_front() {
            return Err(failure);
        }
        let Some(delivery) = batch.delivery.as_ref() else {
            return Ok(ApplySourceBatchReply::Rejected {
                reason_code: "v2_required".into(),
            });
        };
        if self.state.current_cursor.as_deref().unwrap_or_default() != batch.current_cursor {
            return Ok(ApplySourceBatchReply::Rejected {
                reason_code: "stale_cursor".into(),
            });
        }
        if delivery.mode == SourceDeliveryMode::ChangeFeed
            && delivery
                .offset_start
                .zip(self.state.committed_offset)
                .is_some_and(|(start, committed)| start > committed)
        {
            self.state.generation_status = Some(SourceGenerationStatus::RecoveryRequired);
            self.state.latest_transaction_reason = Some("missing_source_range".into());
            return Ok(ApplySourceBatchReply::Rejected {
                reason_code: "missing_source_range".into(),
            });
        }
        self.state.found = true;
        self.state.current_cursor = Some(batch.proposed_next_cursor.clone());
        self.state.open_transaction = false;
        self.state.last_committed_batch_digest = Some(batch.batch_digest.clone());
        self.state.latest_transaction_idempotency_key = Some(batch.idempotency_key.clone());
        self.state.sync_generation = Some(delivery.sync_generation);
        match delivery.mode {
            SourceDeliveryMode::Snapshot if delivery.snapshot_complete => {
                self.state.generation_status = Some(SourceGenerationStatus::Active);
                self.state.delivery_mode = Some(SourceDeliveryMode::ChangeFeed);
                self.state.source_feed_epoch = delivery.source_feed_epoch.clone();
                self.state.committed_offset = delivery.offset_end;
            }
            SourceDeliveryMode::Snapshot => {
                self.state.generation_status = Some(SourceGenerationStatus::Snapshotting);
                self.state.delivery_mode = Some(SourceDeliveryMode::Snapshot);
                self.state.source_feed_epoch = None;
                self.state.committed_offset = None;
            }
            SourceDeliveryMode::ChangeFeed => {
                if self.state.source_feed_epoch != delivery.source_feed_epoch {
                    return Ok(ApplySourceBatchReply::Rejected {
                        reason_code: "feed_epoch_mismatch".into(),
                    });
                }
                self.state.generation_status = Some(SourceGenerationStatus::Active);
                self.state.delivery_mode = Some(SourceDeliveryMode::ChangeFeed);
                self.state.committed_offset = delivery.offset_end;
            }
        }
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

fn sequenced_record(external_id: &str, sequence: u64) -> SourceRecord {
    let mut record = issue();
    record.external_id = external_id.into();
    record.source_version = format!("revision-{external_id}-{sequence}");
    record.display_name = format!("Object {external_id}");
    record.source_sequence = Some(sequence);
    record
}

#[test]
fn github_fixtures_preserve_stable_shared_number_identity() {
    let issue = issue();
    let mut later_fixture = github_object_sync::parse(include_bytes!(
        "../adapters/fixtures/github_object_sync.issue.json"
    ))
    .unwrap();
    later_fixture.observed_at_ms += 60_000;
    let later_observation =
        github_object_sync::translate(later_fixture, "sannrox/sekai-chisei").unwrap();
    let pull = github_object_sync::translate(
        github_object_sync::parse(include_bytes!(
            "../adapters/fixtures/github_object_sync.pull_request.json"
        ))
        .unwrap(),
        "sannrox/sekai-chisei",
    )
    .unwrap();

    assert_eq!(issue.external_id, "665");
    assert_eq!(pull.external_id, "665");
    assert_eq!(issue.source_id(), pull.source_id());
    assert_eq!(issue.source_id(), "github:sannrox/sekai-chisei#665");
    assert_eq!(issue.type_name, "Issue");
    assert_eq!(pull.type_name, "PullRequest");
    assert_eq!(issue.payload_digest, later_observation.payload_digest);
}

#[test]
fn batch_and_serialization_are_deterministic_and_match_contract() {
    let first_record = issue();
    let mut second_record = first_record.clone();
    second_record.external_id = "666".into();
    second_record.source_version = "I_revision-666".into();
    second_record.display_name = "Follow-up".into();

    let first = batch(vec![second_record.clone(), first_record.clone()]);
    let second = batch(vec![first_record, second_record]);
    object_sync_conformance::assert_deterministic_batch(&first, &second).unwrap();
    let serialized = serialize_source_batch(&first).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(value["contract_version"], "sekai.source-batch/v1");
    assert_eq!(value["namespace"], "acme");
    assert_eq!(value["producer_identity"], "connector/github-primary");
    assert_eq!(value["source"], "github");
    assert_eq!(value["source_instance"], "sannrox/sekai-chisei");
    assert_eq!(value["adapter_id"], "adapter.github.object_sync");
    assert_eq!(value["type_digest"], TYPE_DIGEST);
    assert_eq!(value["records"][0]["external_id"], "665");
    assert!(first.idempotency_key.starts_with("sync-"));
    assert!(first.batch_digest.starts_with("sha256:"));
}

#[test]
fn v2_builder_preserves_order_and_binds_delivery_identity() {
    let delivery = SourceDeliveryWindow {
        mode: SourceDeliveryMode::ChangeFeed,
        sync_generation: 3,
        source_feed_epoch: Some("feed-epoch-a".into()),
        offset_start: Some(40),
        offset_end: Some(42),
        snapshot_complete: false,
    };
    let first = build_source_batch_v2(
        &config(),
        "cursor:40",
        "cursor:42",
        1_787_510_500_000,
        vec![sequenced_record("671", 41), sequenced_record("672", 42)],
        delivery.clone(),
    )
    .unwrap();
    let later_collection = build_source_batch_v2(
        &config(),
        "cursor:40",
        "cursor:42",
        1_787_510_900_000,
        vec![sequenced_record("671", 41), sequenced_record("672", 42)],
        delivery.clone(),
    )
    .unwrap();
    assert_eq!(first.idempotency_key, later_collection.idempotency_key);
    assert_eq!(first.batch_digest, later_collection.batch_digest);
    assert_eq!(
        first
            .records
            .iter()
            .map(|record| record.source_sequence)
            .collect::<Vec<_>>(),
        [Some(41), Some(42)]
    );

    let mut next_generation = delivery;
    next_generation.sync_generation = 4;
    let changed = build_source_batch_v2(
        &config(),
        "cursor:40",
        "cursor:42",
        1_787_510_500_000,
        vec![sequenced_record("671", 41), sequenced_record("672", 42)],
        next_generation,
    )
    .unwrap();
    assert_ne!(first.idempotency_key, changed.idempotency_key);
    assert_ne!(first.batch_digest, changed.batch_digest);
}

#[test]
fn v2_builder_rejects_reordered_duplicate_and_missing_internal_sequences() {
    for (records, expected) in [
        (
            vec![sequenced_record("671", 42), sequenced_record("672", 41)],
            "reordered_source_sequence",
        ),
        (
            vec![sequenced_record("671", 41), sequenced_record("672", 41)],
            "duplicate_source_sequence",
        ),
        (
            vec![sequenced_record("671", 41), sequenced_record("672", 43)],
            "noncontiguous_source_sequence",
        ),
    ] {
        let error = build_source_batch_v2(
            &config(),
            "cursor:40",
            "cursor:42",
            1_787_510_500_000,
            records,
            SourceDeliveryWindow {
                mode: SourceDeliveryMode::ChangeFeed,
                sync_generation: 1,
                source_feed_epoch: Some("feed-epoch-a".into()),
                offset_start: Some(40),
                offset_end: Some(42),
                snapshot_complete: false,
            },
        )
        .unwrap_err();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn terminal_snapshot_handoff_then_two_feed_batches_are_contiguous() {
    let root = temporary_root("v2-handoff");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let mut transport = GenerationTransport::default();
    let mut snapshot = ScriptedGenerationSnapshot {
        pages: VecDeque::from([GenerationSnapshotPage {
            records: snapshot_page_one(),
            proposed_next_cursor: "snapshot:complete".into(),
            collected_at_ms: 1_787_511_100_000,
            complete: true,
            source_feed_epoch: Some("feed-epoch-a".into()),
            handoff_offset: Some(40),
        }]),
        observed: Vec::new(),
    };
    let snapshot_outcome = run_generation_snapshot_v2(
        &config(),
        &outbox,
        &mut transport,
        &mut snapshot,
        SnapshotRunLimits::default(),
    )
    .unwrap();
    assert_eq!(snapshot_outcome.disposition, SourceRunDisposition::CaughtUp);
    assert_eq!(snapshot_outcome.sync_generation, Some(1));
    assert_eq!(snapshot_outcome.committed_offset, Some(40));

    let mut feed = ScriptedFeed {
        pages: VecDeque::from([
            Ok(ChangeFeedPage {
                offset_start: 40,
                records: vec![sequenced_record("674", 41)],
                proposed_next_cursor: "feed:41".into(),
                collected_at_ms: 1_787_511_160_000,
                caught_up: false,
            }),
            Ok(ChangeFeedPage {
                offset_start: 41,
                records: vec![sequenced_record("675", 42)],
                proposed_next_cursor: "feed:42".into(),
                collected_at_ms: 1_787_511_220_000,
                caught_up: true,
            }),
        ]),
        reads: Vec::new(),
    };
    assert_eq!(
        run_change_feed(&config(), &outbox, &mut transport, &mut feed, 10)
            .unwrap()
            .disposition,
        SourceRunDisposition::InProgress
    );
    let caught_up = run_change_feed(&config(), &outbox, &mut transport, &mut feed, 10).unwrap();
    assert_eq!(caught_up.disposition, SourceRunDisposition::CaughtUp);
    assert_eq!(caught_up.committed_offset, Some(42));
    assert_eq!(
        feed.reads,
        [("feed-epoch-a".into(), 40), ("feed-epoch-a".into(), 41)]
    );
    assert_eq!(transport.applied.len(), 3);
    assert_eq!(transport.applied[0].current_cursor, "");
    assert_eq!(transport.applied[1].current_cursor, "snapshot:complete");
    assert_eq!(transport.applied[2].current_cursor, "feed:41");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovery_starts_only_the_next_snapshot_generation_from_plane_cursor() {
    let root = temporary_root("snapshot-next-generation");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let mut transport = GenerationTransport {
        state: SourceSyncStateView {
            found: true,
            current_cursor: Some("plane:recovery-cursor".into()),
            generation_status: Some(SourceGenerationStatus::RecoveryRequired),
            delivery_mode: Some(SourceDeliveryMode::ChangeFeed),
            sync_generation: Some(2),
            source_feed_epoch: Some("old-epoch".into()),
            committed_offset: Some(91),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut snapshot = ScriptedGenerationSnapshot {
        pages: VecDeque::from([GenerationSnapshotPage {
            records: snapshot_page_one(),
            proposed_next_cursor: "snapshot:generation-3".into(),
            collected_at_ms: 1_787_511_300_000,
            complete: true,
            source_feed_epoch: Some("feed-epoch-b".into()),
            handoff_offset: Some(100),
        }]),
        observed: Vec::new(),
    };
    let outcome = run_generation_snapshot_v2(
        &config(),
        &outbox,
        &mut transport,
        &mut snapshot,
        SnapshotRunLimits::default(),
    )
    .unwrap();
    assert_eq!(outcome.disposition, SourceRunDisposition::CaughtUp);
    assert_eq!(outcome.sync_generation, Some(3));
    assert_eq!(
        snapshot.observed,
        [Some("plane:recovery-cursor".to_string())]
    );
    assert_eq!(transport.applied[0].current_cursor, "plane:recovery-cursor");
    assert_eq!(
        transport.applied[0]
            .delivery
            .as_ref()
            .unwrap()
            .sync_generation,
        3
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn feed_requires_snapshot_and_reports_unsupported_ordering() {
    let root = temporary_root("feed-gates");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let mut transport = GenerationTransport::default();
    let mut unread = ScriptedFeed {
        pages: VecDeque::new(),
        reads: Vec::new(),
    };
    assert_eq!(
        run_change_feed(&config(), &outbox, &mut transport, &mut unread, 10)
            .unwrap()
            .disposition,
        SourceRunDisposition::SnapshotRequired
    );
    assert!(unread.reads.is_empty());

    transport.state = SourceSyncStateView {
        found: true,
        current_cursor: Some("snapshot:complete".into()),
        generation_status: Some(SourceGenerationStatus::Active),
        delivery_mode: Some(SourceDeliveryMode::ChangeFeed),
        sync_generation: Some(1),
        source_feed_epoch: Some("feed-epoch-a".into()),
        committed_offset: Some(40),
        ..Default::default()
    };
    let mut unsupported = ScriptedFeed {
        pages: VecDeque::from([Err(ChangeFeedSourceFailure::UnsupportedOrdering)]),
        reads: Vec::new(),
    };
    assert_eq!(
        run_change_feed(&config(), &outbox, &mut transport, &mut unsupported, 10)
            .unwrap()
            .disposition,
        SourceRunDisposition::UnsupportedOrdering
    );
    assert_eq!(
        github_object_sync::direct_feed_capability(),
        github_object_sync::DirectFeedCapability::UnsupportedOrdering
    );
    assert!(transport.applied.is_empty());

    let mut unavailable = ScriptedFeed {
        pages: VecDeque::from([Err(ChangeFeedSourceFailure::Unavailable)]),
        reads: Vec::new(),
    };
    assert_eq!(
        run_change_feed(&config(), &outbox, &mut transport, &mut unavailable, 10)
            .unwrap()
            .disposition,
        SourceRunDisposition::Pending
    );
    assert!(transport.applied.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn feed_fails_closed_for_open_foreign_and_mismatched_state() {
    for state in [
        SourceSyncStateView {
            found: true,
            current_cursor: Some("feed:40".into()),
            open_transaction: true,
            generation_status: Some(SourceGenerationStatus::Active),
            delivery_mode: Some(SourceDeliveryMode::ChangeFeed),
            sync_generation: Some(1),
            source_feed_epoch: Some("feed-epoch-a".into()),
            committed_offset: Some(40),
            ..Default::default()
        },
        SourceSyncStateView {
            found: false,
            current_cursor: Some("copied:cursor".into()),
            ..Default::default()
        },
        SourceSyncStateView {
            found: true,
            current_cursor: Some("feed:40".into()),
            generation_status: Some(SourceGenerationStatus::Active),
            delivery_mode: Some(SourceDeliveryMode::ChangeFeed),
            sync_generation: Some(1),
            committed_offset: Some(40),
            ..Default::default()
        },
    ] {
        let root = temporary_root("feed-state");
        let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
        let mut transport = GenerationTransport {
            state,
            ..Default::default()
        };
        let mut unread = ScriptedFeed {
            pages: VecDeque::new(),
            reads: Vec::new(),
        };
        assert_eq!(
            run_change_feed(&config(), &outbox, &mut transport, &mut unread, 10)
                .unwrap()
                .disposition,
            SourceRunDisposition::RecoveryRequired
        );
        assert!(unread.reads.is_empty());
        assert!(transport.applied.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn feed_runner_keeps_shared_outbox_bindings_isolated() {
    let root = temporary_root("feed-shared-outbox");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let mut other_config = config();
    other_config.source_instance = "sannrox/other-repository".into();
    let mut other_record = issue();
    other_record.source_instance = other_config.source_instance.clone();
    let other = build_source_batch(
        &other_config,
        "",
        "other:snapshot",
        1_787_511_100_000,
        vec![other_record],
    )
    .unwrap();
    outbox.enqueue(&other).unwrap();

    let mut transport = GenerationTransport {
        state: SourceSyncStateView {
            found: true,
            current_cursor: Some("feed:40".into()),
            generation_status: Some(SourceGenerationStatus::Active),
            delivery_mode: Some(SourceDeliveryMode::ChangeFeed),
            sync_generation: Some(1),
            source_feed_epoch: Some("feed-epoch-a".into()),
            committed_offset: Some(40),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut feed = ScriptedFeed {
        pages: VecDeque::from([Ok(ChangeFeedPage {
            offset_start: 40,
            records: vec![sequenced_record("674", 41)],
            proposed_next_cursor: "feed:41".into(),
            collected_at_ms: 1_787_511_160_000,
            caught_up: true,
        })]),
        reads: Vec::new(),
    };
    assert_eq!(
        run_change_feed(&config(), &outbox, &mut transport, &mut feed, 10)
            .unwrap()
            .disposition,
        SourceRunDisposition::CaughtUp
    );
    assert_eq!(transport.applied.len(), 1);
    assert_eq!(outbox.pending().unwrap(), [other]);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn plane_missing_range_requires_recovery_without_running_snapshot() {
    let root = temporary_root("feed-plane-gap");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let mut transport = GenerationTransport {
        state: SourceSyncStateView {
            found: true,
            current_cursor: Some("feed:40".into()),
            generation_status: Some(SourceGenerationStatus::Active),
            delivery_mode: Some(SourceDeliveryMode::ChangeFeed),
            sync_generation: Some(1),
            source_feed_epoch: Some("feed-epoch-a".into()),
            committed_offset: Some(40),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut feed = ScriptedFeed {
        pages: VecDeque::from([Ok(ChangeFeedPage {
            offset_start: 50,
            records: vec![sequenced_record("674", 51)],
            proposed_next_cursor: "feed:51".into(),
            collected_at_ms: 1_787_511_160_000,
            caught_up: false,
        })]),
        reads: Vec::new(),
    };
    assert_eq!(
        run_change_feed(&config(), &outbox, &mut transport, &mut feed, 10)
            .unwrap()
            .disposition,
        SourceRunDisposition::RecoveryRequired
    );
    assert_eq!(transport.applied.len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn feed_runner_never_counts_historical_replay_as_current_progress() {
    let root = temporary_root("feed-historical-replay");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let historical = build_source_batch_v2(
        &config(),
        "feed:40",
        "feed:41",
        1_787_511_160_000,
        vec![sequenced_record("674", 41)],
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
    outbox.enqueue(&historical).unwrap();
    let mut transport = ScriptedTransport {
        replies: VecDeque::from([Ok(ApplySourceBatchReply::Committed {
            idempotency_key: historical.idempotency_key.clone(),
            batch_digest: historical.batch_digest.clone(),
            committed_cursor: historical.proposed_next_cursor.clone(),
        })]),
        state: Some(SourceSyncStateView {
            found: true,
            current_cursor: Some("feed:42".into()),
            last_committed_batch_digest: Some(format!("sha256:{}", "e".repeat(64))),
            generation_status: Some(SourceGenerationStatus::Active),
            delivery_mode: Some(SourceDeliveryMode::ChangeFeed),
            sync_generation: Some(1),
            source_feed_epoch: Some("feed-epoch-a".into()),
            committed_offset: Some(42),
            latest_transaction_idempotency_key: Some("sync-historical-successor".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut unread = ScriptedFeed {
        pages: VecDeque::new(),
        reads: Vec::new(),
    };
    let outcome = run_change_feed(&config(), &outbox, &mut transport, &mut unread, 10).unwrap();
    assert_eq!(outcome.disposition, SourceRunDisposition::RecoveryRequired);
    assert_eq!(outcome.batches_committed, 0);
    assert!(unread.reads.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn v2_outbox_restart_replays_exact_batch_and_invalid_values_stay_secret_safe() {
    let root = temporary_root("v2-restart");
    let batch = build_source_batch_v2(
        &config(),
        "feed:40",
        "feed:41",
        1_787_511_160_000,
        vec![sequenced_record("674", 41)],
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
    let mut ambiguous = ScriptedTransport {
        replies: VecDeque::from([Err(TransportFailure::Ambiguous)]),
        ..Default::default()
    };
    let mut committed = ScriptedTransport {
        replies: VecDeque::from([Ok(ApplySourceBatchReply::Committed {
            idempotency_key: batch.idempotency_key.clone(),
            batch_digest: batch.batch_digest.clone(),
            committed_cursor: batch.proposed_next_cursor.clone(),
        })]),
        ..Default::default()
    };
    object_sync_conformance::run_restart_and_commit(&root, &batch, &mut ambiguous, &mut committed)
        .unwrap();

    let cursor_secret = "ghp_sensitive-cursor";
    let cursor_error = build_source_batch_v2(
        &config(),
        cursor_secret,
        "feed:41",
        1_787_511_160_000,
        vec![sequenced_record("674", 41)],
        SourceDeliveryWindow {
            mode: SourceDeliveryMode::ChangeFeed,
            sync_generation: 1,
            source_feed_epoch: Some("feed-epoch-a".into()),
            offset_start: Some(40),
            offset_end: Some(41),
            snapshot_complete: false,
        },
    )
    .unwrap_err();
    assert!(!cursor_error.contains(cursor_secret));
    let epoch_secret = "ghp_sensitive-epoch";
    let epoch_error = build_source_batch_v2(
        &config(),
        "feed:40",
        "feed:41",
        1_787_511_160_000,
        vec![sequenced_record("674", 41)],
        SourceDeliveryWindow {
            mode: SourceDeliveryMode::ChangeFeed,
            sync_generation: 1,
            source_feed_epoch: Some(epoch_secret.into()),
            offset_start: Some(40),
            offset_end: Some(41),
            snapshot_complete: false,
        },
    )
    .unwrap_err();
    assert!(!epoch_error.contains(epoch_secret));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sdk_rejects_unbound_type_revision_before_building() {
    let mut unbound = config();
    unbound.type_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    let error = build_source_batch(
        &unbound,
        "cursor:664",
        "cursor:665",
        1_787_510_500_000,
        vec![issue()],
    )
    .unwrap_err();
    assert!(error.contains("unbound_type_revision"));
}

#[test]
fn outbox_allows_exact_reenqueue_but_blocks_distinct_unresolved_binding_batch() {
    let root = temporary_root("binding-order");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let first = batch(vec![issue()]);
    assert_eq!(outbox.enqueue(&first).unwrap(), first);
    assert_eq!(outbox.enqueue(&first).unwrap(), first);

    let mut distinct = issue();
    distinct.external_id = "666".into();
    distinct.source_version = "I_revision-666".into();
    distinct.display_name = "Later unresolved batch".into();
    let second = batch(vec![distinct]);
    assert!(
        outbox
            .enqueue(&second)
            .unwrap_err()
            .contains("distinct unresolved batch")
    );
    assert_eq!(outbox.pending().unwrap(), [first]);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_outbox_instances_publish_only_one_unresolved_binding_batch() {
    let root = temporary_root("concurrent-binding");
    let first_outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let second_outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let first = batch(vec![issue()]);
    let mut second_record = issue();
    second_record.external_id = "666".into();
    second_record.source_version = "I_revision-666".into();
    second_record.display_name = "Concurrent batch".into();
    let second = batch(vec![second_record]);
    let barrier = Arc::new(Barrier::new(3));
    let handles = [(first_outbox, first), (second_outbox, second)].map(|(outbox, batch)| {
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            outbox.enqueue(&batch)
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);

    let reopened = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    assert_eq!(reopened.pending().unwrap().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn outbox_restarts_retains_ambiguous_progress_and_removes_exact_commit() {
    let root = temporary_root("restart");
    let batch = batch(vec![issue()]);
    let mut ambiguous = ScriptedTransport {
        replies: VecDeque::from([Err(TransportFailure::Ambiguous)]),
        ..Default::default()
    };
    let mut committed = ScriptedTransport {
        replies: VecDeque::from([Ok(ApplySourceBatchReply::Committed {
            idempotency_key: batch.idempotency_key.clone(),
            batch_digest: batch.batch_digest.clone(),
            committed_cursor: batch.proposed_next_cursor.clone(),
        })]),
        ..Default::default()
    };

    object_sync_conformance::run_restart_and_commit(&root, &batch, &mut ambiguous, &mut committed)
        .unwrap();
    assert_eq!(
        ambiguous.applied.as_slice(),
        std::slice::from_ref(&batch.idempotency_key)
    );
    assert_eq!(
        committed.applied.as_slice(),
        std::slice::from_ref(&batch.idempotency_key)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn mismatched_commit_stays_pending_and_rejection_is_safely_quarantined() {
    let root = temporary_root("quarantine");
    let batch = batch(vec![issue()]);
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    outbox.enqueue(&batch).unwrap();
    let mut mismatched = ScriptedTransport {
        replies: VecDeque::from([Ok(ApplySourceBatchReply::Committed {
            idempotency_key: batch.idempotency_key.clone(),
            batch_digest: format!("sha256:{}", "0".repeat(64)),
            committed_cursor: batch.proposed_next_cursor.clone(),
        })]),
        ..Default::default()
    };
    let report = outbox.flush(&mut mismatched, true).unwrap();
    assert_eq!(
        report.entries[0].disposition,
        object_sync_sdk::FlushDisposition::Pending
    );
    assert_eq!(
        outbox.pending().unwrap().as_slice(),
        std::slice::from_ref(&batch)
    );

    let mut rejected = ScriptedTransport {
        replies: VecDeque::from([Ok(ApplySourceBatchReply::Rejected {
            reason_code: "authorization: bearer TOP-SECRET".into(),
        })]),
        ..Default::default()
    };
    let report = outbox.flush(&mut rejected, true).unwrap();
    assert_eq!(
        report.entries[0].disposition,
        object_sync_sdk::FlushDisposition::Quarantined
    );
    assert!(outbox.pending().unwrap().is_empty());
    assert_eq!(outbox.quarantine_count().unwrap(), 1);
    object_sync_conformance::assert_files_omit(
        &root,
        &[
            "TOP-SECRET",
            "authorization: bearer",
            "SEKAI_CREDENTIAL",
            "github_pat_",
        ],
    )
    .unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn outbox_enforces_file_and_entry_bounds() {
    let root = temporary_root("bounds");
    let limits = OutboxLimits {
        max_pending_files: 1,
        max_entry_bytes: object_sync_sdk::DEFAULT_MAX_ENTRY_BYTES,
    };
    let outbox = SourceOutbox::open(&root, limits).unwrap();
    let first = batch(vec![issue()]);
    outbox.enqueue(&first).unwrap();

    let mut other = issue();
    other.source_instance = "sannrox/other-repository".into();
    other.external_id = "666".into();
    other.source_version = "I_revision-666".into();
    let mut other_config = config();
    other_config.source_instance = other.source_instance.clone();
    let second = build_source_batch(
        &other_config,
        "cursor:664",
        "cursor:665",
        1_787_510_500_000,
        vec![other],
    )
    .unwrap();
    assert!(outbox.enqueue(&second).unwrap_err().contains("file limit"));
    std::fs::remove_dir_all(root).unwrap();

    let tiny_root = temporary_root("entry-bounds");
    let tiny = SourceOutbox::open(
        &tiny_root,
        OutboxLimits {
            max_pending_files: 1,
            max_entry_bytes: 32,
        },
    )
    .unwrap();
    assert!(tiny.enqueue(&first).unwrap_err().contains("byte limit"));
    std::fs::remove_dir_all(tiny_root).unwrap();
}

#[test]
fn snapshot_runner_pages_from_plane_state_and_preserves_cross_page_identity() {
    let root = temporary_root("snapshot-pages");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let page_one_cursor = "opaque:snapshot-a:page-1";
    let complete_cursor = "opaque:snapshot-a:complete";
    let mut source = ScriptedPageSource::new([
        (
            None,
            Ok(SnapshotRead::Page(SnapshotPage {
                records: snapshot_page_one(),
                proposed_next_cursor: page_one_cursor.into(),
                collected_at_ms: 1_787_511_100_000,
                complete: false,
            })),
        ),
        (
            Some(page_one_cursor),
            Ok(SnapshotRead::Page(SnapshotPage {
                records: snapshot_page_two(),
                proposed_next_cursor: complete_cursor.into(),
                collected_at_ms: 1_787_511_160_000,
                complete: true,
            })),
        ),
    ]);
    let mut transport = CheckpointTransport::default();

    let outcome = run_snapshot(
        &config(),
        &outbox,
        &mut transport,
        &mut source,
        SnapshotRunLimits {
            max_pages_per_run: 4,
            max_records_per_page: 2,
        },
    )
    .unwrap();

    assert_eq!(
        outcome,
        SnapshotRunOutcome::Complete {
            pages_committed: 2,
            committed_cursor: complete_cursor.into(),
        }
    );
    object_sync_conformance::assert_snapshot_chain(&transport.applied).unwrap();
    object_sync_conformance::assert_cross_page_identity(
        &transport.applied[0],
        &transport.applied[1],
        "github:sannrox/sekai-chisei#671",
    )
    .unwrap();
    assert_eq!(source.observed, [None, Some(page_one_cursor.to_string())]);
    assert_eq!(
        transport.state.current_cursor.as_deref(),
        Some(complete_cursor)
    );
    assert!(transport.state_reads >= 2);
    assert!(outbox.pending().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn snapshot_runner_restart_uses_durable_plane_checkpoint_not_local_page_state() {
    let root = temporary_root("snapshot-checkpoint-restart");
    let page_one_cursor = "opaque:snapshot-b:page-1";
    let complete_cursor = "opaque:snapshot-b:complete";
    let mut transport = CheckpointTransport::default();
    let mut first_process = ScriptedPageSource::new([(
        None,
        Ok(SnapshotRead::Page(SnapshotPage {
            records: snapshot_page_one(),
            proposed_next_cursor: page_one_cursor.into(),
            collected_at_ms: 1_787_511_100_000,
            complete: false,
        })),
    )]);
    let first_outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let first = run_snapshot(
        &config(),
        &first_outbox,
        &mut transport,
        &mut first_process,
        SnapshotRunLimits {
            max_pages_per_run: 1,
            max_records_per_page: 2,
        },
    )
    .unwrap();
    assert_eq!(
        first,
        SnapshotRunOutcome::InProgress {
            pages_committed: 1,
            committed_cursor: Some(page_one_cursor.into()),
        }
    );
    drop(first_outbox);

    let restarted_outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let mut restarted_process = ScriptedPageSource::new([(
        Some(page_one_cursor),
        Ok(SnapshotRead::Page(SnapshotPage {
            records: snapshot_page_two(),
            proposed_next_cursor: complete_cursor.into(),
            collected_at_ms: 1_787_511_160_000,
            complete: true,
        })),
    )]);
    let restarted = run_snapshot(
        &config(),
        &restarted_outbox,
        &mut transport,
        &mut restarted_process,
        SnapshotRunLimits {
            max_pages_per_run: 1,
            max_records_per_page: 2,
        },
    )
    .unwrap();
    assert_eq!(
        restarted,
        SnapshotRunOutcome::Complete {
            pages_committed: 1,
            committed_cursor: complete_cursor.into(),
        }
    );
    assert_eq!(
        restarted_process.observed,
        [Some(page_one_cursor.to_string())]
    );
    object_sync_conformance::assert_snapshot_chain(&transport.applied).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn snapshot_runner_retains_ambiguous_page_and_replays_it_before_collecting_more() {
    let root = temporary_root("snapshot-ambiguous");
    let complete_cursor = "opaque:snapshot-c:complete";
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let mut source = ScriptedPageSource::new([(
        None,
        Ok(SnapshotRead::Page(SnapshotPage {
            records: snapshot_page_one(),
            proposed_next_cursor: complete_cursor.into(),
            collected_at_ms: 1_787_511_100_000,
            complete: true,
        })),
    )]);
    let mut transport = CheckpointTransport {
        failures: VecDeque::from([TransportFailure::Ambiguous]),
        ..Default::default()
    };
    let pending = run_snapshot(
        &config(),
        &outbox,
        &mut transport,
        &mut source,
        SnapshotRunLimits::default(),
    )
    .unwrap();
    assert_eq!(
        pending,
        SnapshotRunOutcome::Pending {
            pages_committed: 0,
            committed_cursor: None,
        }
    );
    assert_eq!(outbox.pending().unwrap().len(), 1);
    drop(outbox);

    let restarted_outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let mut restarted_source =
        ScriptedPageSource::new([(Some(complete_cursor), Ok(SnapshotRead::Complete))]);
    let complete = run_snapshot(
        &config(),
        &restarted_outbox,
        &mut transport,
        &mut restarted_source,
        SnapshotRunLimits::default(),
    )
    .unwrap();
    assert_eq!(
        complete,
        SnapshotRunOutcome::Complete {
            pages_committed: 0,
            committed_cursor: complete_cursor.into(),
        }
    );
    assert_eq!(transport.applied.len(), 2);
    assert_eq!(
        transport.applied[0].batch_digest,
        transport.applied[1].batch_digest
    );
    assert!(restarted_outbox.pending().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn snapshot_runner_never_flushes_another_binding_from_a_shared_outbox() {
    let root = temporary_root("snapshot-binding-scope");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let target_cursor = "opaque:snapshot-target:complete";
    let target = build_source_batch(
        &config(),
        "",
        target_cursor,
        1_787_511_100_000,
        snapshot_page_one(),
    )
    .unwrap();
    outbox.enqueue(&target).unwrap();

    let mut other_config = config();
    other_config.source_instance = "sannrox/other-repository".into();
    let mut other_records = snapshot_page_two();
    for record in &mut other_records {
        record.source_instance = other_config.source_instance.clone();
    }
    let other = build_source_batch(
        &other_config,
        "",
        "opaque:snapshot-other:complete",
        1_787_511_160_000,
        other_records,
    )
    .unwrap();
    outbox.enqueue(&other).unwrap();

    let mut transport = CheckpointTransport::default();
    let mut source = ScriptedPageSource::new([(Some(target_cursor), Ok(SnapshotRead::Complete))]);
    assert_eq!(
        run_snapshot(
            &config(),
            &outbox,
            &mut transport,
            &mut source,
            SnapshotRunLimits::default(),
        )
        .unwrap(),
        SnapshotRunOutcome::Complete {
            pages_committed: 0,
            committed_cursor: target_cursor.into(),
        }
    );
    assert_eq!(transport.applied.as_slice(), std::slice::from_ref(&target));
    assert_eq!(outbox.pending().unwrap(), [other]);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn snapshot_runner_does_not_treat_historical_replay_as_checkpoint_advance() {
    let root = temporary_root("snapshot-historical-replay");
    let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
    let cursor_a = "opaque:snapshot-cycle:a";
    let cursor_b = "opaque:snapshot-cycle:b";
    let mut transport = CheckpointTransport::default();
    let mut initial_source = ScriptedPageSource::new([
        (
            None,
            Ok(SnapshotRead::Page(SnapshotPage {
                records: snapshot_page_one(),
                proposed_next_cursor: cursor_a.into(),
                collected_at_ms: 1_787_511_100_000,
                complete: false,
            })),
        ),
        (
            Some(cursor_a),
            Ok(SnapshotRead::Page(SnapshotPage {
                records: snapshot_page_two(),
                proposed_next_cursor: cursor_b.into(),
                collected_at_ms: 1_787_511_160_000,
                complete: false,
            })),
        ),
    ]);
    assert_eq!(
        run_snapshot(
            &config(),
            &outbox,
            &mut transport,
            &mut initial_source,
            SnapshotRunLimits {
                max_pages_per_run: 2,
                max_records_per_page: 2,
            },
        )
        .unwrap(),
        SnapshotRunOutcome::InProgress {
            pages_committed: 2,
            committed_cursor: Some(cursor_b.into()),
        }
    );

    let mut cycle_records = snapshot_page_one();
    for record in &mut cycle_records {
        record.source_version.push_str("-cycle");
        record.payload_digest = format!("sha256:{}", "d".repeat(64));
    }
    let cycle = build_source_batch(
        &config(),
        cursor_b,
        cursor_a,
        1_787_511_220_000,
        cycle_records,
    )
    .unwrap();
    assert!(matches!(
        transport.apply_source_batch(&cycle).unwrap(),
        ApplySourceBatchReply::Committed { .. }
    ));
    assert_eq!(transport.state.current_cursor.as_deref(), Some(cursor_a));

    let mut replayed_source = ScriptedPageSource::new([(
        Some(cursor_a),
        Ok(SnapshotRead::Page(SnapshotPage {
            records: snapshot_page_two(),
            proposed_next_cursor: cursor_b.into(),
            collected_at_ms: 1_787_511_160_000,
            complete: true,
        })),
    )]);
    assert_eq!(
        run_snapshot(
            &config(),
            &outbox,
            &mut transport,
            &mut replayed_source,
            SnapshotRunLimits::default(),
        )
        .unwrap(),
        SnapshotRunOutcome::RecoveryRequired {
            pages_committed: 0,
            committed_cursor: Some(cursor_a.into()),
        }
    );
    assert_eq!(transport.state.current_cursor.as_deref(), Some(cursor_a));
    assert!(outbox.pending().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn snapshot_runner_fails_closed_for_open_foreign_and_invalid_progress() {
    let open_root = temporary_root("snapshot-open");
    let open_outbox = SourceOutbox::open(&open_root, OutboxLimits::default()).unwrap();
    let mut open_transport = CheckpointTransport {
        state: SourceSyncStateView {
            found: true,
            current_cursor: Some("opaque:snapshot-d:page-1".into()),
            open_transaction: true,
            last_committed_batch_digest: Some(format!("sha256:{}", "a".repeat(64))),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut unread = ScriptedPageSource::default();
    assert_eq!(
        run_snapshot(
            &config(),
            &open_outbox,
            &mut open_transport,
            &mut unread,
            SnapshotRunLimits::default(),
        )
        .unwrap(),
        SnapshotRunOutcome::RecoveryRequired {
            pages_committed: 0,
            committed_cursor: Some("opaque:snapshot-d:page-1".into()),
        }
    );
    assert!(unread.observed.is_empty());
    std::fs::remove_dir_all(open_root).unwrap();

    let foreign_root = temporary_root("snapshot-foreign");
    let foreign_outbox = SourceOutbox::open(&foreign_root, OutboxLimits::default()).unwrap();
    let mut foreign_transport = CheckpointTransport {
        state: SourceSyncStateView {
            found: false,
            current_cursor: Some("opaque:copied-from-another-binding".into()),
            open_transaction: false,
            last_committed_batch_digest: None,
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        run_snapshot(
            &config(),
            &foreign_outbox,
            &mut foreign_transport,
            &mut unread,
            SnapshotRunLimits::default(),
        )
        .unwrap(),
        SnapshotRunOutcome::RecoveryRequired {
            pages_committed: 0,
            committed_cursor: Some("opaque:copied-from-another-binding".into()),
        }
    );
    assert!(foreign_transport.applied.is_empty());
    std::fs::remove_dir_all(foreign_root).unwrap();

    let invalid_root = temporary_root("snapshot-invalid");
    let invalid_outbox = SourceOutbox::open(&invalid_root, OutboxLimits::default()).unwrap();
    let mut invalid_transport = CheckpointTransport::default();
    let mut invalid_source = ScriptedPageSource::new([(
        None,
        Ok(SnapshotRead::Page(SnapshotPage {
            records: snapshot_page_one(),
            proposed_next_cursor: "ghp_not-a-checkpoint".into(),
            collected_at_ms: 1_787_511_100_000,
            complete: false,
        })),
    )]);
    assert_eq!(
        run_snapshot(
            &config(),
            &invalid_outbox,
            &mut invalid_transport,
            &mut invalid_source,
            SnapshotRunLimits::default(),
        )
        .unwrap_err(),
        SnapshotRunError::InvalidPage
    );
    assert!(invalid_transport.applied.is_empty());
    assert!(invalid_outbox.pending().unwrap().is_empty());
    std::fs::remove_dir_all(invalid_root).unwrap();
}

#[test]
fn snapshot_runner_distinguishes_source_unavailable_from_invalid_input() {
    for (failure, expected) in [
        (
            SnapshotSourceFailure::Unavailable,
            SnapshotRunError::SourceUnavailable,
        ),
        (
            SnapshotSourceFailure::Invalid,
            SnapshotRunError::InvalidPage,
        ),
    ] {
        let root = temporary_root("snapshot-source-failure");
        let outbox = SourceOutbox::open(&root, OutboxLimits::default()).unwrap();
        let mut transport = CheckpointTransport::default();
        let mut source = ScriptedPageSource::new([(None, Err(failure))]);
        assert_eq!(
            run_snapshot(
                &config(),
                &outbox,
                &mut transport,
                &mut source,
                SnapshotRunLimits::default(),
            )
            .unwrap_err(),
            expected
        );
        assert!(transport.applied.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn github_adapter_rejects_foreign_invalid_secret_and_unbounded_input() {
    let fixture = github_object_sync::parse(include_bytes!(
        "../adapters/fixtures/github_object_sync.issue.json"
    ))
    .unwrap();
    assert!(github_object_sync::translate(fixture.clone(), "other/repository").is_err());
    assert!(github_object_sync::translate(fixture.clone(), "Sannrox/sekai-chisei").is_err());

    let mut invalid = fixture.clone();
    invalid.kind = "Discussion".into();
    assert!(
        github_object_sync::translate(invalid, "sannrox/sekai-chisei")
            .unwrap_err()
            .contains("Issue or PullRequest")
    );
    let mut invalid = fixture.clone();
    invalid.number = 0;
    assert!(github_object_sync::translate(invalid, "sannrox/sekai-chisei").is_err());
    let mut invalid = fixture.clone();
    invalid.revision.clear();
    assert!(github_object_sync::translate(invalid, "sannrox/sekai-chisei").is_err());
    let mut invalid = fixture;
    invalid
        .properties
        .insert("access_token".into(), "redacted".into());
    assert!(
        github_object_sync::translate(invalid, "sannrox/sekai-chisei")
            .unwrap_err()
            .contains("secret-like")
    );
    assert!(
        github_object_sync::parse(&vec![
            b'x';
            github_object_sync::MAX_GITHUB_FIXTURE_BYTES + 1
        ])
        .unwrap_err()
        .contains("byte limit")
    );
}

#[test]
fn state_transport_seam_reads_without_credentials() {
    let expected = SourceSyncStateView {
        found: true,
        current_cursor: Some("cursor:665".into()),
        open_transaction: false,
        last_committed_batch_digest: Some(format!("sha256:{}", "a".repeat(64))),
        ..Default::default()
    };
    let mut transport = ScriptedTransport {
        state: Some(expected.clone()),
        ..Default::default()
    };
    let state = transport
        .get_source_sync_state(&GetSourceSyncStateInput {
            namespace: "acme".into(),
            source_instance: "sannrox/sekai-chisei".into(),
            type_digest: TYPE_DIGEST.into(),
        })
        .unwrap();
    assert_eq!(state, expected);
}

#[test]
fn object_sync_is_absent_from_evidence_discovery() {
    let evidence = sekai_chisei::evidence_adapter_catalog::built_in_evidence_adapters();
    assert!(
        evidence
            .iter()
            .all(|profile| profile.adapter_id != "adapter.github.object_sync")
    );
    let families = sekai_chisei::evidence_adapter_catalog::built_in_evidence_adapter_families();
    assert!(
        families
            .iter()
            .all(|family| family.family != "source_control.object_sync")
    );

    let source = sekai_chisei::source_adapter_catalog::built_in_source_adapters();
    assert_eq!(source.len(), 1);
    assert_eq!(source[0].adapter_id, "adapter.github.object_sync");
    assert_eq!(source[0].type_digest, GITHUB_OBJECT_SYNC_TYPE_DIGEST);
}
