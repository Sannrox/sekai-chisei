//! The SDK conformance kit against the fake source, wired the way the
//! connector runs: outbox, one transaction per batch, plane-owned cursor.

use sekai_connector_template::config::ConnectorConfig;
use sekai_connector_template::fake::{FakeSource, RECORD_KIND, SCHEMA_REVISION};
use sekai_connector_template::{RunOutcome, run_once};
use sekai_source_sdk::{
    ApplySourceBatchReply, GetSourceSyncStateInput, OutboxLimits, SnapshotPageSource, SnapshotRead,
    SnapshotSourceFailure, SourceBatch, SourceOutbox, SourceSyncStateView, SourceSyncTransport,
    TransportFailure, assert_deterministic_discovery, assert_snapshot_chain, run_check_conformance,
};
use std::path::Path;

/// In-memory plane: commits every valid batch that resumes from its cursor,
/// unless it denies the descriptor.
#[derive(Default)]
struct Plane {
    cursor: Option<String>,
    committed: Vec<SourceBatch>,
    deny: bool,
}

impl SourceSyncTransport for Plane {
    fn apply_source_batch(
        &mut self,
        batch: &SourceBatch,
    ) -> Result<ApplySourceBatchReply, TransportFailure> {
        if self.deny
            || batch.validate().is_err()
            || batch.current_cursor != self.cursor.clone().unwrap_or_default()
        {
            return Ok(ApplySourceBatchReply::Rejected {
                reason_code: "denial".into(),
            });
        }
        self.cursor = Some(batch.proposed_next_cursor.clone());
        self.committed.push(batch.clone());
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
        Ok(SourceSyncStateView {
            found: self.cursor.is_some(),
            current_cursor: self.cursor.clone(),
            ..SourceSyncStateView::default()
        })
    }
}

fn config() -> ConnectorConfig {
    ConnectorConfig::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("connector.json")).unwrap()
}

#[test]
fn shipped_config_references_credentials_by_name() {
    let config = config();
    assert_eq!(config.credential_env, "SEKAI_CREDENTIAL");
    assert_eq!(config.source_credential_env, "CONNECTOR_SOURCE_CREDENTIAL");
}

#[test]
fn check_reads_no_records_and_discovery_drafts_one_descriptor() {
    let config = config();
    let mut source = FakeSource::new(&config.source, &config.source_instance);
    assert_eq!(
        run_check_conformance(&mut source, FakeSource::records_read),
        Ok(Ok(()))
    );
    let drafts = assert_deterministic_discovery(&mut source)
        .unwrap()
        .descriptor_drafts()
        .unwrap();
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].source, config.source);
    assert_eq!(drafts[0].record_kind, RECORD_KIND);
    assert_eq!(drafts[0].schema_revision, SCHEMA_REVISION);
}

#[test]
fn run_commits_one_batch_per_page_through_the_final_page() {
    let config = config();
    let root = tempfile::tempdir().unwrap();
    let outbox = SourceOutbox::open(root.path(), OutboxLimits::default()).unwrap();
    let mut source = FakeSource::new(&config.source, &config.source_instance);
    let mut plane = Plane::default();

    let mut outcomes = Vec::new();
    loop {
        let outcome = run_once(&config, &outbox, &mut source, &mut plane).unwrap();
        outcomes.push(outcome.clone());
        if !matches!(
            outcome,
            RunOutcome::Committed {
                complete: false,
                ..
            }
        ) {
            break;
        }
    }
    assert_eq!(
        outcomes,
        [
            RunOutcome::Committed {
                cursor: "page-1".into(),
                complete: false,
            },
            RunOutcome::Committed {
                cursor: "page-2".into(),
                complete: true,
            },
        ]
    );
    assert_snapshot_chain(&plane.committed).unwrap();
    assert_eq!(
        run_once(&config, &outbox, &mut source, &mut plane),
        Ok(RunOutcome::UpToDate)
    );
    assert!(outbox.pending().unwrap().is_empty());
}

#[test]
fn a_rejected_batch_is_quarantined_not_retried() {
    let config = config();
    let root = tempfile::tempdir().unwrap();
    let outbox = SourceOutbox::open(root.path(), OutboxLimits::default()).unwrap();
    let mut source = FakeSource::new(&config.source, &config.source_instance);
    let mut plane = Plane {
        deny: true,
        ..Plane::default()
    };
    let outcome = run_once(&config, &outbox, &mut source, &mut plane);
    assert_eq!(outcome, Ok(RunOutcome::Quarantined));
    assert!(outbox.pending().unwrap().is_empty());
}

#[test]
fn a_page_that_repeats_the_committed_cursor_is_refused() {
    /// Returns the fake's first page but never moves past it.
    struct Stuck(FakeSource);
    impl SnapshotPageSource for Stuck {
        fn read_page(
            &mut self,
            _committed_cursor: Option<&str>,
            max_records: usize,
        ) -> Result<SnapshotRead, SnapshotSourceFailure> {
            self.0.read_page(None, max_records)
        }
    }
    let config = config();
    let root = tempfile::tempdir().unwrap();
    let outbox = SourceOutbox::open(root.path(), OutboxLimits::default()).unwrap();
    let mut source = Stuck(FakeSource::new(&config.source, &config.source_instance));
    let mut plane = Plane::default();
    assert_eq!(
        run_once(&config, &outbox, &mut source, &mut plane),
        Ok(RunOutcome::Committed {
            cursor: "page-1".into(),
            complete: false,
        })
    );
    assert!(run_once(&config, &outbox, &mut source, &mut plane).is_err());
    assert_eq!(plane.committed.len(), 1);
}

#[test]
fn another_bindings_pending_batch_is_left_alone() {
    let config = config();
    let root = tempfile::tempdir().unwrap();
    let outbox = SourceOutbox::open(root.path(), OutboxLimits::default()).unwrap();
    let other = ConnectorConfig {
        source_instance: "other".into(),
        ..config.clone()
    };
    let mut other_source = FakeSource::new(&other.source, &other.source_instance);
    // Leave the other binding's first page pending in the shared outbox.
    let SnapshotRead::Page(page) = other_source.read_page(None, 10).unwrap() else {
        panic!("fake has a first page");
    };
    let pending = sekai_source_sdk::build_registered_source_batch(
        &other.adapter(),
        &other.source,
        "",
        &page.proposed_next_cursor,
        page.collected_at_ms,
        page.records,
    )
    .unwrap();
    outbox.enqueue(&pending).unwrap();

    let mut plane = Plane::default();
    let mut source = FakeSource::new(&config.source, &config.source_instance);
    assert_eq!(
        run_once(&config, &outbox, &mut source, &mut plane),
        Ok(RunOutcome::Committed {
            cursor: "page-1".into(),
            complete: false,
        })
    );
    assert!(
        plane
            .committed
            .iter()
            .all(|batch| batch.source_instance == config.source_instance)
    );
    assert_eq!(outbox.pending().unwrap(), [pending]);
}

#[test]
fn a_credential_never_goes_to_a_remote_plaintext_target() {
    let refused = sekai_connector_template::transport::GrpcTransport::connect(
        "http://plane.invalid:50051",
        Some("token".into()),
    );
    assert!(refused.is_err_and(|error| error.contains("https")));
}

#[test]
fn completion_before_any_committed_page_is_refused() {
    struct Empty;
    impl SnapshotPageSource for Empty {
        fn read_page(
            &mut self,
            _committed_cursor: Option<&str>,
            _max_records: usize,
        ) -> Result<SnapshotRead, SnapshotSourceFailure> {
            Ok(SnapshotRead::Complete)
        }
    }
    let config = config();
    let root = tempfile::tempdir().unwrap();
    let outbox = SourceOutbox::open(root.path(), OutboxLimits::default()).unwrap();
    assert!(run_once(&config, &outbox, &mut Empty, &mut Plane::default()).is_err());
}
