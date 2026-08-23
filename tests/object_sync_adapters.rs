#[path = "../adapters/github_object_sync.rs"]
mod github_object_sync;
#[path = "../adapters/object_sync_conformance.rs"]
mod object_sync_conformance;
#[path = "../adapters/object_sync_sdk.rs"]
mod object_sync_sdk;

use object_sync_sdk::{
    ApplySourceBatchReply, GetSourceSyncStateInput, OutboxLimits, SourceAdapterConfig,
    SourceOutbox, SourceSyncStateView, SourceSyncTransport, TransportFailure, build_source_batch,
    serialize_source_batch,
};
use sekai_chisei::sekai::object_sync::{GITHUB_OBJECT_SYNC_TYPE_DIGEST, SourceBatch, SourceRecord};
use std::collections::VecDeque;
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
