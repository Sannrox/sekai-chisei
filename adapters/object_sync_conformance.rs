//! Reusable offline conformance checks for source-sync transports and outboxes.

use crate::object_sync_sdk::{FlushDisposition, OutboxLimits, SourceOutbox, SourceSyncTransport};
use sekai_chisei::sekai::object_lineage::{
    LINEAGE_KIND_DATASET, LINEAGE_KIND_OBJECT, LINEAGE_KIND_SOURCE, ObjectLineage,
    bind_sync_lineage, dataset_id_for,
};
use sekai_chisei::sekai::object_sync::{
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_GITHUB, SourceBatch, SourceRecord, SyncDecision,
    SyncedObject, sync_github_record,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const OBJECT_SYNC_LIFECYCLE_CONFORMANCE_VERSION: &str =
    "sekai.object-sync-lifecycle-conformance/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleStage {
    Initial,
    Refresh,
    Tombstone,
    Reversal,
    ImmutableRevisionConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleObservation {
    pub stage: LifecycleStage,
    pub source_instance: String,
    pub external_id: String,
    pub source_version: String,
    pub type_name: String,
    pub display_name: String,
    pub state: String,
    pub deleted: bool,
    pub observed_at_ms: i64,
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleFixture {
    pub contract_version: String,
    pub observations: Vec<LifecycleObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleProjection {
    pub stage: LifecycleStage,
    pub record: SourceRecord,
    pub decision: SyncDecision,
    pub lineage: ObjectLineage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleConformanceReport {
    pub contract_version: String,
    pub adapter_id: String,
    pub type_digest: String,
    pub projections: Vec<LifecycleProjection>,
}

#[derive(Serialize)]
struct ExpectedGitHubPayload<'a> {
    repository: &'a str,
    kind: &'a str,
    number: u64,
    revision: &'a str,
    title: &'a str,
    state: &'a str,
    deleted: bool,
    properties: &'a BTreeMap<String, String>,
}

pub fn github_issue_lifecycle_fixture() -> LifecycleFixture {
    let observation =
        |stage, source_version: &str, display_name: &str, state: &str, deleted, observed_at_ms| {
            LifecycleObservation {
                stage,
                source_instance: "sannrox/sekai-chisei".into(),
                external_id: "674".into(),
                source_version: source_version.into(),
                type_name: "Issue".into(),
                display_name: display_name.into(),
                state: state.into(),
                deleted,
                observed_at_ms,
                properties: BTreeMap::from([("author".into(), "sannrox".into())]),
            }
        };
    LifecycleFixture {
        contract_version: OBJECT_SYNC_LIFECYCLE_CONFORMANCE_VERSION.into(),
        observations: vec![
            observation(
                LifecycleStage::Initial,
                "issue-674-v1",
                "Connector lifecycle conformance",
                "open",
                false,
                1_787_510_500_000,
            ),
            observation(
                LifecycleStage::Refresh,
                "issue-674-v2",
                "Enforce connector lifecycle conformance",
                "closed",
                false,
                1_787_510_560_000,
            ),
            observation(
                LifecycleStage::Tombstone,
                "issue-674-v3",
                "Enforce connector lifecycle conformance",
                "deleted",
                true,
                1_787_510_620_000,
            ),
            observation(
                LifecycleStage::Reversal,
                "issue-674-v4",
                "Enforce connector lifecycle conformance",
                "open",
                false,
                1_787_510_680_000,
            ),
            observation(
                LifecycleStage::ImmutableRevisionConflict,
                "issue-674-v4",
                "Conflicting immutable revision",
                "open",
                false,
                1_787_510_740_000,
            ),
        ],
    }
}

pub fn run_lifecycle_fixture<F>(
    adapter_id: &str,
    mut normalize: F,
) -> Result<LifecycleConformanceReport, String>
where
    F: FnMut(&LifecycleObservation) -> Result<SourceRecord, String>,
{
    let fixture = github_issue_lifecycle_fixture();
    let mut projections = Vec::with_capacity(fixture.observations.len());
    for observation in &fixture.observations {
        let record = normalize(observation)?;
        let decision = sync_github_record(record.clone(), GITHUB_OBJECT_SYNC_TYPE_DIGEST);
        let object = projected_object(&decision)
            .ok_or_else(|| "lifecycle fixture did not produce a projectable object".to_string())?;
        let lineage = bind_sync_lineage(
            GITHUB_OBJECT_SYNC_TYPE_DIGEST,
            &object.source_id,
            &object.type_name,
            &object.object_id,
        )?;
        projections.push(LifecycleProjection {
            stage: observation.stage,
            record,
            decision,
            lineage,
        });
    }
    Ok(LifecycleConformanceReport {
        contract_version: fixture.contract_version,
        adapter_id: adapter_id.into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        projections,
    })
}

pub fn assert_lifecycle_report(report: &LifecycleConformanceReport) -> Result<(), String> {
    let fixture = github_issue_lifecycle_fixture();
    if report.contract_version != OBJECT_SYNC_LIFECYCLE_CONFORMANCE_VERSION
        || report.type_digest != GITHUB_OBJECT_SYNC_TYPE_DIGEST
        || report.adapter_id.trim().is_empty()
    {
        return Err("lifecycle report contract binding diverged".into());
    }
    if report.projections.len() != fixture.observations.len() {
        return Err("lifecycle report does not contain every required stage".into());
    }

    for (projection, observation) in report.projections.iter().zip(&fixture.observations) {
        let expected_payload_digest = expected_github_payload_digest(observation)?;
        let mut expected_properties = observation.properties.clone();
        expected_properties.insert("state".into(), observation.state.clone());
        if projection.stage != observation.stage
            || projection.record.source != SOURCE_GITHUB
            || projection.record.source_instance != observation.source_instance
            || projection.record.external_id != observation.external_id
            || projection.record.source_version != observation.source_version
            || projection.record.type_name != observation.type_name
            || projection.record.display_name != observation.display_name
            || projection.record.deleted != observation.deleted
            || projection.record.observed_at_ms != observation.observed_at_ms
            || projection.record.properties != expected_properties
        {
            return Err("normalized lifecycle observation diverged from the fixed fixture".into());
        }
        if projection.record.payload_digest != expected_payload_digest {
            return Err("normalized lifecycle payload digest diverged from canonical input".into());
        }
        if projection.record.source_sequence.is_some() {
            return Err("snapshot lifecycle record unexpectedly included a source sequence".into());
        }

        let expected_decision = sync_github_record(projection.record.clone(), &report.type_digest);
        if projection.decision != expected_decision {
            return Err("projected lifecycle decision diverged from normalized input".into());
        }
        let object = projected_object(&projection.decision)
            .ok_or_else(|| "lifecycle stage was rejected instead of projected".to_string())?;
        let expected_lineage = bind_sync_lineage(
            &report.type_digest,
            &object.source_id,
            &object.type_name,
            &object.object_id,
        )?;
        if projection.lineage != expected_lineage {
            return Err("source-to-dataset-to-object lineage binding diverged".into());
        }
        assert_lineage_shape(&projection.lineage, object)?;
        match projection.stage {
            LifecycleStage::Tombstone
                if !matches!(projection.decision, SyncDecision::Tombstone(_)) =>
            {
                return Err("tombstone stage did not tombstone the projected object".into());
            }
            LifecycleStage::Initial
            | LifecycleStage::Refresh
            | LifecycleStage::Reversal
            | LifecycleStage::ImmutableRevisionConflict
                if !matches!(projection.decision, SyncDecision::Upsert(_)) =>
            {
                return Err("active lifecycle stage did not upsert the projected object".into());
            }
            LifecycleStage::Initial
            | LifecycleStage::Refresh
            | LifecycleStage::Tombstone
            | LifecycleStage::Reversal
            | LifecycleStage::ImmutableRevisionConflict => {}
        }
    }

    let first_four = &report.projections[..4];
    let initial = projected_object(&first_four[0].decision).expect("validated initial projection");
    for projection in first_four {
        let object =
            projected_object(&projection.decision).expect("validated lifecycle projection");
        if object.source_id != initial.source_id
            || object.object_id != initial.object_id
            || object.type_name != initial.type_name
            || object.type_digest != initial.type_digest
            || projection.lineage.source_id != report.projections[0].lineage.source_id
            || projection.lineage.dataset_id != report.projections[0].lineage.dataset_id
            || projection.lineage.object_id != report.projections[0].lineage.object_id
        {
            return Err(
                "lifecycle refresh changed stable source, object, type, or lineage identity".into(),
            );
        }
    }
    if projected_object(&first_four[2].decision).is_none_or(|object| !object.tombstoned)
        || projected_object(&first_four[3].decision).is_none_or(|object| object.tombstoned)
    {
        return Err("tombstone reversal did not reactivate the same object identity".into());
    }

    let current =
        projected_object(&report.projections[3].decision).expect("validated reversal projection");
    let conflict =
        projected_object(&report.projections[4].decision).expect("validated conflict projection");
    if conflict.source_id != current.source_id
        || conflict.object_id != current.object_id
        || conflict.type_name != current.type_name
        || conflict.type_digest != current.type_digest
        || conflict.source_version != current.source_version
        || conflict.payload_digest == current.payload_digest
    {
        return Err(
            "current immutable-revision conflict was not preserved for fail-closed detection"
                .into(),
        );
    }
    Ok(())
}

fn expected_github_payload_digest(observation: &LifecycleObservation) -> Result<String, String> {
    let number = observation
        .external_id
        .parse::<u64>()
        .map_err(|_| "lifecycle fixture external id is invalid".to_string())?;
    let mut properties = observation.properties.clone();
    properties.insert("state".into(), observation.state.clone());
    let payload = ExpectedGitHubPayload {
        repository: &observation.source_instance,
        kind: &observation.type_name,
        number,
        revision: &observation.source_version,
        title: &observation.display_name,
        state: &observation.state,
        deleted: observation.deleted,
        properties: &properties,
    };
    let canonical = serde_json::to_vec(&payload)
        .map_err(|_| "lifecycle payload cannot be canonicalized".to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

fn projected_object(decision: &SyncDecision) -> Option<&SyncedObject> {
    match decision {
        SyncDecision::Upsert(object) | SyncDecision::Tombstone(object) => Some(object),
        SyncDecision::Conflict { .. } | SyncDecision::Reject { .. } => None,
    }
}

fn assert_lineage_shape(lineage: &ObjectLineage, object: &SyncedObject) -> Result<(), String> {
    let expected_dataset = dataset_id_for(&object.type_digest, &object.type_name);
    if lineage.type_digest != object.type_digest
        || lineage.source_id != object.source_id
        || lineage.dataset_id != expected_dataset
        || lineage.object_id != object.object_id
        || lineage.nodes.len() != 3
        || lineage.nodes[0].kind != LINEAGE_KIND_SOURCE
        || lineage.nodes[0].id != object.source_id
        || lineage.nodes[1].kind != LINEAGE_KIND_DATASET
        || lineage.nodes[1].id != expected_dataset
        || lineage.nodes[2].kind != LINEAGE_KIND_OBJECT
        || lineage.nodes[2].id != object.object_id
    {
        return Err("lineage is not the required source-to-dataset-to-object chain".into());
    }
    Ok(())
}

pub fn assert_deterministic_batch(first: &SourceBatch, second: &SourceBatch) -> Result<(), String> {
    if first.idempotency_key != second.idempotency_key
        || first.batch_digest != second.batch_digest
        || first.records != second.records
    {
        return Err("source adapter batch construction is not deterministic".into());
    }
    Ok(())
}

pub fn assert_snapshot_chain(batches: &[SourceBatch]) -> Result<(), String> {
    if batches.is_empty() || !batches[0].current_cursor.is_empty() {
        return Err("snapshot chain did not start without a committed checkpoint".into());
    }
    for pair in batches.windows(2) {
        if pair[0].proposed_next_cursor != pair[1].current_cursor {
            return Err("snapshot page did not resume from the prior committed cursor".into());
        }
        if pair[0].idempotency_key == pair[1].idempotency_key
            || pair[0].batch_digest == pair[1].batch_digest
        {
            return Err("distinct snapshot pages reused batch identity".into());
        }
    }
    Ok(())
}

pub fn assert_cross_page_identity(
    first: &SourceBatch,
    second: &SourceBatch,
    source_id: &str,
) -> Result<(), String> {
    let first_record = first
        .records
        .iter()
        .find(|record| record.source_id() == source_id)
        .ok_or_else(|| "snapshot page one is missing the shared source identity".to_string())?;
    let second_record = second
        .records
        .iter()
        .find(|record| record.source_id() == source_id)
        .ok_or_else(|| "snapshot page two is missing the shared source identity".to_string())?;
    if first_record.type_name != second_record.type_name
        || first_record.source_version == second_record.source_version
    {
        return Err("cross-page source identity was not a compatible refresh".into());
    }
    Ok(())
}

pub fn run_restart_and_commit<T: SourceSyncTransport>(
    root: &Path,
    batch: &SourceBatch,
    ambiguous: &mut T,
    committed: &mut T,
) -> Result<(), String> {
    let outbox = SourceOutbox::open(root, OutboxLimits::default())?;
    outbox.enqueue(batch)?;
    let first = outbox.flush(ambiguous, true)?;
    if first.entries.len() != 1
        || first.entries[0].disposition != FlushDisposition::Pending
        || outbox.pending()?.len() != 1
    {
        return Err("ambiguous source delivery did not remain pending".into());
    }

    let restarted = SourceOutbox::open(root, OutboxLimits::default())?;
    if restarted.pending()? != [batch.clone()] {
        return Err("source outbox did not recover the exact pending batch".into());
    }
    let second = restarted.flush(committed, true)?;
    if second.entries.len() != 1
        || second.entries[0].disposition != FlushDisposition::Committed
        || !restarted.pending()?.is_empty()
    {
        return Err("exact committed source delivery was not removed".into());
    }
    Ok(())
}

pub fn assert_files_omit(root: &Path, forbidden: &[&str]) -> Result<(), String> {
    if !root.exists() {
        return Ok(());
    }
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory)
            .map_err(|_| "failed to inspect source conformance files".to_string())?
        {
            let entry =
                entry.map_err(|_| "failed to inspect source conformance files".to_string())?;
            let metadata = entry
                .metadata()
                .map_err(|_| "failed to inspect source conformance file".to_string())?;
            if metadata.is_dir() {
                directories.push(entry.path());
                continue;
            }
            let bytes = fs::read(entry.path())
                .map_err(|_| "failed to read source conformance file".to_string())?;
            let text = String::from_utf8_lossy(&bytes);
            if forbidden.iter().any(|value| text.contains(value)) {
                return Err("source adapter persisted forbidden sensitive data".into());
            }
        }
    }
    Ok(())
}
