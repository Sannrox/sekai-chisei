//! Versioned source-adapter SDK and conformance kit.
//!
//! Out-of-process connectors depend on this crate. They never take a
//! dependency on the `sekai-chisei` control-plane package. The crate version
//! and `conformance_suite_digest()` are the pins connector certification
//! records.

pub mod change_capture;
pub mod conformance;
pub mod contract;
pub mod discover;
pub mod feed;
pub mod github;
pub mod lineage;
pub mod sdk;
pub mod snapshot;

pub use change_capture::{
    CHANGE_CAPTURE_CONFORMANCE_VERSION, CaptureEvent, CaptureSummary, CapturedChange,
    ChangeOperation, DriftHandling, PositionFamily, SchemaChangeClass, SourcePosition,
    assert_change_capture, change_capture_fixture,
};
pub use conformance::{
    LifecycleConformanceReport, LifecycleFixture, LifecycleObservation, LifecycleProjection,
    LifecycleStage, OBJECT_SYNC_LIFECYCLE_CONFORMANCE_VERSION, assert_cross_page_identity,
    assert_deterministic_batch, assert_deterministic_discovery, assert_files_omit,
    assert_lifecycle_report, assert_snapshot_chain, github_issue_lifecycle_fixture,
    run_check_conformance, run_lifecycle_fixture, run_restart_and_commit,
};
pub use contract::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, ADAPTER_REGISTERED_OBJECT_SYNC,
    ADAPTER_REGISTERED_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC, GITHUB_OBJECT_SYNC_RECORD_TYPES,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, GITHUB_OBJECT_SYNC_TYPE_REVISION, MAX_SOURCE_BATCH_RECORDS,
    MAX_SOURCE_CURSOR_BYTES, MAX_SOURCE_DISPLAY_NAME_BYTES, MAX_SOURCE_FEED_EPOCH_BYTES,
    MAX_SOURCE_IDENTIFIER_BYTES, MAX_SOURCE_PROPERTY_KEY_BYTES, MAX_SOURCE_PROPERTY_VALUE_BYTES,
    MAX_SOURCE_RECORD_PROPERTIES, OperationOutcome, ReplayDisposition, SOURCE_BATCH_V2_VERSION,
    SOURCE_BATCH_VERSION, SOURCE_GITHUB, SOURCE_TYPE_REVISION_VERSION, SourceBatch,
    SourceBatchReplayMaterial, SourceBatchResult, SourceBatchStatus, SourceBatchTransaction,
    SourceBatchValidationError, SourceBinding, SourceCheckpoint, SourceDeliveryMode,
    SourceDeliveryWindow, SourceRecord, SourceRecordResult, SourceSyncGeneration,
    SourceSyncGenerationStatus, SourceSyncState, SourceTypeRevisionDescriptor, SyncDecision,
    SyncedObject, contains_secret_like_text, detect_identity_conflict, is_schema_drift_denial,
    object_id_for, source_id, sync_github_record,
};
pub use discover::{
    ColumnProfileHint, ConnectionFailure, DescriptorDraft, DiscoveredColumn, DiscoveredRecordKind,
    MAX_DISCOVERED_COLUMNS, MAX_DISCOVERED_RECORD_KINDS, PROFILE_RATIO_SCALE,
    SOURCE_DISCOVERY_VERSION, SourceDiscovery, SourceInspector, column_name_suggests_sensitive,
};
pub use feed::{
    ChangeFeedPage, ChangeFeedRunError, ChangeFeedSource, ChangeFeedSourceFailure, run_change_feed,
};
pub use github::{
    DirectFeedCapability, GitHubObjectFixture, GitHubSource, MAX_GITHUB_FIXTURE_BYTES,
    direct_feed_capability, parse as parse_github_fixture, translate as translate_github_fixture,
};
pub use lineage::{
    LINEAGE_KIND_ACTION, LINEAGE_KIND_DATASET, LINEAGE_KIND_OBJECT, LINEAGE_KIND_SOURCE,
    LINEAGE_KIND_WRITEBACK, LineageNode, ObjectLineage, bind_sync_lineage, bind_writeback,
    dataset_id_for,
};
pub use sdk::{
    ApplySourceBatchReply, DEFAULT_MAX_ENTRY_BYTES, DEFAULT_MAX_PENDING_FILES, FlushDisposition,
    FlushEntry, FlushReport, GetSourceSyncStateInput, MAX_QUARANTINE_REASON_BYTES,
    OUTBOX_FORMAT_VERSION, OutboxLimits, SourceAdapterConfig, SourceGenerationStatus, SourceOutbox,
    SourceRunDisposition, SourceRunReport, SourceSyncStateView, SourceSyncTransport,
    TransportFailure, build_registered_source_batch, build_source_batch, build_source_batch_v2,
    serialize_source_batch,
};
pub use snapshot::{
    DEFAULT_MAX_SNAPSHOT_PAGES_PER_RUN, GenerationSnapshotPage, GenerationSnapshotRead,
    GenerationSnapshotSource, SnapshotPage, SnapshotPageSource, SnapshotRead, SnapshotRunError,
    SnapshotRunLimits, SnapshotRunOutcome, SnapshotSourceFailure, run_generation_snapshot_v2,
    run_snapshot,
};

/// Crate version adapters and certifications pin.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Digest of the crate version, batch contract versions, and the conformance
/// suite source. Connector certifications record this next to the test-suite
/// digest so a suite-behavior change cannot keep the previous pin.
pub fn conformance_suite_digest() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(SDK_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(OBJECT_SYNC_LIFECYCLE_CONFORMANCE_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(SOURCE_BATCH_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(SOURCE_BATCH_V2_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(SOURCE_DISCOVERY_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(include_str!("conformance.rs").as_bytes());
    hasher.update(b"\n");
    hasher.update(CHANGE_CAPTURE_CONFORMANCE_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(include_str!("change_capture.rs").as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_version_is_semver() {
        let mut parts = SDK_VERSION.split('.');
        assert!(parts.next().unwrap().parse::<u64>().is_ok());
        assert!(parts.next().unwrap().parse::<u64>().is_ok());
        assert!(parts.next().unwrap().parse::<u64>().is_ok());
    }

    #[test]
    fn conformance_digest_is_stable_for_this_version() {
        let first = conformance_suite_digest();
        let second = conformance_suite_digest();
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), "sha256:".len() + 64);
        use sha2::{Digest, Sha256};
        let mut versions_only = Sha256::new();
        versions_only.update(SDK_VERSION.as_bytes());
        versions_only.update(b"\n");
        versions_only.update(OBJECT_SYNC_LIFECYCLE_CONFORMANCE_VERSION.as_bytes());
        versions_only.update(b"\n");
        versions_only.update(SOURCE_BATCH_VERSION.as_bytes());
        versions_only.update(b"\n");
        versions_only.update(SOURCE_BATCH_V2_VERSION.as_bytes());
        versions_only.update(b"\n");
        let versions_only = format!("sha256:{:x}", versions_only.finalize());
        assert_ne!(
            first, versions_only,
            "digest must bind conformance.rs, not only version strings"
        );
    }
}
