//! Bounded inbound object sync from one system of record.
//!
//! Adapters collect records and propose a next opaque cursor. The control plane
//! validates and commits the complete batch before it advances its checkpoint.
//! This is not a pipeline product.
//!
//! Contract types live in `sekai-source-sdk` so out-of-process adapters can
//! depend on a versioned crate. This module re-exports them and keeps
//! control-plane classification that needs definition-diff.

pub use sekai_source_sdk::{
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

pub fn classify_source_record_compatibility(
    admitted: Option<&SyncedObject>,
    incoming: &SyncedObject,
) -> crate::sekai::definition_diff::DefinitionCompatibilityClass {
    use crate::sekai::definition_diff::DefinitionCompatibilityClass;
    let Some(admitted) = admitted else {
        return DefinitionCompatibilityClass::Compatible;
    };
    if detect_identity_conflict(admitted, incoming).is_some()
        || admitted.type_name != incoming.type_name
    {
        return DefinitionCompatibilityClass::Breaking;
    }
    if admitted.source_version == incoming.source_version
        && (admitted.payload_digest != incoming.payload_digest
            || admitted.properties != incoming.properties)
    {
        return DefinitionCompatibilityClass::Breaking;
    }
    DefinitionCompatibilityClass::Compatible
}

/// Per-record quarantine reason. Compatible siblings in a quarantined batch
/// are labeled `batch_quarantined` instead of inheriting another record's
/// conflict code.
pub fn schema_quarantine_record_reason(
    binding_type_digest: &str,
    batch_type_digest: &str,
    admitted: Option<&SyncedObject>,
    incoming: &SyncedObject,
    batch_reason: &str,
) -> String {
    use crate::sekai::definition_diff::DefinitionCompatibilityClass;
    if binding_type_digest != batch_type_digest {
        return batch_reason.to_string();
    }
    match classify_source_record_compatibility(admitted, incoming) {
        DefinitionCompatibilityClass::Breaking => {
            if admitted.is_some_and(|admitted| {
                detect_identity_conflict(admitted, incoming).is_some()
                    || admitted.type_name != incoming.type_name
            }) {
                "type_identity_conflict: source identity conflicts with its bound type or graph object"
                    .into()
            } else {
                "source_revision_conflict: immutable source version is bound to different payload content"
                    .into()
            }
        }
        _ => format!("batch_quarantined: {batch_reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    const TYPE_DIGEST: &str = GITHUB_OBJECT_SYNC_TYPE_DIGEST;
    const PAYLOAD_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn issue() -> SourceRecord {
        SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            external_id: "12".into(),
            source_version: "issue-node-v7".into(),
            type_name: "Issue".into(),
            display_name: "Broken deploy".into(),
            payload_digest: PAYLOAD_DIGEST.into(),
            properties: BTreeMap::from([
                ("state".into(), "open".into()),
                ("title".into(), "Broken deploy".into()),
            ]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        }
    }

    fn valid_batch() -> SourceBatch {
        let mut batch = SourceBatch {
            contract_version: SOURCE_BATCH_VERSION.into(),
            namespace: "acme".into(),
            producer_identity: "connector/github-primary".into(),
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            family: FAMILY_OBJECT_SYNC.into(),
            adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
            adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
            type_digest: TYPE_DIGEST.into(),
            current_cursor: "cursor:41".into(),
            proposed_next_cursor: "cursor:42".into(),
            idempotency_key: "batch-42".into(),
            batch_digest: String::new(),
            collected_at_ms: 20,
            records: vec![issue()],
            delivery: None,
        };
        batch.batch_digest = batch.canonical_digest().unwrap();
        batch
    }

    fn valid_v2_snapshot() -> SourceBatch {
        let mut batch = valid_batch();
        batch.contract_version = SOURCE_BATCH_V2_VERSION.into();
        batch.delivery = Some(SourceDeliveryWindow {
            mode: SourceDeliveryMode::Snapshot,
            sync_generation: 1,
            source_feed_epoch: Some("github-events-2026-08".into()),
            offset_start: None,
            offset_end: Some(40),
            snapshot_complete: true,
        });
        batch.batch_digest = batch.canonical_digest().unwrap();
        batch
    }

    fn valid_v2_change_feed() -> SourceBatch {
        let mut batch = valid_batch();
        batch.contract_version = SOURCE_BATCH_V2_VERSION.into();
        batch.current_cursor = "cursor:40".into();
        batch.proposed_next_cursor = "cursor:42".into();
        batch.records[0].source_sequence = Some(41);
        let mut second = issue();
        second.external_id = "13".into();
        second.source_sequence = Some(42);
        batch.records.push(second);
        batch.delivery = Some(SourceDeliveryWindow {
            mode: SourceDeliveryMode::ChangeFeed,
            sync_generation: 1,
            source_feed_epoch: Some("github-events-2026-08".into()),
            offset_start: Some(40),
            offset_end: Some(42),
            snapshot_complete: false,
        });
        batch.batch_digest = batch.canonical_digest().unwrap();
        batch
    }

    #[test]
    fn valid_source_batch_is_admitted() {
        let batch = valid_batch();
        batch
            .validate_for_producer("connector/github-primary")
            .unwrap();
        assert_eq!(
            batch.server_validation_outcome("connector/github-primary"),
            OperationOutcome::Success
        );
        assert_eq!(
            batch
                .validate_for_producer("connector/foreign")
                .unwrap_err()
                .code,
            "producer_identity_mismatch"
        );
        assert_eq!(
            batch.server_validation_outcome("connector/foreign"),
            OperationOutcome::Denial
        );
    }

    #[test]
    fn github_type_revision_descriptor_and_digest_are_fixed() {
        let material = "sekai.source-type-revision/v1\nsource_control.object_sync\ngithub\nIssue\nPullRequest\n";
        assert_eq!(
            GITHUB_OBJECT_SYNC_TYPE_REVISION,
            SourceTypeRevisionDescriptor {
                contract_version: SOURCE_TYPE_REVISION_VERSION,
                family: FAMILY_OBJECT_SYNC,
                source: SOURCE_GITHUB,
                record_types: &["Issue", "PullRequest"],
                digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST,
            }
        );
        assert_eq!(
            format!("sha256:{:x}", Sha256::digest(material)),
            GITHUB_OBJECT_SYNC_TYPE_DIGEST
        );
    }

    #[test]
    fn unbound_type_revision_fails_closed() {
        let mut batch = valid_batch();
        batch.type_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        batch.batch_digest = batch.canonical_digest().unwrap();
        assert_eq!(batch.validate().unwrap_err().code, "unbound_type_revision");
    }

    #[test]
    fn canonical_digest_is_stable_across_collection_time() {
        let first = valid_batch();
        let mut second = first.clone();
        second.collected_at_ms += 9_000;
        assert_eq!(
            first.canonical_digest().unwrap(),
            second.canonical_digest().unwrap()
        );
        assert!(second.validate().is_ok());
    }

    #[test]
    fn v1_canonical_digest_matches_pre_v2_golden() {
        assert_eq!(
            valid_batch().canonical_digest().unwrap(),
            "sha256:ce53c092fa3bbff8d70fb0f07ea4140977fe38f6832eaba0f4a9eae29f33d6fa"
        );
    }

    #[test]
    fn valid_v2_snapshot_and_change_feed_are_admitted() {
        valid_v2_snapshot().validate().unwrap();
        valid_v2_change_feed().validate().unwrap();
    }

    #[test]
    fn persisted_v1_result_json_deserializes_with_additive_state_defaults() {
        let json = serde_json::json!({
            "transaction": {
                "transaction_id": "tx-1",
                "binding_id": "binding-1",
                "namespace": "acme",
                "producer_identity": "connector/github-primary",
                "idempotency_key": "batch-1",
                "batch_digest": format!("sha256:{}", "a".repeat(64)),
                "current_cursor": "",
                "proposed_next_cursor": "cursor:1",
                "status": "COMMITTED",
                "outcome": "success",
                "opened_at_ms": 10,
                "closed_at_ms": 11,
                "reason": "committed"
            },
            "records": [{
                "transaction_id": "tx-1",
                "source_id": "github:acme/ops#12",
                "source_version": "node-v1",
                "decision": {
                    "upsert": {
                        "object_id": "object-1",
                        "type_name": "Issue",
                        "source_id": "github:acme/ops#12",
                        "source_version": "node-v1",
                        "payload_digest": PAYLOAD_DIGEST,
                        "properties": {},
                        "tombstoned": false,
                        "type_digest": TYPE_DIGEST
                    }
                },
                "outcome": "success",
                "reason": "upserted"
            }],
            "checkpoint_advanced": true
        });
        let result: SourceBatchResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.transaction.contract_version, SOURCE_BATCH_VERSION);
        assert!(result.transaction.delivery_mode.is_none());
        assert!(result.transaction.sync_generation.is_none());
        assert!(result.records[0].source_sequence.is_none());
    }

    #[test]
    fn generation_state_serde_uses_stable_status_vocabulary() {
        let generation = SourceSyncGeneration {
            binding_id: "binding-1".into(),
            sync_generation: 2,
            status: SourceSyncGenerationStatus::RecoveryRequired,
            delivery_mode: SourceDeliveryMode::ChangeFeed,
            source_feed_epoch: Some("epoch-1".into()),
            committed_offset: Some(42),
            reason: "missing_range".into(),
            created_at_ms: 10,
            updated_at_ms: 20,
        };
        let json = serde_json::to_value(&generation).unwrap();
        assert_eq!(json["status"], "RECOVERY_REQUIRED");
        assert_eq!(
            serde_json::from_value::<SourceSyncGeneration>(json).unwrap(),
            generation
        );
    }

    #[test]
    fn delivery_positions_above_signed_storage_range_fail_stably() {
        let mut batch = valid_v2_change_feed();
        batch.delivery.as_mut().unwrap().offset_end = Some(i64::MAX as u64 + 1);
        batch.records[1].source_sequence = Some(i64::MAX as u64 + 1);
        batch.batch_digest = batch.canonical_digest().unwrap();
        assert_eq!(
            batch.validate().unwrap_err().code,
            "delivery_position_out_of_range"
        );
    }

    #[test]
    fn v1_delivery_metadata_fails_closed() {
        let mut delivery = valid_batch();
        delivery.delivery = valid_v2_snapshot().delivery;
        assert_eq!(
            delivery.validate().unwrap_err().code,
            "unexpected_delivery_metadata"
        );
        assert_eq!(
            delivery.canonical_digest().unwrap_err().code,
            "unexpected_delivery_metadata"
        );

        let mut sequence = valid_batch();
        sequence.records[0].source_sequence = Some(1);
        assert_eq!(
            sequence.validate().unwrap_err().code,
            "unexpected_delivery_metadata"
        );
        assert_eq!(
            sequence.canonical_digest().unwrap_err().code,
            "unexpected_delivery_metadata"
        );
    }

    #[test]
    fn v2_reordered_duplicate_and_noncontiguous_sequences_fail_closed() {
        let mut reordered = valid_v2_change_feed();
        reordered.records[0].source_sequence = Some(42);
        reordered.records[1].source_sequence = Some(41);
        reordered.batch_digest = reordered.canonical_digest().unwrap();
        assert_eq!(
            reordered.validate().unwrap_err().code,
            "reordered_source_sequence"
        );

        let mut duplicate = valid_v2_change_feed();
        duplicate.records[1].source_sequence = Some(41);
        duplicate.batch_digest = duplicate.canonical_digest().unwrap();
        assert_eq!(
            duplicate.validate().unwrap_err().code,
            "duplicate_source_sequence"
        );

        let mut gap = valid_v2_change_feed();
        gap.records[1].source_sequence = Some(43);
        gap.delivery.as_mut().unwrap().offset_end = Some(43);
        gap.batch_digest = gap.canonical_digest().unwrap();
        assert_eq!(
            gap.validate().unwrap_err().code,
            "noncontiguous_source_sequence"
        );
    }

    #[test]
    fn v2_missing_range_and_bad_snapshot_metadata_fail_closed() {
        let mut missing_range = valid_v2_change_feed();
        missing_range.delivery.as_mut().unwrap().offset_end = None;
        missing_range.batch_digest = missing_range.canonical_digest().unwrap();
        assert_eq!(
            missing_range.validate().unwrap_err().code,
            "missing_delivery_range"
        );

        let mut snapshot = valid_v2_snapshot();
        snapshot.delivery.as_mut().unwrap().offset_start = Some(0);
        snapshot.batch_digest = snapshot.canonical_digest().unwrap();
        assert_eq!(
            snapshot.validate().unwrap_err().code,
            "invalid_snapshot_metadata"
        );

        let mut missing_handoff = valid_v2_snapshot();
        missing_handoff.delivery.as_mut().unwrap().offset_end = None;
        missing_handoff.batch_digest = missing_handoff.canonical_digest().unwrap();
        assert_eq!(
            missing_handoff.validate().unwrap_err().code,
            "invalid_snapshot_metadata"
        );
    }

    #[test]
    fn v2_missing_and_mixed_record_metadata_fail_closed() {
        let mut missing_delivery = valid_batch();
        missing_delivery.contract_version = SOURCE_BATCH_V2_VERSION.into();
        assert_eq!(
            missing_delivery.validate().unwrap_err().code,
            "missing_delivery_metadata"
        );

        let mut missing_sequence = valid_v2_change_feed();
        missing_sequence.records[0].source_sequence = None;
        missing_sequence.batch_digest = missing_sequence.canonical_digest().unwrap();
        assert_eq!(
            missing_sequence.validate().unwrap_err().code,
            "missing_source_sequence"
        );

        let mut snapshot_sequence = valid_v2_snapshot();
        snapshot_sequence.records[0].source_sequence = Some(1);
        snapshot_sequence.batch_digest = snapshot_sequence.canonical_digest().unwrap();
        assert_eq!(
            snapshot_sequence.validate().unwrap_err().code,
            "unexpected_source_sequence"
        );

        let mut incomplete_snapshot_metadata = valid_v2_snapshot();
        incomplete_snapshot_metadata
            .delivery
            .as_mut()
            .unwrap()
            .source_feed_epoch = None;
        incomplete_snapshot_metadata.batch_digest =
            incomplete_snapshot_metadata.canonical_digest().unwrap();
        assert_eq!(
            incomplete_snapshot_metadata.validate().unwrap_err().code,
            "missing_feed_epoch"
        );
    }

    #[test]
    fn source_feed_epoch_validation_does_not_echo_secret_like_content() {
        let secret = "ghp_sensitive-feed-epoch";
        let mut batch = valid_v2_change_feed();
        batch.delivery.as_mut().unwrap().source_feed_epoch = Some(secret.into());
        batch.batch_digest = batch.canonical_digest().unwrap();
        let error = batch.validate().unwrap_err();
        assert_eq!(error.code, "secret_like_text");
        assert!(!error.message.contains(secret));
    }

    #[test]
    fn unknown_contract_version_fails_closed() {
        let mut batch = valid_batch();
        batch.contract_version = "sekai.source-batch/v3".into();
        let error = batch.validate().unwrap_err();
        assert_eq!(error.code, "unsupported_version");
        assert_eq!(
            batch.canonical_digest().unwrap_err().code,
            "unsupported_version"
        );
    }

    #[test]
    fn foreign_contract_values_and_malformed_digests_fail_closed() {
        let mut family = valid_batch();
        family.family = "source_control.other".into();
        family.batch_digest = family.canonical_digest().unwrap();
        assert_eq!(family.validate().unwrap_err().code, "foreign_family");

        let mut adapter = valid_batch();
        adapter.adapter_version = "2.0.0".into();
        adapter.batch_digest = adapter.canonical_digest().unwrap();
        assert_eq!(adapter.validate().unwrap_err().code, "unsupported_adapter");

        let mut digest = valid_batch();
        digest.records[0].payload_digest = "sha256:abc".into();
        digest.batch_digest = digest.canonical_digest().unwrap();
        assert_eq!(digest.validate().unwrap_err().code, "invalid_digest");
    }

    #[test]
    fn mixed_and_unsupported_records_fail_closed() {
        let mut mixed = valid_batch();
        mixed.records[0].source_instance = "other/repository".into();
        mixed.batch_digest = mixed.canonical_digest().unwrap();
        assert_eq!(mixed.validate().unwrap_err().code, "mixed_source_identity");

        let mut unsupported = valid_batch();
        unsupported.records[0].type_name = "Discussion".into();
        unsupported.batch_digest = unsupported.canonical_digest().unwrap();
        assert_eq!(
            unsupported.validate().unwrap_err().code,
            "unsupported_record_type"
        );

        let mut ambiguous = valid_batch();
        let mut pull = issue();
        pull.type_name = "PullRequest".into();
        ambiguous.records.push(pull);
        ambiguous.batch_digest = ambiguous.canonical_digest().unwrap();
        assert_eq!(
            ambiguous.validate().unwrap_err().code,
            "ambiguous_record_identity"
        );
    }

    #[test]
    fn github_repository_and_number_identity_are_canonical() {
        for source_instance in ["not-a-repository", "Owner/repository"] {
            let mut repository = valid_batch();
            repository.source_instance = source_instance.into();
            repository.records[0].source_instance = repository.source_instance.clone();
            repository.batch_digest = repository.canonical_digest().unwrap();
            assert_eq!(
                repository.validate().unwrap_err().code,
                "invalid_source_instance"
            );
        }

        for external_id in ["0", "01", "not-a-number"] {
            let mut number = valid_batch();
            number.records[0].external_id = external_id.into();
            number.batch_digest = number.canonical_digest().unwrap();
            assert_eq!(number.validate().unwrap_err().code, "invalid_external_id");
            assert!(matches!(
                sync_github_record(number.records.remove(0), GITHUB_OBJECT_SYNC_TYPE_DIGEST),
                SyncDecision::Reject { .. }
            ));
        }
    }

    #[test]
    fn record_property_and_cursor_bounds_fail_closed() {
        let mut too_many = valid_batch();
        too_many.records = (0..=MAX_SOURCE_BATCH_RECORDS)
            .map(|index| {
                let mut record = issue();
                record.external_id = index.to_string();
                record
            })
            .collect();
        too_many.batch_digest = too_many.canonical_digest().unwrap();
        assert_eq!(too_many.validate().unwrap_err().code, "record_bounds");

        let mut properties = valid_batch();
        properties.records[0].properties = (0..=MAX_SOURCE_RECORD_PROPERTIES)
            .map(|index| (format!("property_{index}"), "value".into()))
            .collect();
        properties.batch_digest = properties.canonical_digest().unwrap();
        assert_eq!(properties.validate().unwrap_err().code, "property_bounds");

        let mut cursor = valid_batch();
        cursor.proposed_next_cursor = "x".repeat(MAX_SOURCE_CURSOR_BYTES + 1);
        cursor.batch_digest = cursor.canonical_digest().unwrap();
        assert_eq!(cursor.validate().unwrap_err().code, "cursor_bounds");
    }

    #[test]
    fn secret_like_text_is_rejected() {
        let mut property = valid_batch();
        property.records[0]
            .properties
            .insert("access_token".into(), "redacted".into());
        property.batch_digest = property.canonical_digest().unwrap();
        assert_eq!(property.validate().unwrap_err().code, "secret_like_text");

        let mut cursor = valid_batch();
        cursor.proposed_next_cursor = "ghp_not-a-checkpoint".into();
        cursor.batch_digest = cursor.canonical_digest().unwrap();
        assert_eq!(cursor.validate().unwrap_err().code, "secret_like_text");
    }

    #[test]
    fn replay_material_requires_exact_canonical_input() {
        let first = valid_batch();
        let material = first.replay_material().unwrap();

        let mut replay = first.clone();
        replay.collected_at_ms += 1;
        assert_eq!(
            replay.compare_replay(&material).unwrap(),
            ReplayDisposition::ExactReplay
        );
        assert_eq!(replay.replay_material().unwrap(), material);

        let mut conflict = first;
        conflict.proposed_next_cursor = "cursor:43".into();
        conflict.batch_digest = conflict.canonical_digest().unwrap();
        assert_eq!(
            conflict.compare_replay(&material).unwrap_err().code,
            "idempotency_conflict"
        );
    }

    #[test]
    fn server_validation_never_emits_partial_or_unknown() {
        let valid = valid_batch();
        assert!(matches!(
            valid.server_validation_outcome("connector/github-primary"),
            OperationOutcome::Success | OperationOutcome::Denial
        ));

        let mut invalid = valid;
        invalid.batch_digest = format!("sha256:{}", "0".repeat(64));
        assert!(matches!(
            invalid.server_validation_outcome("connector/github-primary"),
            OperationOutcome::Success | OperationOutcome::Denial
        ));
        assert_eq!(
            invalid.server_validation_outcome("connector/github-primary"),
            OperationOutcome::Denial
        );
    }

    #[test]
    fn github_issue_upserts_stable_object_id() {
        let first = match sync_github_record(issue(), GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        let second = match sync_github_record(issue(), GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        assert_eq!(first.object_id, second.object_id);
        assert_eq!(first.source_id, "github:acme/ops#12");
        assert_eq!(first.source_version, "issue-node-v7");
        assert_eq!(first.properties["state"], "open");
        assert!(!first.tombstoned);
    }

    #[test]
    fn deleted_github_record_tombstones() {
        let mut record = issue();
        record.deleted = true;
        match sync_github_record(record, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Tombstone(object) => assert!(object.tombstoned),
            other => panic!("expected tombstone, got {other:?}"),
        }
    }

    #[test]
    fn foreign_source_is_rejected() {
        let mut record = issue();
        record.source = "jira".into();
        match sync_github_record(record, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Reject { reason } => assert!(reason.contains("GitHub")),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn issue_and_pull_request_share_github_number_identity() {
        let issue_object = match sync_github_record(issue(), GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        let mut pull = issue();
        pull.type_name = "PullRequest".into();
        let pull_object = match sync_github_record(pull, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        assert_eq!(issue_object.object_id, pull_object.object_id);
        assert_eq!(issue_object.source_id, pull_object.source_id);
        assert_eq!(issue_object.source_id, "github:acme/ops#12");
    }

    #[test]
    fn additional_github_kinds_are_rejected() {
        let mut record = issue();
        record.type_name = "Discussion".into();
        match sync_github_record(record, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Reject { reason } => {
                assert!(reason.contains("Issue and PullRequest only"));
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn type_revision_change_is_a_conflict() {
        let upserted = match sync_github_record(issue(), GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("{other:?}"),
        };
        let mut moved = upserted.clone();
        moved.type_digest = "unbound-revision".into();
        moved.object_id = object_id_for(&moved.type_digest, &moved.source_id);
        assert!(detect_identity_conflict(&upserted, &moved).is_some());
        assert_eq!(
            classify_source_record_compatibility(Some(&upserted), &moved),
            crate::sekai::definition_diff::DefinitionCompatibilityClass::Breaking
        );
        assert!(is_schema_drift_denial(Some("type_identity_conflict")));
        assert!(!is_schema_drift_denial(Some("stale_cursor")));
    }

    #[test]
    fn additive_property_refresh_is_compatible() {
        let admitted = match sync_github_record(issue(), GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        let mut refreshed = admitted.clone();
        refreshed.source_version = "issue-node-v8".into();
        refreshed
            .properties
            .insert("body".into(), "additive field".into());
        assert_eq!(
            classify_source_record_compatibility(Some(&admitted), &refreshed),
            crate::sekai::definition_diff::DefinitionCompatibilityClass::Compatible
        );
        assert!(
            schema_quarantine_record_reason(
                GITHUB_OBJECT_SYNC_TYPE_DIGEST,
                GITHUB_OBJECT_SYNC_TYPE_DIGEST,
                Some(&admitted),
                &refreshed,
                "type_identity_conflict: sibling",
            )
            .starts_with("batch_quarantined:")
        );
    }

    fn valid_registered_batch() -> SourceBatch {
        let mut batch = SourceBatch {
            contract_version: SOURCE_BATCH_VERSION.into(),
            namespace: "ops".into(),
            producer_identity: "connector/pager".into(),
            source: "synthetic.pager".into(),
            source_instance: "ops-local".into(),
            family: FAMILY_OBJECT_SYNC.into(),
            adapter_id: ADAPTER_REGISTERED_OBJECT_SYNC.into(),
            adapter_version: ADAPTER_REGISTERED_OBJECT_SYNC_VERSION.into(),
            type_digest: format!("sha256:{}", "a".repeat(64)),
            current_cursor: String::new(),
            proposed_next_cursor: "cursor:1".into(),
            idempotency_key: "pager-1".into(),
            batch_digest: String::new(),
            collected_at_ms: 20,
            records: vec![SourceRecord {
                source: "synthetic.pager".into(),
                source_instance: "ops-local".into(),
                external_id: "42".into(),
                source_version: "alert-v1".into(),
                type_name: "Alert".into(),
                display_name: "checkout latency".into(),
                payload_digest: PAYLOAD_DIGEST.into(),
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

    #[test]
    fn registered_envelope_validates_without_catalog_liveness() {
        valid_registered_batch().validate().unwrap();
    }

    #[test]
    fn registered_batches_reject_github_kinds_and_mixed_record_types() {
        let mut github_kind = valid_registered_batch();
        github_kind.records[0].type_name = "Issue".into();
        github_kind.batch_digest = github_kind.canonical_digest().unwrap();
        assert_eq!(
            github_kind.validate().unwrap_err().code,
            "unsupported_record_type"
        );

        let mut mixed = valid_registered_batch();
        let mut service = mixed.records[0].clone();
        service.external_id = "43".into();
        service.type_name = "Service".into();
        mixed.records.push(service);
        mixed.batch_digest = mixed.canonical_digest().unwrap();
        assert_eq!(mixed.validate().unwrap_err().code, "mixed_record_type");
    }

    #[test]
    fn registered_batches_cannot_reuse_github_source_or_adapter() {
        let mut github_source = valid_registered_batch();
        github_source.source = SOURCE_GITHUB.into();
        github_source.source_instance = "acme/ops".into();
        github_source.adapter_id = ADAPTER_GITHUB_OBJECT_SYNC.into();
        github_source.adapter_version = ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into();
        github_source.records[0].source = SOURCE_GITHUB.into();
        github_source.records[0].source_instance = "acme/ops".into();
        github_source.batch_digest = github_source.canonical_digest().unwrap();
        assert_eq!(
            github_source.validate().unwrap_err().code,
            "unbound_type_revision"
        );

        let mut github_digest = valid_registered_batch();
        github_digest.type_digest = GITHUB_OBJECT_SYNC_TYPE_DIGEST.into();
        github_digest.batch_digest = github_digest.canonical_digest().unwrap();
        assert_eq!(github_digest.validate().unwrap_err().code, "foreign_source");

        let mut github_adapter = valid_registered_batch();
        github_adapter.adapter_id = ADAPTER_GITHUB_OBJECT_SYNC.into();
        github_adapter.adapter_version = ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into();
        github_adapter.batch_digest = github_adapter.canonical_digest().unwrap();
        assert_eq!(
            github_adapter.validate().unwrap_err().code,
            "unsupported_adapter"
        );
    }
}
