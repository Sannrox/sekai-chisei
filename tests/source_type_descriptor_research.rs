//! Research spike for #817: additive source-type descriptors.
//!
//! These checks prove identity and lifecycle on two local synthetic kinds.
//! They do not advertise a catalog profile or change ApplySourceBatch.

use sekai_chisei::sekai::object_sync::{
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_GITHUB, SourceRecord, SyncDecision, object_id_for,
    sync_github_record,
};
use sekai_chisei::sekai::source_type_descriptor::{
    infer_descriptor_from_name, project_registered_record, synthetic_cmdb_service_v1,
    synthetic_pager_alert_v1,
};
use sekai_chisei::source_adapter_catalog::built_in_source_adapters;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn synthetic(source: &str, kind: &str, key: &str, version: &str, title: &str) -> SourceRecord {
    SourceRecord {
        source: source.into(),
        source_instance: "ops-local".into(),
        external_id: key.into(),
        source_version: version.into(),
        type_name: kind.into(),
        display_name: title.into(),
        payload_digest: format!("sha256:{:x}", Sha256::digest(title.as_bytes())),
        properties: BTreeMap::from([("title".into(), title.into())]),
        deleted: false,
        observed_at_ms: 10,
        source_sequence: None,
    }
}

#[test]
fn two_local_kinds_do_not_collide_with_each_other_or_github() {
    let pager = synthetic_pager_alert_v1();
    let cmdb = synthetic_cmdb_service_v1();
    let alert = match project_registered_record(
        &pager,
        synthetic("synthetic.pager", "Alert", "42", "v1", "pager"),
    )
    .unwrap()
    {
        SyncDecision::Upsert(object) => object,
        other => panic!("expected upsert, got {other:?}"),
    };
    let service = match project_registered_record(
        &cmdb,
        synthetic("synthetic.cmdb", "Service", "42", "v1", "cmdb"),
    )
    .unwrap()
    {
        SyncDecision::Upsert(object) => object,
        other => panic!("expected upsert, got {other:?}"),
    };
    let github = match sync_github_record(
        SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            external_id: "42".into(),
            source_version: "node-v1".into(),
            type_name: "Issue".into(),
            display_name: "Service checkout latency incident".into(),
            payload_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            properties: BTreeMap::from([("state".into(), "open".into())]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        },
        GITHUB_OBJECT_SYNC_TYPE_DIGEST,
    ) {
        SyncDecision::Upsert(object) => object,
        other => panic!("expected github upsert, got {other:?}"),
    };

    assert_ne!(alert.source_id, service.source_id);
    assert_ne!(alert.object_id, service.object_id);
    assert_ne!(alert.object_id, github.object_id);
    assert_eq!(
        github.object_id,
        object_id_for(GITHUB_OBJECT_SYNC_TYPE_DIGEST, "github:acme/ops#42")
    );
    assert!(infer_descriptor_from_name("Incident").is_err());
    assert_eq!(built_in_source_adapters().len(), 1);
    assert_eq!(built_in_source_adapters()[0].source, SOURCE_GITHUB);
}
