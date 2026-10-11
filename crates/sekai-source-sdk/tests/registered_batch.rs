//! Registered-descriptor batches (ADR 0060) through the v1 builder.

use sekai_source_sdk::{
    ADAPTER_REGISTERED_OBJECT_SYNC, GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_GITHUB,
    SourceAdapterConfig, SourceRecord, build_registered_source_batch,
};

const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn config(type_digest: &str) -> SourceAdapterConfig {
    SourceAdapterConfig {
        namespace: "acme".into(),
        producer_identity: "connector/crm".into(),
        source_instance: "eu-1".into(),
        type_digest: type_digest.into(),
    }
}

fn record(source: &str, id: &str) -> SourceRecord {
    SourceRecord {
        source: source.into(),
        source_instance: "eu-1".into(),
        external_id: id.into(),
        source_version: "1".into(),
        type_name: "Account".into(),
        display_name: id.into(),
        payload_digest: DIGEST.into(),
        properties: Default::default(),
        deleted: false,
        observed_at_ms: 1,
        source_sequence: None,
    }
}

#[test]
fn builds_a_deterministic_registered_batch() {
    let build = |records| {
        build_registered_source_batch(&config(DIGEST), "crm", "", "page-1", 1, records).unwrap()
    };
    let first = build(vec![record("crm", "b"), record("crm", "a")]);
    let second = build(vec![record("crm", "a"), record("crm", "b")]);
    assert_eq!(first.adapter_id, ADAPTER_REGISTERED_OBJECT_SYNC);
    assert_eq!(first.source, "crm");
    assert_eq!(first.idempotency_key, second.idempotency_key);
    assert_eq!(first.batch_digest, second.batch_digest);
}

#[test]
fn refuses_the_github_profile_and_foreign_records() {
    let github = build_registered_source_batch(
        &config(GITHUB_OBJECT_SYNC_TYPE_DIGEST),
        "crm",
        "",
        "page-1",
        1,
        vec![record("crm", "a")],
    );
    assert!(github.is_err());
    let github_source = build_registered_source_batch(
        &config(DIGEST),
        SOURCE_GITHUB,
        "",
        "page-1",
        1,
        vec![record(SOURCE_GITHUB, "a")],
    );
    assert!(github_source.is_err());
    let foreign = build_registered_source_batch(
        &config(DIGEST),
        "crm",
        "",
        "page-1",
        1,
        vec![record("other", "a")],
    );
    assert!(foreign.is_err());
}
