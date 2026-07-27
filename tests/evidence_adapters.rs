#[path = "../adapters/github_check_webhook.rs"]
mod github_check_webhook;
#[path = "../adapters/http_health_poll.rs"]
mod http_health_poll;
#[path = "../adapters/ontology_concept_catalog.rs"]
mod ontology_concept_catalog;
#[allow(dead_code)]
#[path = "../adapters/sdk.rs"]
mod sdk;

use sdk::AdapterConfig;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn config() -> AdapterConfig {
    AdapterConfig {
        target: "http://127.0.0.1:50051".into(),
        producer_identity: "producer:reference-adapters".into(),
        source_instance: "reference-primary".into(),
        namespace: "acme".into(),
        target_external_id: "service:payments".into(),
        target_kind: "service".into(),
        classification: "internal".into(),
    }
}

fn outbox(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sekai-evidence-adapter-{name}-{}",
        uuid::Uuid::new_v4()
    ))
}

#[test]
fn github_webhook_fixture_conforms_to_the_canonical_envelope() {
    let input = include_bytes!("../adapters/fixtures/github_check_run.completed.json");
    let draft = github_check_webhook::translate(github_check_webhook::parse(input).unwrap())
        .expect("translate webhook");
    assert_eq!(draft.source_type, "github_check_run");
    assert_eq!(draft.signal, "verification");
    assert_eq!(draft.evidence_type, github_check_webhook::EVIDENCE_TYPE);
    assert_eq!(draft.content["outcome"], "success");
    assert_eq!(draft.provenance["delivery"], "webhook");
    github_check_webhook::CONFORMANCE_PROFILE
        .validate(&draft)
        .unwrap();

    let outbox = outbox("github");
    let (envelope, receipt) =
        sdk::prepare_delivery_in(&outbox, &config(), draft, 1_752_394_000_000).unwrap();
    assert_eq!(envelope.contract_version, sdk::EVIDENCE_CONTRACT_VERSION);
    assert!(envelope.source_record_id.starts_with("88201:"));
    assert_eq!(envelope.source_version, "2026-07-13T08:02:31Z");
    assert_eq!(envelope.namespace, "acme");
    assert_eq!(envelope.target_external_id, "service:payments");
    assert_eq!(envelope.content_digest.len(), 64);
    assert_eq!(envelope.idempotency_key.len(), 64);
    assert_eq!(envelope.intent, "upsert");
    receipt.acknowledge().unwrap();
    std::fs::remove_dir(outbox).unwrap();
}

#[test]
fn github_same_second_updates_keep_distinct_source_identity() {
    let input = include_bytes!("../adapters/fixtures/github_check_run.completed.json");
    let first = github_check_webhook::translate(github_check_webhook::parse(input).unwrap())
        .expect("translate webhook");
    let mut changed: serde_json::Value = serde_json::from_slice(input).unwrap();
    changed["check_run"]["conclusion"] = serde_json::json!("failure");
    let second = github_check_webhook::translate(
        github_check_webhook::parse(&serde_json::to_vec(&changed).unwrap()).unwrap(),
    )
    .expect("translate same-second update");

    assert_eq!(first.source_sequence, second.source_sequence);
    assert_ne!(first.source_record_id, second.source_record_id);
}

#[test]
fn health_poll_fixture_conforms_with_bounded_freshness() {
    let input = include_bytes!("../adapters/fixtures/http_health.degraded.json");
    let draft = http_health_poll::translate(
        http_health_poll::parse(input).unwrap(),
        "payments-health",
        Some("etag-17"),
        300_000,
    )
    .expect("translate health snapshot");
    assert_eq!(draft.source_type, "http_health_endpoint");
    assert_eq!(draft.signal, "operational_health");
    assert_eq!(draft.evidence_type, http_health_poll::EVIDENCE_TYPE);
    assert_eq!(draft.source_version, "etag-17");
    assert_eq!(draft.content["status"], "degraded");
    assert_eq!(draft.provenance["delivery"], "poll");
    assert_eq!(draft.expires_at_ms, Some(draft.observed_at_ms + 300_000));
    http_health_poll::CONFORMANCE_PROFILE
        .validate(&draft)
        .unwrap();

    let outbox = outbox("health");
    let (first, first_receipt) =
        sdk::prepare_delivery_in(&outbox, &config(), draft.clone(), 1_752_394_000_000).unwrap();
    let (replay, replay_receipt) =
        sdk::prepare_delivery_in(&outbox, &config(), draft, 1_752_394_999_999).unwrap();
    assert_eq!(first.content_digest, replay.content_digest);
    assert_eq!(first.idempotency_key, replay.idempotency_key);
    assert_eq!(first.collected_at_ms, replay.collected_at_ms);
    assert_eq!(first.source_record_id, replay.source_record_id);
    assert_eq!(first.source_version, replay.source_version);
    #[cfg(unix)]
    {
        assert_eq!(
            std::fs::metadata(&outbox).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let entry = std::fs::read_dir(&outbox)
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.path().extension().is_some_and(|value| value == "bin"))
            .unwrap();
        assert_eq!(
            entry.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    first_receipt.acknowledge().unwrap();
    replay_receipt.acknowledge().unwrap();
    std::fs::remove_dir(outbox).unwrap();
}

#[cfg(unix)]
#[test]
fn outbox_rejects_symlink_entries_without_changing_the_target() {
    use std::os::unix::fs::symlink;

    let input = include_bytes!("../adapters/fixtures/http_health.degraded.json");
    let draft = http_health_poll::translate(
        http_health_poll::parse(input).unwrap(),
        "payments-health",
        Some("etag-17"),
        300_000,
    )
    .unwrap();
    let outbox = outbox("symlink");
    let (_, receipt) = sdk::prepare_delivery_in(&outbox, &config(), draft.clone(), 1_000).unwrap();
    let entry_name = std::fs::read_dir(&outbox)
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.path().extension().is_some_and(|value| value == "bin"))
        .unwrap()
        .file_name();
    receipt.acknowledge().unwrap();

    let target = outbox.with_extension("target");
    std::fs::write(&target, b"not an envelope").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&target, outbox.join(entry_name)).unwrap();

    assert!(sdk::prepare_delivery_in(&outbox, &config(), draft, 2_000).is_err());
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o644
    );
    std::fs::remove_file(
        std::fs::read_dir(&outbox)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path(),
    )
    .unwrap();
    std::fs::remove_file(target).unwrap();
    std::fs::remove_dir(outbox).unwrap();
}

#[test]
fn ontology_concept_catalog_fixture_conforms_to_the_canonical_envelope() {
    let input = include_bytes!("../adapters/fixtures/ontology_concept_catalog.service.json");
    let draft =
        ontology_concept_catalog::translate(ontology_concept_catalog::parse(input).unwrap())
            .expect("translate concept catalog");
    assert_eq!(draft.source_type, "concept_catalog_document");
    assert_eq!(draft.signal, "other");
    assert_eq!(draft.evidence_type, ontology_concept_catalog::EVIDENCE_TYPE);
    assert_eq!(draft.content["classes"][0]["name"], "Service");
    assert_eq!(draft.content["relations"][0]["name"], "depends_on");
    assert_eq!(draft.provenance["delivery"], "document");
    ontology_concept_catalog::CONFORMANCE_PROFILE
        .validate(&draft)
        .unwrap();

    let outbox = outbox("ontology-catalog");
    let (envelope, receipt) =
        sdk::prepare_delivery_in(&outbox, &config(), draft, 1_752_394_000_000).unwrap();
    assert_eq!(envelope.contract_version, sdk::EVIDENCE_CONTRACT_VERSION);
    assert_eq!(envelope.source_record_id, "platform-services-v1");
    assert_eq!(envelope.source_sequence, 17);
    assert_eq!(envelope.intent, "upsert");
    assert_eq!(envelope.content_digest.len(), 64);
    receipt.acknowledge().unwrap();
    std::fs::remove_dir(outbox).unwrap();
}

#[test]
fn adapters_reject_malformed_source_inputs_before_submission() {
    assert!(github_check_webhook::parse(br#"{"action":"completed"}"#).is_err());
    assert!(ontology_concept_catalog::parse(br#"{"catalog_id":""}"#).is_err());
    let input = br#"{"status":"ok","observed_at":"not-a-time"}"#;
    let payload = http_health_poll::parse(input).unwrap();
    assert!(http_health_poll::translate(payload, "health", None, 1_000).is_err());
}

#[test]
fn conformance_profiles_reject_adapter_contract_drift() {
    let input = include_bytes!("../adapters/fixtures/http_health.degraded.json");
    let mut draft = http_health_poll::translate(
        http_health_poll::parse(input).unwrap(),
        "payments-health",
        Some("etag-17"),
        300_000,
    )
    .unwrap();
    draft.evidence_type = github_check_webhook::EVIDENCE_TYPE.into();
    assert!(
        http_health_poll::CONFORMANCE_PROFILE
            .validate(&draft)
            .unwrap_err()
            .contains("evidence_type")
    );

    draft.evidence_type = http_health_poll::EVIDENCE_TYPE.into();
    draft.expires_at_ms = None;
    assert!(
        http_health_poll::CONFORMANCE_PROFILE
            .validate(&draft)
            .unwrap_err()
            .contains("bounded freshness")
    );
}
