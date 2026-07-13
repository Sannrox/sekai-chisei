#[path = "../adapters/github_check_webhook.rs"]
mod github_check_webhook;
#[path = "../adapters/http_health_poll.rs"]
mod http_health_poll;
#[allow(dead_code)]
#[path = "../adapters/sdk.rs"]
mod sdk;

use sdk::AdapterConfig;

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

    let envelope = draft.into_envelope(&config(), 1_752_394_000_000).unwrap();
    assert_eq!(envelope.contract_version, sdk::EVIDENCE_CONTRACT_VERSION);
    assert_eq!(envelope.source_record_id, "88201");
    assert_eq!(envelope.source_version, "2026-07-13T08:02:31Z");
    assert_eq!(envelope.namespace, "acme");
    assert_eq!(envelope.target_external_id, "service:payments");
    assert_eq!(envelope.content_digest.len(), 64);
    assert_eq!(envelope.idempotency_key.len(), 64);
    assert_eq!(envelope.intent, "upsert");
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

    let first = draft
        .clone()
        .into_envelope(&config(), 1_752_394_000_000)
        .unwrap();
    let replay = draft.into_envelope(&config(), 1_752_394_999_999).unwrap();
    assert_eq!(first.content_digest, replay.content_digest);
    assert_eq!(first.idempotency_key, replay.idempotency_key);
}

#[test]
fn adapters_reject_malformed_source_inputs_before_submission() {
    assert!(github_check_webhook::parse(br#"{"action":"completed"}"#).is_err());
    let input = br#"{"status":"ok","observed_at":"not-a-time"}"#;
    let payload = http_health_poll::parse(input).unwrap();
    assert!(http_health_poll::translate(payload, "health", None, 1_000).is_err());
}
