use serde::Deserialize;
use std::collections::BTreeSet;

const FIXTURE: &str = include_str!("fixtures/runtime_claim_pressure/v1.json");

#[derive(Debug, Deserialize)]
struct Scope {
    namespace: String,
    runtime_id: String,
}

#[derive(Debug, Deserialize)]
struct ConsumerSafety {
    scale_only_when_sample_status: String,
    require_authoritative: bool,
    unknown_action: String,
    payload_fields_exposed: bool,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    contract_version: String,
    parent_issue: u64,
    consumer: String,
    scope: Scope,
    consumer_safety: ConsumerSafety,
    required_cases: Vec<String>,
}

#[test]
fn tenkai_pressure_fixture_freezes_safe_consumption_and_coverage() {
    let fixture: Fixture = serde_json::from_str(FIXTURE).expect("parse pressure fixture");
    assert_eq!(fixture.contract_version, "sekai.runtime-work-pressure/v1");
    assert_eq!(fixture.parent_issue, 489);
    assert_eq!(fixture.consumer, "Sannrox/tenkai");
    assert_eq!(fixture.scope.namespace, "example");
    assert_eq!(fixture.scope.runtime_id, "shikigami");
    assert_eq!(
        fixture.consumer_safety.scale_only_when_sample_status,
        "current"
    );
    assert!(fixture.consumer_safety.require_authoritative);
    assert_eq!(
        fixture.consumer_safety.unknown_action,
        "keep_last_safe_capacity_intent"
    );
    assert!(!fixture.consumer_safety.payload_fields_exposed);
    assert_eq!(
        fixture
            .required_cases
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [
            "concurrent_claims",
            "dead_lettered_work",
            "empty_work",
            "growing_backlog",
            "lease_expiry_pressure",
            "parked_work",
            "unavailable_projection",
        ]
        .into_iter()
        .collect()
    );
}
