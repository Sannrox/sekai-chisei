//! Contract-shape checks for the managed Shikigami routing fixture (#471).
//!
//! This fixture is deliberately situation-specific. It describes only the
//! hosted Shikigami plane-model boundary and is not a generic evaluator.

use std::collections::BTreeSet;

use serde::Deserialize;

const FIXTURE: &str = include_str!("fixtures/managed_shikigami_routing/v1.json");

#[derive(Debug, Deserialize)]
struct MinimumConsumer {
    released_version: Option<String>,
    intended_version: String,
    required_commit: String,
}

#[derive(Debug, Deserialize)]
struct SyntheticContext {
    principal: String,
    credential_id: String,
    namespace: String,
    logical_model: String,
    route_override: String,
    provider_credential_ref: String,
}

#[derive(Debug, Deserialize)]
struct ConformanceCase {
    id: String,
    class: String,
    summary: String,
    evidence_tests: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ConformanceFixture {
    contract_version: String,
    parent_issue: u64,
    consumer: String,
    minimum_consumer: MinimumConsumer,
    synthetic_context: SyntheticContext,
    required_cases: Vec<ConformanceCase>,
}

fn fixture() -> ConformanceFixture {
    serde_json::from_str(FIXTURE).expect("parse managed Shikigami routing fixture")
}

fn evidence_source(path: &str) -> &'static str {
    match path {
        "crates/sekai-provider/src/llm/anthropic.rs" => {
            include_str!("../crates/sekai-provider/src/llm/anthropic.rs")
        }
        "crates/sekai-provider/src/llm/openai.rs" => {
            include_str!("../crates/sekai-provider/src/llm/openai.rs")
        }
        "src/grpc/chisei_service.rs" => include_str!("../src/grpc/chisei_service.rs"),
        "src/grpc/provider_execution.rs" => include_str!("../src/grpc/provider_execution.rs"),
        "src/grpc/mod.rs" => include_str!("../src/grpc/mod.rs"),
        "src/provider_credentials.rs" => include_str!("../src/provider_credentials.rs"),
        other => panic!("fixture references unsupported evidence source {other:?}"),
    }
}

#[test]
fn managed_routing_fixture_binds_every_case_to_executable_evidence() {
    let fixture = fixture();
    assert_eq!(
        fixture.contract_version,
        "sekai.managed-shikigami-routing-conformance/v1"
    );
    assert_eq!(fixture.parent_issue, 471);
    assert_eq!(fixture.consumer, "Sannrox/shikigami");
    assert!(fixture.minimum_consumer.released_version.is_none());
    assert_eq!(fixture.minimum_consumer.intended_version, "v1.0.5");
    assert_eq!(fixture.minimum_consumer.required_commit.len(), 40);

    let expected = BTreeSet::from([
        ("caller_cannot_select_authority", "negative"),
        ("community_runtime_remains_tenant_free", "negative"),
        ("explicit_retry_is_new_attempt", "positive"),
        ("invalid_identity_fails_closed", "negative"),
        ("policy_selects_physical_route", "positive"),
        ("provider_failure_fails_closed", "negative"),
        ("provider_secret_stays_server_side", "negative"),
        ("service_principal_authenticates", "positive"),
        ("tool_call_stream_round_trip", "positive"),
        ("usage_and_receipt_are_normalized", "positive"),
    ]);
    let actual = fixture
        .required_cases
        .iter()
        .map(|case| (case.id.as_str(), case.class.as_str()))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(fixture.required_cases.len(), expected.len());
    assert!(fixture.required_cases.iter().all(|case| matches!(
        case.class.as_str(),
        "positive" | "negative"
    ) && !case.summary.trim().is_empty()
        && !case.evidence_tests.is_empty()));

    for case in &fixture.required_cases {
        for evidence in &case.evidence_tests {
            let (source_path, test_name) = evidence
                .split_once('#')
                .unwrap_or_else(|| panic!("invalid evidence reference {evidence:?}"));
            assert!(
                evidence_source(source_path).contains(&format!("fn {test_name}(")),
                "case {:?} references missing executable test {evidence:?}",
                case.id
            );
        }
    }
}

#[test]
fn fixture_keeps_route_authority_and_secrets_out_of_the_client() {
    let fixture = fixture();
    assert!(fixture.synthetic_context.principal.starts_with("service:"));
    assert!(
        fixture
            .synthetic_context
            .credential_id
            .starts_with("credential:")
    );
    assert_eq!(fixture.synthetic_context.namespace, "managed-conformance");
    assert_eq!(fixture.synthetic_context.logical_model, "managed-default");
    assert!(fixture.synthetic_context.route_override.is_empty());
    assert!(
        fixture
            .synthetic_context
            .provider_credential_ref
            .starts_with("credential:provider:")
    );

    let lowered = FIXTURE.to_ascii_lowercase();
    for forbidden in [
        "authorization: bearer",
        "api_key",
        "api-key",
        "sk-",
        "tenant_id",
        "aldunis",
    ] {
        assert!(
            !lowered.contains(forbidden),
            "fixture contains forbidden private or credential-bearing term {forbidden:?}"
        );
    }
}
