#[path = "../adapters/batch_responses_harness.rs"]
mod batch_responses_harness;
#[allow(dead_code)]
#[path = "../adapters/sdk.rs"]
mod sdk;

use batch_responses_harness as batch;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const FIXTURES: [(&str, &[u8]); 6] = [
    (
        "cancelled.sse",
        include_bytes!("fixtures/responses/cancelled.sse"),
    ),
    (
        "failed-partial.sse",
        include_bytes!("fixtures/responses/failed-partial.sse"),
    ),
    (
        "fragmented-and-unknown.sse",
        include_bytes!("fixtures/responses/fragmented-and-unknown.sse"),
    ),
    (
        "incomplete.sse",
        include_bytes!("fixtures/responses/incomplete.sse"),
    ),
    (
        "interrupted.sse",
        include_bytes!("fixtures/responses/interrupted.sse"),
    ),
    (
        "multiple-tools.sse",
        include_bytes!("fixtures/responses/multiple-tools.sse"),
    ),
];

#[derive(serde::Deserialize)]
struct Manifest {
    profile: String,
    fixtures: BTreeMap<String, String>,
}

#[test]
fn headless_batch_harness_passes_the_canonical_corpus() {
    let manifest: Manifest =
        serde_json::from_slice(include_bytes!("fixtures/responses/manifest.json")).unwrap();
    assert_eq!(manifest.profile, batch::HARNESS_PROFILE);
    assert_eq!(manifest.fixtures.len(), FIXTURES.len());
    for (name, bytes) in FIXTURES {
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            manifest.fixtures[name]
        );
        let result = batch::run_fixture(bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(result.terminal.starts_with("response.") || result.terminal.starts_with("chisei."));
    }
    let tools =
        batch::run_fixture(include_bytes!("fixtures/responses/multiple-tools.sse")).unwrap();
    assert_eq!(tools.tool_calls.len(), 2);
    let first = &tools.tool_calls[&0];
    assert_eq!(first.item_id, "item_a");
    assert_eq!(first.call_id, "call_y");
    assert_eq!(first.name, "lookup_weather");
    assert_eq!(first.output_index, 0);
    assert_eq!(first.arguments, r#"{"city":"Berlin"}"#);
    let forward = batch::run_fixture(include_bytes!(
        "fixtures/responses/fragmented-and-unknown.sse"
    ))
    .unwrap();
    assert_eq!(forward.unknown_events, 1);
}

#[test]
fn batch_outcome_uses_shared_receipt_and_evidence_contracts() {
    let result =
        batch::run_fixture(include_bytes!("fixtures/responses/multiple-tools.sse")).unwrap();
    let receipt = batch::operation_receipt(
        &result,
        batch::BatchReceiptContext {
            operation_id: "operation-batch-1",
            namespace: "analytics",
            operation_class: "dataset-validation",
            actor: "batch-worker",
            policy_version: "analytics-policy-v3",
            verification_passed: Some(true),
            started_at_ms: 100,
            completed_at_ms: 200,
        },
    )
    .unwrap();
    let completeness = receipt.completeness();
    assert!(!completeness.complete);
    assert!(completeness.errors.is_empty());
    assert_eq!(receipt.uncovered_surfaces.len(), 4);
    assert_eq!(receipt.schema_version, batch::HARNESS_PROFILE);
    let verification = receipt
        .events
        .iter()
        .find(|event| {
            event.kind == sekai_chisei::chisei::receipt::ReceiptEventKind::VerificationRecorded
        })
        .unwrap();
    assert_eq!(verification.timestamp_ms, 200);
    assert_eq!(
        verification.attributes.get("status").map(String::as_str),
        Some("passed")
    );
    assert_eq!(
        receipt
            .events
            .last()
            .unwrap()
            .attributes
            .get("status")
            .map(String::as_str),
        Some("completed")
    );

    let draft = batch::evidence(&result, &receipt.operation_id, true, 200).unwrap();
    batch::CONFORMANCE_PROFILE.validate(&draft).unwrap();
    let config = sdk::AdapterConfig {
        target: "http://127.0.0.1:50051".into(),
        producer_identity: "producer:batch-harness".into(),
        source_instance: "analytics-nightly".into(),
        namespace: receipt.namespace.clone(),
        target_external_id: "dataset:customer-health".into(),
        target_kind: "dataset".into(),
        classification: "internal".into(),
    };
    let outbox = std::env::temp_dir().join(format!(
        "sekai-batch-harness-test-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let (envelope, acknowledgement) =
        sdk::prepare_delivery_in(&outbox, &config, draft, 201).unwrap();
    assert_eq!(envelope.contract_version, sdk::EVIDENCE_CONTRACT_VERSION);
    assert_eq!(
        envelope.causality.as_ref().unwrap().operation_id,
        receipt.operation_id
    );
    assert_eq!(envelope.evidence_type, batch::EVIDENCE_TYPE);
    acknowledgement.acknowledge().unwrap();
    std::fs::remove_dir(outbox).unwrap();
}

#[test]
fn batch_harness_rejects_events_after_terminal() {
    let invalid = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\nevent: response.created\ndata: {\"type\":\"response.created\"}\n\n";
    assert!(batch::run_fixture(invalid).is_err());

    let mismatched_type = b"event: response.output_text.delta\ndata: {\"type\":\"response.failed\",\"item_id\":\"msg_a\",\"output_index\":0,\"delta\":\"corrupt\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert!(batch::run_fixture(mismatched_type).is_err());
}

#[test]
fn terminal_metadata_accepts_canonical_top_level_forms() {
    let top_level = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"status\":\"completed\",\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}\n\n";
    let result = batch::run_fixture(top_level).unwrap();
    assert_eq!(result.input_tokens, Some(2));
    assert_eq!(result.output_tokens, Some(1));

    let split = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"},\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}\n\n";
    let result = batch::run_fixture(split).unwrap();
    assert_eq!(result.input_tokens, Some(3));
    assert_eq!(result.output_tokens, Some(2));

    let type_only = b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert_eq!(
        batch::run_fixture(type_only).unwrap().terminal,
        "response.completed"
    );

    let unknown_usage =
        b"event: response.completed\ndata: {\"type\":\"response.completed\",\"usage\":null}\n\n";
    let result = batch::run_fixture(unknown_usage).unwrap();
    assert_eq!(result.input_tokens, None);
    assert_eq!(result.output_tokens, None);
}

#[test]
fn batch_harness_rejects_an_unterminated_final_frame() {
    let truncated = b"event: response.completed\ndata: {\"type\":\"response.completed\"}";
    assert!(batch::run_fixture(truncated).is_err());
}

#[test]
fn batch_harness_bounds_streams_and_individual_frames() {
    let oversized_stream = vec![b' '; batch::MAX_STREAM_BYTES + 1];
    assert!(batch::run_fixture(&oversized_stream).is_err());

    let mut oversized_frame = vec![b'a'; batch::MAX_SSE_FRAME_BYTES + 1];
    oversized_frame.extend_from_slice(b"\n\n");
    assert!(batch::run_fixture(&oversized_frame).is_err());
}

#[test]
fn batch_harness_requires_executable_tool_call_metadata() {
    let missing_name = b"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_a\",\"call_id\":\"call_a\",\"status\":\"completed\",\"arguments\":\"{}\"}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert!(batch::run_fixture(missing_name).is_err());

    let unfinished_message = b"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_a\",\"status\":\"in_progress\"}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert!(batch::run_fixture(unfinished_message).is_err());

    let incomplete_message = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_a\",\"output_index\":0,\"delta\":\"partial\"}\n\nevent: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_a\",\"status\":\"incomplete\",\"content\":[{\"type\":\"output_text\",\"text\":\"partial\"}]}}\n\nevent: response.incomplete\ndata: {\"type\":\"response.incomplete\"}\n\n";
    let incomplete = batch::run_fixture(incomplete_message).unwrap();
    assert_eq!(incomplete.terminal, "response.incomplete");
    assert_eq!(incomplete.text, "partial");

    for arguments in ["null", "[]", "\"text\""] {
        let fixture = format!(
            "event: response.output_item.done\ndata: {{\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{{\"type\":\"function_call\",\"id\":\"item_a\",\"call_id\":\"call_a\",\"name\":\"tool\",\"status\":\"completed\",\"arguments\":{}}}}}\n\nevent: response.completed\ndata: {{\"type\":\"response.completed\"}}\n\n",
            serde_json::to_string(arguments).unwrap()
        );
        assert!(batch::run_fixture(fixture.as_bytes()).is_err());
    }
}

#[test]
fn batch_harness_binds_response_identity_and_assembles_canonical_text_order() {
    let spliced = b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_a\"}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_b\",\"status\":\"completed\"}}\n\n";
    assert!(batch::run_fixture(spliced).is_err());

    let unbound_terminal = b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_a\"}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert!(batch::run_fixture(unbound_terminal).is_err());

    let late_created = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_a\",\"output_index\":0,\"delta\":\"spliced\"}\n\nevent: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_b\"}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_b\",\"status\":\"completed\"}}\n\n";
    assert!(batch::run_fixture(late_created).is_err());

    let interleaved = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_b\",\"output_index\":1,\"delta\":\"second-\"}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_a\",\"output_index\":0,\"delta\":\"first\"}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_b\",\"output_index\":1,\"delta\":\"item\"}\n\nevent: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":1,\"item\":{\"type\":\"message\",\"id\":\"msg_b\",\"content\":[{\"type\":\"output_text\",\"text\":\"second-item\"}]}}\n\nevent: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_a\",\"content\":[{\"type\":\"output_text\",\"text\":\"first\"}]}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert_eq!(
        batch::run_fixture(interleaved).unwrap().text,
        "firstsecond-item"
    );

    let content_interleaved = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_a\",\"output_index\":0,\"content_index\":1,\"delta\":\"tail\"}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_a\",\"output_index\":0,\"content_index\":0,\"delta\":\"head\"}\n\nevent: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_a\",\"content\":[{\"type\":\"output_text\",\"text\":\"head\"},{\"type\":\"output_text\",\"text\":\"tail\"}]}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert_eq!(
        batch::run_fixture(content_interleaved).unwrap().text,
        "headtail"
    );

    let refusal = b"event: response.refusal.delta\ndata: {\"type\":\"response.refusal.delta\",\"item_id\":\"msg_a\",\"output_index\":0,\"content_index\":0,\"delta\":\"cannot comply\"}\n\nevent: response.refusal.done\ndata: {\"type\":\"response.refusal.done\",\"item_id\":\"msg_a\",\"output_index\":0,\"content_index\":0,\"refusal\":\"cannot comply\"}\n\nevent: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_a\",\"status\":\"completed\",\"content\":[{\"type\":\"refusal\",\"refusal\":\"cannot comply\"}]}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert_eq!(batch::run_fixture(refusal).unwrap().text, "cannot comply");

    let corrupted = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_a\",\"output_index\":0,\"delta\":\"wrong\"}\n\nevent: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_a\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":\"right\"}]}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert!(batch::run_fixture(corrupted).is_err());

    let empty = b"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_a\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":\"\"}]}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    assert_eq!(batch::run_fixture(empty).unwrap().text, "");

    let terminal_only = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"id\":\"msg_a\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":\"authoritative\"}]}]}}\n\n";
    assert_eq!(
        batch::run_fixture(terminal_only).unwrap().text,
        "authoritative"
    );

    let terminal_omits_streamed = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_a\",\"output_index\":0,\"delta\":\"partial\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n";
    assert!(batch::run_fixture(terminal_omits_streamed).is_err());
}

#[test]
fn ambiguous_terminals_do_not_become_verification_results() {
    let result = batch::run_fixture(include_bytes!("fixtures/responses/interrupted.sse")).unwrap();
    assert!(batch::evidence(&result, "operation-interrupted", false, 200).is_err());

    let receipt = batch::operation_receipt(
        &result,
        batch::BatchReceiptContext {
            operation_id: "operation-interrupted",
            namespace: "analytics",
            operation_class: "dataset-validation",
            actor: "batch-worker",
            policy_version: "analytics-policy-v3",
            verification_passed: None,
            started_at_ms: 100,
            completed_at_ms: 200,
        },
    )
    .unwrap();
    let outcome = receipt.events.last().unwrap();
    assert_eq!(
        outcome.attributes.get("status").map(String::as_str),
        Some("interrupted")
    );
    assert!(!outcome.attributes.contains_key("passed"));
    assert!(!outcome.attributes.contains_key("outcome_metric"));
    assert!(!outcome.attributes.contains_key("outcome_value"));
}
