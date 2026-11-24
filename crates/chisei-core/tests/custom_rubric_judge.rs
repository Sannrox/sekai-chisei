//! A `chisei.custom-rubric/v1` judge runs through the production stochastic
//! evaluator, with the same trials, budget, and thresholds as the bounded
//! rubric (ADR 0155). A loopback model endpoint stands in for the provider
//! and records each request, so the test checks what reaches the model.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chisei_core::chisei::evaluation_execution::{
    NodeExecution, STATUS_FAIL, STATUS_PASS, STOCHASTIC_TRIAL_RESULT_CONTRACT,
    build_evaluator_input, execute_stochastic_node,
};
use chisei_core::chisei::evaluation_manifest::{
    MANIFEST_CONTRACT, RESOLVER_VERSION, ResolvedEvaluationManifest, ResolvedEvaluationNode,
    ResolvedEvaluatorBinding, ResolvedInvariantBinding,
};
use chisei_core::chisei::evaluation_plan::{
    CUSTOM_RUBRIC_PROFILE, EvaluationRubric, EvaluatorResourceLimits, NODE_REQUIRED,
    STOCHASTIC_AGGREGATION_MEAN_VARIANCE, STOCHASTIC_EGRESS_LOCAL_ONLY,
    STOCHASTIC_RAW_RETENTION_NONE, StochasticEvaluatorPolicy, rubric_digest,
};
use chisei_core::chisei::stochastic_evaluation::{
    BOUNDED_RUBRIC_IMPLEMENTATION_DIGEST, CUSTOM_RUBRIC_PROFILE_DIGEST,
    production_stochastic_evaluator_registry,
};
use chisei_core::config::Config;
use serde_json::{Value, json};

const RUBRIC: &str = "The answer cites the source record it relies on.";

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

/// Serves one fixed judge result on `/v1/chat/completions` and keeps every
/// request body. Returns the base URL.
fn loopback_judge(result: Value) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback judge");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    let body = json!({
        "choices": [{
            "message": {"content": result.to_string()},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 40, "completion_tokens": 8}
    })
    .to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut request = vec![0; length];
            if reader.read_exact(&mut request).is_err() {
                continue;
            }
            if let Ok(request) = serde_json::from_slice(&request) {
                seen.lock().unwrap().push(request);
            }
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (url, requests)
}

fn judge(scale_max_points: Option<u32>, result: Value) -> (NodeExecution, Vec<Value>) {
    let (url, requests) = loopback_judge(result);
    let state = tempfile::tempdir().expect("registry state dir");
    let mut config = Config::from_lookup(&|_| Err(std::env::VarError::NotPresent));
    config.db_path = state.path().join("chisei.db").display().to_string();
    config.ollama_url = url;
    let registry = production_stochastic_evaluator_registry(config).expect("registry");
    let policy = StochasticEvaluatorPolicy {
        provider: "ollama".into(),
        model: "ollama/judge-fixture:latest".into(),
        prompt_profile: CUSTOM_RUBRIC_PROFILE.into(),
        prompt_profile_digest: CUSTOM_RUBRIC_PROFILE_DIGEST.into(),
        result_schema: STOCHASTIC_TRIAL_RESULT_CONTRACT.into(),
        trial_count: 2,
        temperature_millis: 0,
        top_p_millionths: 1_000_000,
        seed_supported: false,
        base_seed: 0,
        aggregation_rule: STOCHASTIC_AGGREGATION_MEAN_VARIANCE.into(),
        minimum_mean_score_micros: 500_000,
        minimum_pass_rate_basis_points: 0,
        maximum_score_variance_micros_squared: 1_000_000_000_000,
        gate_eligible: true,
        max_retries_per_trial: 0,
        max_tokens_per_trial: 16_384,
        max_total_tokens: 32_768,
        egress_policy: STOCHASTIC_EGRESS_LOCAL_ONLY.into(),
        raw_response_retention: STOCHASTIC_RAW_RETENTION_NONE.into(),
        rubric: Some(EvaluationRubric {
            text: RUBRIC.into(),
            digest: rubric_digest(RUBRIC),
            scale_max_points,
        }),
    };
    let node = ResolvedEvaluationNode {
        metric_objectives: Vec::new(),
        node_id: "cites-source".into(),
        evaluator: ResolvedEvaluatorBinding {
            declared_metrics: Vec::new(),
            definition_id: "evaluator:cites-source".into(),
            definition_digest: digest('a'),
            implementation_digest: BOUNDED_RUBRIC_IMPLEMENTATION_DIGEST.into(),
            stochastic_policy: Some(policy),
        },
        depends_on_node_ids: vec![],
        input_bindings: vec![],
        parameters_json: "{}".into(),
        invariants: vec![ResolvedInvariantBinding {
            invariant_version_id: "invariant:cites-source".into(),
            content_digest: digest('b'),
            predicate_kind: "bounded_quality_review/v1".into(),
            input_schema: "fixture.subject/v1".into(),
            result_schema: STOCHASTIC_TRIAL_RESULT_CONTRACT.into(),
            evidence_types: vec![],
            provenance_evidence_object_ids: vec![],
            waiver_version_ids: vec![],
        }],
        evidence_object_ids: vec![],
        classification: NODE_REQUIRED.into(),
    };
    let manifest = ResolvedEvaluationManifest {
        contract_version: MANIFEST_CONTRACT.into(),
        resolver_version: RESOLVER_VERSION.into(),
        manifest_id: "manifest:custom-rubric".into(),
        manifest_digest: digest('c'),
        namespace: "rubric".into(),
        plan_version_id: "plan:custom-rubric".into(),
        plan_digest: digest('d'),
        subject_profile: "fixture.subject/v1".into(),
        subject_identity: "subject:custom-rubric".into(),
        subject_content_digest: digest('e'),
        invariant_set_id: "set:custom-rubric".into(),
        invariant_set_digest: digest('f'),
        invariant_profile_digest: digest('1'),
        evaluation_time_ms: 1,
        resolved_by: "custom-rubric-test".into(),
        requirements: vec![],
        nodes: vec![node],
        evidence: vec![],
        waivers: vec![],
        created_at_ms: 1,
    };
    let input = build_evaluator_input(&manifest, &manifest.nodes[0], vec![], &BTreeMap::new())
        .expect("build stochastic input");
    let execution = execute_stochastic_node(
        &registry,
        &manifest,
        &manifest.nodes[0],
        input,
        &EvaluatorResourceLimits {
            timeout_ms: 10_000,
            max_input_bytes: 64 * 1024,
            max_output_bytes: 16 * 1024,
            max_evidence_items: 8,
        },
        Duration::from_secs(20),
        Arc::new(AtomicBool::new(false)),
    )
    .expect("execute rubric trials");
    let requests = requests.lock().unwrap().clone();
    (execution, requests)
}

fn system_prompt(request: &Value) -> &str {
    request["messages"]
        .as_array()
        .and_then(|messages| messages.iter().find(|m| m["role"] == "system"))
        .and_then(|message| message["content"].as_str())
        .expect("system message")
}

fn trial_scores(execution: &NodeExecution) -> Vec<u32> {
    let evidence = execution.receipt.stochastic_evidence.as_ref().unwrap();
    evidence.trials.iter().map(|t| t.score_micros).collect()
}

#[test]
fn binary_rubric_records_zero_or_one_and_reaches_the_model_delimited() {
    let (failed, requests) = judge(
        None,
        json!({"passed": false, "reason_code": "criteria_not_met"}),
    );
    assert_eq!(failed.receipt.status, STATUS_FAIL);
    assert_eq!(trial_scores(&failed), vec![0, 0]);
    assert_eq!(requests.len(), 2, "one request per fixed trial");
    let system = system_prompt(&requests[0]);
    assert!(system.contains(&format!("<criteria>\n{RUBRIC}\n</criteria>")));
    assert!(system.starts_with("You are a bounded evaluator."));

    let (passed, _) = judge(None, json!({"passed": true, "reason_code": "criteria_met"}));
    assert_eq!(passed.receipt.status, STATUS_PASS);
    assert_eq!(trial_scores(&passed), vec![1_000_000, 1_000_000]);
}

#[test]
fn graded_rubric_scales_scores_and_refuses_one_past_its_maximum() {
    let (graded, requests) = judge(
        Some(4),
        json!({"passed": true, "score": 3, "reason_code": "criteria_met"}),
    );
    assert_eq!(graded.receipt.status, STATUS_PASS);
    assert_eq!(trial_scores(&graded), vec![750_000, 750_000]);
    assert!(system_prompt(&requests[0]).ends_with("Scale maximum: 4."));

    let (overflow, _) = judge(
        Some(4),
        json!({"passed": true, "score": 5, "reason_code": "criteria_met"}),
    );
    assert_ne!(overflow.receipt.status, STATUS_PASS);
}
