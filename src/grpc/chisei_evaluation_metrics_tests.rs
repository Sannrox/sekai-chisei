//! Multi-metric evaluators judged by plan-owned objectives, through the gRPC
//! evaluation path (ADR 0154).

use super::*;
use crate::chisei::evaluation_compare as compare_domain;
use crate::chisei::evaluation_metrics::METRICS_RESULT_SCHEMA;

const METRICS_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Reports the metric values it is handed as parameters, so a test picks the
/// measurement and the plan alone decides the verdict. Its own status is a
/// deliberate `fail`: the executor must not trust it.
struct MetricsFixtureEvaluator;

impl DeterministicEvaluator for MetricsFixtureEvaluator {
    fn evaluate(
        &self,
        input: &evaluation_execution_domain::DeterministicEvaluatorInput,
    ) -> Result<DeterministicEvaluatorOutput, String> {
        let value = |name: &str| input.parameters.get(name).cloned().unwrap();
        Ok(DeterministicEvaluatorOutput {
            contract_version: EVALUATOR_RESULT_CONTRACT.into(),
            status: "fail".into(),
            reason_code: "measured".into(),
            result: serde_json::json!({
                "contract_version": METRICS_RESULT_SCHEMA,
                "metrics": [
                    {"name": "accuracy", "kind": "integer_micros", "value": value("accuracy")},
                    {"name": "latency_ms", "kind": "integer_micros", "value": value("latency_ms")},
                    {"name": "tokens", "kind": "integer_micros", "value": 42},
                ],
            }),
        })
    }
}

fn metrics_service() -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let registry = Arc::new(evaluation_execution_domain::DeterministicEvaluatorRegistry::default());
    registry
        .register(METRICS_DIGEST, Arc::new(MetricsFixtureEvaluator))
        .unwrap();
    let chisei = crate::chisei_store::ChiseiStore::from_shared_runtime(db);
    let facts = crate::chisei::sekai_facts::SekaiFacts::in_process(shared_sekai_store(&chisei));
    ChiseiServiceImpl::new_with_evaluator_registry(chisei, config(":memory:"), registry)
        .with_sekai_facts(facts)
        .unwrap()
}

async fn put_metrics_definition(svc: &ChiseiServiceImpl) -> String {
    let mut request = evaluator_definition_request("acme");
    let definition = request.definition.as_mut().unwrap();
    definition.evaluator_id = "quality".into();
    definition.implementation_digest = METRICS_DIGEST.into();
    definition
        .supported_result_schemas
        .push(METRICS_RESULT_SCHEMA.into());
    definition.parameter_schema_json = r#"{"type":"object","properties":{"accuracy":{"type":"integer"},"latency_ms":{"type":"integer"}},"required":["accuracy","latency_ms"],"additionalProperties":false}"#.into();
    definition.declared_metrics = ["accuracy", "latency_ms", "tokens"]
        .into_iter()
        .map(|name| EvaluationMetricDeclaration {
            name: name.into(),
            kind: "integer_micros".into(),
        })
        .collect();
    svc.put_evaluator_definition(Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap()
        .definition_id
}

fn objective(metric: &str, direction: &str, threshold: i64) -> EvaluationMetricObjective {
    EvaluationMetricObjective {
        metric: metric.into(),
        objective: direction.into(),
        threshold_micros: Some(threshold),
        ..Default::default()
    }
}

async fn run_measurement(
    svc: &ChiseiServiceImpl,
    definition_id: &str,
    invariant_id: &str,
    version: &str,
    accuracy: i64,
    latency_ms: i64,
) -> (ResolvedEvaluationManifest, EvaluationExecutionProjection) {
    let mut request = evaluation_plan_request("acme", definition_id, invariant_id, version);
    let node = &mut request.plan.as_mut().unwrap().nodes[0];
    node.parameters_json = format!(r#"{{"accuracy":{accuracy},"latency_ms":{latency_ms}}}"#);
    node.metric_objectives = vec![
        objective("accuracy", "maximize", 900_000),
        objective("latency_ms", "minimize", 250_000_000),
    ];
    let plan = svc
        .put_evaluation_plan(Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert_eq!(plan.nodes[0].metric_objectives.len(), 2);
    let manifest = svc
        .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
            "acme",
            &format!("metrics-resolve-{version}"),
            &plan.plan_version_id,
            10,
        )))
        .await
        .unwrap()
        .into_inner()
        .manifest
        .unwrap();
    let execution = svc
        .execute_evaluation_manifest(Request::new(ExecuteEvaluationManifestRequest {
            execution: Some(EvaluationExecutionRequest {
                contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
                executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
                namespace: "acme".into(),
                manifest_digest: manifest.manifest_digest.clone(),
                max_total_duration_ms: 1_000,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    (manifest, execution)
}

fn verdicts(execution: &EvaluationExecutionProjection) -> Vec<(String, i64, String)> {
    execution.steps[0]
        .metric_verdicts
        .iter()
        .map(|verdict| {
            (
                verdict.name.clone(),
                verdict.integer_micros_value,
                verdict.verdict.clone(),
            )
        })
        .collect()
}

fn owned(rows: &[(&str, i64, &str)]) -> Vec<(String, i64, String)> {
    rows.iter()
        .map(|(name, value, verdict)| (name.to_string(), *value, verdict.to_string()))
        .collect()
}

#[tokio::test]
async fn a_node_passes_only_when_every_bound_objective_is_met() {
    let svc = metrics_service();
    let invariant_id = install_invariant(&svc, "acme");
    let definition_id = put_metrics_definition(&svc).await;

    // Values exactly at both thresholds meet maximize and minimize.
    let (at_manifest, at_threshold) = run_measurement(
        &svc,
        &definition_id,
        &invariant_id,
        "1.0.0",
        900_000,
        250_000_000,
    )
    .await;
    assert_eq!(
        at_threshold.status,
        evaluation_execution_domain::VERDICT_ALLOW
    );
    assert_eq!(at_threshold.steps[0].status, STATUS_PASS);
    assert_eq!(at_threshold.steps[0].reason_code, "metric_objectives_met");
    assert_eq!(
        verdicts(&at_threshold),
        owned(&[
            ("accuracy", 900_000, "met"),
            ("latency_ms", 250_000_000, "met"),
            ("tokens", 42, "advisory"),
        ])
    );
    let accuracy = &at_threshold.steps[0].metric_verdicts[0];
    assert_eq!(
        accuracy.objective,
        Some(objective("accuracy", "maximize", 900_000))
    );

    // One objective one micro short fails the node and the gate.
    let (below_manifest, below) = run_measurement(
        &svc,
        &definition_id,
        &invariant_id,
        "2.0.0",
        899_999,
        250_000_000,
    )
    .await;
    assert_eq!(below.status, evaluation_execution_domain::VERDICT_DENY);
    assert_eq!(below.steps[0].status, "fail");
    assert_eq!(below.steps[0].reason_code, "metric_objective_unmet");
    assert_eq!(
        verdicts(&below),
        owned(&[
            ("accuracy", 899_999, "unmet"),
            ("latency_ms", 250_000_000, "met"),
            ("tokens", 42, "advisory"),
        ])
    );

    // The receipts carry the verdicts, and comparison diffs them per metric.
    let finished = |manifest: &ResolvedEvaluationManifest| {
        let digest = manifest.manifest_digest.clone();
        let svc = &svc;
        async move {
            let receipt = execution_receipt(svc, &digest, None).await.unwrap();
            compare_domain::FinishedExecution::from_receipt("acme", &digest, &receipt).unwrap()
        }
    };
    let baseline = finished(&at_manifest).await;
    let candidate = finished(&below_manifest).await;
    let comparison = compare_domain::compare(&baseline, &candidate).unwrap();
    assert_eq!(comparison.outcome, compare_domain::Outcome::Regressed);
    let changes = comparison.nodes[0]
        .metrics
        .iter()
        .map(|metric| (metric.name.as_str(), metric.change))
        .collect::<Vec<_>>();
    assert_eq!(
        changes,
        [
            ("accuracy", compare_domain::Change::Regressed),
            ("latency_ms", compare_domain::Change::Unchanged),
            ("tokens", compare_domain::Change::Unchanged),
        ]
    );
}

#[tokio::test]
async fn a_plan_cannot_bind_an_objective_to_an_undeclared_metric() {
    let svc = metrics_service();
    let invariant_id = install_invariant(&svc, "acme");
    let definition_id = put_metrics_definition(&svc).await;
    let mut request = evaluation_plan_request("acme", &definition_id, &invariant_id, "1.0.0");
    let node = &mut request.plan.as_mut().unwrap().nodes[0];
    node.parameters_json = r#"{"accuracy":1,"latency_ms":1}"#.into();
    node.metric_objectives = vec![objective("cost", "minimize", 1)];
    let error = svc
        .put_evaluation_plan(Request::new(request))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(error.message().contains("does not declare"), "{error:?}");
}
