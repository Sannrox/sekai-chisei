//! Custom-rubric evaluator definitions through the gRPC definition path
//! (ADR 0155): the rubric round-trips, is checked against its digest, and a
//! changed rubric or scale is a new definition version.

use super::*;

const RUBRIC: &str = "The answer cites the source record it relies on.";

fn rubric_service() -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let registry = Arc::new(evaluation_execution_domain::DeterministicEvaluatorRegistry::default());
    let chisei = crate::chisei_store::ChiseiStore::from_shared_runtime(db);
    let facts = crate::chisei::sekai_facts::SekaiFacts::in_process(shared_sekai_store(&chisei));
    ChiseiServiceImpl::new_with_evaluator_registry(chisei, config(":memory:"), registry)
        .with_sekai_facts(facts)
        .unwrap()
}

fn rubric_request(version: &str, rubric: EvaluationRubric) -> PutEvaluatorDefinitionRequest {
    let mut request = evaluator_definition_request("acme");
    let definition = request.definition.as_mut().unwrap();
    definition.evaluator_id = "cites-source".into();
    definition.version = version.into();
    definition.execution_class = evaluation_plan_domain::STOCHASTIC_EXECUTION_CLASS.into();
    definition.supported_result_schemas =
        vec![evaluation_plan_domain::STOCHASTIC_RESULT_SCHEMA.into()];
    definition.stochastic_policy = Some(StochasticEvaluatorPolicy {
        provider: "ollama".into(),
        model: "ollama/judge-fixture:latest".into(),
        prompt_profile: evaluation_plan_domain::CUSTOM_RUBRIC_PROFILE.into(),
        prompt_profile_digest: crate::chisei::stochastic_evaluation::CUSTOM_RUBRIC_PROFILE_DIGEST
            .into(),
        result_schema: evaluation_plan_domain::STOCHASTIC_RESULT_SCHEMA.into(),
        trial_count: 2,
        top_p_millionths: 1_000_000,
        aggregation_rule: evaluation_plan_domain::STOCHASTIC_AGGREGATION_MEAN_VARIANCE.into(),
        minimum_mean_score_micros: 500_000,
        max_tokens_per_trial: 4_096,
        max_total_tokens: 8_192,
        egress_policy: evaluation_plan_domain::STOCHASTIC_EGRESS_LOCAL_ONLY.into(),
        raw_response_retention: evaluation_plan_domain::STOCHASTIC_RAW_RETENTION_NONE.into(),
        rubric: Some(rubric),
        ..Default::default()
    });
    request
}

fn rubric(scale_max_points: u32) -> EvaluationRubric {
    EvaluationRubric {
        text: RUBRIC.into(),
        digest: evaluation_plan_domain::rubric_digest(RUBRIC),
        scale_max_points,
    }
}

async fn put(
    svc: &ChiseiServiceImpl,
    request: PutEvaluatorDefinitionRequest,
) -> Result<EvaluatorDefinition, Status> {
    svc.put_evaluator_definition(Request::new(request))
        .await
        .map(|response| response.into_inner().record.unwrap().definition.unwrap())
}

#[tokio::test]
async fn rubric_definitions_round_trip_and_version_with_their_criteria() {
    let svc = rubric_service();
    let binary = put(&svc, rubric_request("1.0.0", rubric(0))).await.unwrap();
    assert_eq!(binary.stochastic_policy.unwrap().rubric, Some(rubric(0)));

    // The same version with a different scale is different content.
    let error = put(&svc, rubric_request("1.0.0", rubric(4)))
        .await
        .unwrap_err();
    assert!(error.message().contains("different content"), "{error:?}");

    let graded = put(&svc, rubric_request("1.1.0", rubric(4))).await.unwrap();
    assert_eq!(graded.stochastic_policy.unwrap().rubric, Some(rubric(4)));
    assert_ne!(graded.content_digest, binary.content_digest);

    let mut tampered = rubric(0);
    tampered.text = "The answer is short.".into();
    let error = put(&svc, rubric_request("1.2.0", tampered))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(
        error.message().contains("digest does not match"),
        "{error:?}"
    );
}
