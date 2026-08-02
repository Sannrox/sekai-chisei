//! Shared SQLite/PostgreSQL persistence conformance for evaluator definitions and plans.

use sekai_chisei::chisei::evaluation_plan::*;
use sekai_chisei::db::{postgres::PostgresDb, runtime_db::RuntimeDb, sekai::SekaiDb};
use std::sync::Arc;

fn definition(namespace: &str, suffix: &str) -> EvaluatorDefinition {
    EvaluatorDefinition {
        contract_version: EVALUATOR_DEFINITION_CONTRACT.into(),
        definition_id: String::new(),
        namespace: namespace.into(),
        evaluator_id: format!("schema-check-{suffix}"),
        version: "1.0.0".into(),
        implementation_digest: format!("sha256:{}", "a".repeat(64)),
        execution_class: DETERMINISTIC_EXECUTION_CLASS.into(),
        supported_predicate_kinds: vec!["schema_conforms".into()],
        supported_input_schemas: vec!["schema://document/v1".into()],
        supported_result_schemas: vec!["schema://pass-fail/v1".into()],
        parameter_schema_json:
            r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#.into(),
        evidence_classifications: vec!["internal".into()],
        resource_limits: EvaluatorResourceLimits {
            timeout_ms: 1_000,
            max_input_bytes: 4_096,
            max_output_bytes: 1_024,
            max_evidence_items: 8,
        },
        adapter_endpoint: String::new(),
        stochastic_policy: None,
        source_ref: "repo://evaluators/schema-check@1".into(),
        content_digest: String::new(),
        created_by: String::new(),
        created_at_ms: 0,
    }
}

fn stochastic_definition(
    namespace: &str,
    suffix: &str,
    gate_eligible: bool,
) -> EvaluatorDefinition {
    let mut definition = definition(
        namespace,
        &format!(
            "{suffix}-stochastic-{}",
            if gate_eligible { "gated" } else { "advisory" }
        ),
    );
    definition.execution_class = STOCHASTIC_EXECUTION_CLASS.into();
    definition.supported_result_schemas = vec![STOCHASTIC_RESULT_SCHEMA.into()];
    definition.stochastic_policy = Some(StochasticEvaluatorPolicy {
        provider: "openai".into(),
        model: "openai/gpt-fixture".into(),
        prompt_profile: "chisei.fixture-rubric/v1".into(),
        prompt_profile_digest: format!("sha256:{}", "b".repeat(64)),
        result_schema: STOCHASTIC_RESULT_SCHEMA.into(),
        trial_count: 3,
        temperature_millis: 200,
        top_p_millionths: 900_000,
        seed_supported: true,
        base_seed: 17,
        aggregation_rule: STOCHASTIC_AGGREGATION_MEAN_VARIANCE.into(),
        minimum_mean_score_micros: 800_000,
        minimum_pass_rate_basis_points: 6_667,
        maximum_score_variance_micros_squared: 10_000_000_000,
        gate_eligible,
        max_retries_per_trial: 1,
        max_tokens_per_trial: 100,
        max_total_tokens: 600,
        egress_policy: STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL.into(),
        raw_response_retention: STOCHASTIC_RAW_RETENTION_NONE.into(),
    });
    definition
}

fn plan(namespace: &str, suffix: &str, definition_id: &str) -> EvaluationPlan {
    EvaluationPlan {
        contract_version: EVALUATION_PLAN_CONTRACT.into(),
        plan_version_id: String::new(),
        namespace: namespace.into(),
        plan_id: format!("document-review-{suffix}"),
        version: "1.0.0".into(),
        accepted_subject_profiles: vec!["document/v1".into()],
        nodes: vec![EvaluationPlanNode {
            node_id: "schema".into(),
            evaluator_definition_id: definition_id.into(),
            depends_on_node_ids: vec![],
            input_bindings: vec![EvaluationInputBinding {
                name: "document".into(),
                source_kind: INPUT_INVARIANT.into(),
                schema_id: "schema://document/v1".into(),
            }],
            parameters_json: "{}".into(),
            invariant_version_ids: vec!["governed-invariant-version:fixture".into()],
            classification: NODE_REQUIRED.into(),
        }],
        reducer: FIXED_REDUCER.into(),
        source_ref: "repo://plans/document-review@1".into(),
        content_digest: String::new(),
        created_by: String::new(),
        created_at_ms: 0,
    }
}

fn exercise(db: &RuntimeDb, namespace: &str, suffix: &str) -> (String, String) {
    let stored_definition = db
        .put_evaluator_definition(definition(namespace, suffix), "operator", 10)
        .unwrap();
    let replay = db
        .put_evaluator_definition(definition(namespace, suffix), "other", 20)
        .unwrap();
    assert_eq!(stored_definition, replay);
    assert_eq!(
        db.get_evaluator_availability(&stored_definition.definition_id)
            .unwrap()
            .unwrap()
            .state,
        AVAILABILITY_ENABLED
    );
    let stored_plan = db
        .put_evaluation_plan(
            plan(namespace, suffix, &stored_definition.definition_id),
            "operator",
            25,
        )
        .unwrap();
    let transition = db
        .set_evaluator_availability(
            &stored_definition.definition_id,
            AVAILABILITY_DISABLED,
            "",
            "maintenance",
            "disable-1",
            "operator",
            30,
        )
        .unwrap();
    let transition_replay = db
        .set_evaluator_availability(
            &stored_definition.definition_id,
            AVAILABILITY_DISABLED,
            "",
            "maintenance",
            "disable-1",
            "other",
            40,
        )
        .unwrap();
    assert_eq!(transition, transition_replay);
    // Historical idempotent replay remains valid after the selected evaluator
    // is disabled; only publication of a new plan version is blocked.
    let replay = db
        .put_evaluation_plan(
            plan(namespace, suffix, &stored_definition.definition_id),
            "other",
            60,
        )
        .unwrap();
    assert_eq!(stored_plan, replay);
    let mut new_version = plan(namespace, suffix, &stored_definition.definition_id);
    new_version.version = "2.0.0".into();
    assert!(
        db.put_evaluation_plan(new_version, "operator", 70)
            .unwrap_err()
            .contains("unavailable")
    );
    let listed = db
        .list_evaluation_plans(namespace, Some(&stored_plan.plan_id))
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].plan_version_id, stored_plan.plan_version_id);

    let advisory_definition = db
        .put_evaluator_definition(
            stochastic_definition(namespace, suffix, false),
            "operator",
            80,
        )
        .unwrap();
    assert!(
        db.put_evaluation_plan(
            plan(
                namespace,
                &format!("{suffix}-stochastic-advisory"),
                &advisory_definition.definition_id,
            ),
            "operator",
            90,
        )
        .unwrap_err()
        .contains("gate eligibility")
    );
    let gated_definition = db
        .put_evaluator_definition(
            stochastic_definition(namespace, suffix, true),
            "operator",
            100,
        )
        .unwrap();
    db.put_evaluation_plan(
        plan(
            namespace,
            &format!("{suffix}-stochastic-gated"),
            &gated_definition.definition_id,
        ),
        "operator",
        110,
    )
    .unwrap();
    (stored_definition.definition_id, stored_plan.plan_version_id)
}

#[test]
fn sqlite_evaluation_plan_conformance_and_restart() {
    let path = std::env::temp_dir().join(format!(
        "sekai-evaluation-plan-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let path = path.to_string_lossy().into_owned();
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&path).unwrap()));
    let (definition_id, plan_id) = exercise(&db, "sqlite-evaluation", "sqlite");
    drop(db);
    let restarted = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&path).unwrap()));
    assert!(
        restarted
            .get_evaluator_definition(&definition_id)
            .unwrap()
            .is_some()
    );
    assert!(restarted.get_evaluation_plan(&plan_id).unwrap().is_some());
    std::fs::remove_file(path).ok();
}

fn postgres() -> RuntimeDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    };
    RuntimeDb::Postgres(Arc::new(db))
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_evaluation_plan_conformance_and_restart() {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("pg-evaluation-{suffix}");
    let (definition_id, plan_id) = exercise(&postgres(), &namespace, &suffix);
    let restarted = postgres();
    assert!(
        restarted
            .get_evaluator_definition(&definition_id)
            .unwrap()
            .is_some()
    );
    assert!(restarted.get_evaluation_plan(&plan_id).unwrap().is_some());
}
