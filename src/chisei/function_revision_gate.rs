//! Evaluation gates for LLM function revisions (#1312).
//!
//! Palantir analog: Foundry markings inherit along data dependencies, and AIP
//! Evals execute a function over test cases, retain outputs, and fail the
//! suite when scores miss the threshold. Sekai retains each fixture output as
//! evidence at the union (most restrictive) of the input markings. The
//! existing `stochastic_model/v1` rubric scores that evidence; a score below
//! the manifest threshold is a deny gate on publish.

use crate::chisei::evaluation_execution::{
    self, EvaluationEvidenceInput, EvaluationExecutionProjection, EvaluationGateDecision,
    NodeExecution, StochasticEvaluatorRegistry, VERDICT_ALLOW, VERDICT_UNAVAILABLE,
};
use crate::chisei::evaluation_manifest::{
    ResolvedEvaluationManifest, ResolvedEvaluationNode, ResolvedEvaluatorBinding,
    ResolvedEvidenceBinding, ResolvedInvariantBinding,
};
use crate::chisei::evaluation_plan::{
    EvaluatorResourceLimits, NODE_REQUIRED, STOCHASTIC_AGGREGATION_MEAN_VARIANCE,
    STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL, STOCHASTIC_RAW_RETENTION_NONE,
    STOCHASTIC_RESULT_SCHEMA, StochasticEvaluatorPolicy,
};
use crate::chisei::stochastic_evaluation::{
    BOUNDED_RUBRIC_IMPLEMENTATION_DIGEST, BOUNDED_RUBRIC_PROFILE, BOUNDED_RUBRIC_PROFILE_DIGEST,
};
use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::evidence::EvidenceClassification;
use crate::sekai::function::{
    Function, FunctionBudget, FunctionHost, FunctionInvocation, LlmStepHost, PipelineStep,
    function_digest, invoke_with_llm, validate_function,
};
use crate::sekai::markings::{
    MarkingDecision, PrincipalAuthority, evaluate_marking_access, object_classification,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

pub const FUNCTION_REVISION_SUBJECT_PROFILE: &str = "chisei.function-revision/v1";
pub const FUNCTION_OUTPUT_EVIDENCE_TYPE: &str = "function_revision_output";
pub const FUNCTION_OUTPUT_SCHEMA: &str = "chisei.function-revision-output/v1";
pub const FUNCTION_OUTPUT_SCHEMA_VERSION: &str = "1";

/// Most restrictive marking among the fixture inputs (union of the lattice).
pub fn inherited_marking(inputs: &[Object]) -> Option<EvidenceClassification> {
    inputs
        .iter()
        .filter_map(|object| object_classification(object).ok().flatten())
        .max()
}

/// Evaluator route may read retained evidence only when its ceiling covers the
/// inherited marking.
pub fn evaluator_may_see(
    authority: &PrincipalAuthority,
    marking: Option<EvidenceClassification>,
) -> bool {
    evaluate_marking_access("function-revision-eval", marking, authority).decision
        != MarkingDecision::Deny
}

pub fn has_llm_step(function: &Function) -> bool {
    function
        .pipeline
        .iter()
        .any(|step| matches!(step, PipelineStep::Llm(_)))
}

/// Frozen rubric policy for a function-revision gate. Threshold is the
/// manifest `minimum_mean_score_micros`.
pub fn function_revision_rubric_policy(
    minimum_mean_score_micros: u32,
) -> StochasticEvaluatorPolicy {
    StochasticEvaluatorPolicy {
        provider: "openai".into(),
        model: "openai/function-revision-rubric".into(),
        prompt_profile: BOUNDED_RUBRIC_PROFILE.into(),
        prompt_profile_digest: BOUNDED_RUBRIC_PROFILE_DIGEST.into(),
        result_schema: STOCHASTIC_RESULT_SCHEMA.into(),
        trial_count: 2,
        temperature_millis: 0,
        top_p_millionths: 1_000_000,
        seed_supported: true,
        base_seed: 40,
        aggregation_rule: STOCHASTIC_AGGREGATION_MEAN_VARIANCE.into(),
        minimum_mean_score_micros,
        minimum_pass_rate_basis_points: 10_000,
        maximum_score_variance_micros_squared: 7_000_000_000,
        gate_eligible: true,
        max_retries_per_trial: 0,
        max_tokens_per_trial: 100,
        max_total_tokens: 200,
        egress_policy: STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL.into(),
        raw_response_retention: STOCHASTIC_RAW_RETENTION_NONE.into(),
    }
}

pub struct FunctionRevisionGateRequest<'a> {
    pub db: &'a RuntimeDb,
    pub function: &'a Function,
    pub fixtures: &'a [Object],
    pub llm_host: &'a dyn LlmStepHost,
    pub evaluator_authority: &'a PrincipalAuthority,
    pub registry: &'a StochasticEvaluatorRegistry,
    pub minimum_mean_score_micros: u32,
    pub expected_label: &'a str,
    pub host: FunctionHost,
    pub budget: FunctionBudget,
}

#[derive(Debug, Clone)]
pub struct RetainedFunctionOutput {
    pub fixture_id: String,
    pub inherited_marking: Option<EvidenceClassification>,
    pub evidence: EvaluationEvidenceInput,
    pub invocation: FunctionInvocation,
}

#[derive(Debug, Clone)]
pub struct FunctionRevisionGate {
    function_digest: String,
    inherited_marking: Option<EvidenceClassification>,
    retained: Vec<RetainedFunctionOutput>,
    projection: EvaluationExecutionProjection,
}

impl FunctionRevisionGate {
    pub fn function_digest(&self) -> &str {
        &self.function_digest
    }

    pub fn inherited_marking(&self) -> Option<EvidenceClassification> {
        self.inherited_marking
    }

    pub fn retained(&self) -> &[RetainedFunctionOutput] {
        &self.retained
    }

    pub fn projection(&self) -> &EvaluationExecutionProjection {
        &self.projection
    }

    pub fn decision(&self) -> Option<&EvaluationGateDecision> {
        self.projection.decision.as_ref()
    }

    pub fn verdict(&self) -> &str {
        self.decision()
            .map(|decision| decision.verdict.as_str())
            .unwrap_or(VERDICT_UNAVAILABLE)
    }
}

/// Invoke the revision over a fixture set, retain each output as evidence at
/// the inherited marking, score with the existing rubric evaluator, and reduce
/// the gate.
pub fn gate_function_revision(
    request: FunctionRevisionGateRequest<'_>,
) -> Result<FunctionRevisionGate, String> {
    let FunctionRevisionGateRequest {
        db,
        function,
        fixtures,
        llm_host,
        evaluator_authority,
        registry,
        minimum_mean_score_micros,
        expected_label,
        host,
        budget,
    } = request;
    if expected_label.trim().is_empty() {
        return Err("function revision evaluation gate requires expected_label".into());
    }
    if minimum_mean_score_micros == 0 {
        return Err("function revision gate threshold must be positive".into());
    }
    validate_function(function)?;
    if !has_llm_step(function) {
        return Err("function revision evaluation gate requires an llm step".into());
    }
    if fixtures.is_empty() {
        return Err("function revision evaluation gate requires a fixture set".into());
    }
    let policy = function_revision_rubric_policy(minimum_mean_score_micros);
    crate::chisei::evaluation_plan::validate_stochastic_policy(
        &policy,
        std::slice::from_ref(&policy.result_schema),
    )?;

    let function_digest = function_digest(function);
    let mut seen_ids = BTreeSet::new();
    let mut stored_fixtures = Vec::with_capacity(fixtures.len());
    for fixture in fixtures {
        if !seen_ids.insert(fixture.id.as_str()) {
            return Err(format!(
                "duplicate function revision fixture id {}",
                fixture.id
            ));
        }
        let stored = db.get_object(&fixture.id)?.ok_or_else(|| {
            format!(
                "function revision fixture {} is not in the store",
                fixture.id
            )
        })?;
        stored_fixtures.push(stored);
    }
    let suite_marking = inherited_marking(&stored_fixtures);
    let mut retained = Vec::with_capacity(stored_fixtures.len());
    for fixture in &stored_fixtures {
        let fixture_id = fixture.id.clone();
        let invocation = invoke_with_llm(
            db,
            function,
            &HashMap::new(),
            move |object| Ok(object.id == fixture_id),
            host.clone(),
            budget.clone(),
            llm_host,
        )?;
        if !invocation
            .result
            .objects
            .iter()
            .any(|object| object.id == fixture.id)
        {
            return Err(format!(
                "function revision did not select fixture {}",
                fixture.id
            ));
        }
        let content = serde_json::json!({
            "fixture_id": fixture.id,
            "function_digest": function_digest,
            "output": invocation.result.structured,
            "output_digest": invocation.receipt.output_digest,
            "inherited_marking": suite_marking.map(|value| value.as_str()),
        });
        let content_digest = digest_value(&content);
        retained.push(RetainedFunctionOutput {
            fixture_id: fixture.id.clone(),
            inherited_marking: suite_marking,
            evidence: EvaluationEvidenceInput {
                evidence_object_id: format!("evidence:function-output:{}", fixture.id),
                submission_id: format!("submission:function-output:{}", fixture.id),
                content_digest: content_digest.clone(),
                schema_id: FUNCTION_OUTPUT_SCHEMA.into(),
                schema_version: FUNCTION_OUTPUT_SCHEMA_VERSION.into(),
                content,
            },
            invocation,
        });
    }

    let visible = evaluator_may_see(evaluator_authority, suite_marking);
    let evidence_inputs: Vec<EvaluationEvidenceInput> = if visible {
        retained.iter().map(|item| item.evidence.clone()).collect()
    } else {
        Vec::new()
    };
    let manifest = function_revision_manifest(
        &function_digest,
        function,
        &retained,
        &policy,
        expected_label,
    );
    let node = &manifest.nodes[0];
    let input = evaluation_execution::build_evaluator_input(
        &manifest,
        node,
        evidence_inputs,
        &BTreeMap::new(),
    )?;
    let limits = EvaluatorResourceLimits {
        timeout_ms: 1_000,
        max_input_bytes: 64 * 1024,
        max_output_bytes: 16 * 1024,
        max_evidence_items: 16,
    };
    let execution = if visible {
        evaluation_execution::execute_stochastic_node(
            registry,
            &manifest,
            node,
            input,
            &limits,
            Duration::from_secs(2),
            Arc::new(AtomicBool::new(false)),
        )?
    } else {
        evaluation_execution::make_nonexecuted_node(
            &manifest,
            node,
            &input,
            evaluation_execution::STATUS_UNKNOWN,
            evaluation_execution::REASON_EVIDENCE_UNAVAILABLE,
        )?
    };
    let projection = projection_from_execution(&manifest, execution)?;
    Ok(FunctionRevisionGate {
        function_digest,
        inherited_marking: suite_marking,
        retained,
        projection,
    })
}

/// Persist the revision only when the bound gate is `allow`.
pub fn publish_function_revision(
    db: &RuntimeDb,
    function: &Function,
    gate: &FunctionRevisionGate,
) -> Result<(), String> {
    validate_function(function)?;
    if function_digest(function) != gate.function_digest {
        return Err("evaluation gate does not bind this function revision".into());
    }
    if gate.verdict() != VERDICT_ALLOW {
        return Err(format!(
            "function revision publish denied: {}",
            gate.verdict()
        ));
    }
    db.create_function(function)
}

fn function_revision_manifest(
    function_digest: &str,
    function: &Function,
    retained: &[RetainedFunctionOutput],
    policy: &StochasticEvaluatorPolicy,
    expected_label: &str,
) -> ResolvedEvaluationManifest {
    let evidence: Vec<ResolvedEvidenceBinding> = retained
        .iter()
        .map(|item| ResolvedEvidenceBinding {
            evidence_object_id: item.evidence.evidence_object_id.clone(),
            submission_id: item.evidence.submission_id.clone(),
            content_digest: item.evidence.content_digest.clone(),
            evidence_type: FUNCTION_OUTPUT_EVIDENCE_TYPE.into(),
            schema_id: item.evidence.schema_id.clone(),
            schema_version: item.evidence.schema_version.clone(),
            classification: item
                .inherited_marking
                .map(|value| value.as_str().to_string())
                .unwrap_or_default(),
            observed_at_ms: 1,
            expires_at_ms: 0,
            source_identity_digest: function_digest.to_string(),
        })
        .collect();
    let evidence_object_ids: Vec<String> = evidence
        .iter()
        .map(|item| item.evidence_object_id.clone())
        .collect();
    let node = ResolvedEvaluationNode {
        node_id: "function-revision-rubric".into(),
        evaluator: ResolvedEvaluatorBinding {
            definition_id: "definition:bounded-rubric-score".into(),
            definition_digest: BOUNDED_RUBRIC_PROFILE_DIGEST.into(),
            implementation_digest: BOUNDED_RUBRIC_IMPLEMENTATION_DIGEST.into(),
            stochastic_policy: Some(policy.clone()),
        },
        depends_on_node_ids: Vec::new(),
        input_bindings: Vec::new(),
        parameters_json: serde_json::json!({ "expected_label": expected_label }).to_string(),
        invariants: vec![ResolvedInvariantBinding {
            invariant_version_id: "invariant:function-revision-quality".into(),
            content_digest: digest_bytes(b"function-revision-quality"),
            predicate_kind: BOUNDED_RUBRIC_PROFILE.into(),
            input_schema: FUNCTION_OUTPUT_SCHEMA.into(),
            result_schema: STOCHASTIC_RESULT_SCHEMA.into(),
            evidence_types: vec![FUNCTION_OUTPUT_EVIDENCE_TYPE.into()],
            provenance_evidence_object_ids: evidence_object_ids.clone(),
            waiver_version_ids: Vec::new(),
        }],
        evidence_object_ids,
        classification: NODE_REQUIRED.into(),
    };
    let manifest_digest = digest_bytes(
        format!(
            "{}:{}:{}",
            function_digest,
            policy.minimum_mean_score_micros,
            retained
                .iter()
                .map(|item| item.evidence.content_digest.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )
        .as_bytes(),
    );
    ResolvedEvaluationManifest {
        contract_version: crate::chisei::evaluation_manifest::MANIFEST_CONTRACT.into(),
        resolver_version: crate::chisei::evaluation_manifest::RESOLVER_VERSION.into(),
        manifest_id: format!("manifest:function-revision:{function_digest}"),
        manifest_digest,
        namespace: "function-revision".into(),
        plan_version_id: "plan:function-revision".into(),
        plan_digest: digest_bytes(b"plan:function-revision"),
        subject_profile: FUNCTION_REVISION_SUBJECT_PROFILE.into(),
        subject_identity: function.name.clone(),
        subject_content_digest: function_digest.to_string(),
        invariant_set_id: "set:function-revision".into(),
        invariant_set_digest: digest_bytes(b"set:function-revision"),
        invariant_profile_digest: digest_bytes(b"profile:function-revision"),
        evaluation_time_ms: 1,
        resolved_by: "chisei.function-revision-gate".into(),
        requirements: Vec::new(),
        nodes: vec![node],
        evidence,
        waivers: Vec::new(),
        created_at_ms: 1,
    }
}

fn projection_from_execution(
    manifest: &ResolvedEvaluationManifest,
    execution: NodeExecution,
) -> Result<EvaluationExecutionProjection, String> {
    let steps = vec![execution.receipt];
    let decision = evaluation_execution::reduce_gate(manifest, &steps)?;
    Ok(EvaluationExecutionProjection {
        manifest_digest: manifest.manifest_digest.clone(),
        operation_id: format!("function-revision-gate:{}", manifest.manifest_digest),
        namespace: manifest.namespace.clone(),
        status: decision.verdict.clone(),
        steps,
        decision: Some(decision),
    })
}

fn digest_value(value: &serde_json::Value) -> String {
    digest_bytes(&serde_json::to_vec(value).unwrap_or_default())
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_execution::{
        STOCHASTIC_TRIAL_RESULT_CONTRACT, StochasticEvaluator, StochasticTrialError,
        StochasticTrialInput, StochasticTrialOutput, VERDICT_DENY, VERDICT_UNKNOWN,
    };
    use crate::db::sekai::SekaiDb;
    use crate::domain::KIND_COMPONENT;
    use crate::sekai::function::{LlmStep, OperatorStep};
    use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
    use std::sync::Arc;

    const LLM_OUTPUT_SCHEMA: &str = r#"{"type":"object","properties":{"label":{"type":"string"}},"required":["label"],"additionalProperties":false}"#;

    struct ScriptedHost {
        output: serde_json::Value,
    }

    impl LlmStepHost for ScriptedHost {
        fn complete(
            &self,
            _prompt_revision: &str,
            _model_route: &str,
            _bound_inputs: &serde_json::Value,
            _output_schema: &str,
        ) -> Result<serde_json::Value, String> {
            Ok(self.output.clone())
        }
    }

    /// Scores retained function outputs with the existing rubric contract.
    struct ScriptedRubric;

    #[async_trait::async_trait]
    impl StochasticEvaluator for ScriptedRubric {
        async fn evaluate_trial(
            &self,
            input: &StochasticTrialInput,
        ) -> Result<StochasticTrialOutput, StochasticTrialError> {
            let expected = input
                .base
                .parameters
                .get("expected_label")
                .and_then(|value| value.as_str())
                .unwrap_or("systems");
            let passed = !input.base.evidence.is_empty()
                && input.base.evidence.iter().all(|evidence| {
                    evidence
                        .content
                        .get("output")
                        .and_then(|output| output.get("label"))
                        .and_then(|label| label.as_str())
                        == Some(expected)
                });
            Ok(StochasticTrialOutput {
                contract_version: STOCHASTIC_TRIAL_RESULT_CONTRACT.into(),
                passed,
                score_micros: if passed { 900_000 } else { 100_000 },
                reason_code: if passed {
                    "criteria_met".into()
                } else {
                    "criteria_not_met".into()
                },
                result: serde_json::json!({}),
                input_tokens: 10,
                output_tokens: 5,
            })
        }
    }

    fn db() -> RuntimeDb {
        RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    fn fixture(id: &str, marking: Option<&str>) -> Object {
        let mut properties = HashMap::from([("language".into(), "rust".into())]);
        if let Some(marking) = marking {
            properties.insert(OBJECT_CLASSIFICATION_PROPERTY.into(), marking.into());
        }
        Object {
            id: id.into(),
            kind: KIND_COMPONENT.into(),
            name: id.into(),
            namespace: "function-revision".into(),
            external_id: id.into(),
            properties,
            created: 1,
            updated: 1,
        }
    }

    fn classify_function(name: &str, prompt_revision: &str) -> Function {
        Function {
            name: name.into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![
                PipelineStep::Operator(OperatorStep {
                    op: "filter".into(),
                    kind: KIND_COMPONENT.into(),
                    property: "language".into(),
                    value: "rust".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    alias: "".into(),
                }),
                PipelineStep::Llm(LlmStep {
                    prompt_revision: prompt_revision.into(),
                    input_bindings: BTreeMap::from([("language".into(), "language".into())]),
                    output_schema: LLM_OUTPUT_SCHEMA.into(),
                    model_route: "native/scripted".into(),
                }),
            ],
        }
    }

    fn host() -> FunctionHost {
        FunctionHost {
            now_ms: 1_700_000_000_000,
            rng_seed: 7,
        }
    }

    fn authority(ceiling: Option<EvidenceClassification>) -> PrincipalAuthority {
        PrincipalAuthority {
            principal: "evaluator".into(),
            classification_ceiling: ceiling,
            classification_token: ceiling.map(|value| value.as_str().into()),
            allowed_purposes: Default::default(),
        }
    }

    fn rubric_registry() -> StochasticEvaluatorRegistry {
        let registry = StochasticEvaluatorRegistry::default();
        registry
            .register(
                BOUNDED_RUBRIC_IMPLEMENTATION_DIGEST,
                Arc::new(ScriptedRubric),
            )
            .unwrap();
        registry
    }

    fn seed_fixture(db: &RuntimeDb, object: &Object) {
        db.create_object(object).unwrap();
    }

    fn gate(
        db: &RuntimeDb,
        function: &Function,
        fixtures: &[Object],
        output: serde_json::Value,
        ceiling: Option<EvidenceClassification>,
    ) -> FunctionRevisionGate {
        gate_function_revision(FunctionRevisionGateRequest {
            db,
            function,
            fixtures,
            llm_host: &ScriptedHost { output },
            evaluator_authority: &authority(ceiling),
            registry: &rubric_registry(),
            minimum_mean_score_micros: 800_000,
            expected_label: "systems",
            host: host(),
            budget: FunctionBudget::default(),
        })
        .unwrap()
    }

    #[test]
    fn degraded_llm_revision_denies_publish_with_a_receipt() {
        let db = db();
        let fixture = fixture("c1", None);
        seed_fixture(&db, &fixture);
        let function = classify_function("classify-degraded", "classify/degraded");
        let result = gate(
            &db,
            &function,
            std::slice::from_ref(&fixture),
            serde_json::json!({"label": "garbage"}),
            Some(EvidenceClassification::Public),
        );
        assert_eq!(result.verdict(), VERDICT_DENY);
        let decision = result.decision().expect("gate receipt");
        assert!(decision.decision_digest.starts_with("sha256:"));
        assert_eq!(result.retained.len(), 1);
        assert_eq!(
            result.retained[0].invocation.receipt.function_digest,
            result.function_digest()
        );
        assert!(
            result.retained[0]
                .invocation
                .receipt
                .output_digest
                .starts_with("sha256:")
        );
        let error = publish_function_revision(&db, &function, &result).unwrap_err();
        assert!(error.contains("publish denied"));
        assert!(db.get_function("classify-degraded").unwrap().is_none());
    }

    #[test]
    fn unchanged_llm_revision_passes_and_publishes_with_a_receipt() {
        let db = db();
        let fixture = fixture("c1", None);
        seed_fixture(&db, &fixture);
        let function = classify_function("classify-stable", "classify/v1");
        let result = gate(
            &db,
            &function,
            std::slice::from_ref(&fixture),
            serde_json::json!({"label": "systems"}),
            Some(EvidenceClassification::Public),
        );
        assert_eq!(result.verdict(), VERDICT_ALLOW);
        let decision = result.decision().expect("gate receipt");
        assert!(decision.decision_digest.starts_with("sha256:"));
        assert_eq!(result.projection.steps[0].status, "pass");
        publish_function_revision(&db, &function, &result).unwrap();
        assert_eq!(
            db.get_function("classify-stable").unwrap().unwrap().name,
            "classify-stable"
        );
    }

    #[test]
    fn retained_outputs_inherit_the_strictest_input_marking() {
        let db = db();
        let public = fixture("public", Some("public"));
        let confidential = fixture("confidential", Some("confidential"));
        seed_fixture(&db, &public);
        seed_fixture(&db, &confidential);
        let function = classify_function("classify-marked", "classify/v1");
        let result = gate(
            &db,
            &function,
            &[public, confidential],
            serde_json::json!({"label": "systems"}),
            Some(EvidenceClassification::Restricted),
        );
        assert_eq!(
            result.inherited_marking,
            Some(EvidenceClassification::Confidential)
        );
        assert!(
            result
                .retained
                .iter()
                .all(|item| item.inherited_marking == Some(EvidenceClassification::Confidential))
        );
        assert_eq!(result.verdict(), VERDICT_ALLOW);
    }

    #[test]
    fn evaluator_without_clearance_cannot_see_retained_evidence() {
        let db = db();
        let fixture = fixture("secret", Some("confidential"));
        seed_fixture(&db, &fixture);
        let function = classify_function("classify-secret", "classify/v1");
        let result = gate(
            &db,
            &function,
            std::slice::from_ref(&fixture),
            serde_json::json!({"label": "systems"}),
            Some(EvidenceClassification::Public),
        );
        assert_eq!(result.verdict(), VERDICT_UNKNOWN);
        assert_eq!(
            result.projection.steps[0].reason_code,
            evaluation_execution::REASON_EVIDENCE_UNAVAILABLE
        );
        assert!(publish_function_revision(&db, &function, &result).is_err());
        assert!(db.get_function("classify-secret").unwrap().is_none());
    }

    #[test]
    fn publish_refuses_a_gate_bound_to_a_different_revision() {
        let db = db();
        let fixture = fixture("c1", None);
        seed_fixture(&db, &fixture);
        let passing = classify_function("classify-a", "classify/v1");
        let other = classify_function("classify-b", "classify/v2");
        let result = gate(
            &db,
            &passing,
            std::slice::from_ref(&fixture),
            serde_json::json!({"label": "systems"}),
            Some(EvidenceClassification::Public),
        );
        let error = publish_function_revision(&db, &other, &result).unwrap_err();
        assert!(error.contains("does not bind this function revision"));
    }

    #[test]
    fn missing_fixture_fails_closed_before_scoring() {
        let db = db();
        let fixture = fixture("missing", None);
        let function = classify_function("classify-missing", "classify/v1");
        let error = gate_function_revision(FunctionRevisionGateRequest {
            db: &db,
            function: &function,
            fixtures: std::slice::from_ref(&fixture),
            llm_host: &ScriptedHost {
                output: serde_json::json!({"label": "systems"}),
            },
            evaluator_authority: &authority(Some(EvidenceClassification::Public)),
            registry: &rubric_registry(),
            minimum_mean_score_micros: 800_000,
            expected_label: "systems",
            host: host(),
            budget: FunctionBudget::default(),
        })
        .unwrap_err();
        assert!(error.contains("is not in the store"));
    }

    #[test]
    fn caller_supplied_marking_cannot_weaken_stored_fixture_marking() {
        let db = db();
        let stored = fixture("secret", Some("confidential"));
        seed_fixture(&db, &stored);
        let mut forged = stored.clone();
        forged
            .properties
            .insert(OBJECT_CLASSIFICATION_PROPERTY.into(), "public".into());
        let function = classify_function("classify-forged-marking", "classify/v1");
        let result = gate(
            &db,
            &function,
            std::slice::from_ref(&forged),
            serde_json::json!({"label": "systems"}),
            Some(EvidenceClassification::Public),
        );
        assert_eq!(
            result.inherited_marking(),
            Some(EvidenceClassification::Confidential)
        );
        assert_eq!(result.verdict(), VERDICT_UNKNOWN);
    }
}
