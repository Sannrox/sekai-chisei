use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tonic::{Request, Response, Status};

use super::llm_service::{estimate_chat_request, execute_chat_request};
use super::pb::chisei::chisei_service_server::ChiseiService;
use super::pb::chisei::*;
use crate::chisei::budget::BudgetTracker;
use crate::chisei::eval::EvalStore;
use crate::chisei::pipeline as pipe;
use crate::chisei::policy::PolicyResolver;
use crate::config::Config;
use crate::db::sekai::SekaiDb;

pub struct ChiseiServiceImpl {
    budget: Arc<BudgetTracker>,
    policy: Arc<PolicyResolver>,
    pipeline: pipe::Pipeline,
    eval: Arc<EvalStore>,
    planned_executions: Arc<Mutex<HashMap<String, ExecutionPlan>>>,
    evolve_history: Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    evolve_enhancements: Arc<Mutex<HashMap<String, String>>>,
    db: Arc<SekaiDb>,
    config: Config,
}

const MAX_CACHED_EXECUTION_PLANS: usize = 128;
const MAX_CACHED_EXECUTION_PLAN_AGE_MS: i64 = 15 * 60 * 1000;

impl ChiseiServiceImpl {
    pub fn new(db: Arc<SekaiDb>, config: Config) -> Self {
        let _ = db.migrate_chisei();
        db.migrate_audit();
        let eval = Arc::new(EvalStore::new());
        for suite in db.list_eval_suite_records().unwrap_or_default() {
            eval.create_suite(suite);
        }
        for run in db.list_all_eval_run_records().unwrap_or_default() {
            eval.create_run(run);
        }
        for iteration in db.list_all_eval_iteration_records().unwrap_or_default() {
            eval.create_iteration(iteration);
        }
        let evolve_history = Arc::new(Mutex::new(
            db.list_evolve_task_records()
                .unwrap_or_default()
                .into_iter()
                .map(|task| (task.id.clone(), task))
                .collect(),
        ));
        let evolve_enhancements = Arc::new(Mutex::new(
            db.list_evolve_enhancements().unwrap_or_default(),
        ));
        Self {
            budget: Arc::new(BudgetTracker::new()),
            policy: Arc::new(PolicyResolver::new()),
            pipeline: pipe::default_pipeline_with(config.sample_rate, config.sample_risk_threshold),
            eval,
            planned_executions: Arc::new(Mutex::new(HashMap::new())),
            evolve_history,
            evolve_enhancements,
            db,
            config,
        }
    }

    /// Build a background scoring job sharing this service's DB, in-memory eval store, budget,
    /// and config — so emitted runs are visible to live regression checks immediately.
    pub fn scoring_job(&self) -> crate::chisei::scoring::ScoringJob {
        crate::chisei::scoring::ScoringJob::new(
            self.db.clone(),
            self.eval.clone(),
            self.config.clone(),
            self.budget.clone(),
        )
    }

    pub fn with_budget(db: Arc<SekaiDb>, config: Config, budget: Arc<BudgetTracker>) -> Self {
        let _ = db.migrate_chisei();
        db.migrate_audit();
        let eval = Arc::new(EvalStore::new());
        for suite in db.list_eval_suite_records().unwrap_or_default() {
            eval.create_suite(suite);
        }
        for run in db.list_all_eval_run_records().unwrap_or_default() {
            eval.create_run(run);
        }
        for iteration in db.list_all_eval_iteration_records().unwrap_or_default() {
            eval.create_iteration(iteration);
        }
        let evolve_history = Arc::new(Mutex::new(
            db.list_evolve_task_records()
                .unwrap_or_default()
                .into_iter()
                .map(|task| (task.id.clone(), task))
                .collect(),
        ));
        let evolve_enhancements = Arc::new(Mutex::new(
            db.list_evolve_enhancements().unwrap_or_default(),
        ));
        Self {
            budget,
            policy: Arc::new(PolicyResolver::new()),
            pipeline: pipe::default_pipeline_with(config.sample_rate, config.sample_risk_threshold),
            eval,
            planned_executions: Arc::new(Mutex::new(HashMap::new())),
            evolve_history,
            evolve_enhancements,
            db,
            config,
        }
    }

    async fn plan_from_input(&self, input: ExecutionInput) -> Result<ExecutionPlan, Status> {
        let normalized_user_id = if input.user_id.is_empty() {
            "default".to_string()
        } else {
            input.user_id.clone()
        };
        let budget_pressure = self.budget.namespace_pressure(&input.namespace);
        let namespace_hint = input.namespace.trim().to_string();
        let mut pipeline_req = pipe::PipelineRequest {
            request_id: input.request_id.clone(),
            namespace: input.namespace.clone(),
            spec: input.spec.clone(),
            model: input.preferred_model.clone(),
            runtime: input.preferred_runtime.clone(),
            task_type: input.task_type.clone(),
            priority: input.priority,
            risk_score: 0.0,
            budget_pressure: budget_pressure.clone(),
            review_model: String::new(),
            egress_records: vec![],
            external_egress: true,
        };
        let affinity = crate::chisei::affinity::get_affinity(&self.db, namespace_hint.as_str());
        let initial_run = self.pipeline.run(&mut pipeline_req, &self.db);
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let fallback_runtime = pipeline_req.runtime.clone();
        let (initial_runtime, initial_model) = self
            .resolve_model_for_run(
                &input,
                &fallback_runtime,
                &initial_run,
                effective_policy.as_ref(),
            )
            .await?;
        let initial_provider = crate::llm::provider_name(&initial_model).to_string();
        let initial_provider_is_external =
            crate::chisei::egress::is_external_provider(&initial_provider);
        let (run, resolved_runtime, resolved_model, provider, provider_is_external) =
            if initial_provider_is_external {
                (
                    initial_run,
                    initial_runtime,
                    initial_model,
                    initial_provider,
                    true,
                )
            } else {
                let mut local_pipeline_req = pipe::PipelineRequest {
                    request_id: input.request_id.clone(),
                    namespace: input.namespace.clone(),
                    spec: input.spec.clone(),
                    model: input.preferred_model.clone(),
                    runtime: input.preferred_runtime.clone(),
                    task_type: input.task_type.clone(),
                    priority: input.priority,
                    risk_score: 0.0,
                    budget_pressure: budget_pressure.clone(),
                    review_model: String::new(),
                    egress_records: vec![],
                    external_egress: false,
                };
                let local_run = self.pipeline.run(&mut local_pipeline_req, &self.db);
                let (local_runtime, local_model) = self
                    .resolve_model_for_run(
                        &input,
                        &local_pipeline_req.runtime,
                        &local_run,
                        effective_policy.as_ref(),
                    )
                    .await?;
                let local_provider = crate::llm::provider_name(&local_model).to_string();
                if crate::chisei::egress::is_external_provider(&local_provider) {
                    (
                        initial_run,
                        initial_runtime,
                        initial_model,
                        initial_provider,
                        true,
                    )
                } else {
                    (local_run, local_runtime, local_model, local_provider, false)
                }
            };
        let egress_decisions =
            build_egress_decisions(&run.egress_records, &provider, provider_is_external);
        let prepared_messages = build_prepared_messages(&input, &run.prepared_spec);
        let estimate_req = super::pb::llm::ChatRequest {
            model: resolved_model.clone(),
            system: input.system.clone(),
            messages: prepared_messages
                .iter()
                .map(|m| super::pb::llm::Message {
                    role: m.role.clone(),
                    content: m.content.clone(),
                    tool_call_id: m.tool_call_id.clone(),
                    tool_calls: m
                        .tool_calls
                        .iter()
                        .map(|tc| super::pb::llm::ToolCall {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            args_json: tc.args_json.clone(),
                        })
                        .collect(),
                })
                .collect(),
            tools: input
                .tools
                .iter()
                .map(|t| super::pb::llm::ToolDef {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema_json: t.input_schema_json.clone(),
                })
                .collect(),
            max_tokens: input.max_tokens,
            user_id: Some(normalized_user_id.clone()),
        };
        let estimated_tokens = estimate_chat_request(&estimate_req);
        let allowed = self
            .budget
            .check(&normalized_user_id, estimated_tokens)
            .is_ok();
        let usage = self.budget.get_usage(&normalized_user_id);
        let budget_reason = if allowed {
            String::new()
        } else {
            format!(
                "budget exceeded: used {} + {} > {}",
                usage.tokens_used, estimated_tokens, usage.max_tokens
            )
        };
        let mut normalized_input = input.clone();
        normalized_input.user_id = normalized_user_id;
        normalized_input.estimated_tokens = estimated_tokens;
        let mut warnings = run.warnings();
        let final_route_bias_value =
            crate::chisei::model_routing::route_bias(&run.steps).map(str::to_string);
        let final_route_bias = final_route_bias_value.as_deref();
        let review_policy = if let Some(p) = run.review_policy.as_ref() {
            let model = if p.model.is_empty() {
                resolved_model.clone()
            } else {
                self.resolve_live_model(&p.model, effective_policy.as_ref(), final_route_bias)
                    .await
                    .unwrap_or_else(|_| resolved_model.clone())
            };
            Some(ReviewPolicy {
                confidence_threshold: p.confidence_threshold,
                max_cycles: p.max_cycles,
                model,
            })
        } else {
            None
        };
        let namespace_eval_signal = if namespace_hint.is_empty() {
            None
        } else {
            self.eval.namespace_regression_signal(&namespace_hint)
        };
        if let Some(signal) = namespace_eval_signal
            .as_ref()
            .filter(|signal| signal.regressed)
        {
            warnings.push(signal.reason.clone());
        }
        let eval_regressed = namespace_eval_signal
            .as_ref()
            .map(|signal| signal.regressed)
            .unwrap_or(false);
        let eval_regression_reason = namespace_eval_signal
            .as_ref()
            .filter(|signal| signal.regressed)
            .map(|signal| signal.reason.clone())
            .unwrap_or_default();
        let executable = allowed && !eval_regressed;
        let low_success_namespace = affinity.low_success;
        // Sampling: the pipeline decides from request metadata; the eval-driven
        // adaptive trigger (oversample regressed namespaces) is applied here since the
        // eval store lives on the service.
        let mut sampling = crate::chisei::sampling::decode_sampling(&run.steps).unwrap_or(
            crate::chisei::sampling::SamplingDecision {
                sampled: false,
                effective_rate: self.config.sample_rate,
                reason: "not_sampled".into(),
            },
        );
        if eval_regressed && !sampling.sampled {
            sampling.sampled = true;
            sampling.effective_rate = 1.0;
            sampling.reason = "eval_regressed".into();
        }
        if sampling.sampled {
            let mut evidence = std::collections::HashMap::new();
            evidence.insert(
                "effective_rate".to_string(),
                sampling.effective_rate.to_string(),
            );
            evidence.insert("risk_score".to_string(), run.risk_score.to_string());
            evidence.insert("model".to_string(), resolved_model.clone());
            let _ = self.db.record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                actor: "chisei.sampling".into(),
                action: "sample".into(),
                reason: sampling.reason.clone(),
                evidence,
                target_id: input.request_id.clone(),
                outcome: "sampled".into(),
            });
        }
        self.record_egress_audit(
            "prepare_context",
            &input.request_id,
            &provider,
            &resolved_model,
            &egress_decisions,
        );
        Ok(ExecutionPlan {
            plan_id: uuid::Uuid::new_v4().to_string(),
            input: Some(normalized_input),
            resolved_runtime,
            resolved_model: resolved_model.clone(),
            enriched_spec: run.prepared_spec.clone(),
            prepared_system: input.system.clone(),
            prepared_messages,
            tools: input.tools.clone(),
            budget: Some(BudgetVerdict {
                allowed,
                usage: Some(BudgetUsage {
                    user_id: usage.user_id,
                    tokens_used: usage.tokens_used,
                    max_tokens: usage.max_tokens,
                    period_type: usage.period_type.as_str().into(),
                    period_start: usage.period_start,
                }),
                reason: budget_reason,
            }),
            steps: run
                .steps
                .iter()
                .map(|s| StepDecision {
                    step: s.step.clone(),
                    action: s.action.clone(),
                    reasoning: s.reasoning.clone(),
                    confidence: s.confidence,
                    suggestion: s.suggestion.clone(),
                    value: s.value.clone(),
                })
                .collect(),
            review_policy,
            risk_score: run.risk_score,
            low_success_namespace,
            executable,
            warnings,
            max_tokens: input.max_tokens,
            created_at: chrono::Utc::now().timestamp_millis(),
            affinity_namespaces: affinity.namespaces,
            eval_regressed,
            eval_regression_reason,
            sampled: sampling.sampled,
            sample_rate: sampling.effective_rate,
            sample_reason: sampling.reason,
            egress_decisions,
        })
    }

    fn cache_plan(&self, plan: ExecutionPlan) {
        let mut plans = self
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        prune_expired_plans(&mut plans);
        let inserted_plan_id = plan.plan_id.clone();
        plans.insert(inserted_plan_id.clone(), plan);
        prune_excess_plans(&mut plans, Some(&inserted_plan_id));
    }

    async fn resolve_model_for_run(
        &self,
        input: &ExecutionInput,
        fallback_runtime: &str,
        run: &pipe::RunResult,
        policy: Option<&crate::chisei::policy::Policy>,
    ) -> Result<(String, String), Status> {
        let recommended_model = run
            .recommended_model()
            .map(|(model, _)| model.to_string())
            .unwrap_or_else(|| input.preferred_model.clone());
        let route_bias_value =
            crate::chisei::model_routing::route_bias(&run.steps).map(str::to_string);
        let route_bias = route_bias_value.as_deref();
        let preferred_model = choose_preferred_model(
            &input.preferred_model,
            &recommended_model,
            route_bias,
            policy,
        );
        let preferred_runtime = if input.preferred_runtime.is_empty() {
            fallback_runtime
        } else {
            &input.preferred_runtime
        };
        let (runtime, model) = self
            .policy
            .resolve(&input.namespace, preferred_runtime, &preferred_model)
            .map_err(Status::invalid_argument)?;
        let model = self
            .resolve_live_model(&model, policy, route_bias)
            .await
            .map_err(Status::failed_precondition)?;
        Ok((runtime, model))
    }

    fn record_egress_audit(
        &self,
        action: &str,
        request_id: &str,
        provider: &str,
        model: &str,
        decisions: &[EgressDecision],
    ) {
        let included_count: usize = decisions.iter().map(|d| d.included.len()).sum();
        let redacted_count: usize = decisions.iter().map(|d| d.redacted.len()).sum();
        let mut evidence = std::collections::HashMap::new();
        evidence.insert("provider".to_string(), provider.to_string());
        evidence.insert("model".to_string(), model.to_string());
        evidence.insert("decisions".to_string(), decisions.len().to_string());
        evidence.insert("included_count".to_string(), included_count.to_string());
        evidence.insert("redacted_count".to_string(), redacted_count.to_string());
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.egress".into(),
            action: action.into(),
            reason: "context egress policy applied".into(),
            evidence,
            target_id: request_id.into(),
            outcome: if redacted_count > 0 {
                "redacted".into()
            } else {
                "included".into()
            },
        });
    }

    async fn resolve_live_model(
        &self,
        model: &str,
        policy: Option<&crate::chisei::policy::Policy>,
        route_bias: Option<&str>,
    ) -> Result<String, String> {
        let empty_allowed = Vec::new();
        let allowed_models = policy
            .map(|policy| policy.allowed_models.as_slice())
            .unwrap_or(empty_allowed.as_slice());
        let base_context = crate::chisei::model_routing::RoutingContext {
            requested: model,
            allowed_models,
            route_bias,
            config: &self.config,
            ollama_models: &[],
        };
        let needs_ollama_first = !model.contains('/')
            && model != "native-default"
            && model != "cheap"
            && model != "capable"
            && crate::llm::provider_name(model) == "native";
        if !needs_ollama_first
            && let Ok(resolved) = crate::chisei::model_routing::resolve_model(base_context.clone())
        {
            return Ok(resolved);
        }

        let ollama_models = crate::llm::ollama::list_models(&self.config.ollama_url)
            .await
            .unwrap_or_default();
        crate::chisei::model_routing::resolve_model(crate::chisei::model_routing::RoutingContext {
            ollama_models: &ollama_models,
            ..base_context
        })
    }

    fn evolve_tasks(&self) -> Vec<crate::chisei::evolve::TaskRecord> {
        let mut tasks: Vec<_> = self
            .evolve_history
            .lock()
            .expect("evolve history poisoned")
            .values()
            .cloned()
            .collect();
        tasks.sort_by(|a, b| a.id.cmp(&b.id));
        tasks
    }

    fn evolve_task(&self, request_id: &str) -> Option<crate::chisei::evolve::TaskRecord> {
        self.evolve_history
            .lock()
            .expect("evolve history poisoned")
            .get(request_id)
            .cloned()
    }

    fn record_evolve_task(
        &self,
        request_id: &str,
        namespace: &str,
        spec: &str,
        original_spec: Option<&str>,
        status: &str,
        tokens_used: i32,
    ) -> Result<(), String> {
        if request_id.is_empty() {
            return Ok(());
        }
        let mut history = self.evolve_history.lock().expect("evolve history poisoned");
        let entry = history.entry(request_id.to_string()).or_insert_with(|| {
            crate::chisei::evolve::TaskRecord {
                id: request_id.to_string(),
                spec: spec.to_string(),
                status: status.to_string(),
                namespace: namespace.to_string(),
                tokens_used,
                original_spec: original_spec.map(ToOwned::to_owned),
                created: chrono::Utc::now().timestamp(),
            }
        });
        entry.namespace = namespace.to_string();
        entry.spec = spec.to_string();
        entry.status = status.to_string();
        entry.tokens_used = tokens_used;
        entry.original_spec = original_spec.map(ToOwned::to_owned);
        self.db.put_evolve_task(entry)?;
        Ok(())
    }

    fn tracked_original_spec(
        &self,
        request_id: &str,
        submitted_spec: &str,
        prepared_spec: &str,
    ) -> Option<String> {
        if prepared_spec != submitted_spec {
            return Some(submitted_spec.to_string());
        }
        self.evolve_enhancements
            .lock()
            .expect("evolve enhancements poisoned")
            .get(request_id)
            .cloned()
    }
}

fn choose_preferred_model(
    explicit_model: &str,
    recommended_model: &str,
    route_bias: Option<&str>,
    policy: Option<&crate::chisei::policy::Policy>,
) -> String {
    if !explicit_model.is_empty() {
        return explicit_model.to_string();
    }
    let Some(route_bias) = route_bias else {
        return recommended_model.to_string();
    };
    let alias = format!("ollama/{route_bias}");
    if let Some(policy) = policy {
        if policy.default_model == alias
            || policy.allowed_models.iter().any(|model| model == &alias)
        {
            return alias;
        }
        if policy.default_model == route_bias
            || policy
                .allowed_models
                .iter()
                .any(|model| model == route_bias)
        {
            return route_bias.to_string();
        }
    }
    recommended_model.to_string()
}

fn prune_cached_plans(plans: &mut HashMap<String, ExecutionPlan>) {
    prune_expired_plans(plans);
    prune_excess_plans(plans, None);
}

fn prune_expired_plans(plans: &mut HashMap<String, ExecutionPlan>) {
    let cutoff = chrono::Utc::now().timestamp_millis() - MAX_CACHED_EXECUTION_PLAN_AGE_MS;
    plans.retain(|_, plan| plan.created_at >= cutoff);
}

fn prune_excess_plans(plans: &mut HashMap<String, ExecutionPlan>, protected_plan_id: Option<&str>) {
    while plans.len() > MAX_CACHED_EXECUTION_PLANS {
        let Some(oldest_id) = plans
            .iter()
            .filter(|(plan_id, _)| protected_plan_id != Some(plan_id.as_str()))
            .min_by(|left, right| {
                left.1
                    .created_at
                    .cmp(&right.1.created_at)
                    .then_with(|| left.0.cmp(right.0))
            })
            .map(|(plan_id, _)| plan_id.clone())
        else {
            break;
        };
        plans.remove(&oldest_id);
    }
}

fn build_egress_decisions(
    records: &[crate::chisei::egress::ContextEgressRecord],
    provider: &str,
    external: bool,
) -> Vec<EgressDecision> {
    if records.is_empty() {
        return vec![EgressDecision {
            provider: provider.into(),
            external,
            included: vec![],
            redacted: vec![],
            reasons: vec!["no sekai context selected".into()],
        }];
    }
    records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let object_ref = if record
                .included_fields
                .iter()
                .any(|field| field == "identity")
            {
                record.object_ref.clone()
            } else {
                format!("object#{}", index + 1)
            };
            EgressDecision {
                provider: provider.into(),
                external,
                included: record
                    .included_fields
                    .iter()
                    .map(|field| format!("{object_ref}.{field}"))
                    .collect(),
                redacted: record
                    .redacted_fields
                    .iter()
                    .map(|field| format!("{object_ref}.{field}"))
                    .collect(),
                reasons: record.reasons.clone(),
            }
        })
        .collect()
}

fn build_prepared_messages(input: &ExecutionInput, enriched_spec: &str) -> Vec<ChatMessage> {
    let mut messages = input.messages.clone();
    if messages.is_empty() {
        return vec![ChatMessage {
            role: "user".into(),
            content: enriched_spec.into(),
            tool_call_id: String::new(),
            tool_calls: vec![],
        }];
    }
    if !enriched_spec.is_empty() && enriched_spec != input.spec {
        messages.push(ChatMessage {
            role: "user".into(),
            content: format!("[Task spec]\n{enriched_spec}"),
            tool_call_id: String::new(),
            tool_calls: vec![],
        });
    }
    messages
}

fn eval_iteration_pb(iteration: crate::chisei::eval::Iteration) -> EvalIteration {
    EvalIteration {
        id: iteration.id,
        run_id: iteration.run_id,
        suite_id: iteration.suite_id,
        changed_file: iteration.changed_file,
        diff_hash: iteration.diff_hash,
        parent_iteration_id: iteration.parent_iteration_id,
        baseline_run_id: iteration.baseline_run_id,
        candidate_run_id: iteration.candidate_run_id,
        delta: iteration.delta,
        regressed: iteration.regressed,
        created: iteration.created,
    }
}

#[tonic::async_trait]
impl ChiseiService for ChiseiServiceImpl {
    async fn check_budget(
        &self,
        req: Request<CheckBudgetRequest>,
    ) -> Result<Response<CheckBudgetResponse>, Status> {
        let r = req.into_inner();
        let allowed = self.budget.check(&r.user_id, r.estimated_tokens).is_ok();
        let u = self.budget.get_usage(&r.user_id);
        Ok(Response::new(CheckBudgetResponse {
            allowed,
            usage: Some(BudgetUsage {
                user_id: u.user_id,
                tokens_used: u.tokens_used,
                max_tokens: u.max_tokens,
                period_type: u.period_type.as_str().into(),
                period_start: u.period_start,
            }),
        }))
    }

    async fn record_usage(
        &self,
        req: Request<RecordUsageRequest>,
    ) -> Result<Response<RecordUsageResponse>, Status> {
        let r = req.into_inner();
        self.budget.record(&r.user_id, r.tokens_used);
        let u = self.budget.get_usage(&r.user_id);
        Ok(Response::new(RecordUsageResponse {
            usage: Some(BudgetUsage {
                user_id: u.user_id,
                tokens_used: u.tokens_used,
                max_tokens: u.max_tokens,
                period_type: u.period_type.as_str().into(),
                period_start: u.period_start,
            }),
        }))
    }

    async fn set_budget_limit(
        &self,
        req: Request<SetBudgetLimitRequest>,
    ) -> Result<Response<SetBudgetLimitResponse>, Status> {
        let r = req.into_inner();
        self.budget.set_limit(
            &r.user_id,
            r.max_tokens,
            crate::chisei::budget::PeriodType::parse(&r.period_type),
        );
        Ok(Response::new(SetBudgetLimitResponse {}))
    }

    async fn resolve_policy(
        &self,
        req: Request<ResolvePolicyRequest>,
    ) -> Result<Response<ResolvePolicyResponse>, Status> {
        let r = req.into_inner();
        let effective_policy = self.policy.effective_policy(&r.namespace);
        let (runtime, model) = self
            .policy
            .resolve(&r.namespace, &r.preferred_runtime, &r.preferred_model)
            .map_err(Status::invalid_argument)?;
        let model = self
            .resolve_live_model(&model, effective_policy.as_ref(), None)
            .await
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(ResolvePolicyResponse {
            resolution: Some(PolicyResolution { runtime, model }),
        }))
    }

    async fn run_pipeline(
        &self,
        req: Request<RunPipelineRequest>,
    ) -> Result<Response<RunPipelineResponse>, Status> {
        let r = req
            .into_inner()
            .request
            .ok_or(Status::invalid_argument("request required"))?;
        let mut pr = pipe::PipelineRequest {
            request_id: r.request_id,
            namespace: r.namespace,
            spec: r.spec,
            model: r.model,
            runtime: r.runtime,
            task_type: r.task_type,
            priority: r.priority,
            risk_score: 0.0,
            budget_pressure: self.budget.namespace_pressure(""),
            review_model: String::new(),
            egress_records: vec![],
            external_egress: true,
        };
        let result = self.pipeline.run(&mut pr, &self.db);
        let steps = result
            .steps
            .iter()
            .map(|s| StepDecision {
                step: s.step.clone(),
                action: s.action.clone(),
                reasoning: s.reasoning.clone(),
                confidence: s.confidence,
                suggestion: s.suggestion.clone(),
                value: s.value.clone(),
            })
            .collect();
        Ok(Response::new(RunPipelineResponse {
            result: Some(PipelineRunResult {
                request_id: result.request_id,
                steps,
                timestamp: result.timestamp,
                prepared_spec: result.prepared_spec,
            }),
        }))
    }

    async fn list_pipeline_runs(
        &self,
        _r: Request<ListPipelineRunsRequest>,
    ) -> Result<Response<ListPipelineRunsResponse>, Status> {
        Ok(Response::new(ListPipelineRunsResponse { runs: vec![] }))
    }

    async fn plan_execution(
        &self,
        req: Request<PlanExecutionRequest>,
    ) -> Result<Response<PlanExecutionResponse>, Status> {
        let input = req
            .into_inner()
            .input
            .ok_or(Status::invalid_argument("input required"))?;
        let plan = self.plan_from_input(input).await?;
        if let Some(plan_input) = &plan.input {
            let namespace_hint = plan_input.namespace.trim().to_string();
            self.record_evolve_task(
                &plan_input.request_id,
                &namespace_hint,
                &plan.enriched_spec,
                self.tracked_original_spec(
                    &plan_input.request_id,
                    &plan_input.spec,
                    &plan.enriched_spec,
                )
                .as_deref(),
                if plan.executable { "planned" } else { "failed" },
                plan_input.estimated_tokens,
            )
            .map_err(Status::internal)?;
        }
        self.cache_plan(plan.clone());
        Ok(Response::new(PlanExecutionResponse { plan: Some(plan) }))
    }

    async fn execute_plan(
        &self,
        req: Request<ExecutePlanRequest>,
    ) -> Result<Response<ExecutePlanResponse>, Status> {
        let requested_plan = req
            .into_inner()
            .plan
            .ok_or(Status::invalid_argument("plan required"))?;
        let plan = {
            let mut plans = self
                .planned_executions
                .lock()
                .expect("planned executions poisoned");
            prune_cached_plans(&mut plans);
            plans
                .remove(&requested_plan.plan_id)
                .ok_or(Status::not_found("execution plan not found"))?
        };
        if !plan.executable {
            return Err(Status::failed_precondition(
                "execution plan is not executable",
            ));
        }
        let input = plan
            .input
            .clone()
            .ok_or(Status::invalid_argument("plan input required"))?;
        let namespace_hint = input.namespace.trim().to_string();
        let provider = crate::llm::provider_name(&plan.resolved_model).to_string();
        if crate::chisei::egress::is_external_provider(&provider)
            && plan.egress_decisions.is_empty()
        {
            return Err(Status::failed_precondition(
                "external execution plan missing egress decisions",
            ));
        }
        if let Some(signal) = self
            .eval
            .namespace_regression_signal(&namespace_hint)
            .filter(|signal| signal.regressed)
        {
            return Err(Status::failed_precondition(signal.reason));
        }
        let normalized_user_id = if input.user_id.is_empty() {
            "default".to_string()
        } else {
            input.user_id.clone()
        };
        self.record_egress_audit(
            "execute_context",
            &input.request_id,
            &provider,
            &plan.resolved_model,
            &plan.egress_decisions,
        );
        let llm_req = super::pb::llm::ChatRequest {
            model: plan.resolved_model.clone(),
            system: plan.prepared_system.clone(),
            messages: plan
                .prepared_messages
                .iter()
                .map(|m| super::pb::llm::Message {
                    role: m.role.clone(),
                    content: m.content.clone(),
                    tool_call_id: m.tool_call_id.clone(),
                    tool_calls: m
                        .tool_calls
                        .iter()
                        .map(|tc| super::pb::llm::ToolCall {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            args_json: tc.args_json.clone(),
                        })
                        .collect(),
                })
                .collect(),
            tools: plan
                .tools
                .iter()
                .map(|t| super::pb::llm::ToolDef {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema_json: t.input_schema_json.clone(),
                })
                .collect(),
            max_tokens: plan.max_tokens,
            user_id: Some(normalized_user_id),
        };
        let chat = execute_chat_request(&self.config, self.budget.clone(), llm_req).await?;
        self.record_evolve_task(
            &input.request_id,
            &namespace_hint,
            &plan.enriched_spec,
            self.tracked_original_spec(&input.request_id, &input.spec, &plan.enriched_spec)
                .as_deref(),
            "done",
            chat.input_tokens + chat.output_tokens,
        )
        .map_err(Status::internal)?;
        // Sampling consumption: a sampled request was selected for deeper
        // observation, so capture its actual execution outcome as a durable
        // audit record keyed to the request. Unsampled executions skip this —
        // bounded overhead is the whole point of sampling.
        if plan.sampled {
            let mut evidence = std::collections::HashMap::new();
            evidence.insert("model".to_string(), plan.resolved_model.clone());
            evidence.insert("input_tokens".to_string(), chat.input_tokens.to_string());
            evidence.insert("output_tokens".to_string(), chat.output_tokens.to_string());
            evidence.insert("stop_reason".to_string(), chat.stop_reason.clone());
            evidence.insert("sample_rate".to_string(), plan.sample_rate.to_string());
            let _ = self.db.record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                actor: "chisei.sampling".into(),
                action: "sample_observed".into(),
                reason: plan.sample_reason.clone(),
                evidence,
                target_id: input.request_id.clone(),
                outcome: "observed".into(),
            });
            // Durable, judge-able record (spec + output) that the scoring job consumes to
            // produce real eval runs. Kept in its own table so large content stays out of the
            // audit evidence JSON. Only captured when scoring is enabled — otherwise there is no
            // consumer and the (full-content) rows would accumulate as dead data.
            if self.config.scoring_enabled {
                let _ =
                    self.db
                        .put_sample_observation(&crate::chisei::scoring::SampleObservation {
                            request_id: input.request_id.clone(),
                            namespace: namespace_hint.clone(),
                            spec: plan.enriched_spec.clone(),
                            resolved_model: plan.resolved_model.clone(),
                            output_content: chat.content.clone(),
                            sample_reason: plan.sample_reason.clone(),
                            input_tokens: chat.input_tokens,
                            output_tokens: chat.output_tokens,
                            stop_reason: chat.stop_reason.clone(),
                            timestamp: chrono::Utc::now().timestamp_millis(),
                            scored: false,
                        });
            }
        }
        Ok(Response::new(ExecutePlanResponse {
            response: Some(PlannedChatResponse {
                content: chat.content,
                tool_calls: chat
                    .tool_calls
                    .into_iter()
                    .map(|tc| ToolCall {
                        id: tc.id,
                        name: tc.name,
                        args_json: tc.args_json,
                    })
                    .collect(),
                input_tokens: chat.input_tokens,
                output_tokens: chat.output_tokens,
                stop_reason: chat.stop_reason,
                provider,
            }),
            executed_at: chrono::Utc::now().timestamp(),
        }))
    }

    async fn get_affinity(
        &self,
        req: Request<GetAffinityRequest>,
    ) -> Result<Response<GetAffinityResponse>, Status> {
        let r = req.into_inner();
        let a = crate::chisei::affinity::get_affinity(&self.db, &r.namespace);
        Ok(Response::new(GetAffinityResponse {
            result: Some(AffinityResult {
                namespaces: a.namespaces,
                best_model: a.best_model,
                low_success: a.low_success,
            }),
        }))
    }

    async fn create_eval_suite(
        &self,
        req: Request<CreateEvalSuiteRequest>,
    ) -> Result<Response<CreateEvalSuiteResponse>, Status> {
        let s = req
            .into_inner()
            .suite
            .ok_or(Status::invalid_argument("suite required"))?;
        let suite = crate::chisei::eval::Suite {
            id: s.id.clone(),
            name: s.name.clone(),
            description: s.description.clone(),
            cases: s
                .cases
                .iter()
                .map(|c| crate::chisei::eval::Case {
                    id: c.id.clone(),
                    name: c.name.clone(),
                    namespace: c.namespace.clone(),
                    spec: c.spec.clone(),
                    assertions: c
                        .assertions
                        .iter()
                        .map(|a| crate::chisei::eval::Assertion {
                            assert_type: a.r#type.clone(),
                            value: a.value.clone(),
                        })
                        .collect(),
                })
                .collect(),
        };
        self.db.put_eval_suite(&suite).map_err(Status::internal)?;
        self.eval.create_suite(suite);
        Ok(Response::new(CreateEvalSuiteResponse { suite: Some(s) }))
    }

    async fn list_eval_suites(
        &self,
        _r: Request<ListEvalSuitesRequest>,
    ) -> Result<Response<ListEvalSuitesResponse>, Status> {
        let suites = self.eval.list_suites();
        let pb: Vec<EvalSuite> = suites
            .iter()
            .map(|s| EvalSuite {
                id: s.id.clone(),
                name: s.name.clone(),
                description: s.description.clone(),
                cases: vec![],
            })
            .collect();
        Ok(Response::new(ListEvalSuitesResponse { suites: pb }))
    }

    async fn get_eval_suite(
        &self,
        req: Request<GetEvalSuiteRequest>,
    ) -> Result<Response<GetEvalSuiteResponse>, Status> {
        let s = self
            .eval
            .get_suite(&req.into_inner().id)
            .ok_or(Status::not_found("not found"))?;
        Ok(Response::new(GetEvalSuiteResponse {
            suite: Some(EvalSuite {
                id: s.id,
                name: s.name,
                description: s.description,
                cases: vec![],
            }),
        }))
    }

    async fn create_eval_run(
        &self,
        req: Request<CreateEvalRunRequest>,
    ) -> Result<Response<CreateEvalRunResponse>, Status> {
        let req = req.into_inner();
        let r = req.run.ok_or(Status::invalid_argument("run required"))?;
        let run = crate::chisei::eval::Run {
            id: r.id.clone(),
            suite_id: r.suite_id.clone(),
            config_ref: r.config_ref.clone(),
            results: r
                .results
                .iter()
                .map(|cr| crate::chisei::eval::CaseResult {
                    case_id: cr.case_id.clone(),
                    passed: cr.passed,
                    status: cr.status.clone(),
                    result: cr.result.clone(),
                    score: cr.score,
                    reason: cr.reason.clone(),
                    elapsed: cr.elapsed,
                })
                .collect(),
            timestamp: r.timestamp,
        };
        self.db.put_eval_run(&run).map_err(Status::internal)?;
        self.eval.create_run(run);
        if !req.changed_file.is_empty() {
            let iteration = self
                .eval
                .track_iteration(&r.suite_id, &r.id, &req.changed_file, &req.diff_hash)
                .map_err(Status::internal)?;
            self.db
                .put_eval_iteration(&iteration)
                .map_err(Status::internal)?;
        }
        Ok(Response::new(CreateEvalRunResponse { run: Some(r) }))
    }

    async fn get_eval_run(
        &self,
        req: Request<GetEvalRunRequest>,
    ) -> Result<Response<GetEvalRunResponse>, Status> {
        let run = self
            .eval
            .get_run(&req.into_inner().id)
            .ok_or(Status::not_found("not found"))?;
        Ok(Response::new(GetEvalRunResponse {
            run: Some(EvalRun {
                id: run.id,
                suite_id: run.suite_id,
                config_ref: run.config_ref,
                results: run
                    .results
                    .into_iter()
                    .map(|result| CaseResult {
                        case_id: result.case_id,
                        passed: result.passed,
                        status: result.status,
                        result: result.result,
                        score: result.score,
                        reason: result.reason,
                        elapsed: result.elapsed,
                    })
                    .collect(),
                timestamp: run.timestamp,
            }),
        }))
    }

    async fn list_eval_runs(
        &self,
        req: Request<ListEvalRunsRequest>,
    ) -> Result<Response<ListEvalRunsResponse>, Status> {
        let runs = self.eval.list_runs(&req.into_inner().suite_id);
        let pb: Vec<EvalRun> = runs
            .iter()
            .map(|r| EvalRun {
                id: r.id.clone(),
                suite_id: r.suite_id.clone(),
                config_ref: r.config_ref.clone(),
                results: vec![],
                timestamp: r.timestamp,
            })
            .collect();
        Ok(Response::new(ListEvalRunsResponse { runs: pb }))
    }

    async fn track_eval_iteration(
        &self,
        req: Request<TrackEvalIterationRequest>,
    ) -> Result<Response<TrackEvalIterationResponse>, Status> {
        let r = req.into_inner();
        if r.suite_id.is_empty() || r.run_id.is_empty() || r.changed_file.is_empty() {
            return Err(Status::invalid_argument(
                "suite_id, run_id, and changed_file are required",
            ));
        }
        let iteration = self
            .eval
            .track_iteration(&r.suite_id, &r.run_id, &r.changed_file, &r.diff_hash)
            .map_err(Status::internal)?;
        self.db
            .put_eval_iteration(&iteration)
            .map_err(Status::internal)?;
        Ok(Response::new(TrackEvalIterationResponse {
            iteration: Some(eval_iteration_pb(iteration)),
        }))
    }

    async fn get_latest_eval_iteration(
        &self,
        req: Request<GetLatestEvalIterationRequest>,
    ) -> Result<Response<GetLatestEvalIterationResponse>, Status> {
        let iteration = self
            .eval
            .latest_iteration_for_file(&req.into_inner().changed_file)
            .ok_or(Status::not_found("iteration not found"))?;
        Ok(Response::new(GetLatestEvalIterationResponse {
            iteration: Some(eval_iteration_pb(iteration)),
        }))
    }

    async fn list_eval_iterations(
        &self,
        req: Request<ListEvalIterationsRequest>,
    ) -> Result<Response<ListEvalIterationsResponse>, Status> {
        let r = req.into_inner();
        let mut iterations = if r.changed_file.is_empty() {
            self.eval.list_iterations(&r.suite_id)
        } else {
            self.eval.list_iterations_for_file(&r.changed_file)
        };
        if !r.suite_id.is_empty() {
            iterations.retain(|iteration| iteration.suite_id == r.suite_id);
        }
        Ok(Response::new(ListEvalIterationsResponse {
            iterations: iterations.into_iter().map(eval_iteration_pb).collect(),
        }))
    }

    async fn compare_runs(
        &self,
        req: Request<CompareRunsRequest>,
    ) -> Result<Response<CompareRunsResponse>, Status> {
        let r = req.into_inner();
        let d = self
            .eval
            .compare_runs(&r.baseline_id, &r.candidate_id)
            .ok_or(Status::not_found("runs not found"))?;
        Ok(Response::new(CompareRunsResponse {
            decision: Some(GateDecision {
                verdict: d.verdict,
                reason: d.reason,
                baseline_score: d.baseline_score,
                candidate_score: d.candidate_score,
            }),
        }))
    }

    async fn eval_variance(
        &self,
        req: Request<EvalVarianceRequest>,
    ) -> Result<Response<EvalVarianceResponse>, Status> {
        let r = req.into_inner();
        let variance = self.eval.variance(&r.suite_id, &r.config_ref);
        Ok(Response::new(EvalVarianceResponse {
            variance: Some(EvalVariance {
                suite_id: variance.suite_id,
                config_ref: variance.config_ref,
                run_count: variance.run_count,
                mean_score: variance.mean_score,
                std_dev: variance.std_dev,
                min_score: variance.min_score,
                max_score: variance.max_score,
                cases: variance
                    .cases
                    .into_iter()
                    .map(|case| EvalVarianceCase {
                        case_id: case.case_id,
                        run_count: case.run_count,
                        pass_rate: case.pass_rate,
                        mean_score: case.mean_score,
                        min_score: case.min_score,
                        max_score: case.max_score,
                        std_dev: case.std_dev,
                    })
                    .collect(),
            }),
        }))
    }

    async fn eval_model_compare(
        &self,
        req: Request<EvalModelCompareRequest>,
    ) -> Result<Response<EvalModelCompareResponse>, Status> {
        let r = req.into_inner();
        let comparison = self.eval.model_compare(&r.suite_id);
        Ok(Response::new(EvalModelCompareResponse {
            comparison: Some(EvalModelComparison {
                suite_id: comparison.suite_id,
                models: comparison
                    .models
                    .into_iter()
                    .map(|model| EvalModelVariance {
                        model_id: model.model_id,
                        variance: Some(EvalVariance {
                            suite_id: model.variance.suite_id,
                            config_ref: model.variance.config_ref,
                            run_count: model.variance.run_count,
                            mean_score: model.variance.mean_score,
                            std_dev: model.variance.std_dev,
                            min_score: model.variance.min_score,
                            max_score: model.variance.max_score,
                            cases: model
                                .variance
                                .cases
                                .into_iter()
                                .map(|case| EvalVarianceCase {
                                    case_id: case.case_id,
                                    run_count: case.run_count,
                                    pass_rate: case.pass_rate,
                                    mean_score: case.mean_score,
                                    min_score: case.min_score,
                                    max_score: case.max_score,
                                    std_dev: case.std_dev,
                                })
                                .collect(),
                        }),
                    })
                    .collect(),
            }),
        }))
    }

    async fn evolve_suggest(
        &self,
        r: Request<EvolveSuggestRequest>,
    ) -> Result<Response<EvolveSuggestResponse>, Status> {
        let request_id = r.into_inner().request_id;
        let task = self
            .evolve_task(&request_id)
            .ok_or(Status::not_found("task not found"))?;
        let tasks = self.evolve_tasks();
        let namespace_tasks: Vec<_> = tasks
            .into_iter()
            .filter(|candidate| candidate.namespace == task.namespace)
            .collect();
        let patterns = crate::chisei::evolve::mine_patterns(&namespace_tasks);
        let suggestions = crate::chisei::evolve::suggest(&task, &patterns);
        Ok(Response::new(EvolveSuggestResponse {
            suggestions: suggestions
                .into_iter()
                .map(|suggestion| EvolveSuggestion {
                    message: suggestion.message,
                    confidence: suggestion.confidence,
                    category: suggestion.category,
                })
                .collect(),
        }))
    }

    async fn evolve_enhance(
        &self,
        req: Request<EvolveEnhanceRequest>,
    ) -> Result<Response<EvolveEnhanceResponse>, Status> {
        let r = req.into_inner();
        let tasks = self.evolve_tasks();
        let patterns = self
            .evolve_task(&r.request_id)
            .map(|task| {
                tasks
                    .into_iter()
                    .filter(|candidate| candidate.namespace == task.namespace)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| self.evolve_tasks());
        let mined_patterns = crate::chisei::evolve::mine_patterns(&patterns);
        let (enhanced, modified) = crate::chisei::evolve::enhance_spec(&r.spec, &mined_patterns);
        if modified && !r.request_id.is_empty() {
            self.evolve_enhancements
                .lock()
                .expect("evolve enhancements poisoned")
                .insert(r.request_id.clone(), r.spec.clone());
            self.db
                .put_evolve_enhancement(&r.request_id, &r.spec)
                .map_err(Status::internal)?;
        }
        Ok(Response::new(EvolveEnhanceResponse {
            enhanced_spec: enhanced,
            modified,
        }))
    }

    async fn evolve_recommend(
        &self,
        req: Request<EvolveRecommendRequest>,
    ) -> Result<Response<EvolveRecommendResponse>, Status> {
        let task = self
            .evolve_task(&req.into_inner().request_id)
            .ok_or(Status::not_found("task not found"))?;
        let recommendation = crate::chisei::evolve::recommend(&task).ok_or(
            Status::failed_precondition("task does not need a recommendation"),
        )?;
        Ok(Response::new(EvolveRecommendResponse {
            recommendation: Some(EvolveRecommendation {
                action: recommendation.action,
                reason: recommendation.reason,
            }),
        }))
    }

    async fn evolve_report(
        &self,
        _r: Request<EvolveReportRequest>,
    ) -> Result<Response<EvolveReportResponse>, Status> {
        let summary = crate::chisei::evolve::report(&self.evolve_tasks());
        Ok(Response::new(EvolveReportResponse {
            report: Some(EvolveReport {
                total_tasks: summary.total_tasks,
                succeeded: summary.succeeded,
                failed: summary.failed,
                success_rate: summary.success_rate,
                patterns: summary
                    .patterns
                    .into_iter()
                    .map(|pattern| EvolvePattern {
                        pattern: pattern.pattern,
                        occurrences: pattern.occurrences,
                        success_rate: pattern.success_rate,
                        category: pattern.category,
                    })
                    .collect(),
            }),
        }))
    }

    async fn evolve_patterns(
        &self,
        _r: Request<EvolvePatternsRequest>,
    ) -> Result<Response<EvolvePatternsResponse>, Status> {
        let patterns = crate::chisei::evolve::mine_patterns(&self.evolve_tasks());
        Ok(Response::new(EvolvePatternsResponse {
            patterns: patterns
                .into_iter()
                .map(|pattern| EvolvePattern {
                    pattern: pattern.pattern,
                    occurrences: pattern.occurrences,
                    success_rate: pattern.success_rate,
                    category: pattern.category,
                })
                .collect(),
        }))
    }

    async fn evolve_variance(
        &self,
        _r: Request<EvolveVarianceRequest>,
    ) -> Result<Response<EvolveVarianceResponse>, Status> {
        let report = crate::chisei::evolve::analyze_variance(
            &self.evolve_tasks(),
            chrono::Utc::now().timestamp(),
        );
        Ok(Response::new(EvolveVarianceResponse {
            report: Some(EvolveVarianceReport {
                patterns: report
                    .patterns
                    .into_iter()
                    .map(|pattern| EvolvePatternVariance {
                        pattern: pattern.pattern,
                        sample_size: pattern.sample_size,
                        mean_success_rate: pattern.mean_success_rate,
                        std_dev: pattern.std_dev,
                        ci_95_lower: pattern.ci_95_lower,
                        ci_95_upper: pattern.ci_95_upper,
                        risk_flag: pattern.risk_flag,
                        trend: pattern.trend,
                        windows: pattern
                            .windows
                            .into_iter()
                            .map(|window| EvolveVarianceWindow {
                                window: window.window,
                                total: window.total,
                                succeeded: window.succeeded,
                                success_rate: window.success_rate,
                            })
                            .collect(),
                    })
                    .collect(),
                insights: report.insights,
            }),
        }))
    }

    async fn evolve_ab_results(
        &self,
        _r: Request<EvolveAbResultsRequest>,
    ) -> Result<Response<EvolveAbResultsResponse>, Status> {
        let report = crate::chisei::evolve::compute_ab_results(&self.evolve_tasks());
        Ok(Response::new(EvolveAbResultsResponse {
            report: Some(EvolveAbReport {
                enhanced: Some(EvolveAbGroup {
                    total: report.enhanced.total,
                    succeeded: report.enhanced.succeeded,
                    success_rate: report.enhanced.success_rate,
                }),
                non_enhanced: Some(EvolveAbGroup {
                    total: report.non_enhanced.total,
                    succeeded: report.non_enhanced.succeeded,
                    success_rate: report.non_enhanced.success_rate,
                }),
            }),
        }))
    }

    async fn evolve_templates(
        &self,
        _r: Request<EvolveTemplatesRequest>,
    ) -> Result<Response<EvolveTemplatesResponse>, Status> {
        let templates = crate::chisei::evolve::generate_templates(&self.evolve_tasks());
        Ok(Response::new(EvolveTemplatesResponse {
            templates: templates
                .into_iter()
                .map(|template| EvolveTemplate {
                    id: template.name.clone(),
                    name: template.name,
                    content: template.content,
                    created: chrono::Utc::now().timestamp(),
                })
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use std::fs;
    use std::sync::Arc;

    fn config(db_path: &str) -> Config {
        Config {
            grpc_port: 0,
            db_path: db_path.to_string(),
            anthropic_api_key: None,
            openai_api_key: None,
            ollama_url: "http://127.0.0.1:11434".into(),
            native_llm_url: Some("http://127.0.0.1:9999".into()),
            auth_token: None,
            sample_rate: 0.0,
            sample_risk_threshold: 0.7,
            scoring_enabled: false,
            scoring_interval_secs: 60,
            scoring_model: "claude-opus-4-8".into(),
            scoring_batch_size: 16,
        }
    }

    fn memory_service() -> ChiseiServiceImpl {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        ChiseiServiceImpl::new(db, config(":memory:"))
    }

    fn file_service(path: &str) -> ChiseiServiceImpl {
        let db = Arc::new(SekaiDb::new(path).unwrap());
        ChiseiServiceImpl::new(db, config(path))
    }

    async fn create_suite(svc: &ChiseiServiceImpl, namespace: &str) {
        svc.create_eval_suite(Request::new(CreateEvalSuiteRequest {
            suite: Some(EvalSuite {
                id: "suite-1".into(),
                name: "suite".into(),
                description: String::new(),
                cases: vec![EvalCase {
                    id: "case-1".into(),
                    name: "case".into(),
                    namespace: namespace.into(),
                    spec: "spec".into(),
                    assertions: vec![],
                }],
            }),
        }))
        .await
        .unwrap();
    }

    fn eval_run(id: &str, suite_id: &str, score: i32, timestamp: i64) -> EvalRun {
        EvalRun {
            id: id.into(),
            suite_id: suite_id.into(),
            config_ref: "native-default".into(),
            results: vec![CaseResult {
                case_id: "case-1".into(),
                passed: score >= 80,
                status: if score >= 80 { "done" } else { "failed" }.into(),
                result: "result".into(),
                score,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp,
        }
    }

    #[tokio::test]
    async fn create_eval_run_auto_tracks_iteration() {
        let svc = memory_service();
        create_suite(&svc, "context-a").await;

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 90, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 70, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        let latest = svc
            .get_latest_eval_iteration(Request::new(GetLatestEvalIterationRequest {
                changed_file: "skills/context-a.md".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .iteration
            .unwrap();
        assert_eq!(latest.baseline_run_id, "run-1");
        assert_eq!(latest.candidate_run_id, "run-2");
        assert!(latest.regressed);

        let listed = svc
            .list_eval_iterations(Request::new(ListEvalIterationsRequest {
                suite_id: "suite-1".into(),
                changed_file: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.iterations.len(), 2);
    }

    #[tokio::test]
    async fn sqlite_reload_restores_iterations_and_regression_gate() {
        let path = format!(
            "{}/sekai-chisei-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let svc = file_service(&path);
        create_suite(&svc, "context-a").await;

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        drop(svc);

        let svc = file_service(&path);
        let latest = svc
            .get_latest_eval_iteration(Request::new(GetLatestEvalIterationRequest {
                changed_file: "skills/context-a.md".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .iteration
            .unwrap();
        assert!(latest.regressed);

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-1".into(),
                    namespace: "context-a".into(),
                    spec: "ship context-a fix".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert!(plan.eval_regressed);
        assert!(!plan.executable);
        assert!(plan.eval_regression_reason.contains("context-a"));
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("regressed"))
        );

        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn execute_plan_rechecks_regression_gate() {
        let svc = memory_service();
        create_suite(&svc, "context-a").await;

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        let mut plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-1".into(),
                    namespace: "context-a".into(),
                    spec: "ship context-a fix".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert!(plan.eval_regressed);
        assert!(!plan.executable);

        plan.executable = true;
        if let Some(input) = plan.input.as_mut() {
            input.namespace = "context-b".into();
        }
        let err = svc
            .execute_plan(Request::new(ExecutePlanRequest { plan: Some(plan) }))
            .await
            .expect_err("forged executable flag should be rejected");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("not executable"));
    }

    #[tokio::test]
    async fn eval_regressed_context_is_force_sampled_and_audited() {
        let svc = memory_service();
        create_suite(&svc, "context-a").await;

        // Two runs whose drop trips the regression signal for context-a.
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-sample".into(),
                    namespace: "context-a".into(),
                    spec: "ship context-a fix".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        // Base rate is 0.0 in the test config, so sampling here is purely the
        // eval-driven adaptive trigger.
        assert!(plan.sampled);
        assert_eq!(plan.sample_reason, "eval_regressed");
        assert_eq!(plan.sample_rate, 1.0);

        // A matching audit decision was recorded.
        let decisions = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("sample".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|d| d.target_id == "task-sample" && d.reason == "eval_regressed"),
            "expected a sampling audit decision for task-sample"
        );
    }

    #[tokio::test]
    async fn plan_execution_exposes_and_audits_egress_decisions() {
        let svc = memory_service();
        svc.db
            .create_object(&Object {
                id: "asset-secret".into(),
                kind: "asset".into(),
                name: "SecretCo".into(),
                namespace: "".into(),
                external_id: "asset:SECRET".into(),
                properties: std::collections::HashMap::from([
                    ("verdict".into(), "approved".into()),
                    ("score".into(), "99".into()),
                    (
                        crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                        "verdict".into(),
                    ),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-egress".into(),
                    namespace: "asset:SECRET".into(),
                    spec: "analyze the referenced asset".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        assert!(plan.egress_decisions.iter().any(|decision| {
            decision.provider == "native"
                && decision.external
                && decision.included.contains(&"object#1.verdict".into())
                && decision.redacted.contains(&"object#1.score".into())
                && decision.redacted.contains(&"object#1.identity".into())
        }));
        assert!(plan.enriched_spec.contains("prior_verdict: approved"));
        assert!(!plan.enriched_spec.contains("score: 99"));
        assert!(!plan.enriched_spec.contains("SecretCo"));
        let egress_text = format!("{:?}", plan.egress_decisions);
        assert!(!egress_text.contains("asset:SECRET"));

        let decisions = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                actor: Some("chisei.egress".into()),
                action: Some("prepare_context".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(decisions.iter().any(|d| {
            d.target_id == "task-egress"
                && d.evidence.get("provider") == Some(&"native".to_string())
                && d.evidence.get("redacted_count") == Some(&"2".to_string())
        }));
    }

    #[tokio::test]
    async fn execute_plan_rejects_external_plan_without_egress_decisions() {
        let svc = memory_service();
        let plan = ExecutionPlan {
            plan_id: "plan-forged-egress".into(),
            input: Some(ExecutionInput {
                request_id: "task-forged-egress".into(),
                namespace: "ns".into(),
                spec: "do work".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
            }),
            resolved_runtime: "kiro".into(),
            resolved_model: "native-default".into(),
            enriched_spec: "do work".into(),
            prepared_system: String::new(),
            prepared_messages: vec![ChatMessage {
                role: "user".into(),
                content: "do work".into(),
                tool_call_id: String::new(),
                tool_calls: vec![],
            }],
            tools: vec![],
            budget: Some(BudgetVerdict {
                allowed: true,
                usage: None,
                reason: String::new(),
            }),
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 512,
            created_at: chrono::Utc::now().timestamp_millis(),
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
        };
        svc.cache_plan(plan.clone());

        let err = svc
            .execute_plan(Request::new(ExecutePlanRequest { plan: Some(plan) }))
            .await
            .expect_err("external plan without egress decisions should be rejected");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("missing egress decisions"));
    }

    #[tokio::test]
    async fn sqlite_reload_backfills_legacy_iteration_context_gates() {
        let path = format!(
            "{}/sekai-chisei-legacy-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let svc = file_service(&path);
        create_suite(&svc, "context-a").await;

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        svc.db
            .conn
            .lock()
            .unwrap()
            .execute("UPDATE chisei_eval_iterations SET namespace = ''", [])
            .unwrap();
        drop(svc);

        let svc = file_service(&path);
        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-1".into(),
                    namespace: "context-a".into(),
                    spec: "ship context-a fix".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert!(plan.eval_regressed);
        assert!(plan.eval_regression_reason.contains("context-a"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cache_plan_keeps_newest_inserted_plan() {
        let svc = memory_service();
        let now = chrono::Utc::now().timestamp_millis();
        for i in 0..MAX_CACHED_EXECUTION_PLANS {
            svc.cache_plan(ExecutionPlan {
                plan_id: format!("plan-{i:03}"),
                input: None,
                resolved_runtime: String::new(),
                resolved_model: String::new(),
                enriched_spec: String::new(),
                prepared_system: String::new(),
                prepared_messages: vec![],
                tools: vec![],
                budget: None,
                steps: vec![],
                review_policy: None,
                risk_score: 0.0,
                low_success_namespace: false,
                executable: true,
                warnings: vec![],
                max_tokens: 0,
                created_at: now,
                affinity_namespaces: vec![],
                eval_regressed: false,
                eval_regression_reason: String::new(),
                sampled: false,
                sample_rate: 0.0,
                sample_reason: String::new(),
                egress_decisions: vec![],
            });
        }
        let newest = ExecutionPlan {
            plan_id: "plan-new".into(),
            input: None,
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            enriched_spec: String::new(),
            prepared_system: String::new(),
            prepared_messages: vec![],
            tools: vec![],
            budget: None,
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 0,
            created_at: now,
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
        };
        svc.cache_plan(newest.clone());

        let plans = svc
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        assert_eq!(plans.len(), MAX_CACHED_EXECUTION_PLANS);
        assert!(plans.contains_key(&newest.plan_id));
    }

    #[test]
    fn cache_plan_prunes_expired_entries() {
        let svc = memory_service();
        let expired = ExecutionPlan {
            plan_id: "plan-old".into(),
            input: None,
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            enriched_spec: String::new(),
            prepared_system: String::new(),
            prepared_messages: vec![],
            tools: vec![],
            budget: None,
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 0,
            created_at: chrono::Utc::now().timestamp_millis()
                - MAX_CACHED_EXECUTION_PLAN_AGE_MS
                - 1,
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
        };
        let fresh = ExecutionPlan {
            plan_id: "plan-fresh".into(),
            created_at: chrono::Utc::now().timestamp_millis(),
            ..expired.clone()
        };
        svc.cache_plan(expired);
        svc.cache_plan(fresh.clone());

        let plans = svc
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        assert!(!plans.contains_key("plan-old"));
        assert!(plans.contains_key(&fresh.plan_id));
    }

    #[test]
    fn cache_plan_keeps_inserted_plan_when_timestamps_tie() {
        let svc = memory_service();
        let now = chrono::Utc::now().timestamp_millis();
        for i in 0..MAX_CACHED_EXECUTION_PLANS {
            svc.cache_plan(ExecutionPlan {
                plan_id: format!("plan-z{i:03}"),
                input: None,
                resolved_runtime: String::new(),
                resolved_model: String::new(),
                enriched_spec: String::new(),
                prepared_system: String::new(),
                prepared_messages: vec![],
                tools: vec![],
                budget: None,
                steps: vec![],
                review_policy: None,
                risk_score: 0.0,
                low_success_namespace: false,
                executable: true,
                warnings: vec![],
                max_tokens: 0,
                created_at: now,
                affinity_namespaces: vec![],
                eval_regressed: false,
                eval_regression_reason: String::new(),
                sampled: false,
                sample_rate: 0.0,
                sample_reason: String::new(),
                egress_decisions: vec![],
            });
        }
        let inserted = ExecutionPlan {
            plan_id: "plan-a".into(),
            input: None,
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            enriched_spec: String::new(),
            prepared_system: String::new(),
            prepared_messages: vec![],
            tools: vec![],
            budget: None,
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 0,
            created_at: now,
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
        };
        svc.cache_plan(inserted.clone());

        let plans = svc
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        assert_eq!(plans.len(), MAX_CACHED_EXECUTION_PLANS);
        assert!(plans.contains_key(&inserted.plan_id));
    }
}
