use regex::Regex;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use tonic::{Request, Response, Status};

use super::llm_service::{
    estimate_chat_request, execute_chat_request, execute_chat_request_stream,
};
use super::pb::chisei::chisei_service_server::ChiseiService;
use super::pb::chisei::*;
use crate::chisei::budget::BudgetTracker;
use crate::chisei::controller::ActivePromotions;
use crate::chisei::eval::EvalStore;
use crate::chisei::pipeline as pipe;
use crate::chisei::policy::{Policy, PolicyResolver};
use crate::chisei::privacy::{DataClass, LeakAction, LeakFinding, LeakRule, TaskClass};
use crate::chisei::promotion::CandidateStore;
use crate::config::Config;
use crate::db::chisei_budget::{METRIC_REQUESTS, METRIC_TOKENS};
use crate::db::sekai::SekaiDb;
use crate::domain::{ListFilter, Object};

pub struct ChiseiServiceImpl {
    budget: Arc<BudgetTracker>,
    policy: Arc<PolicyResolver>,
    pipeline: pipe::Pipeline,
    eval: Arc<EvalStore>,
    planned_executions: Arc<Mutex<HashMap<String, ExecutionPlan>>>,
    evolve_history: Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    evolve_enhancements: Arc<Mutex<HashMap<String, String>>>,
    candidates: Arc<CandidateStore>,
    active_promotions: Arc<ActivePromotions>,
    db: Arc<SekaiDb>,
    config: Config,
}

const MAX_CACHED_EXECUTION_PLANS: usize = 128;
const MAX_CACHED_EXECUTION_PLAN_AGE_MS: i64 = 15 * 60 * 1000;
const POLICY_KIND: &str = "policy";

struct FinishStreamedExecution<'a> {
    db: &'a SekaiDb,
    evolve_history: &'a Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    request_id: &'a str,
    namespace: &'a str,
    enriched_spec: &'a str,
    original_spec: Option<&'a str>,
    resolved_model: &'a str,
    sampled: bool,
    sample_rate: f64,
    sample_reason: &'a str,
    scoring_enabled: bool,
    task_class: &'a str,
    response: &'a PlannedChatResponse,
}

struct EvolveTaskRecord<'a> {
    request_id: &'a str,
    namespace: &'a str,
    spec: &'a str,
    original_spec: Option<&'a str>,
    status: &'a str,
    tokens_used: i32,
}

fn record_evolve_task_on(
    db: &SekaiDb,
    evolve_history: &Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    task: EvolveTaskRecord<'_>,
) -> Result<(), String> {
    if task.request_id.is_empty() {
        return Ok(());
    }
    let mut history = evolve_history.lock().expect("evolve history poisoned");
    let entry = history
        .entry(task.request_id.to_string())
        .or_insert_with(|| crate::chisei::evolve::TaskRecord {
            id: task.request_id.to_string(),
            spec: task.spec.to_string(),
            status: task.status.to_string(),
            namespace: task.namespace.to_string(),
            tokens_used: task.tokens_used,
            original_spec: task.original_spec.map(ToOwned::to_owned),
            created: chrono::Utc::now().timestamp(),
        });
    entry.namespace = task.namespace.to_string();
    entry.spec = task.spec.to_string();
    entry.status = task.status.to_string();
    entry.tokens_used = task.tokens_used;
    entry.original_spec = task.original_spec.map(ToOwned::to_owned);
    db.put_evolve_task(entry)?;
    Ok(())
}
fn finish_streamed_execution(execution: &FinishStreamedExecution) -> Result<(), String> {
    record_evolve_task_on(
        execution.db,
        execution.evolve_history,
        EvolveTaskRecord {
            request_id: execution.request_id,
            namespace: execution.namespace,
            spec: execution.enriched_spec,
            original_spec: execution.original_spec,
            status: "done",
            tokens_used: execution.response.input_tokens + execution.response.output_tokens,
        },
    )?;
    if execution.sampled {
        let mut evidence = HashMap::new();
        evidence.insert("model".to_string(), execution.resolved_model.to_string());
        evidence.insert(
            "input_tokens".to_string(),
            execution.response.input_tokens.to_string(),
        );
        evidence.insert(
            "output_tokens".to_string(),
            execution.response.output_tokens.to_string(),
        );
        evidence.insert(
            "stop_reason".to_string(),
            execution.response.stop_reason.clone(),
        );
        evidence.insert("sample_rate".to_string(), execution.sample_rate.to_string());
        let _ = execution
            .db
            .record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                actor: "chisei.sampling".into(),
                action: "sample_observed".into(),
                reason: execution.sample_reason.to_string(),
                evidence,
                target_id: execution.request_id.to_string(),
                outcome: "observed".into(),
            });
        if execution.scoring_enabled {
            let _ =
                execution
                    .db
                    .put_sample_observation(&crate::chisei::scoring::SampleObservation {
                        request_id: execution.request_id.to_string(),
                        namespace: execution.namespace.to_string(),
                        spec: execution.enriched_spec.to_string(),
                        resolved_model: execution.resolved_model.to_string(),
                        output_content: execution.response.content.clone(),
                        sample_reason: execution.sample_reason.to_string(),
                        input_tokens: execution.response.input_tokens,
                        output_tokens: execution.response.output_tokens,
                        stop_reason: execution.response.stop_reason.clone(),
                        timestamp: chrono::Utc::now().timestamp_millis(),
                        scored: false,
                        task_class: execution.task_class.to_string(),
                    });
        }
    }
    Ok(())
}

fn persist_namespace_policy(db: &SekaiDb, namespace: &str, policy: &Policy) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    let external_id = format!("policy:{namespace}");
    let mut properties = policy_properties(policy);
    properties.insert("namespace".to_string(), namespace.to_string());

    if let Some(mut existing) = db.find_by_external_id(&external_id)? {
        existing.name = namespace.to_string();
        existing.namespace = namespace.to_string();
        existing.properties = properties;
        existing.updated = now;
        db.update_object(&existing)
    } else {
        db.create_object(&Object {
            id: format!("policy-{namespace}"),
            kind: POLICY_KIND.to_string(),
            name: namespace.to_string(),
            namespace: namespace.to_string(),
            external_id,
            properties,
            created: now,
            updated: now,
        })
    }
}

impl ChiseiServiceImpl {
    pub fn new(db: Arc<SekaiDb>, config: Config) -> Self {
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
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
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        Self {
            budget: Arc::new(BudgetTracker::new(db.clone())),
            policy,
            pipeline: pipe::default_pipeline_with(config.sample_rate, config.sample_risk_threshold),
            eval,
            planned_executions: Arc::new(Mutex::new(HashMap::new())),
            evolve_history,
            evolve_enhancements,
            candidates: Arc::new(CandidateStore::new()),
            active_promotions: Arc::new(ActivePromotions::new()),
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

    /// This service's live candidate store, for propose/gate/promote workflows that need to share
    /// its DB and in-memory `EvalStore` (e.g. a periodic promotion-controller driver, or direct
    /// RPC-triggered promotion).
    pub fn candidate_store(&self) -> Arc<CandidateStore> {
        self.candidates.clone()
    }

    /// This service's live active-promotions registry — the same one `resolve_policy` consults,
    /// so promotions/rollbacks driven through `candidate_store()` have a real, immediate effect on
    /// live routing.
    pub fn active_promotions(&self) -> Arc<ActivePromotions> {
        self.active_promotions.clone()
    }

    pub fn with_budget(db: Arc<SekaiDb>, config: Config, budget: Arc<BudgetTracker>) -> Self {
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
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
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        Self {
            budget,
            policy,
            pipeline: pipe::default_pipeline_with(config.sample_rate, config.sample_risk_threshold),
            eval,
            planned_executions: Arc::new(Mutex::new(HashMap::new())),
            evolve_history,
            evolve_enhancements,
            candidates: Arc::new(CandidateStore::new()),
            active_promotions: Arc::new(ActivePromotions::new()),
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
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let data_class = self.data_class(effective_policy.as_ref());
        let task_class = TaskClass::parse(&input.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        let template_only =
            data_class == DataClass::Sensitive && task_class == TaskClass::TemplateOnly;
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
            external_egress: !safe_only,
            template_only,
        };
        let affinity = crate::chisei::affinity::get_affinity(&self.db, namespace_hint.as_str());
        let initial_run = self.pipeline.run(&mut pipeline_req, &self.db);
        let fallback_runtime = pipeline_req.runtime.clone();
        let (initial_runtime, initial_model) = self
            .resolve_model_for_run(
                &input,
                &fallback_runtime,
                &initial_run,
                effective_policy.as_ref(),
                safe_only,
                &safe_providers,
            )
            .await?;
        let initial_provider = crate::llm::provider_name(&initial_model).to_string();
        let initial_provider_is_external =
            crate::chisei::egress::is_external_provider(&initial_provider);
        let (run, resolved_runtime, resolved_model, provider, provider_is_external) =
            if initial_provider_is_external || safe_only || template_only {
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
                    template_only,
                };
                let local_run = self.pipeline.run(&mut local_pipeline_req, &self.db);
                let (local_runtime, local_model) = self
                    .resolve_model_for_run(
                        &input,
                        &local_pipeline_req.runtime,
                        &local_run,
                        effective_policy.as_ref(),
                        safe_only,
                        &safe_providers,
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
            .check_with_metric(&normalized_user_id, estimated_tokens, METRIC_TOKENS)
            .is_ok();
        let usage = self
            .budget
            .get_usage_with_metric(&normalized_user_id, METRIC_TOKENS);
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
                self.resolve_live_model(
                    &p.model,
                    effective_policy.as_ref(),
                    final_route_bias,
                    safe_only,
                    &safe_providers,
                )
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
        let mut executable = allowed && !eval_regressed;
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
        if safe_only {
            let provider_safe =
                crate::chisei::privacy::provider_safe_to_send(&provider, &safe_providers);
            if !provider_safe {
                self.record_privacy_audit(
                    "blocked",
                    &input.request_id,
                    &provider,
                    data_class,
                    task_class,
                    "unsafe_provider",
                );
                return Err(Status::failed_precondition(
                    crate::chisei::privacy::gate_reason(data_class, task_class, &provider),
                ));
            }
            self.record_privacy_audit(
                "forced_local",
                &input.request_id,
                &provider,
                data_class,
                task_class,
                "safe_provider_required",
            );
        } else if template_only && provider_is_external {
            self.record_privacy_audit(
                "allowed_template_only",
                &input.request_id,
                &provider,
                data_class,
                task_class,
                "template_only_sanitization_contract",
            );
        }
        let mut egress_decisions = egress_decisions;
        let leak_findings = self.leak_findings_for_payload(
            &input.namespace,
            &provider,
            data_class,
            &payload_for_leak_check(&input.system, &prepared_messages, &input.tools),
        );
        if !leak_findings.is_empty() {
            egress_decisions.extend(leak_findings_to_decisions(
                &provider,
                provider_is_external,
                &leak_findings,
            ));
            self.record_leak_audit("leak_check", &input.request_id, &provider, &leak_findings);
            if leak_findings
                .iter()
                .any(|finding| finding.action == LeakAction::Block)
            {
                executable = false;
                warnings.push("privacy leak checker blocked outbound payload".into());
            }
        }
        if data_class == DataClass::Sensitive
            && task_class == TaskClass::TemplateOnly
            && !crate::chisei::privacy::provider_safe_to_send(&provider, &safe_providers)
            && let Some(warning) = self
                .run_leak_reviewer(&input.request_id, &provider, &input.spec)
                .await
        {
            warnings.push(warning);
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
            task_class: task_class.as_str().into(),
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
        safe_only: bool,
        safe_providers: &std::collections::HashSet<String>,
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
            .resolve_live_model(&model, policy, route_bias, safe_only, safe_providers)
            .await
            .map_err(Status::failed_precondition)?;
        Ok((runtime, model))
    }

    fn data_class(&self, policy: Option<&crate::chisei::policy::Policy>) -> DataClass {
        policy
            .map(|policy| DataClass::parse(&policy.data_class))
            .filter(|class| *class != DataClass::Unclassified)
            .unwrap_or_else(|| DataClass::parse(&self.config.default_data_class))
    }

    fn leak_findings_for_payload(
        &self,
        namespace: &str,
        provider: &str,
        data_class: DataClass,
        payload: &str,
    ) -> Vec<LeakFinding> {
        let safe = crate::chisei::privacy::safe_providers(&self.config);
        if crate::chisei::privacy::provider_safe_to_send(provider, &safe) {
            return vec![];
        }
        let rules = self.leak_rules(namespace);
        let entities = if data_class == DataClass::Sensitive {
            self.sensitive_entities(namespace)
        } else {
            vec![]
        };
        crate::chisei::privacy::check_payload(payload, &rules, &entities)
    }

    fn leak_rules(&self, namespace: &str) -> Vec<LeakRule> {
        let mut rules = Vec::new();
        for ns in ["", namespace] {
            let Ok(objects) = self.db.list_all_objects(&ListFilter {
                kind: Some("leak_rule".into()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            }) else {
                continue;
            };
            for obj in objects {
                let Some(pattern) = obj.properties.get("pattern") else {
                    continue;
                };
                let Ok(pattern) = Regex::new(pattern) else {
                    continue;
                };
                rules.push(LeakRule {
                    id: obj.id,
                    label: obj
                        .properties
                        .get("label")
                        .cloned()
                        .filter(|value| !value.is_empty())
                        .unwrap_or(obj.name),
                    pattern,
                    action: LeakAction::parse(
                        obj.properties
                            .get("action")
                            .map(String::as_str)
                            .unwrap_or("block"),
                    ),
                });
            }
        }
        rules
    }

    fn sensitive_entities(&self, namespace: &str) -> Vec<String> {
        let objects = self
            .db
            .list_all_objects(&ListFilter {
                namespace: Some(namespace.to_string()),
                ..Default::default()
            })
            .unwrap_or_default();
        crate::chisei::privacy::entity_scan_literals(&objects)
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

    fn record_privacy_audit(
        &self,
        outcome: &str,
        request_id: &str,
        provider: &str,
        data_class: DataClass,
        task_class: TaskClass,
        reason: &str,
    ) {
        let mut evidence = std::collections::HashMap::new();
        evidence.insert("provider".to_string(), provider.to_string());
        evidence.insert("data_class".to_string(), data_class.as_str().to_string());
        evidence.insert("task_class".to_string(), task_class.as_str().to_string());
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.privacy".into(),
            action: "gate".into(),
            reason: reason.into(),
            evidence,
            target_id: request_id.into(),
            outcome: outcome.into(),
        });
    }

    fn record_leak_audit(
        &self,
        action: &str,
        request_id: &str,
        provider: &str,
        findings: &[LeakFinding],
    ) {
        let mut evidence = std::collections::HashMap::new();
        evidence.insert("provider".to_string(), provider.to_string());
        evidence.insert("finding_count".to_string(), findings.len().to_string());
        evidence.insert(
            "block_count".to_string(),
            findings
                .iter()
                .filter(|finding| finding.action == LeakAction::Block)
                .count()
                .to_string(),
        );
        evidence.insert(
            "labels".to_string(),
            findings
                .iter()
                .map(|finding| format!("{}:{}", finding.rule_label, finding.match_count))
                .collect::<Vec<_>>()
                .join(","),
        );
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.privacy".into(),
            action: action.into(),
            reason: "leak checker evaluated outbound payload".into(),
            evidence,
            target_id: request_id.into(),
            outcome: if findings
                .iter()
                .any(|finding| finding.action == LeakAction::Block)
            {
                "leak_blocked".into()
            } else {
                "leak_warned".into()
            },
        });
    }

    async fn run_leak_reviewer(
        &self,
        request_id: &str,
        provider: &str,
        abstract_task: &str,
    ) -> Option<String> {
        let model = self.config.leak_review_model.as_ref()?;
        let safe = crate::chisei::privacy::safe_providers(&self.config);
        let reviewer_provider = crate::llm::provider_name(model);
        if !crate::chisei::privacy::provider_safe_to_send(reviewer_provider, &safe) {
            self.record_leak_reviewer_audit(
                request_id,
                provider,
                model,
                "reviewer_error",
                "reviewer model is not safe to send sensitive-review prompts",
            );
            return Some("local leak reviewer was skipped because its model is not safe".into());
        }
        let Ok(reviewer) = crate::llm::resolve(
            model,
            self.config.anthropic_api_key.as_deref(),
            self.config.openai_api_key.as_deref(),
            &self.config.ollama_url,
            self.config.native_llm_url.as_deref(),
        ) else {
            self.record_leak_reviewer_audit(
                request_id,
                provider,
                model,
                "reviewer_error",
                "reviewer provider is not configured",
            );
            return Some("local leak reviewer could not run".into());
        };
        let req = crate::llm::ChatRequest {
            model: model.clone(),
            system: "You are a local privacy reviewer. Answer only SAFE or RISK with one short reason. Does this abstract request reveal sector, position, timing, or proprietary intent?".into(),
            messages: vec![crate::llm::Message {
                role: "user".into(),
                content: abstract_task.to_string(),
                tool_call_id: String::new(),
                tool_calls: vec![],
            }],
            tools: vec![],
            max_tokens: 64,
        };
        match reviewer.chat(&req).await {
            Ok(resp) => {
                let lower = resp.content.to_ascii_lowercase();
                let risky = lower.contains("risk") || lower.contains("unsafe");
                self.record_leak_reviewer_audit(
                    request_id,
                    provider,
                    model,
                    if risky { "warn" } else { "pass" },
                    if risky {
                        "reviewer flagged template-inversion risk"
                    } else {
                        "reviewer did not flag template-inversion risk"
                    },
                );
                risky.then(|| "local leak reviewer flagged template-inversion risk".into())
            }
            Err(_) => {
                self.record_leak_reviewer_audit(
                    request_id,
                    provider,
                    model,
                    "reviewer_error",
                    "reviewer call failed",
                );
                Some("local leak reviewer could not run".into())
            }
        }
    }

    fn record_leak_reviewer_audit(
        &self,
        request_id: &str,
        provider: &str,
        reviewer_model: &str,
        outcome: &str,
        reason: &str,
    ) {
        let mut evidence = std::collections::HashMap::new();
        evidence.insert("provider".to_string(), provider.to_string());
        evidence.insert("reviewer_model".to_string(), reviewer_model.to_string());
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.privacy".into(),
            action: "leak_review".into(),
            reason: reason.into(),
            evidence,
            target_id: request_id.into(),
            outcome: outcome.into(),
        });
    }

    async fn resolve_live_model(
        &self,
        model: &str,
        policy: Option<&crate::chisei::policy::Policy>,
        route_bias: Option<&str>,
        safe_only: bool,
        safe_providers: &std::collections::HashSet<String>,
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
            safe_only,
            safe_providers,
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
        record_evolve_task_on(
            &self.db,
            &self.evolve_history,
            EvolveTaskRecord {
                request_id,
                namespace,
                spec,
                original_spec,
                status,
                tokens_used,
            },
        )
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

fn budget_metric(metric: &str) -> Result<&'static str, Status> {
    if metric.trim().eq_ignore_ascii_case(METRIC_REQUESTS) {
        Ok(METRIC_REQUESTS)
    } else if metric.trim().is_empty() || metric.trim().eq_ignore_ascii_case(METRIC_TOKENS) {
        Ok(METRIC_TOKENS)
    } else {
        Err(Status::invalid_argument(
            "unsupported budget metric; use tokens or requests",
        ))
    }
}

/// Builds the budget scope id for a request. An explicit `subject` bypasses
/// hierarchy construction entirely (kept for legacy/direct callers and any
/// caller that wants a flat, non-nested scope) and chains only through the
/// unset `global` root. Otherwise the scope is built from whichever of
/// project/agent/work_unit are present, in that nesting order, so that
/// `CheckBudget`/`RecordUsage` walk and deduct the whole ancestor chain
/// (project -> agent -> work_unit) atomically — see `db::chisei_budget`.
fn budget_subject(
    subject: &str,
    project: &str,
    agent: &str,
    key_id: &str,
    work_unit: &str,
    legacy_user_id: &str,
) -> Result<String, Status> {
    if !subject.trim().is_empty() {
        return Ok(subject.trim().to_string());
    }
    let mut segments = Vec::new();
    if !project.trim().is_empty() {
        segments.push(format!("project:{}", project.trim()));
    }
    if !agent.trim().is_empty() {
        segments.push(format!("agent:{}", agent.trim()));
    }
    if !work_unit.trim().is_empty() {
        segments.push(format!("work_unit:{}", work_unit.trim()));
    }
    if !segments.is_empty() {
        return Ok(segments.join("/"));
    }
    if !key_id.trim().is_empty() {
        return Ok(format!("gateway_key:{}", key_id.trim()));
    }
    if !legacy_user_id.trim().is_empty() {
        return Ok(legacy_user_id.trim().to_string());
    }
    Err(Status::invalid_argument("budget subject required"))
}

fn policy_scopes(req: &ResolvePolicyRequest) -> Vec<String> {
    let mut scopes = Vec::new();
    push_scope(&mut scopes, req.subject.trim());
    if !req.agent.trim().is_empty() {
        push_scope(&mut scopes, &format!("agent:{}", req.agent.trim()));
    }
    if !req.key_id.trim().is_empty() {
        push_scope(&mut scopes, &format!("gateway_key:{}", req.key_id.trim()));
    }
    push_scope(&mut scopes, req.namespace.trim());
    push_scope(&mut scopes, req.project.trim());
    if !req.project.trim().is_empty() {
        push_scope(&mut scopes, &format!("project:{}", req.project.trim()));
    }
    scopes
}

/// Map a request's task class to a cost-tier route bias. Only explicit bulk
/// task classes route to the cheaper tier, and only while no eval regression is
/// active for the scope — a regression fails safe back to the capable tier.
/// Unknown or primary classes never bias to cheap.
fn cheap_route_bias(task_class: &str, eval_regressed: bool) -> Option<&'static str> {
    if eval_regressed {
        return None;
    }
    match task_class.trim().to_ascii_lowercase().as_str() {
        "background" | "bulk" | "batch" | "small_fast" | "small-fast" => Some("cheap"),
        _ => None,
    }
}

/// Whether a runtime supports automatic cheap-tier routing. Limited to the
/// hosted providers whose model tiers are reliably ordered by
/// `named_model_cost_rank` (the metric the demotion gate compares). Ollama and
/// native models are excluded: their cost depends on installed parameter size,
/// not the model name, so the name-based gate cannot tell tiers apart and would
/// silently discard the cheaper choice. Cost tiering for those runtimes is a
/// follow-up. This also guards against non-provider runtimes (e.g. the "kiro"
/// default) producing a bogus alias or a runtime/model mismatch.
fn is_known_provider_runtime(runtime: &str) -> bool {
    matches!(runtime.trim(), "openai" | "anthropic")
}

fn push_scope(scopes: &mut Vec<String>, scope: &str) {
    if scope.is_empty() || scopes.iter().any(|existing| existing == scope) {
        return;
    }
    scopes.push(scope.to_string());
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

fn load_namespace_policies(db: &SekaiDb, resolver: &PolicyResolver) {
    for kind in ["policy", "namespace_policy"] {
        let Ok(objects) = db.list_all_objects(&ListFilter {
            kind: Some(kind.into()),
            ..Default::default()
        }) else {
            continue;
        };
        for obj in objects {
            let namespace = policy_namespace(&obj);
            if namespace.is_empty() {
                continue;
            }
            resolver.set_namespace_policy(&namespace, policy_from_properties(&obj.properties));
        }
    }
}

fn policy_namespace(obj: &crate::domain::Object) -> String {
    if !obj.namespace.trim().is_empty() {
        return obj.namespace.trim().to_string();
    }
    for prefix in ["namespace_policy:", "policy:", "namespace:"] {
        if let Some(value) = obj.external_id.strip_prefix(prefix)
            && !value.trim().is_empty()
        {
            return value.trim().to_string();
        }
    }
    obj.name.trim().to_string()
}

fn policy_from_properties(properties: &std::collections::HashMap<String, String>) -> Policy {
    Policy {
        allowed_runtimes: csv_property(properties.get("allowed_runtimes")),
        allowed_models: csv_property(properties.get("allowed_models")),
        default_runtime: properties
            .get("default_runtime")
            .cloned()
            .unwrap_or_default(),
        default_model: properties.get("default_model").cloned().unwrap_or_default(),
        data_class: properties.get("data_class").cloned().unwrap_or_default(),
    }
}

fn policy_properties(policy: &Policy) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("allowed_runtimes".into(), policy.allowed_runtimes.join(",")),
        ("allowed_models".into(), policy.allowed_models.join(",")),
        ("default_runtime".into(), policy.default_runtime.clone()),
        ("default_model".into(), policy.default_model.clone()),
        ("data_class".into(), policy.data_class.clone()),
    ])
}

fn policy_from_request(r: &SetNamespacePolicyRequest) -> Policy {
    Policy {
        allowed_runtimes: r.allowed_runtimes.clone(),
        allowed_models: r.allowed_models.clone(),
        default_runtime: r.default_runtime.clone(),
        default_model: r.default_model.clone(),
        data_class: DataClass::parse(&r.data_class).as_str().into(),
    }
}

fn csv_property(value: Option<&String>) -> Vec<String> {
    value
        .map(String::as_str)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
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

fn payload_for_leak_check(system: &str, messages: &[ChatMessage], tools: &[ToolDef]) -> String {
    let mut payload = String::new();
    payload.push_str(system);
    for message in messages {
        payload.push('\n');
        payload.push_str(&message.role);
        payload.push_str(": ");
        payload.push_str(&message.content);
    }
    for tool in tools {
        payload.push('\n');
        payload.push_str(&tool.name);
        payload.push_str(": ");
        payload.push_str(&tool.description);
        payload.push('\n');
        payload.push_str(&tool.input_schema_json);
    }
    payload
}

fn leak_findings_to_decisions(
    provider: &str,
    external: bool,
    findings: &[LeakFinding],
) -> Vec<EgressDecision> {
    findings
        .iter()
        .map(|finding| EgressDecision {
            provider: provider.into(),
            external,
            included: vec![],
            redacted: vec![],
            reasons: vec![format!(
                "leak_checker {} {} match(es)",
                finding.rule_label, finding.match_count
            )],
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
    type ExecutePlanStreamStream =
        Pin<Box<dyn futures_util::Stream<Item = Result<ExecutePlanStreamEvent, Status>> + Send>>;

    async fn check_budget(
        &self,
        req: Request<CheckBudgetRequest>,
    ) -> Result<Response<CheckBudgetResponse>, Status> {
        let r = req.into_inner();
        let metric = budget_metric(&r.metric)?;
        let budget_subject = budget_subject(
            &r.subject,
            &r.project,
            &r.agent,
            &r.key_id,
            &r.work_unit,
            &r.user_id,
        )?;
        let allowed = self
            .budget
            .check_with_metric(&budget_subject, r.estimated_tokens, metric)
            .is_ok();
        let u = self.budget.get_usage_with_metric(&budget_subject, metric);
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
        let metric = budget_metric(&r.metric)?;
        let budget_subject = budget_subject(
            &r.subject,
            &r.project,
            &r.agent,
            &r.key_id,
            &r.work_unit,
            &r.user_id,
        )?;
        self.budget
            .record_with_metric(&budget_subject, r.tokens_used, metric);
        let u = self.budget.get_usage_with_metric(&budget_subject, metric);
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
        let metric = budget_metric(&r.metric)?;
        let period = crate::chisei::budget::PeriodType::parse_strict(&r.period_type)
            .map_err(Status::invalid_argument)?;
        let budget_subject = budget_subject(
            &r.subject,
            &r.project,
            &r.agent,
            &r.key_id,
            &r.work_unit,
            &r.user_id,
        )?;
        self.budget
            .set_limit_with_metric(&budget_subject, metric, r.max_tokens, period)
            .map_err(Status::internal)?;
        Ok(Response::new(SetBudgetLimitResponse {}))
    }

    async fn set_namespace_policy(
        &self,
        req: Request<SetNamespacePolicyRequest>,
    ) -> Result<Response<SetNamespacePolicyResponse>, Status> {
        let r = req.into_inner();
        if r.namespace.trim().is_empty() {
            return Err(Status::invalid_argument("namespace required"));
        }
        let policy = policy_from_request(&r);
        let policy_data_class = policy.data_class.clone();
        persist_namespace_policy(&self.db, &r.namespace, &policy).map_err(Status::internal)?;
        self.policy.set_namespace_policy(&r.namespace, policy);
        let (runtime, model) = self
            .policy
            .resolve(&r.namespace, &r.default_runtime, &r.default_model)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(SetNamespacePolicyResponse {
            resolution: Some(PolicyResolution {
                runtime,
                model,
                data_class: policy_data_class,
                eval_regressed: false,
                eval_regression_reason: String::new(),
                route_bias: String::new(),
            }),
        }))
    }

    async fn resolve_policy(
        &self,
        req: Request<ResolvePolicyRequest>,
    ) -> Result<Response<ResolvePolicyResponse>, Status> {
        let r = req.into_inner();
        let scopes = policy_scopes(&r);
        let (policy_scope, effective_policy) = self
            .policy
            .effective_policy_for_scopes(&scopes)
            .map(|(scope, policy)| (scope, Some(policy)))
            .unwrap_or_else(|| {
                let fallback = if r.namespace.trim().is_empty() {
                    r.project.trim().to_string()
                } else {
                    r.namespace.trim().to_string()
                };
                (fallback, None)
            });
        let regression_signal = self
            .eval
            .namespace_regression_signal(&policy_scope)
            .filter(|signal| signal.regressed);
        let preferred_model = regression_signal
            .as_ref()
            .and(effective_policy.as_ref())
            .map(|policy| policy.default_model.as_str())
            .filter(|model| !model.is_empty())
            .unwrap_or(&r.preferred_model);
        let (runtime, model) = if let Some(policy) = effective_policy.as_ref() {
            self.policy
                .apply_policy(policy, &r.preferred_runtime, preferred_model)
                .map_err(Status::invalid_argument)?
        } else {
            self.policy
                .resolve(&policy_scope, &r.preferred_runtime, preferred_model)
                .map_err(Status::invalid_argument)?
        };

        let data_class = self.data_class(effective_policy.as_ref());
        let task_class = TaskClass::parse(&r.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        // Resolve the capable-tier model first; this is the baseline the request
        // would get with no cost tiering.
        let capable_model = self
            .resolve_live_model(
                &model,
                effective_policy.as_ref(),
                None,
                safe_only,
                &safe_providers,
            )
            .await
            .map_err(|err| {
                if safe_only {
                    Status::permission_denied(format!(
                        "{}: {err}",
                        crate::chisei::privacy::gate_reason(data_class, task_class, "unsafe")
                    ))
                } else {
                    Status::failed_precondition(err)
                }
            })?;

        // Eval-gated cost tiering: only explicit bulk task classes route to the
        // cheaper tier, and only while no eval regression is active for the
        // scope. Everything else (primary/unknown) stays on the capable tier.
        // A bare "cheap" is rejected by apply_policy, so the cheaper tier is
        // selected via the provider-scoped "{runtime}/cheap" alias, which only
        // resolves for a recognized provider family. Cheap resolution is
        // best-effort: any failure falls back to the capable model.
        //
        // A promoted "capable" revert (chisei::controller) overrides the static heuristic even
        // when it would otherwise say cheap: it's evidence-backed (gated against held eval
        // history, not just the live per-request signal) and stays active until an operator or a
        // later promotion clears it, covering gaps the live regression check alone can't (e.g. a
        // regressed iteration since pruned). Promotions are written under the candidate's raw
        // namespace (from sampled observations), which may differ from `policy_scope` (the first
        // *matching policy* scope - subject/agent/gateway-key rank ahead of namespace); check both
        // so a subject/agent-scoped policy doesn't silently hide the override. Normalize the class
        // the same way promotion/scoring do (trim + lowercase) - the override is keyed by the
        // normalized class, but `cheap_route_bias` below normalizes internally, so an unnormalized
        // lookup here would miss the override for non-canonical casing/whitespace.
        let normalized_task_class = crate::chisei::scoring::normalize_task_class(&r.task_class);
        let capable_override_active = self
            .active_promotions
            .capable_override_active(&policy_scope, &normalized_task_class)
            || self
                .active_promotions
                .capable_override_active(&r.namespace, &normalized_task_class);
        let wants_cheap = !capable_override_active
            && cheap_route_bias(&r.task_class, regression_signal.is_some()) == Some("cheap");
        let cheap_model = if wants_cheap && is_known_provider_runtime(&runtime) {
            self.resolve_live_model(
                &format!("{}/cheap", runtime.trim()),
                effective_policy.as_ref(),
                Some("cheap"),
                safe_only,
                &safe_providers,
            )
            .await
            .ok()
        } else {
            None
        };
        // Record the cheap bias only when it produced an actual demotion to a
        // strictly cheaper cost tier, so the audited route_bias reflects
        // realized cost reductions rather than intent or equal-cost swaps.
        let (model, route_bias) = match cheap_model {
            Some(cheap)
                if crate::chisei::model_routing::named_model_cost_rank(&cheap)
                    < crate::chisei::model_routing::named_model_cost_rank(&capable_model) =>
            {
                (cheap, Some("cheap"))
            }
            _ => (capable_model, None),
        };

        let provider = crate::llm::provider_name(&model);
        if safe_only && !crate::chisei::privacy::provider_safe_to_send(provider, &safe_providers) {
            return Err(Status::permission_denied(
                crate::chisei::privacy::gate_reason(data_class, task_class, provider),
            ));
        }

        Ok(Response::new(ResolvePolicyResponse {
            resolution: Some(PolicyResolution {
                runtime,
                model,
                eval_regressed: regression_signal.is_some(),
                eval_regression_reason: regression_signal
                    .map(|signal| signal.reason)
                    .unwrap_or_default(),
                data_class: data_class.as_str().into(),
                route_bias: route_bias.unwrap_or_default().to_string(),
            }),
        }))
    }

    async fn check_egress(
        &self,
        req: Request<CheckEgressRequest>,
    ) -> Result<Response<CheckEgressResponse>, Status> {
        let r = req.into_inner();
        let data_class = self.data_class(self.policy.effective_policy(&r.namespace).as_ref());
        let provider_is_external = crate::chisei::egress::is_external_provider(&r.provider);
        let task_class = TaskClass::parse(&r.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let mut findings = Vec::new();
        if !crate::chisei::privacy::external_allowed(data_class, task_class)
            && !crate::chisei::privacy::provider_safe_to_send(&r.provider, &safe_providers)
        {
            findings.push(EgressDecision {
                provider: r.provider.clone(),
                external: provider_is_external,
                included: vec![],
                redacted: vec![],
                reasons: vec![crate::chisei::privacy::gate_reason(
                    data_class,
                    task_class,
                    &r.provider,
                )],
            });
            return Ok(Response::new(CheckEgressResponse {
                allowed: false,
                findings,
            }));
        }
        let findings =
            self.leak_findings_for_payload(&r.namespace, &r.provider, data_class, &r.payload);
        let allowed = !findings
            .iter()
            .any(|finding| finding.action == LeakAction::Block);
        Ok(Response::new(CheckEgressResponse {
            allowed,
            findings: leak_findings_to_decisions(&r.provider, provider_is_external, &findings),
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
            template_only: TaskClass::parse(&r.task_class) == TaskClass::TemplateOnly,
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

    async fn record_sample_observation(
        &self,
        req: Request<RecordSampleObservationRequest>,
    ) -> Result<Response<RecordSampleObservationResponse>, Status> {
        let observation = req
            .into_inner()
            .observation
            .ok_or(Status::invalid_argument("observation required"))?;
        if observation.request_id.trim().is_empty() {
            return Err(Status::invalid_argument("request_id required"));
        }
        if observation.namespace.trim().is_empty() {
            return Err(Status::invalid_argument("namespace required"));
        }
        if observation.spec.trim().is_empty() {
            return Err(Status::invalid_argument("spec required"));
        }
        if observation.output_content.trim().is_empty() {
            return Err(Status::invalid_argument("output_content required"));
        }
        if !self.config.scoring_enabled {
            return Ok(Response::new(RecordSampleObservationResponse {
                recorded: false,
            }));
        }
        self.db
            .put_sample_observation(&crate::chisei::scoring::SampleObservation {
                request_id: observation.request_id,
                namespace: observation.namespace,
                spec: observation.spec,
                resolved_model: observation.resolved_model,
                output_content: observation.output_content,
                sample_reason: observation.sample_reason,
                input_tokens: observation.input_tokens,
                output_tokens: observation.output_tokens,
                stop_reason: observation.stop_reason,
                timestamp: observation.timestamp,
                scored: false,
                task_class: crate::chisei::scoring::normalize_task_class(&observation.task_class),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(RecordSampleObservationResponse {
            recorded: true,
        }))
    }

    async fn record_gateway_audit(
        &self,
        req: Request<RecordGatewayAuditRequest>,
    ) -> Result<Response<RecordGatewayAuditResponse>, Status> {
        let mut event = req
            .into_inner()
            .event
            .ok_or(Status::invalid_argument("event required"))?;
        if event.actor.trim().is_empty() {
            return Err(Status::invalid_argument("actor required"));
        }
        if event.action.trim().is_empty() {
            return Err(Status::invalid_argument("action required"));
        }
        if event.outcome.trim().is_empty() {
            return Err(Status::invalid_argument("outcome required"));
        }
        if event.id.trim().is_empty() {
            event.id = uuid::Uuid::new_v4().to_string();
        }
        if event.timestamp <= 0 {
            event.timestamp = chrono::Utc::now().timestamp_millis();
        }
        if event.target_id.trim().is_empty() {
            event.target_id = "llm_calls".to_string();
        }
        self.db
            .record_decision(&crate::sekai::audit::Decision {
                id: event.id.clone(),
                timestamp: event.timestamp,
                actor: event.actor.clone(),
                action: event.action.clone(),
                reason: event.reason.clone(),
                evidence: event.evidence.clone(),
                target_id: event.target_id.clone(),
                outcome: event.outcome.clone(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(RecordGatewayAuditResponse {
            event: Some(event),
        }))
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
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let data_class = self.data_class(effective_policy.as_ref());
        let task_class = TaskClass::parse(&plan.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        if safe_only && !crate::chisei::privacy::provider_safe_to_send(&provider, &safe_providers) {
            self.record_privacy_audit(
                "blocked",
                &input.request_id,
                &provider,
                data_class,
                task_class,
                "cached_plan_unsafe_provider",
            );
            return Err(Status::failed_precondition(
                crate::chisei::privacy::gate_reason(data_class, task_class, &provider),
            ));
        }
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
        let payload =
            payload_for_leak_check(&plan.prepared_system, &plan.prepared_messages, &plan.tools);
        let leak_findings =
            self.leak_findings_for_payload(&input.namespace, &provider, data_class, &payload);
        if leak_findings
            .iter()
            .any(|finding| finding.action == LeakAction::Block)
        {
            self.record_leak_audit(
                "execute_leak_check",
                &input.request_id,
                &provider,
                &leak_findings,
            );
            return Err(Status::failed_precondition(
                "privacy leak checker blocked outbound payload",
            ));
        }
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
                            // NOTE: `plan.task_class` holds the *privacy* class ("private"/
                            // "template_only" — see `plan_from_input`), not the routing/cost-tier
                            // class; the raw caller-supplied routing class lives on `input`.
                            task_class: crate::chisei::scoring::normalize_task_class(
                                &input.task_class,
                            ),
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

    async fn execute_plan_stream(
        &self,
        req: Request<ExecutePlanRequest>,
    ) -> Result<Response<Self::ExecutePlanStreamStream>, Status> {
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
        let chat_stream =
            execute_chat_request_stream(&self.config, self.budget.clone(), llm_req).await?;
        let db = self.db.clone();
        let evolve_history = self.evolve_history.clone();
        let request_id = input.request_id.clone();
        let enriched_spec = plan.enriched_spec.clone();
        let original_spec =
            self.tracked_original_spec(&input.request_id, &input.spec, &plan.enriched_spec);
        let resolved_model = plan.resolved_model.clone();
        let sampled = plan.sampled;
        let sample_rate = plan.sample_rate;
        let sample_reason = plan.sample_reason.clone();
        let scoring_enabled = self.config.scoring_enabled;
        // `plan.task_class` holds the *privacy* class here (see `plan_from_input`); the routing/
        // cost-tier class the caller supplied is on the original `input`.
        let task_class = crate::chisei::scoring::normalize_task_class(&input.task_class);

        let stream = async_stream::stream! {
            let mut content = String::new();
            let mut tool_calls = Vec::new();
            let mut input_tokens = 0;
            let mut output_tokens = 0;
            let mut stop_reason = String::new();
            let mut finished = false;

            futures_util::pin_mut!(chat_stream);
            while let Some(next) = chat_stream.next().await {
                let chunk = match next {
                    Ok(chunk) => chunk,
                    Err(err) => {
                        yield Err(err);
                        return;
                    }
                };
                if !chunk.content.is_empty() {
                    content = chunk.content.clone();
                } else if !chunk.content_delta.is_empty() {
                    content.push_str(&chunk.content_delta);
                }
                if !chunk.tool_calls.is_empty() {
                    tool_calls = chunk.tool_calls.clone();
                }
                if chunk.input_tokens > 0 {
                    input_tokens = chunk.input_tokens;
                }
                if chunk.output_tokens > 0 {
                    output_tokens = chunk.output_tokens;
                }
                if !chunk.stop_reason.is_empty() {
                    stop_reason = chunk.stop_reason.clone();
                }
                if chunk.done && !finished {
                    finished = true;
                    let response = PlannedChatResponse {
                        content: content.clone(),
                        tool_calls: tool_calls
                            .iter()
                            .map(|tc| ToolCall {
                                id: tc.id.clone(),
                                name: tc.name.clone(),
                                args_json: tc.args_json.clone(),
                            })
                            .collect(),
                        input_tokens,
                        output_tokens,
                        stop_reason: stop_reason.clone(),
                        provider: provider.clone(),
                    };
                    let execution = FinishStreamedExecution {
                        db: &db,
                        evolve_history: &evolve_history,
                        request_id: &request_id,
                        namespace: &namespace_hint,
                        enriched_spec: &enriched_spec,
                        original_spec: original_spec.as_deref(),
                        resolved_model: &resolved_model,
                        sampled,
                        sample_rate,
                        sample_reason: &sample_reason,
                        scoring_enabled,
                        task_class: &task_class,
                        response: &response,
                    };
                    let _ = finish_streamed_execution(&execution);
                    yield Ok(ExecutePlanStreamEvent {
                        content_delta: chunk.content_delta,
                        response: Some(response),
                        done: true,
                        executed_at: chrono::Utc::now().timestamp(),
                    });
                } else {
                    yield Ok(ExecutePlanStreamEvent {
                        content_delta: chunk.content_delta,
                        response: None,
                        done: false,
                        executed_at: 0,
                    });
                }
            }
            if !finished {
                let response = PlannedChatResponse {
                    content,
                    tool_calls: tool_calls
                        .into_iter()
                        .map(|tc| ToolCall {
                            id: tc.id,
                            name: tc.name,
                            args_json: tc.args_json,
                        })
                        .collect(),
                    input_tokens,
                    output_tokens,
                    stop_reason,
                    provider,
                };
                let execution = FinishStreamedExecution {
                    db: &db,
                    evolve_history: &evolve_history,
                    request_id: &request_id,
                    namespace: &namespace_hint,
                    enriched_spec: &enriched_spec,
                    original_spec: original_spec.as_deref(),
                    resolved_model: &resolved_model,
                    sampled,
                    sample_rate,
                    sample_reason: &sample_reason,
                    scoring_enabled,
                    task_class: &task_class,
                    response: &response,
                };
                let _ = finish_streamed_execution(&execution);
                yield Ok(ExecutePlanStreamEvent {
                    content_delta: String::new(),
                    response: Some(response),
                    done: true,
                    executed_at: chrono::Utc::now().timestamp(),
                });
            }
        };
        Ok(Response::new(Box::pin(stream)))
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

    #[test]
    fn cheap_route_bias_only_for_bulk_classes_and_not_when_regressed() {
        // Explicit bulk classes route to the cheaper tier.
        for class in [
            "background",
            "bulk",
            "batch",
            "small_fast",
            "small-fast",
            "Background",
        ] {
            assert_eq!(cheap_route_bias(class, false), Some("cheap"), "{class}");
        }
        // Primary/unknown/empty never route cheap (fail safe to capable).
        for class in ["primary", "reasoning", "", "unknown"] {
            assert_eq!(cheap_route_bias(class, false), None, "{class}");
        }
        // An active eval regression reverts every class to the capable tier.
        assert_eq!(cheap_route_bias("background", true), None);
        assert_eq!(cheap_route_bias("bulk", true), None);
    }

    #[test]
    fn budget_metric_accepts_tokens_and_requests_case_insensitive() {
        assert_eq!(budget_metric("").unwrap(), METRIC_TOKENS);
        assert_eq!(budget_metric("tokens").unwrap(), METRIC_TOKENS);
        assert_eq!(budget_metric("Tokens").unwrap(), METRIC_TOKENS);
        assert_eq!(budget_metric("requests").unwrap(), METRIC_REQUESTS);
        assert_eq!(budget_metric("REQUESTS").unwrap(), METRIC_REQUESTS);
    }

    #[test]
    fn budget_metric_rejects_unknown_values() {
        let err = budget_metric("characters").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message()
                .contains("unsupported budget metric; use tokens or requests")
        );
    }

    #[tokio::test]
    async fn resolve_policy_routes_bulk_task_class_to_cheaper_model() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        // Treat openai as available without a key so routing can resolve.
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            },
        );

        // Primary work stays on the capable default model, no bias.
        let mut primary = resolve_policy_request("proj", "openai", "gpt-5.5");
        primary.task_class = "primary".into();
        let resolution = svc
            .resolve_policy(Request::new(primary))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolution.model, "gpt-5.5");
        assert_eq!(resolution.route_bias, "");

        // Bulk/background work routes to the cheaper allowed model and records
        // the cheap bias.
        let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
        background.task_class = "background".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolution.model, "gpt-5.5-mini");
        assert_eq!(resolution.route_bias, "cheap");
        assert_eq!(resolution.runtime, "openai");
    }

    #[tokio::test]
    async fn resolve_policy_respects_a_promoted_capable_override() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            },
        );

        // Promote a "capable" revert for (proj, background) directly through the service's own
        // candidate store/active-promotions registry, exactly as a promotion controller would.
        let candidate = crate::chisei::promotion::Candidate {
            id: "candidate-1".into(),
            kind: crate::chisei::promotion::KIND_ROUTING_BIAS.to_string(),
            namespace: "proj".into(),
            task_class: "background".into(),
            payload: serde_json::to_string(&crate::chisei::promotion::RoutingBiasPayload {
                bias: "capable".into(),
            })
            .unwrap(),
            rationale: "test".into(),
            status: crate::chisei::promotion::STATUS_GATE_PASSED.to_string(),
            source_ref: "test".into(),
            created: 1,
        };
        svc.candidate_store().upsert(candidate.clone());
        crate::chisei::controller::promote_candidate(
            &svc.candidate_store(),
            &svc.active_promotions(),
            &svc.db,
            &candidate.id,
        )
        .expect("gate_passed candidate should promote");

        // Without the override, background would route to the cheaper model (as the sibling test
        // above confirms); the active "capable" promotion must force the capable model instead.
        // Non-canonical casing/whitespace on the request's task_class must still hit the
        // (normalized) override - `cheap_route_bias` normalizes internally, so an unnormalized
        // lookup here would otherwise miss the override and route cheap right past it.
        let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
        background.task_class = " Background ".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolution.model, "gpt-5.5");
        assert_eq!(resolution.route_bias, "");
    }

    #[tokio::test]
    async fn resolve_policy_records_no_bias_when_no_cheaper_model_exists() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        // Only one allowed model, so the cheap tier resolves to the same model.
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            },
        );
        let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
        background.task_class = "background".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        // No actual demotion happened, so no cheap bias is recorded.
        assert_eq!(resolution.model, "gpt-5.5");
        assert_eq!(resolution.route_bias, "");
    }

    #[tokio::test]
    async fn resolve_policy_records_no_bias_for_equal_cost_models() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        // Both allowed models are the same cost tier ("mini"), so the cheap
        // alias finds nothing strictly cheaper than the capable default.
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5-mini".into(), "gpt-4.1-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5-mini".into(),
                data_class: String::new(),
            },
        );
        let mut background = resolve_policy_request("proj", "openai", "gpt-5.5-mini");
        background.task_class = "background".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        // Capable default is kept; no equal-cost swap is recorded as a demotion.
        assert_eq!(resolution.model, "gpt-5.5-mini");
        assert_eq!(resolution.route_bias, "");
    }

    #[tokio::test]
    async fn resolve_policy_skips_cheap_routing_for_native_runtime() {
        // native/ollama runtimes are excluded from automatic cheap tiering
        // (their cost tiers are not name-rankable), so a bulk task class stays
        // on the capable tier with no bias even without an eval regression.
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["native".into()],
                allowed_models: vec!["native-default".into(), "native-cheap".into()],
                default_runtime: "native".into(),
                default_model: "native-default".into(),
                data_class: String::new(),
            },
        );
        let mut background = resolve_policy_request("proj", "native", "native-default");
        background.task_class = "background".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolution.model, "native-default");
        assert_eq!(resolution.route_bias, "");
    }

    fn config(db_path: &str) -> Config {
        Config {
            grpc_port: 0,
            sekai_bind: None,
            ops_port: None,
            ops_bind: "127.0.0.1".into(),
            sekai_socket: None,
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
            default_data_class: "unclassified".into(),
            safe_egress_providers: vec![],
            gateway_provided_providers: vec![],
            leak_review_model: None,
            tls_cert: None,
            tls_key: None,
            allow_plaintext: false,
            insecure: false,
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

    fn resolve_policy_request(
        namespace: &str,
        preferred_runtime: &str,
        preferred_model: &str,
    ) -> ResolvePolicyRequest {
        ResolvePolicyRequest {
            namespace: namespace.into(),
            preferred_runtime: preferred_runtime.into(),
            preferred_model: preferred_model.into(),
            subject: String::new(),
            project: String::new(),
            agent: String::new(),
            key_id: String::new(),
            task_class: String::new(),
            user_id: String::new(),
        }
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
    async fn budget_rpcs_accept_gateway_subject_metadata() {
        let svc = memory_service();
        svc.set_budget_limit(Request::new(SetBudgetLimitRequest {
            user_id: String::new(),
            max_tokens: 10,
            period_type: "day".into(),
            subject: String::new(),
            project: "sekai-chisei".into(),
            agent: "codex-app".into(),
            key_id: "codex-app".into(),
            work_unit: String::new(),
            metric: String::new(),
        }))
        .await
        .unwrap();

        let allowed = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 5,
                subject: String::new(),
                project: "sekai-chisei".into(),
                agent: "codex-app".into(),
                key_id: "codex-app".into(),
                work_unit: String::new(),
                metric: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(allowed.allowed);
        assert_eq!(
            allowed.usage.unwrap().user_id,
            "project:sekai-chisei/agent:codex-app"
        );

        svc.record_usage(Request::new(RecordUsageRequest {
            user_id: String::new(),
            tokens_used: 8,
            subject: String::new(),
            project: "sekai-chisei".into(),
            agent: "codex-app".into(),
            key_id: "codex-app".into(),
            work_unit: String::new(),
            metric: String::new(),
        }))
        .await
        .unwrap();

        let denied = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 3,
                subject: String::new(),
                project: "sekai-chisei".into(),
                agent: "codex-app".into(),
                key_id: "codex-app".into(),
                work_unit: String::new(),
                metric: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!denied.allowed);
    }

    #[tokio::test]
    async fn record_gateway_audit_writes_decision_log() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let svc = ChiseiServiceImpl::new(db.clone(), config(":memory:"));
        let response = svc
            .record_gateway_audit(Request::new(RecordGatewayAuditRequest {
                event: Some(GatewayAuditEvent {
                    id: String::new(),
                    timestamp: 0,
                    actor: "codex-app".into(),
                    action: "gateway.model_rewrite".into(),
                    reason: "policy resolved a different model".into(),
                    evidence: HashMap::from([("request_id".into(), "req-1".into())]),
                    target_id: String::new(),
                    outcome: "routed".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .event
            .unwrap();

        assert!(!response.id.is_empty());
        assert!(response.timestamp > 0);
        assert_eq!(response.target_id, "llm_calls");
        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.model_rewrite".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "codex-app");
        assert_eq!(
            decisions[0].evidence.get("request_id").map(String::as_str),
            Some("req-1")
        );
    }

    #[tokio::test]
    async fn set_namespace_policy_applies_to_resolve_policy() {
        let svc = memory_service();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "openai".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();

        let resolved = svc
            .resolve_policy(Request::new(resolve_policy_request(
                "sekai-chisei",
                "openai",
                "gpt-5.5",
            )))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolved.runtime, "openai");
        assert_eq!(resolved.model, "native-default");
    }

    #[tokio::test]
    async fn resolve_policy_prefers_agent_context_over_project_policy() {
        let svc = memory_service();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-mini".into()],
            default_runtime: "native".into(),
            default_model: "native-mini".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "agent:codex-app".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();

        let mut request = resolve_policy_request("sekai-chisei", "native", "native-mini");
        request.project = "sekai-chisei".into();
        request.agent = "codex-app".into();
        let resolved = svc
            .resolve_policy(Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolved.runtime, "native");
        assert_eq!(resolved.model, "native-default");
    }

    #[tokio::test]
    async fn resolve_policy_biases_to_default_model_when_namespace_regressed() {
        let svc = memory_service();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into(), "native-cheap".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();
        create_suite(&svc, "sekai-chisei").await;
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "sekai-chisei".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "sekai-chisei".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        let resolved = svc
            .resolve_policy(Request::new(resolve_policy_request(
                "sekai-chisei",
                "native",
                "native-cheap",
            )))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolved.runtime, "native");
        assert_eq!(resolved.model, "native-default");
        assert!(resolved.eval_regressed);
        assert!(resolved.eval_regression_reason.contains("sekai-chisei"));
    }

    #[tokio::test]
    async fn resolve_policy_reverts_bulk_class_to_capable_when_namespace_regressed() {
        let svc = memory_service();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into(), "native-cheap".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();
        create_suite(&svc, "sekai-chisei").await;
        // Two runs with a score drop mark the namespace as regressed.
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "sekai-chisei".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "sekai-chisei".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        // A bulk task class would normally route cheap, but the active
        // regression forces it back to the capable default tier with no bias.
        let mut background = resolve_policy_request("sekai-chisei", "native", "native-cheap");
        background.task_class = "background".into();
        let resolved = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolved.model, "native-default");
        assert_eq!(resolved.route_bias, "");
        assert!(resolved.eval_regressed);
    }

    #[tokio::test]
    async fn namespace_policy_reloads_from_sekai_object_store() {
        let path = std::env::temp_dir()
            .join(format!("sekai-policy-{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let svc = file_service(&path);
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "openai".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();
        drop(svc);

        let reloaded = file_service(&path);
        let resolved = reloaded
            .resolve_policy(Request::new(resolve_policy_request(
                "sekai-chisei",
                "openai",
                "gpt-5.5",
            )))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolved.runtime, "openai");
        assert_eq!(resolved.model, "native-default");
        let _ = fs::remove_file(path);
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
                    task_class: String::new(),
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
                    task_class: String::new(),
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
                    task_class: String::new(),
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
                    task_class: String::new(),
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

    #[test]
    fn namespace_policy_reloads_data_class_from_sekai_object_store() {
        let path = format!(
            "{}/sekai-chisei-policy-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        {
            let db = SekaiDb::new(&path).unwrap();
            db.create_object(&Object {
                id: "policy-alpha".into(),
                kind: "policy".into(),
                name: "alpha".into(),
                namespace: String::new(),
                external_id: "policy:alpha".into(),
                properties: std::collections::HashMap::from([
                    (
                        "allowed_models".into(),
                        "native-default,ollama/capable".into(),
                    ),
                    ("default_runtime".into(), "kiro".into()),
                    ("default_model".into(), "native-default".into()),
                    ("data_class".into(), "sensitive".into()),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();
        }

        let svc = file_service(&path);
        let policy = svc
            .policy
            .effective_policy("alpha")
            .expect("policy should load from object store");
        assert_eq!(policy.data_class, "sensitive");
        assert_eq!(
            policy.allowed_models,
            vec!["native-default", "ollama/capable"]
        );

        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn set_namespace_policy_persists_data_class() {
        let path = format!(
            "{}/sekai-chisei-policy-rpc-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let svc = file_service(&path);
        let response = svc
            .set_namespace_policy(Request::new(SetNamespacePolicyRequest {
                namespace: "alpha".into(),
                allowed_runtimes: vec!["kiro".into()],
                allowed_models: vec!["native-default".into()],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.resolution.unwrap().data_class, "sensitive");
        drop(svc);

        let reloaded = file_service(&path);
        let policy = reloaded
            .policy
            .effective_policy("alpha")
            .expect("policy should reload");
        assert_eq!(policy.data_class, "sensitive");
        assert_eq!(policy.default_model, "native-default");

        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn sensitive_private_rejects_unsafe_provider() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );

        let err = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-sensitive-private".into(),
                    namespace: "alpha".into(),
                    spec: "analyze private holdings".into(),
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
                    task_class: String::new(),
                }),
            }))
            .await
            .expect_err("unsafe provider should be rejected for sensitive private work");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("not safe"));
    }

    #[tokio::test]
    async fn resolve_policy_denies_sensitive_private_unsafe_provider() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );

        let err = svc
            .resolve_policy(Request::new(ResolvePolicyRequest {
                namespace: "alpha".into(),
                preferred_runtime: "kiro".into(),
                preferred_model: "native-default".into(),
                subject: String::new(),
                project: String::new(),
                agent: String::new(),
                key_id: String::new(),
                task_class: String::new(),
                user_id: String::new(),
            }))
            .await
            .expect_err("sensitive private preflight should deny unsafe provider");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn sensitive_template_only_skips_context_enrichment() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );
        svc.db
            .create_object(&Object {
                id: "asset-secret".into(),
                kind: "asset".into(),
                name: "SecretCo".into(),
                namespace: "alpha".into(),
                external_id: "asset:SECRET".into(),
                properties: std::collections::HashMap::from([(
                    "verdict".into(),
                    "approved".into(),
                )]),
                created: 0,
                updated: 0,
            })
            .unwrap();

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-template".into(),
                    namespace: "alpha".into(),
                    spec: "write a generic evaluation rubric".into(),
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
                    task_class: "template_only".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        assert_eq!(plan.task_class, "template_only");
        assert!(plan.executable);
        assert!(
            plan.steps
                .iter()
                .any(|step| { step.step == "object_context_enrich" && step.action == "skipped" })
        );
        assert!(!plan.enriched_spec.contains("SecretCo"));
        assert!(!plan.enriched_spec.contains("approved"));
    }

    #[tokio::test]
    async fn template_only_plan_blocks_known_entity_leak() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );
        svc.db
            .create_object(&Object {
                id: "asset-secret".into(),
                kind: "asset".into(),
                name: "SecretCo".into(),
                namespace: "alpha".into(),
                external_id: "asset:SECRET".into(),
                properties: std::collections::HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        svc.db
            .create_object(&Object {
                id: "leak-rule-secretco".into(),
                kind: "leak_rule".into(),
                name: "company-name".into(),
                namespace: "alpha".into(),
                external_id: "leak_rule:secretco".into(),
                properties: std::collections::HashMap::from([
                    ("pattern".into(), "SecretCo".into()),
                    ("label".into(), "company_name".into()),
                    ("action".into(), "block".into()),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-leak".into(),
                    namespace: "alpha".into(),
                    spec: "write a generic rubric for SecretCo".into(),
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
                    task_class: "template_only".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        assert!(!plan.executable);
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("leak checker blocked"))
        );
        assert!(plan.egress_decisions.iter().any(|decision| {
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("known_entity:SecretCo"))
        }));
        assert!(plan.egress_decisions.iter().any(|decision| {
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("company_name"))
        }));
        let decisions = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                actor: Some("chisei.privacy".into()),
                action: Some("leak_check".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(decisions.iter().any(|decision| {
            decision.target_id == "task-leak"
                && decision.outcome == "leak_blocked"
                && decision
                    .evidence
                    .get("labels")
                    .is_some_and(|labels| labels.contains("company_name"))
        }));
    }

    #[tokio::test]
    async fn check_egress_denies_sensitive_private_unsafe_provider() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );

        let response = svc
            .check_egress(Request::new(CheckEgressRequest {
                namespace: "alpha".into(),
                payload: "generic payload".into(),
                provider: "native".into(),
                task_class: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(!response.allowed);
        assert!(response.findings.iter().any(|decision| {
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("privacy gate"))
        }));
    }

    #[tokio::test]
    async fn execute_plan_rejects_after_policy_flips_sensitive() {
        let svc = memory_service();
        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-stale-policy".into(),
                    namespace: "alpha".into(),
                    spec: "do ordinary work".into(),
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
                    task_class: String::new(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert!(plan.executable);

        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );

        let err = svc
            .execute_plan(Request::new(ExecutePlanRequest { plan: Some(plan) }))
            .await
            .expect_err("stale external plan should be blocked after policy flip");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("privacy gate"));
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
                task_class: String::new(),
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
            task_class: String::new(),
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
    async fn execute_plan_stream_rejects_external_plan_without_egress_decisions() {
        let svc = memory_service();
        let plan = ExecutionPlan {
            plan_id: "stream-external-plan".into(),
            input: Some(ExecutionInput {
                request_id: "stream-external-plan".into(),
                namespace: "sekai-chisei".into(),
                spec: "do work".into(),
                preferred_model: "gpt-5.5".into(),
                preferred_runtime: "openai".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                task_class: String::new(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
            }),
            resolved_runtime: "openai".into(),
            resolved_model: "gpt-5.5".into(),
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
            task_class: String::new(),
        };
        svc.cache_plan(plan.clone());

        let result = svc
            .execute_plan_stream(Request::new(ExecutePlanRequest { plan: Some(plan) }))
            .await;
        let err = result
            .err()
            .expect("external stream plan without egress decisions should be rejected");
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
            .conn()
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
                    task_class: String::new(),
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
                task_class: String::new(),
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
            task_class: String::new(),
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
            task_class: String::new(),
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
                task_class: String::new(),
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
            task_class: String::new(),
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
