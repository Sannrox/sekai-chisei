use base64::Engine as _;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use prost::Message as _;
use sha2::Digest;
use tonic::{Request, Response, Status};

use super::pb::chisei::chisei_service_server::ChiseiService;
use super::pb::chisei::*;
use super::provider_execution::{
    ProviderExecutionRequest, estimate_chat_request, execute_native_chat_request_stream,
};
use crate::chisei::budget::BudgetTracker;
use crate::chisei::controller::ActivePromotions;
use crate::chisei::epistemic_descriptor::EPISTEMIC_DESCRIPTOR_VERSION;
use crate::chisei::eval::EvalStore;
use crate::chisei::evaluation_execution as evaluation_execution_domain;
use crate::chisei::evaluation_manifest as evaluation_manifest_domain;
use crate::chisei::evaluation_plan as evaluation_plan_domain;
use crate::chisei::external_action as external;
use crate::chisei::external_action_lifecycle as external_lifecycle;
use crate::chisei::external_permit as permit;
use crate::chisei::governed_subject as subject;
use crate::chisei::governed_subject_provenance as subject_provenance;
use crate::chisei::lookup_first;
use crate::chisei::pipeline as pipe;
use crate::chisei::policy::{Policy, PolicyResolver};
use crate::chisei::portfolio::{Objective, PortfolioStore, TaskDemand as PortfolioDemand};
use crate::chisei::privacy::{DataClass, LeakAction, LeakFinding, LeakRule, TaskClass};
use crate::chisei::promotion::CandidateStore;
use crate::chisei::receipt::{
    GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    ReceiptEventKind, ReceiptSurface, UncoveredSurface,
};
use crate::config::Config;
use crate::db::chisei_budget::{METRIC_REQUESTS, METRIC_TOKENS};
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain::{ListFilter, Object};
#[cfg(test)]
use crate::sekai::action_policy::ActionDecision;
use crate::sekai::governed_facts::{self as governed_fact_domain, GovernedFactType};
use crate::sekai::markings;

mod budget_identity;
mod content_execution;
mod context_expansion;
mod evaluation_execution_lifecycle;
mod evaluation_manifest_resolution;
mod execution_planning;
mod external_action_admission;
mod gateway_decide_lifecycle;
mod gateway_receipt_admission;
mod governed_subject_lifecycle;
mod gunshi_issuance_lifecycle;
mod kioku_candidate_governance;
mod live_model;
mod native_execution_lifecycle;
mod policy_resolution;
mod privacy_egress;
mod reported_operation_event_lifecycle;
#[path = "chisei_service_support_auth.rs"]
mod support_auth;
use support_auth::*;
#[path = "chisei_service_support_policy.rs"]
mod support_policy;
use support_policy::*;
#[path = "chisei_service_rpc_control.rs"]
mod rpc_control;
#[path = "chisei_service_rpc_execution.rs"]
mod rpc_execution;

#[cfg(test)]
use crate::chisei::policy::ContextAdmissionAction;
#[cfg(test)]
use context_expansion::{
    evidence_context_config_ref, evidence_context_profile_key,
    pipeline_context_expansion_profile_key,
};
#[cfg(test)]
use live_model::final_runtime_for_model;
#[cfg(test)]
use native_execution_lifecycle::{
    ExecuteLookupFirst, evaluate_execute_lookup_first, native_execution_cost,
};
#[cfg(test)]
use policy_resolution::{
    ResolvePolicyRequest, cheap_route_bias, local_free_runtime_for_model,
    portfolio_runtime_for_model,
};

use budget_identity::{budget_metric, budget_subject};

pub struct ChiseiServiceImpl {
    pub(super) budget: Arc<BudgetTracker>,
    pub(super) policy: Arc<PolicyResolver>,
    pub(super) pipeline: pipe::Pipeline,
    pub(super) eval: Arc<EvalStore>,
    pub(super) portfolio: Arc<PortfolioStore>,
    pub(super) planned_executions: Arc<Mutex<HashMap<String, CachedExecutionPlan>>>,
    pub(super) planned_content_executions: Arc<Mutex<HashMap<String, CachedContentExecutionPlan>>>,
    pub(super) evolve_history: Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    pub(super) candidates: Arc<CandidateStore>,
    pub(super) active_promotions: Arc<ActivePromotions>,
    pub(super) evaluation_execution_lifecycle:
        evaluation_execution_lifecycle::EvaluationExecutionLifecycle,
    pub(super) db: crate::db::store::ChiseiStore,
    pub(super) config: Config,
    pub(super) provider_registry_state_path: Option<PathBuf>,
    pub(super) sekai_commit_lookup:
        Option<Arc<dyn crate::chisei::cross_store_admission::SekaiCommitLookup>>,
}

#[derive(Clone)]
pub(super) struct CachedExecutionPlan {
    plan: ExecutionPlan,
    enterprise_authority: Option<String>,
}

#[derive(Clone)]
pub(super) struct CachedContentExecutionPlan {
    plan: ContentExecutionPlanV1,
    enterprise_authority: Option<String>,
}

pub(super) struct BoundGunshiAllocation {
    issuance_id: String,
    plan: crate::chisei::gunshi::AllocationPlan,
}

const MAX_CACHED_EXECUTION_PLANS: usize = 128;
const MAX_CACHED_EXECUTION_PLAN_AGE_MS: i64 = 15 * 60 * 1000;
const POLICY_KIND: &str = "policy";
const MIN_EVIDENCE_CONTEXT_EVAL_CASES: usize = 3;
const EXECUTION_SCHEMA_VERSION: &str = "chisei.execution/v1";
const AUTH_SOURCE_HEADER: &str = "x-sekai-auth-source";
const DELEGATED_PRINCIPAL_HEADER: &str = "x-sekai-delegated-principal";
const KIOKU_MIN_SAMPLES_PER_ARM: usize = 3;
const KIOKU_REGRESSION_THRESHOLD: f64 = 0.05;
const KIOKU_TRUSTED_OUTCOME_ATTRIBUTE: &str = "kioku_trusted_outcome";
const CHISEI_EXECUTE_SCOPE: &str = "chisei.execute";
const EVALUATION_GATE_STATUS_FOUND: &str = "found";
const EVALUATION_GATE_STATUS_SUITE_NOT_FOUND: &str = "suite_not_found";
const EVALUATION_GATE_STATUS_NO_MATCHING_RUN: &str = "no_matching_run";
// Tenkai sends its local 60-second gate window; the additional 60 seconds
// allows bounded clock skew between the Tenkai and Chisei hosts.
const EVALUATION_GATE_MAX_FUTURE_SKEW_MS: i64 = 120_000;
const MAX_EVALUATION_GATE_CASES: usize = 4096;
const MAX_EVALUATION_GATE_RESULTS: usize = 4096;

#[derive(Clone, PartialEq, prost::Message)]
struct EvaluationGateSuiteSnapshot {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    description: String,
    #[prost(message, repeated, tag = "4")]
    cases: Vec<EvaluationGateCaseSnapshot>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct EvaluationGateCaseSnapshot {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    namespace: String,
    #[prost(string, tag = "4")]
    spec: String,
    #[prost(message, repeated, tag = "5")]
    assertions: Vec<EvaluationGateAssertionSnapshot>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct EvaluationGateAssertionSnapshot {
    #[prost(string, tag = "1")]
    assert_type: String,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(serde::Serialize)]
struct SampleObservationReadbackDigest<'a> {
    version: &'static str,
    request_id: &'a str,
    namespace: &'a str,
    state: &'a str,
    observed_at: i64,
}

struct GatewayPipelineInput<'a> {
    actor: &'a str,
    delegated_principal: Option<&'a str>,
    request_id: &'a str,
    namespace: &'a str,
    spec: &'a str,
    model: &'a str,
    runtime: &'a str,
    task_class: &'a str,
}

struct GatewayPipelineDecision {
    run: pipe::RunResult,
    sampling: crate::chisei::sampling::SamplingDecision,
}

/// Complete result used by local embedding/test callers of the streaming path.
/// This is intentionally not part of the public gRPC contract.
#[derive(Debug)]
pub struct LocalExecutionResponse {
    pub response: Option<PlannedChatResponse>,
    pub executed_at: i64,
}

impl ChiseiServiceImpl {
    /// Internal test/embedding adapter for the streaming-only execution path.
    /// The public gRPC contract exposes `ExecutePlanStream`; this helper is not
    /// a service method and exists only for local callers that need a complete
    /// response in one future.
    pub async fn execute_plan(
        &self,
        req: Request<ExecutePlanRequest>,
    ) -> Result<Response<LocalExecutionResponse>, Status> {
        let mut stream = <Self as ChiseiService>::execute_plan_stream(self, req)
            .await?
            .into_inner();
        let mut response = None;
        let mut executed_at = 0;
        while let Some(event) = stream.next().await {
            let event = event?;
            executed_at = event.executed_at;
            if event.response.is_some() {
                response = event.response;
            }
        }
        let response =
            response.ok_or_else(|| Status::internal("execution stream omitted response"))?;
        Ok(Response::new(LocalExecutionResponse {
            response: Some(response),
            executed_at,
        }))
    }

    #[cfg(feature = "gateway-test-support")]
    pub fn seed_allow_by_default_context_admission(&self, namespaces: &[&str]) {
        for namespace in namespaces {
            self.policy
                .set_context_admission_policy(
                    namespace,
                    crate::chisei::policy::ContextAdmissionPolicy::allow_by_default(),
                )
                .expect("default context admission policy is valid");
        }
    }

    pub fn new(db: impl Into<crate::db::store::ChiseiStore>, config: Config) -> Self {
        Self::new_with_evaluator_registries(
            db,
            config.clone(),
            Arc::new(
                evaluation_execution_domain::production_evaluator_registry()
                    .expect("compiled production evaluator registry must be valid"),
            ),
            Arc::new(
                crate::chisei::stochastic_evaluation::production_stochastic_evaluator_registry(
                    config,
                )
                .expect("compiled stochastic evaluator registry must be valid"),
            ),
        )
    }

    pub fn new_with_evaluator_registry(
        db: impl Into<crate::db::store::ChiseiStore>,
        config: Config,
        evaluator_registry: Arc<evaluation_execution_domain::DeterministicEvaluatorRegistry>,
    ) -> Self {
        Self::new_with_evaluator_registries(
            db,
            config,
            evaluator_registry,
            Arc::new(evaluation_execution_domain::StochasticEvaluatorRegistry::default()),
        )
    }

    pub fn new_with_evaluator_registries(
        db: impl Into<crate::db::store::ChiseiStore>,
        config: Config,
        evaluator_registry: Arc<evaluation_execution_domain::DeterministicEvaluatorRegistry>,
        stochastic_evaluator_registry: Arc<
            evaluation_execution_domain::StochasticEvaluatorRegistry,
        >,
    ) -> Self {
        let db = db.into();
        let provider_registry_state_path = (config.db_path != ":memory:")
            .then(|| crate::provider_profile::provider_registry_state_path(&config.db_path));
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        let eval = Arc::new(EvalStore::with_db(db.clone()));
        let evolve_history = Arc::new(Mutex::new(
            db.list_evolve_task_records()
                .unwrap_or_default()
                .into_iter()
                .map(|task| (task.id.clone(), task))
                .collect(),
        ));
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        let budget = Arc::new(BudgetTracker::new(db.clone()));
        let evaluation_execution_lifecycle =
            evaluation_execution_lifecycle::EvaluationExecutionLifecycle::new(
                db.clone(),
                budget.clone(),
                evaluator_registry,
                stochastic_evaluator_registry,
                crate::chisei::privacy::safe_providers(&config),
            );
        Self {
            budget,
            policy,
            pipeline: pipe::default_pipeline_with(config.sample_rate, config.sample_risk_threshold),
            eval,
            portfolio: Arc::new(PortfolioStore::new(db.clone())),
            planned_executions: Arc::new(Mutex::new(HashMap::new())),
            planned_content_executions: Arc::new(Mutex::new(HashMap::new())),
            evolve_history,
            candidates: Arc::new(CandidateStore::new()),
            active_promotions: Arc::new(ActivePromotions::new()),
            evaluation_execution_lifecycle,
            db,
            config,
            provider_registry_state_path,
            sekai_commit_lookup: None,
        }
    }

    /// Build a background scoring job sharing this service's DB, eval store, budget,
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
    /// its DB and `EvalStore` (e.g. a periodic promotion-controller driver, or direct
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

    pub fn with_budget(
        db: impl Into<crate::db::store::ChiseiStore>,
        config: Config,
        budget: Arc<BudgetTracker>,
    ) -> Self {
        let db = db.into();
        let provider_registry_state_path = (config.db_path != ":memory:")
            .then(|| crate::provider_profile::provider_registry_state_path(&config.db_path));
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        let eval = Arc::new(EvalStore::with_db(db.clone()));
        let evolve_history = Arc::new(Mutex::new(
            db.list_evolve_task_records()
                .unwrap_or_default()
                .into_iter()
                .map(|task| (task.id.clone(), task))
                .collect(),
        ));
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        let evaluator_registry =
            Arc::new(evaluation_execution_domain::DeterministicEvaluatorRegistry::default());
        let stochastic_evaluator_registry = Arc::new(
            crate::chisei::stochastic_evaluation::production_stochastic_evaluator_registry(
                config.clone(),
            )
            .expect("compiled stochastic evaluator registry must be valid"),
        );
        let evaluation_execution_lifecycle =
            evaluation_execution_lifecycle::EvaluationExecutionLifecycle::new(
                db.clone(),
                budget.clone(),
                evaluator_registry,
                stochastic_evaluator_registry,
                crate::chisei::privacy::safe_providers(&config),
            );
        Self {
            budget,
            policy,
            pipeline: pipe::default_pipeline_with(config.sample_rate, config.sample_risk_threshold),
            eval,
            portfolio: Arc::new(PortfolioStore::new(db.clone())),
            planned_executions: Arc::new(Mutex::new(HashMap::new())),
            planned_content_executions: Arc::new(Mutex::new(HashMap::new())),
            evolve_history,
            candidates: Arc::new(CandidateStore::new()),
            active_promotions: Arc::new(ActivePromotions::new()),
            evaluation_execution_lifecycle,
            db,
            config,
            provider_registry_state_path,
            sekai_commit_lookup: None,
        }
    }

    pub fn with_sekai_commit_lookup(
        mut self,
        lookup: Arc<dyn crate::chisei::cross_store_admission::SekaiCommitLookup>,
    ) -> Self {
        self.sekai_commit_lookup = Some(lookup);
        self
    }

    fn bind_gunshi_allocation(
        &self,
        mut input: ExecutionInput,
        binding: GunshiAllocationBinding,
    ) -> Result<(ExecutionInput, BoundGunshiAllocation), Status> {
        let issuance_id = binding.issuance_id.trim();
        if issuance_id.is_empty()
            || issuance_id.len() > 128
            || issuance_id != binding.issuance_id
            || !issuance_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.:".contains(character))
        {
            return Err(Status::invalid_argument(
                "Gunshi issuance_id must be a canonical identifier of at most 128 characters",
            ));
        }
        if binding.allocation_json.len() > 256 * 1024 {
            return Err(Status::invalid_argument(
                "Gunshi allocation exceeds the size limit",
            ));
        }
        let allocation: crate::chisei::gunshi::AllocationPlan =
            serde_json::from_str(&binding.allocation_json).map_err(|error| {
                Status::invalid_argument(format!("invalid Gunshi allocation: {error}"))
            })?;
        allocation.validate().map_err(Status::invalid_argument)?;
        crate::chisei::gunshi_feedback::require_issued_plan(&self.db, issuance_id, &allocation)
            .map_err(Status::failed_precondition)?;

        if input.namespace.trim() != allocation.namespace {
            return Err(Status::failed_precondition(
                "Gunshi allocation namespace does not match execution input",
            ));
        }
        let current_policy_version = self
            .policy
            .effective_policy(&allocation.namespace)
            .map(|policy| policy.version())
            .unwrap_or_else(|| "implicit-allow/v1".into());
        if allocation.policy_version != current_policy_version {
            return Err(Status::failed_precondition(
                "Gunshi allocation policy version is no longer current",
            ));
        }
        if !input.logical_operation_id.trim().is_empty()
            && input.logical_operation_id.trim() != allocation.operation_id
        {
            return Err(Status::failed_precondition(
                "Gunshi allocation operation does not match execution input",
            ));
        }
        if !input.task_class.trim().is_empty()
            && input.task_class.trim() != allocation.operation_class
        {
            return Err(Status::failed_precondition(
                "Gunshi allocation operation class does not match execution input",
            ));
        }
        let allocation_priority = i32::from(allocation.priority);
        if input.priority != 0 && input.priority != allocation_priority {
            return Err(Status::failed_precondition(
                "Gunshi allocation priority does not match execution input",
            ));
        }
        for (name, requested, allocated) in [
            (
                "preferred runtime",
                input.preferred_runtime.trim(),
                allocation.selection.runtime.as_str(),
            ),
            (
                "preferred model",
                input.preferred_model.trim(),
                allocation.selection.model.as_str(),
            ),
            (
                "route override",
                input.route_override.trim(),
                allocation.selection.model.as_str(),
            ),
        ] {
            if !requested.is_empty() && requested != "auto" && requested != allocated {
                return Err(Status::failed_precondition(format!(
                    "execution {name} conflicts with the Gunshi allocation"
                )));
            }
        }
        let requested_tools = input
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<BTreeSet<_>>();
        let allocated_tools = allocation
            .selection
            .tools
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if requested_tools.len() != input.tools.len() || requested_tools != allocated_tools {
            return Err(Status::failed_precondition(
                "execution tools must exactly match the Gunshi allocation",
            ));
        }

        input.logical_operation_id = allocation.operation_id.clone();
        input.task_class = allocation.operation_class.clone();
        input.priority = allocation_priority;
        input.preferred_runtime = allocation.selection.runtime.clone();
        input.preferred_model = allocation.selection.model.clone();
        input.route_override.clear();
        Ok((
            input,
            BoundGunshiAllocation {
                issuance_id: issuance_id.into(),
                plan: allocation,
            },
        ))
    }

    #[cfg(test)]
    fn cache_plan(&self, plan: ExecutionPlan) {
        self.cache_plan_for_enterprise_authority(plan, None);
    }

    fn cache_plan_for_enterprise_authority(
        &self,
        plan: ExecutionPlan,
        enterprise_authority: Option<String>,
    ) {
        let mut plans = self
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        prune_expired_plans(&mut plans);
        let inserted_plan_id = plan.plan_id.clone();
        plans.insert(
            inserted_plan_id.clone(),
            CachedExecutionPlan {
                plan,
                enterprise_authority,
            },
        );
        prune_excess_plans(&mut plans, Some(&inserted_plan_id));
    }
}

#[tonic::async_trait]
impl ChiseiService for ChiseiServiceImpl {
    type ExecutePlanStreamStream =
        Pin<Box<dyn futures_util::Stream<Item = Result<ExecutePlanStreamEvent, Status>> + Send>>;
    type ExecuteContentPlanStreamStream = Pin<
        Box<dyn futures_util::Stream<Item = Result<ExecuteContentPlanStreamEvent, Status>> + Send>,
    >;

    async fn evaluate_governed_subject(
        &self,
        req: Request<EvaluateGovernedSubjectRequest>,
    ) -> Result<Response<EvaluateGovernedSubjectResponse>, Status> {
        rpc_control::evaluate_governed_subject(self, req).await
    }

    async fn export_governed_subject_provenance(
        &self,
        req: Request<ExportGovernedSubjectProvenanceRequest>,
    ) -> Result<Response<ExportGovernedSubjectProvenanceResponse>, Status> {
        rpc_control::export_governed_subject_provenance(self, req).await
    }

    async fn authorize_external_action(
        &self,
        req: Request<AuthorizeExternalActionRequest>,
    ) -> Result<Response<AuthorizeExternalActionResponse>, Status> {
        rpc_control::authorize_external_action(self, req).await
    }

    async fn transition_external_action(
        &self,
        req: Request<TransitionExternalActionRequest>,
    ) -> Result<Response<TransitionExternalActionResponse>, Status> {
        rpc_control::transition_external_action(self, req).await
    }

    async fn redeem_external_action_permit(
        &self,
        req: Request<RedeemExternalActionPermitRequest>,
    ) -> Result<Response<RedeemExternalActionPermitResponse>, Status> {
        rpc_control::redeem_external_action_permit(self, req).await
    }

    async fn set_external_action_policy(
        &self,
        req: Request<SetExternalActionPolicyRequest>,
    ) -> Result<Response<SetExternalActionPolicyResponse>, Status> {
        rpc_control::set_external_action_policy(self, req).await
    }

    async fn decide_gateway_execution(
        &self,
        req: Request<DecideGatewayExecutionRequest>,
    ) -> Result<Response<DecideGatewayExecutionResponse>, Status> {
        rpc_control::decide_gateway_execution(self, req).await
    }

    async fn record_usage(
        &self,
        req: Request<RecordUsageRequest>,
    ) -> Result<Response<RecordUsageResponse>, Status> {
        rpc_control::record_usage(self, req).await
    }

    async fn set_budget_limit(
        &self,
        req: Request<SetBudgetLimitRequest>,
    ) -> Result<Response<SetBudgetLimitResponse>, Status> {
        rpc_control::set_budget_limit(self, req).await
    }

    async fn set_namespace_policy(
        &self,
        req: Request<SetNamespacePolicyRequest>,
    ) -> Result<Response<SetNamespacePolicyResponse>, Status> {
        rpc_control::set_namespace_policy(self, req).await
    }

    async fn get_effective_policy_summary(
        &self,
        req: Request<GetEffectivePolicySummaryRequest>,
    ) -> Result<Response<GetEffectivePolicySummaryResponse>, Status> {
        rpc_control::get_effective_policy_summary(self, req).await
    }

    async fn plan_execution(
        &self,
        req: Request<PlanExecutionRequest>,
    ) -> Result<Response<PlanExecutionResponse>, Status> {
        rpc_execution::plan_execution(self, req).await
    }

    async fn execute_plan_stream(
        &self,
        req: Request<ExecutePlanRequest>,
    ) -> Result<Response<Self::ExecutePlanStreamStream>, Status> {
        rpc_execution::execute_plan_stream(self, req).await
    }

    async fn plan_content_execution(
        &self,
        req: Request<PlanContentExecutionRequest>,
    ) -> Result<Response<PlanContentExecutionResponse>, Status> {
        rpc_execution::plan_content_execution(self, req).await
    }

    async fn execute_content_plan_stream(
        &self,
        req: Request<ExecuteContentPlanRequest>,
    ) -> Result<Response<Self::ExecuteContentPlanStreamStream>, Status> {
        rpc_execution::execute_content_plan_stream(self, req).await
    }

    async fn list_kioku_candidates(
        &self,
        req: Request<ListKiokuCandidatesRequest>,
    ) -> Result<Response<ListKiokuCandidatesResponse>, Status> {
        rpc_execution::list_kioku_candidates(self, req).await
    }

    async fn issue_gunshi_recommendations(
        &self,
        req: Request<IssueGunshiRecommendationsRequest>,
    ) -> Result<Response<IssueGunshiRecommendationsResponse>, Status> {
        rpc_execution::issue_gunshi_recommendations(self, req).await
    }

    async fn set_gunshi_allocation_policy(
        &self,
        req: Request<SetGunshiAllocationPolicyRequest>,
    ) -> Result<Response<SetGunshiAllocationPolicyResponse>, Status> {
        rpc_execution::set_gunshi_allocation_policy(self, req).await
    }

    async fn get_gunshi_allocation_status(
        &self,
        req: Request<GetGunshiAllocationStatusRequest>,
    ) -> Result<Response<GetGunshiAllocationStatusResponse>, Status> {
        rpc_execution::get_gunshi_allocation_status(self, req).await
    }

    async fn review_kioku_memory(
        &self,
        req: Request<ReviewKiokuMemoryRequest>,
    ) -> Result<Response<ReviewKiokuMemoryResponse>, Status> {
        rpc_execution::review_kioku_memory(self, req).await
    }

    async fn get_sample_observation(
        &self,
        req: Request<GetSampleObservationRequest>,
    ) -> Result<Response<GetSampleObservationResponse>, Status> {
        rpc_execution::get_sample_observation(self, req).await
    }

    async fn report_operation_event(
        &self,
        req: Request<ReportOperationEventRequest>,
    ) -> Result<Response<ReportOperationEventResponse>, Status> {
        rpc_execution::report_operation_event(self, req).await
    }

    async fn claim_gateway_dispatch(
        &self,
        req: Request<ClaimGatewayDispatchRequest>,
    ) -> Result<Response<ClaimGatewayDispatchResponse>, Status> {
        rpc_execution::claim_gateway_dispatch(self, req).await
    }

    async fn get_operation_receipt(
        &self,
        req: Request<GetOperationReceiptRequest>,
    ) -> Result<Response<GetOperationReceiptResponse>, Status> {
        rpc_execution::get_operation_receipt(self, req).await
    }

    async fn get_quality_trend(
        &self,
        req: Request<GetQualityTrendRequest>,
    ) -> Result<Response<GetQualityTrendResponse>, Status> {
        rpc_execution::get_quality_trend(self, req).await
    }

    async fn put_evaluator_definition(
        &self,
        req: Request<PutEvaluatorDefinitionRequest>,
    ) -> Result<Response<PutEvaluatorDefinitionResponse>, Status> {
        rpc_execution::put_evaluator_definition(self, req).await
    }

    async fn put_evaluation_plan(
        &self,
        req: Request<PutEvaluationPlanRequest>,
    ) -> Result<Response<PutEvaluationPlanResponse>, Status> {
        rpc_execution::put_evaluation_plan(self, req).await
    }

    async fn resolve_evaluation_plan(
        &self,
        req: Request<ResolveEvaluationPlanRequest>,
    ) -> Result<Response<ResolveEvaluationPlanResponse>, Status> {
        rpc_execution::resolve_evaluation_plan(self, req).await
    }

    async fn get_evaluation_gate_evidence(
        &self,
        req: Request<GetEvaluationGateEvidenceRequest>,
    ) -> Result<Response<GetEvaluationGateEvidenceResponse>, Status> {
        rpc_execution::get_evaluation_gate_evidence(self, req).await
    }

    async fn run_lookup_first_promotion_gate(
        &self,
        req: Request<RunLookupFirstPromotionGateRequest>,
    ) -> Result<Response<RunLookupFirstPromotionGateResponse>, Status> {
        rpc_execution::run_lookup_first_promotion_gate(self, req).await
    }

    async fn execute_evaluation_manifest(
        &self,
        req: Request<ExecuteEvaluationManifestRequest>,
    ) -> Result<Response<ExecuteEvaluationManifestResponse>, Status> {
        rpc_execution::execute_evaluation_manifest(self, req).await
    }

    async fn cancel_evaluation_execution(
        &self,
        req: Request<CancelEvaluationExecutionRequest>,
    ) -> Result<Response<CancelEvaluationExecutionResponse>, Status> {
        rpc_execution::cancel_evaluation_execution(self, req).await
    }
}

#[cfg(test)]
#[path = "chisei_service_tests.rs"]
mod tests;
