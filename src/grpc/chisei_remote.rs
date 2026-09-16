//! Chisei plane: no database. Slice RPCs call the Sekai clerk (ADR 0082).

use std::pin::Pin;

use tonic::{Request, Response, Status};

use super::pb::chisei::chisei_service_server::ChiseiService;
use super::pb::chisei::*;
use crate::chisei::sekai_clerk::{SekaiClerk, decide_invoke_instance};

pub struct ChiseiRemoteImpl {
    clerk: SekaiClerk,
}

impl ChiseiRemoteImpl {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            clerk: SekaiClerk::new(endpoint),
        }
    }

    fn authorization<T>(req: &Request<T>) -> Option<String> {
        req.metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    }

    fn actor<T>(req: &Request<T>) -> String {
        req.metadata()
            .get("x-principal")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .unwrap_or("local")
            .to_string()
    }

    fn slice_only() -> Status {
        Status::failed_precondition(
            "chisei plane: method is not on the clerk slice; use combined sekai-chisei or a later clerk RPC",
        )
    }
}

#[tonic::async_trait]
impl ChiseiService for ChiseiRemoteImpl {
    type ExecutePlanStreamStream =
        Pin<Box<dyn futures_util::Stream<Item = Result<ExecutePlanStreamEvent, Status>> + Send>>;
    type ExecuteContentPlanStreamStream = Pin<
        Box<dyn futures_util::Stream<Item = Result<ExecuteContentPlanStreamEvent, Status>> + Send>,
    >;

    async fn invoke_action_instance(
        &self,
        req: Request<InvokeActionInstanceRequest>,
    ) -> Result<Response<InvokeActionInstanceResponse>, Status> {
        let authorization = Self::authorization(&req);
        let actor = Self::actor(&req);
        let inner = req.into_inner();
        let type_response = self
            .clerk
            .get_governed_action_type(
                &inner.namespace,
                &inner.type_id,
                &inner.version,
                authorization.as_deref(),
            )
            .await?;
        let type_enabled = type_response
            .r#type
            .as_ref()
            .is_some_and(|r#type| r#type.enabled);
        let instance = decide_invoke_instance(
            &inner.namespace,
            &inner.type_id,
            &inner.version,
            &inner.parameters_json,
            &inner.idempotency_key,
            &inner.evidence_submission_ids,
            &inner.request_id,
            &actor,
            type_enabled,
            chrono::Utc::now().timestamp_millis(),
        )?;
        let persisted = self
            .clerk
            .persist_admitted_action(instance, &inner.ontology_digest, authorization.as_deref())
            .await?;
        let stored = persisted
            .instance
            .ok_or_else(|| Status::internal("persist omitted instance"))?;
        let instance_json = serde_json::to_string(&crate::sekai::action_instance::ActionInstance {
            instance_id: stored.instance_id,
            namespace: stored.namespace,
            type_id: stored.type_id,
            version: stored.version,
            principal: stored.principal,
            parameters_json: stored.parameters_json,
            request_digest: stored.request_digest,
            idempotency_key: stored.idempotency_key,
            operation_id: stored.operation_id,
            status: stored.status,
            deny_reason: stored.deny_reason,
            evidence_submission_ids: stored.evidence_submission_ids,
            policy_decision: stored.policy_decision,
            budget_decision: stored.budget_decision,
            created_at_ms: stored.created_at_ms,
            decided_at_ms: stored.decided_at_ms,
        })
        .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(InvokeActionInstanceResponse {
            instance_json,
            replay: persisted.replay,
            receipt_json: persisted.receipt_json,
        }))
    }

    async fn get_operation_receipt(
        &self,
        req: Request<GetOperationReceiptRequest>,
    ) -> Result<Response<GetOperationReceiptResponse>, Status> {
        let authorization = Self::authorization(&req);
        let operation_id = req.into_inner().operation_id;
        if operation_id.trim().is_empty() {
            return Err(Status::invalid_argument("operation_id required"));
        }
        let receipt = self
            .clerk
            .get_persisted_operation_receipt(&operation_id, authorization.as_deref())
            .await?;
        Ok(Response::new(GetOperationReceiptResponse {
            receipt_json: receipt.receipt_json,
            complete: receipt.complete,
            missing_surfaces: Vec::new(),
        }))
    }

    async fn evaluate_governed_subject(
        &self,
        _: Request<EvaluateGovernedSubjectRequest>,
    ) -> Result<Response<EvaluateGovernedSubjectResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn export_governed_subject_provenance(
        &self,
        _: Request<ExportGovernedSubjectProvenanceRequest>,
    ) -> Result<Response<ExportGovernedSubjectProvenanceResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn authorize_external_action(
        &self,
        _: Request<AuthorizeExternalActionRequest>,
    ) -> Result<Response<AuthorizeExternalActionResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn transition_external_action(
        &self,
        _: Request<TransitionExternalActionRequest>,
    ) -> Result<Response<TransitionExternalActionResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn redeem_external_action_permit(
        &self,
        _: Request<RedeemExternalActionPermitRequest>,
    ) -> Result<Response<RedeemExternalActionPermitResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn set_external_action_policy(
        &self,
        _: Request<SetExternalActionPolicyRequest>,
    ) -> Result<Response<SetExternalActionPolicyResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn decide_gateway_execution(
        &self,
        _: Request<DecideGatewayExecutionRequest>,
    ) -> Result<Response<DecideGatewayExecutionResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn record_usage(
        &self,
        _: Request<RecordUsageRequest>,
    ) -> Result<Response<RecordUsageResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn set_budget_limit(
        &self,
        _: Request<SetBudgetLimitRequest>,
    ) -> Result<Response<SetBudgetLimitResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn set_namespace_policy(
        &self,
        _: Request<SetNamespacePolicyRequest>,
    ) -> Result<Response<SetNamespacePolicyResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn get_effective_policy_summary(
        &self,
        _: Request<GetEffectivePolicySummaryRequest>,
    ) -> Result<Response<GetEffectivePolicySummaryResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn plan_execution(
        &self,
        _: Request<PlanExecutionRequest>,
    ) -> Result<Response<PlanExecutionResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn execute_plan_stream(
        &self,
        _: Request<ExecutePlanRequest>,
    ) -> Result<Response<Self::ExecutePlanStreamStream>, Status> {
        Err(Self::slice_only())
    }
    async fn plan_content_execution(
        &self,
        _: Request<PlanContentExecutionRequest>,
    ) -> Result<Response<PlanContentExecutionResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn execute_content_plan_stream(
        &self,
        _: Request<ExecuteContentPlanRequest>,
    ) -> Result<Response<Self::ExecuteContentPlanStreamStream>, Status> {
        Err(Self::slice_only())
    }
    async fn list_kioku_candidates(
        &self,
        _: Request<ListKiokuCandidatesRequest>,
    ) -> Result<Response<ListKiokuCandidatesResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn issue_gunshi_recommendations(
        &self,
        _: Request<IssueGunshiRecommendationsRequest>,
    ) -> Result<Response<IssueGunshiRecommendationsResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn set_gunshi_allocation_policy(
        &self,
        _: Request<SetGunshiAllocationPolicyRequest>,
    ) -> Result<Response<SetGunshiAllocationPolicyResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn get_gunshi_allocation_status(
        &self,
        _: Request<GetGunshiAllocationStatusRequest>,
    ) -> Result<Response<GetGunshiAllocationStatusResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn review_kioku_memory(
        &self,
        _: Request<ReviewKiokuMemoryRequest>,
    ) -> Result<Response<ReviewKiokuMemoryResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn get_sample_observation(
        &self,
        _: Request<GetSampleObservationRequest>,
    ) -> Result<Response<GetSampleObservationResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn report_operation_event(
        &self,
        _: Request<ReportOperationEventRequest>,
    ) -> Result<Response<ReportOperationEventResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn claim_gateway_dispatch(
        &self,
        _: Request<ClaimGatewayDispatchRequest>,
    ) -> Result<Response<ClaimGatewayDispatchResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn get_quality_trend(
        &self,
        _: Request<GetQualityTrendRequest>,
    ) -> Result<Response<GetQualityTrendResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn put_evaluator_definition(
        &self,
        _: Request<PutEvaluatorDefinitionRequest>,
    ) -> Result<Response<PutEvaluatorDefinitionResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn put_evaluation_plan(
        &self,
        _: Request<PutEvaluationPlanRequest>,
    ) -> Result<Response<PutEvaluationPlanResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn resolve_evaluation_plan(
        &self,
        _: Request<ResolveEvaluationPlanRequest>,
    ) -> Result<Response<ResolveEvaluationPlanResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn get_evaluation_gate_evidence(
        &self,
        _: Request<GetEvaluationGateEvidenceRequest>,
    ) -> Result<Response<GetEvaluationGateEvidenceResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn run_lookup_first_promotion_gate(
        &self,
        _: Request<RunLookupFirstPromotionGateRequest>,
    ) -> Result<Response<RunLookupFirstPromotionGateResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn execute_evaluation_manifest(
        &self,
        _: Request<ExecuteEvaluationManifestRequest>,
    ) -> Result<Response<ExecuteEvaluationManifestResponse>, Status> {
        Err(Self::slice_only())
    }
    async fn cancel_evaluation_execution(
        &self,
        _: Request<CancelEvaluationExecutionRequest>,
    ) -> Result<Response<CancelEvaluationExecutionResponse>, Status> {
        Err(Self::slice_only())
    }
}
