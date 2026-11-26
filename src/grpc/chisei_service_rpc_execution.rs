use super::*;
use crate::chisei_store::{
    ChiseiEvaluationStore, ChiseiGatewayStore, ChiseiReceiptStore, ChiseiRoutingProfileStore,
};
use crate::ext::*;

pub(super) async fn plan_execution(
    service: &ChiseiServiceImpl,
    req: Request<PlanExecutionRequest>,
) -> Result<Response<PlanExecutionResponse>, Status> {
    let registry = service.refresh_provider_registry_for_resolution().await?;
    let (registry, hosted) = match req.get_ref().input.as_ref() {
        Some(input) => planning_registry(
            service,
            registry,
            authenticated_actor(&req).as_str(),
            enterprise_authenticated_context(&req)?,
            input,
            &req.get_ref().routing_profile_id,
        )?,
        None => (registry, Vec::new()),
    };
    crate::provider_profile::with_provider_registry_snapshot(registry, async {
        let actor = authenticated_actor(&req);
        let context = enterprise_authenticated_context(&req)?.cloned();
        let request = req.into_inner();
        let mut input = request
            .input
            .ok_or(Status::invalid_argument("input required"))?;
        service.require_in_process_namespace_policy()?;
        if context.is_some()
            && (!input.route_override.trim().is_empty() || request.gunshi_allocation.is_some())
        {
            return Err(Status::permission_denied(
                "enterprise execution route override or Gunshi allocation binding denied",
            ));
        }
        require_execution_namespace_access_with_context(
            service.db.runtime(),
            service.sekai_facts.reader(),
            &service.config,
            &actor,
            context.as_ref(),
            &input.namespace,
        )?;
        let bound_allocation = if let Some(binding) = request.gunshi_allocation {
            let (bound_input, allocation) = service.bind_gunshi_allocation(input, binding)?;
            input = bound_input;
            Some(allocation)
        } else {
            None
        };
        let plan_namespace = input.namespace.clone();
        let mut plan = service.plan_from_input(input, &actor).await?;
        require_hosted_route_policy(service, &plan_namespace, &plan.resolved_runtime)?;
        // A pin is checked against the planning catalog already loaded for
        // this request. The listing never acts as a grant (#1094, #1206).
        let pinned = request.routing_profile_id.trim();
        if !pinned.is_empty() {
            crate::chisei::routing_profiles::check_pin(
                &crate::provider_profile::provider_registry_snapshot(),
                &hosted,
                pinned,
                &plan.resolved_runtime,
            )
            .map_err(Status::failed_precondition)?;
        }
        if let Some(allocation) = bound_allocation {
            let live_policy_version = service
                .policy
                .effective_policy(&allocation.plan.namespace)
                .map(|policy| policy.version())
                .unwrap_or_else(|| "implicit-allow/v1".into());
            if live_policy_version != allocation.plan.policy_version {
                return Err(Status::failed_precondition(
                    "Gunshi allocation policy changed while planning",
                ));
            }
            if plan.resolved_runtime != allocation.plan.selection.runtime
                || plan.resolved_model != allocation.plan.selection.model
            {
                return Err(Status::failed_precondition(
                    "live policy or provider state no longer permits the Gunshi allocation",
                ));
            }
            plan.gunshi_issuance_id = allocation.issuance_id;
            plan.gunshi_allocation_id = allocation.plan.allocation_id;
            plan.gunshi_agent_id = allocation.plan.selection.agent_id;
            plan.gunshi_policy_version = allocation.plan.policy_version;
            plan.gunshi_input_fingerprint = allocation.plan.input_fingerprint;
            plan.gunshi_budget_ceiling_usd_micros = allocation.plan.budget_ceiling_usd_micros;
            plan.gunshi_max_attempts = allocation.plan.attempts.max_attempts;
            plan.gunshi_human_review_required = allocation.plan.verification.human_review_required;
        }
        if let Some(plan_input) = &plan.input {
            let namespace_hint = plan_input.namespace.trim().to_string();
            service
                .record_evolve_task(
                    &plan_input.request_id,
                    &namespace_hint,
                    &plan.enriched_spec,
                    if plan.executable { "planned" } else { "failed" },
                    plan_input.estimated_tokens,
                )
                .map_err(Status::internal)?;
        }
        service
            .record_planned_operation_with_identity(
                &plan,
                &actor,
                !pinned.is_empty(),
                context.as_ref(),
            )
            .map_err(Status::internal)?;
        service.cache_plan_for_enterprise_authority(
            plan.clone(),
            enterprise_execution_authority(context.as_ref()),
        );
        Ok(Response::new(PlanExecutionResponse { plan: Some(plan) }))
    })
    .await
}
pub(super) async fn execute_plan_stream(
    service: &ChiseiServiceImpl,
    req: Request<ExecutePlanRequest>,
) -> Result<Response<tonic::codegen::BoxStream<ExecutePlanStreamEvent>>, Status> {
    let actor = authenticated_actor(&req);
    let context = enterprise_authenticated_context(&req)?.cloned();
    let requested_plan = req
        .into_inner()
        .plan
        .ok_or(Status::invalid_argument("plan required"))?;
    // A hosted route is re-admitted inside execution, after the cached plan
    // is bound and namespace access is checked (#1187).
    let stream = service
        .execute_planned_stream(actor, context, requested_plan)
        .await?;
    Ok(Response::new(stream))
}
pub(super) async fn plan_content_execution(
    service: &ChiseiServiceImpl,
    req: Request<PlanContentExecutionRequest>,
) -> Result<Response<PlanContentExecutionResponse>, Status> {
    let hosted_namespace = req
        .get_ref()
        .input
        .as_ref()
        .and_then(|input| input.execution.as_ref())
        .map(|execution| execution.namespace.clone())
        .unwrap_or_default();
    let registry = service.refresh_provider_registry_for_resolution().await?;
    let registry = match req
        .get_ref()
        .input
        .as_ref()
        .and_then(|input| input.execution.as_ref())
    {
        Some(execution) => {
            planning_registry(
                service,
                registry,
                authenticated_actor(&req).as_str(),
                enterprise_authenticated_context(&req)?,
                execution,
                "",
            )?
            .0
        }
        None => registry,
    };
    crate::provider_profile::with_provider_registry_snapshot(registry, async {
        let actor = authenticated_actor(&req);
        let context = enterprise_authenticated_context(&req)?.cloned();
        let request = req.into_inner();
        let mut input = request
            .input
            .ok_or_else(|| Status::invalid_argument("content input required"))?;
        let mut execution = input
            .execution
            .take()
            .ok_or_else(|| Status::invalid_argument("content execution input required"))?;
        service.require_in_process_namespace_policy()?;
        if context.is_some()
            && (!execution.route_override.trim().is_empty() || request.gunshi_allocation.is_some())
        {
            return Err(Status::permission_denied(
                "enterprise execution route override or Gunshi allocation binding denied",
            ));
        }
        require_execution_namespace_access_with_context(
            service.db.runtime(),
            service.sekai_facts.reader(),
            &service.config,
            &actor,
            context.as_ref(),
            &execution.namespace,
        )?;
        let bound_allocation = if let Some(binding) = request.gunshi_allocation {
            let (bound_input, allocation) = service.bind_gunshi_allocation(execution, binding)?;
            execution = bound_input;
            Some(allocation)
        } else {
            None
        };
        input.execution = Some(execution);
        let mut plan = service.plan_content_from_input(input, &actor).await?;
        let execution_plan = plan
            .execution
            .as_mut()
            .ok_or_else(|| Status::internal("content execution plan missing"))?;
        require_hosted_route_policy(service, &hosted_namespace, &execution_plan.resolved_runtime)?;
        if let Some(allocation) = bound_allocation {
            let live_policy_version = service
                .policy
                .effective_policy(&allocation.plan.namespace)
                .map(|policy| policy.version())
                .unwrap_or_else(|| "implicit-allow/v1".into());
            if live_policy_version != allocation.plan.policy_version {
                return Err(Status::failed_precondition(
                    "Gunshi allocation policy changed while planning",
                ));
            }
            if execution_plan.resolved_runtime != allocation.plan.selection.runtime
                || execution_plan.resolved_model != allocation.plan.selection.model
            {
                return Err(Status::failed_precondition(
                    "live policy or provider state no longer permits the Gunshi allocation",
                ));
            }
            execution_plan.gunshi_issuance_id = allocation.issuance_id;
            execution_plan.gunshi_allocation_id = allocation.plan.allocation_id;
            execution_plan.gunshi_agent_id = allocation.plan.selection.agent_id;
            execution_plan.gunshi_policy_version = allocation.plan.policy_version;
            execution_plan.gunshi_input_fingerprint = allocation.plan.input_fingerprint;
            execution_plan.gunshi_budget_ceiling_usd_micros =
                allocation.plan.budget_ceiling_usd_micros;
            execution_plan.gunshi_max_attempts = allocation.plan.attempts.max_attempts;
            execution_plan.gunshi_human_review_required =
                allocation.plan.verification.human_review_required;
        }
        if let Some(plan_input) = &execution_plan.input {
            service
                .record_evolve_task(
                    &plan_input.request_id,
                    plan_input.namespace.trim(),
                    &execution_plan.enriched_spec,
                    if execution_plan.executable {
                        "planned"
                    } else {
                        "failed"
                    },
                    plan_input.estimated_tokens,
                )
                .map_err(Status::internal)?;
        }
        service
            .record_planned_operation_with_identity(execution_plan, &actor, false, context.as_ref())
            .map_err(Status::internal)?;
        service.cache_content_plan(
            plan.clone(),
            enterprise_execution_authority(context.as_ref()),
        )?;
        Ok(Response::new(PlanContentExecutionResponse {
            plan: Some(plan),
        }))
    })
    .await
}
pub(super) async fn execute_content_plan_stream(
    service: &ChiseiServiceImpl,
    req: Request<ExecuteContentPlanRequest>,
) -> Result<Response<tonic::codegen::BoxStream<ExecuteContentPlanStreamEvent>>, Status> {
    let actor = authenticated_actor(&req);
    let context = enterprise_authenticated_context(&req)?.cloned();
    let request = req.into_inner();
    let requested_plan = request
        .plan
        .ok_or_else(|| Status::invalid_argument("content execution plan required"))?;
    let stream = service
        .execute_content_planned_stream(actor, context, requested_plan, request.resolved_parts)
        .await?;
    Ok(Response::new(stream))
}
pub(super) async fn report_operation_event(
    service: &ChiseiServiceImpl,
    req: Request<ReportOperationEventRequest>,
) -> Result<Response<ReportOperationEventResponse>, Status> {
    reported_operation_event_lifecycle::ReportedOperationEventLifecycle::new(service)
        .admit(req)
        .await
}
pub(super) async fn claim_gateway_dispatch(
    service: &ChiseiServiceImpl,
    req: Request<ClaimGatewayDispatchRequest>,
) -> Result<Response<ClaimGatewayDispatchResponse>, Status> {
    if !is_gateway_service_principal(&req, &service.config) {
        return Err(Status::permission_denied(
            "gateway dispatch claim requires a gateway service principal",
        ));
    }
    let request = req.into_inner();
    if request.caller_scope.trim().is_empty()
        || request.request_alias.trim().is_empty()
        || request.request_id.trim().is_empty()
        || request.operation_id.trim().is_empty()
        || request.dispatch_token.trim().is_empty()
    {
        return Err(Status::invalid_argument(
            "caller_scope, request_alias, request_id, operation_id, and dispatch_token are required",
        ));
    }
    let reserved = service
        .db
        .reserve_gateway_request_alias(
            &request.caller_scope,
            &request.request_alias,
            &request.request_id,
            &request.operation_id,
        )
        .map_err(Status::internal)?;
    if !reserved {
        return Ok(Response::new(ClaimGatewayDispatchResponse {
            claimed: false,
        }));
    }
    let claimed = service
        .db
        .claim_gateway_request_alias_dispatch(
            &request.caller_scope,
            &request.request_alias,
            &request.request_id,
            &request.operation_id,
            &request.dispatch_token,
        )
        .map_err(Status::internal)?;
    Ok(Response::new(ClaimGatewayDispatchResponse { claimed }))
}
pub(super) async fn get_operation_receipt(
    service: &ChiseiServiceImpl,
    req: Request<GetOperationReceiptRequest>,
) -> Result<Response<GetOperationReceiptResponse>, Status> {
    let actor = authenticated_actor(&req);
    // An enterprise (tenant) context gets no administrative inspection, and
    // learns nothing about receipts outside its namespaces (#1770).
    let context = enterprise_authenticated_context(&req)?.cloned();
    let privileged =
        context.is_none() && matches!(actor.as_str(), "root" | "local" | "chisei-gateway");
    let request = req.into_inner();
    let operation_id = request.operation_id.trim();
    let request_id = request.request_id.trim();
    let caller_scope = request.caller_scope.trim();
    let attempt = (request.attempt > 0).then_some(request.attempt);
    if operation_id.is_empty() == request_id.is_empty() {
        return Err(Status::invalid_argument(
            "exactly one of operation_id or request_id is required",
        ));
    }
    let receipt = if !operation_id.is_empty() {
        if let Some(attempt) = attempt {
            match service
                .db
                .find_gateway_receipt_by_logical_operation_id(operation_id, Some(attempt))
            {
                Ok(Some(receipt)) => Ok(Some(receipt)),
                Ok(None) if attempt == 1 => service.db.get_operation_receipt(operation_id),
                Ok(None) => Ok(None),
                Err(error) => Err(error),
            }
        } else {
            let exact = service.db.get_operation_receipt(operation_id);
            let derived = service
                .db
                .find_gateway_receipt_by_logical_operation_id(operation_id, None);
            match (exact, derived) {
                (Ok(Some(_)), Ok(Some(_))) => {
                    Err("logical operation id matches multiple legacy and attempt receipts".into())
                }
                (Ok(Some(receipt)), Ok(None)) | (Ok(None), Ok(Some(receipt))) => Ok(Some(receipt)),
                (Ok(None), Ok(None)) => Ok(None),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
    } else {
        if !privileged {
            return Err(Status::permission_denied(
                "opaque request alias lookup requires administrative inspection access",
            ));
        }
        let alias_lookup = || {
            service.db.find_operation_receipt_by_lookup_request_id(
                request_id,
                (!caller_scope.is_empty()).then_some(caller_scope),
                None,
            )
        };
        if caller_scope.is_empty() {
            match service.db.find_operation_receipt_by_request_id(request_id) {
                Ok(Some(receipt)) => Ok(Some(receipt)),
                Ok(None) => alias_lookup(),
                Err(error) => Err(error),
            }
        } else {
            match alias_lookup() {
                Ok(Some(receipt)) => Ok(Some(receipt)),
                Ok(None) => service.db.find_operation_receipt_by_request_id(request_id),
                Err(error) => Err(error),
            }
        }
    }
    .map_err(|error| {
        if error.contains("matches multiple") {
            Status::failed_precondition(error)
        } else {
            Status::internal(error)
        }
    })
    .and_then(|receipt| match receipt {
        Some(receipt) => Ok(receipt),
        None => {
            if operation_id.is_empty() {
                return Err(Status::not_found("operation receipt not found"));
            }
            let Some(lookup) = &service.sekai_commit_lookup else {
                return Err(Status::not_found("operation receipt not found"));
            };
            let commit = lookup
                .lookup_commit(operation_id)
                .map_err(Status::unavailable)?
                .ok_or_else(|| Status::not_found("operation receipt not found"))?;
            Ok(crate::chisei::sekai_commit::hop_projection_receipt(
                operation_id,
                &commit,
            ))
        }
    });
    let mut receipt = match context.as_ref() {
        // Fail closed: a failed lookup, another principal's receipt, one
        // with no namespace, or a namespace the tenant may not read all
        // answer exactly as a missing id does.
        Some(context) => receipt
            .ok()
            .filter(|receipt| {
                receipt.initiating_actor == actor
                    && require_enterprise_namespace(
                        service.sekai_facts.reader(),
                        context,
                        &receipt.namespace,
                        crate::enterprise::NamespaceAction::Read,
                    )
                    .is_ok()
            })
            .ok_or_else(|| Status::not_found("operation receipt not found"))?,
        None => {
            let receipt = receipt?;
            if actor != receipt.initiating_actor
                // The UDS interceptor assigns `local`; local socket access is
                // the administrative inspection boundary used by sekaictl.
                // This exception is read-only and is not accepted by mutation
                // RPCs.
                && !privileged
            {
                return Err(Status::permission_denied(
                    "operation receipt is not visible to this principal",
                ));
            }
            receipt
        }
    };
    if receipt.operation_class != "sekai_commit_projection"
        && let Some(lookup) = &service.sekai_commit_lookup
        && let Ok(Some(commit)) = lookup.lookup_commit(&receipt.operation_id)
    {
        crate::chisei::sekai_commit::project_commit_handles(&mut receipt, &commit);
    }
    // A marked governed Action's receipt needs clearance for the marking, as
    // the instance does (#1706); Sekai decides it, and a denial reads as
    // missing. Administrative inspection is judged like anyone else.
    if !receipt_marking_cleared(service, &receipt, &actor) {
        return Err(Status::not_found("operation receipt not found"));
    }
    let completeness = receipt.completeness();
    let receipt_json =
        serde_json::to_string(&receipt).map_err(|error| Status::internal(error.to_string()))?;
    Ok(Response::new(GetOperationReceiptResponse {
        receipt_json,
        complete: completeness.complete,
        missing_surfaces: completeness
            .missing_surfaces
            .into_iter()
            .map(|surface| surface.as_str().to_string())
            .collect(),
    }))
}
/// Whether `actor` may see a receipt's marking. Unmarked receipts pass; a
/// marked one needs Sekai clearance, and a failed lookup fails closed.
fn receipt_marking_cleared(
    service: &ChiseiServiceImpl,
    receipt: &crate::chisei::receipt::OperationReceipt,
    actor: &str,
) -> bool {
    let Some(marking) = receipt_marking(receipt) else {
        return true;
    };
    let carrier = crate::domain::Object {
        id: format!("operation-receipt:{}", receipt.operation_id),
        kind: "operation_receipt".into(),
        name: receipt.operation_id.clone(),
        namespace: receipt.namespace.clone(),
        external_id: String::new(),
        properties: std::collections::HashMap::from([(
            crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.to_string(),
            marking.to_string(),
        )]),
        created: receipt.started_at_ms,
        updated: receipt.started_at_ms,
    };
    matches!(
        service
            .sekai_facts
            .reader()
            .marking_clearance(&receipt.operation_id, &carrier, actor),
        Ok(crate::chisei::principal::MarkingClearance::Cleared)
    )
}
/// The marking a receipt records (#1706): a governed Action's on its intent,
/// or a reservation or commit projection's for the instance it names.
fn receipt_marking(receipt: &crate::chisei::receipt::OperationReceipt) -> Option<&str> {
    receipt
        .events
        .iter()
        .find_map(|event| {
            event
                .attributes
                .get(crate::chisei::sekai_commit::RECEIPT_MARKING_ATTRIBUTE)
        })
        .map(String::as_str)
        .filter(|marking| !marking.trim().is_empty())
}

pub(super) async fn get_quality_trend(
    service: &ChiseiServiceImpl,
    req: Request<GetQualityTrendRequest>,
) -> Result<Response<GetQualityTrendResponse>, Status> {
    require_request_namespace_read(service.sekai_facts.reader(), &req, &req.get_ref().namespace)?;
    let request = req.into_inner();
    let namespace = canonical_namespace(&request.namespace)?.to_string();
    let report = crate::quality_trend::query_quality_trends_after_access_check(
        service.db.runtime(),
        &namespace,
        request.since_ms,
        request.until_ms,
    )
    .map_err(map_quality_trend_error)?;
    Ok(Response::new(GetQualityTrendResponse {
        report: Some(quality_trend_report_to_proto(&report)),
    }))
}
/// Experimental (ADR 0156). Splits the requested namespaces into readable and
/// withheld by the caller's own read access; withheld namespaces are named,
/// never counted, and a denial and an unknown namespace look the same.
pub(super) async fn get_execution_telemetry(
    service: &ChiseiServiceImpl,
    req: Request<GetExecutionTelemetryRequest>,
) -> Result<Response<GetExecutionTelemetryResponse>, Status> {
    use crate::execution_telemetry::{
        MAX_TELEMETRY_NAMESPACES, TelemetryDimension, TelemetryError, query_execution_telemetry,
    };
    let request = req.get_ref();
    if request.namespaces.is_empty() || request.namespaces.len() > MAX_TELEMETRY_NAMESPACES {
        return Err(Status::invalid_argument(format!(
            "namespaces must name 1 to {MAX_TELEMETRY_NAMESPACES} namespaces"
        )));
    }
    let group_by = TelemetryDimension::parse(&request.group_by).ok_or_else(|| {
        Status::invalid_argument(
            "group_by must be task_class, model, prompt_variant, tool, evaluator, or outcome_class",
        )
    })?;
    let mut readable = std::collections::BTreeSet::new();
    let mut withheld = std::collections::BTreeSet::new();
    for namespace in &request.namespaces {
        let namespace = canonical_namespace(namespace)?.to_string();
        match require_request_namespace_read(service.sekai_facts.reader(), &req, &namespace) {
            Ok(()) => readable.insert(namespace),
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::PermissionDenied | tonic::Code::NotFound
                ) =>
            {
                withheld.insert(namespace)
            }
            Err(status) => return Err(status),
        };
    }
    let readable: Vec<String> = readable.into_iter().collect();
    let withheld: Vec<String> = withheld.into_iter().collect();
    let actor = authenticated_actor(&req);
    let telemetry = query_execution_telemetry(
        service.db.runtime(),
        &readable,
        &withheld,
        request.since_ms,
        request.until_ms,
        group_by,
        |receipt| receipt_marking_cleared(service, receipt, &actor),
    )
    .map_err(|error| match error {
        TelemetryError::Invalid(message) => Status::invalid_argument(message),
        TelemetryError::NarrowWindow(message) => {
            Status::resource_exhausted(format!("narrow the window: {message}"))
        }
        TelemetryError::Store(message) => Status::internal(message),
    })?;
    Ok(Response::new(GetExecutionTelemetryResponse {
        contract_version: telemetry.contract_version,
        namespaces: telemetry.namespaces,
        withheld_namespaces: telemetry.withheld_namespaces,
        withheld_receipts: telemetry.withheld_receipts,
        since_ms: telemetry.since_ms,
        until_ms: telemetry.until_ms,
        group_by: telemetry.group_by.as_str().into(),
        record_kinds: telemetry.record_kinds,
        receipts: telemetry.receipts,
        unrecorded_receipts: telemetry.unrecorded_receipts,
        groups: telemetry
            .groups
            .into_iter()
            .map(|group| ExecutionTelemetryGroup {
                key: group.key,
                receipts: group.receipts,
                model_calls: group.model_calls,
                priced_model_calls: group.priced_model_calls,
                spend_usd_micros: group.spend_usd_micros,
                input_tokens: group.input_tokens,
                output_tokens: group.output_tokens,
                latency_samples: group.latency_samples,
                latency_p50_ms: group.latency_p50_ms,
                latency_p90_ms: group.latency_p90_ms,
                latency_p99_ms: group.latency_p99_ms,
                outcomes: group.outcomes.into_iter().collect(),
                verifications: group.verifications,
                verifications_passed: group.verifications_passed,
            })
            .collect(),
        gaps: telemetry
            .gaps
            .into_iter()
            .map(|gap| ExecutionTelemetryGap {
                fact: gap.fact,
                reason: gap.reason,
            })
            .collect(),
        digest: telemetry.digest,
    }))
}
pub(super) async fn put_evaluator_definition(
    service: &ChiseiServiceImpl,
    req: Request<PutEvaluatorDefinitionRequest>,
) -> Result<Response<PutEvaluatorDefinitionResponse>, Status> {
    require_eval_admin(&req)?;
    let actor = authenticated_actor(&req);
    let request = req.into_inner();
    if request.definition.is_none() {
        let definition = service
            .db
            .get_evaluator_definition(&request.definition_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::failed_precondition("evaluator definition not found"))?;
        require_namespace_write_access(
            service.sekai_facts.reader(),
            &actor,
            &definition.namespace,
        )?;
        let availability = service
            .db
            .set_evaluator_availability(
                &request.definition_id,
                &request.availability_state,
                &request.superseded_by_definition_id,
                &request.reason,
                &request.request_id,
                &actor,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(map_evaluation_resource_error)?;
        let (implementation_executable, implementation_status) = service
            .evaluation_execution_lifecycle
            .evaluator_capability(&definition);
        return Ok(Response::new(PutEvaluatorDefinitionResponse {
            record: Some(evaluator_record_with_availability(
                &definition,
                &availability,
                implementation_executable,
                &implementation_status,
            )),
        }));
    }
    if !request.availability_state.is_empty() {
        return Err(Status::invalid_argument(
            "definition publication and availability transition are separate writes",
        ));
    }
    let definition = from_proto_evaluator_definition(request.definition.unwrap())?;
    require_namespace_write_access(service.sekai_facts.reader(), &actor, &definition.namespace)?;
    let definition = service
        .db
        .put_evaluator_definition(definition, &actor, chrono::Utc::now().timestamp_millis())
        .map_err(map_evaluation_resource_error)?;
    let (implementation_executable, implementation_status) = service
        .evaluation_execution_lifecycle
        .evaluator_capability(&definition);
    Ok(Response::new(PutEvaluatorDefinitionResponse {
        record: Some(evaluator_record(
            service.db.runtime(),
            &definition,
            implementation_executable,
            &implementation_status,
        )?),
    }))
}
pub(super) async fn put_evaluation_plan(
    service: &ChiseiServiceImpl,
    req: Request<PutEvaluationPlanRequest>,
) -> Result<Response<PutEvaluationPlanResponse>, Status> {
    require_eval_admin(&req)?;
    let actor = authenticated_actor(&req);
    let plan = from_proto_evaluation_plan(
        req.into_inner()
            .plan
            .ok_or_else(|| Status::invalid_argument("evaluation plan required"))?,
    )?;
    require_namespace_write_access(service.sekai_facts.reader(), &actor, &plan.namespace)?;
    let facts =
        evaluation_manifest_resolution::in_process_facts_runtime(service.sekai_facts.reader())?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let plan = evaluation_plan_domain::prepare_plan(plan, &actor, now_ms)
        .map_err(map_evaluation_resource_error)?;
    if let Some(existing) = service
        .db
        .get_evaluation_plan(&plan.plan_version_id)
        .map_err(Status::internal)?
    {
        if existing.content_digest != plan.content_digest {
            return Err(Status::already_exists(
                "evaluation plan version already exists with different content",
            ));
        }
        if !evaluation_manifest_resolution::evaluation_plan_visible(facts, &existing, &actor)
            .map_err(Status::internal)?
        {
            return Err(Status::failed_precondition(
                "governed invariant reference unavailable",
            ));
        }
        return Ok(Response::new(PutEvaluationPlanResponse {
            plan: Some(to_proto_evaluation_plan(&existing)),
        }));
    }
    evaluation_manifest_resolution::validate_evaluation_plan_references(
        service.db.runtime(),
        facts,
        &plan,
        &actor,
    )?;
    let plan = service
        .db
        .put_evaluation_plan(plan, &actor, now_ms)
        .map_err(map_evaluation_resource_error)?;
    Ok(Response::new(PutEvaluationPlanResponse {
        plan: Some(to_proto_evaluation_plan(&plan)),
    }))
}
/// One stored plan version by content digest. The caller needs write access
/// to the namespace, as storing a plan does; a plan that is absent or not
/// visible to the caller reads as not found.
pub(super) async fn get_evaluation_plan(
    service: &ChiseiServiceImpl,
    req: Request<GetEvaluationPlanRequest>,
) -> Result<Response<GetEvaluationPlanResponse>, Status> {
    let actor = authenticated_actor(&req);
    let request = req.into_inner();
    require_namespace_write_access(service.sekai_facts.reader(), &actor, &request.namespace)?;
    let not_found = || Status::not_found("evaluation plan not found");
    let plan = service
        .db
        .find_evaluation_plan_by_digest(&request.namespace, &request.content_digest)
        .map_err(Status::internal)?
        .ok_or_else(not_found)?;
    let facts =
        evaluation_manifest_resolution::in_process_facts_runtime(service.sekai_facts.reader())?;
    if !evaluation_manifest_resolution::evaluation_plan_visible(facts, &plan, &actor)
        .map_err(Status::internal)?
    {
        return Err(not_found());
    }
    Ok(Response::new(GetEvaluationPlanResponse {
        plan: Some(to_proto_evaluation_plan(&plan)),
    }))
}
pub(super) async fn resolve_evaluation_plan(
    service: &ChiseiServiceImpl,
    req: Request<ResolveEvaluationPlanRequest>,
) -> Result<Response<ResolveEvaluationPlanResponse>, Status> {
    let actor = authenticated_actor(&req);
    let request = from_proto_evaluation_resolution(
        req.into_inner()
            .resolution
            .ok_or_else(|| Status::invalid_argument("evaluation resolution required"))?,
    );
    let prepared = evaluation_manifest_domain::prepare_resolution_request(request, &actor)
        .map_err(map_evaluation_resource_error)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    if prepared.request.evaluation_time_ms > now_ms {
        return Err(Status::invalid_argument(
            "evaluation_time_ms cannot be in the future",
        ));
    }
    let outcome = evaluation_manifest_resolution::EvaluationManifestResolutionLifecycle::new(
        service.db.clone(),
        service.sekai_facts.clone(),
    )
    .resolve(&prepared)?;
    Ok(Response::new(to_proto_evaluation_resolution(&outcome)))
}
pub(super) async fn get_evaluation_gate_evidence(
    service: &ChiseiServiceImpl,
    req: Request<GetEvaluationGateEvidenceRequest>,
) -> Result<Response<GetEvaluationGateEvidenceResponse>, Status> {
    require_eval_reader(&req, &service.config)?;
    let request = req.into_inner();
    let suite_id = request.suite_id.trim();
    let release_digest = request.release_digest.trim();
    let artifact_digest = request.artifact_digest.trim();
    if suite_id.is_empty() {
        return Err(Status::invalid_argument("suite_id is required"));
    }
    if release_digest.is_empty() {
        return Err(Status::invalid_argument("release_digest is required"));
    }
    if artifact_digest.is_empty() {
        return Err(Status::invalid_argument("artifact_digest is required"));
    }
    if request.max_timestamp_ms <= 0 {
        return Err(Status::invalid_argument(
            "max_timestamp_ms must be positive",
        ));
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    if request.max_timestamp_ms > now_ms.saturating_add(EVALUATION_GATE_MAX_FUTURE_SKEW_MS) {
        return Err(Status::invalid_argument(
            "max_timestamp_ms is too far in the future",
        ));
    }

    let suite = service
        .eval
        .read_suite_for_gate(suite_id)
        .map_err(|error| {
            Status::unavailable(format!("evaluation gate evidence unavailable: {error}"))
        })?;
    let Some(suite) = suite else {
        return Ok(Response::new(GetEvaluationGateEvidenceResponse {
            status: EVALUATION_GATE_STATUS_SUITE_NOT_FOUND.into(),
            evidence: None,
        }));
    };
    if suite.cases.len() > MAX_EVALUATION_GATE_CASES {
        return Err(Status::resource_exhausted(
            "evaluation suite exceeds the gate evidence case limit",
        ));
    }
    let expected_case_ids = suite
        .cases
        .iter()
        .map(|case| case.id.clone())
        .collect::<Vec<_>>();
    let mut seen_case_ids = BTreeSet::new();
    if expected_case_ids
        .iter()
        .any(|case_id| case_id.trim().is_empty() || !seen_case_ids.insert(case_id.clone()))
    {
        return Err(Status::failed_precondition(
            "evaluation suite has empty or duplicate case ids",
        ));
    }

    let suite_digest = evaluation_gate_suite_digest(&suite);
    let expected_config_ref =
        evaluation_gate_config_ref(release_digest, artifact_digest, &suite_digest);
    let run = service
        .eval
        .read_latest_run_for_gate(suite_id, &expected_config_ref, request.max_timestamp_ms)
        .map_err(|error| {
            Status::unavailable(format!("evaluation gate evidence unavailable: {error}"))
        })?;
    let Some(run) = run else {
        return Ok(Response::new(GetEvaluationGateEvidenceResponse {
            status: EVALUATION_GATE_STATUS_NO_MATCHING_RUN.into(),
            evidence: None,
        }));
    };
    if run.results.len() > MAX_EVALUATION_GATE_RESULTS {
        return Err(Status::resource_exhausted(
            "evaluation run exceeds the gate evidence result limit",
        ));
    }
    let actual_case_ids = run
        .results
        .iter()
        .map(|result| result.case_id.as_str())
        .collect::<BTreeSet<_>>();
    let expected_case_ids_set = expected_case_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_case_ids.len() != run.results.len() || actual_case_ids != expected_case_ids_set {
        return Err(Status::failed_precondition(
            "selected evaluation run does not contain exactly one result for every suite case",
        ));
    }

    Ok(Response::new(GetEvaluationGateEvidenceResponse {
        status: EVALUATION_GATE_STATUS_FOUND.into(),
        evidence: Some(EvaluationGateEvidence {
            suite_id: suite.id,
            release_digest: release_digest.into(),
            artifact_digest: artifact_digest.into(),
            suite_digest,
            config_ref: expected_config_ref,
            run_id: run.id,
            run_timestamp: run.timestamp,
            expected_case_ids,
            results: run
                .results
                .into_iter()
                .map(|result| EvaluationGateCaseResult {
                    case_id: result.case_id,
                    passed: result.passed,
                })
                .collect(),
        }),
    }))
}
pub(super) async fn execute_evaluation_manifest(
    service: &ChiseiServiceImpl,
    req: Request<ExecuteEvaluationManifestRequest>,
) -> Result<Response<ExecuteEvaluationManifestResponse>, Status> {
    let actor = authenticated_actor(&req);
    let request =
        evaluation_execution_domain::prepare_execution_request(from_proto_evaluation_execution(
            req.into_inner()
                .execution
                .ok_or_else(|| Status::invalid_argument("evaluation execution required"))?,
        ))
        .map_err(map_evaluation_resource_error)?;
    require_namespace_write_access(service.sekai_facts.reader(), &actor, &request.namespace)?;
    let manifest = service
        .db
        .get_evaluation_manifest(&request.manifest_digest)
        .map_err(Status::internal)?
        .filter(|manifest| manifest.namespace == request.namespace)
        .ok_or_else(|| Status::not_found("evaluation manifest not found"))?;
    let facts =
        evaluation_manifest_resolution::in_process_facts_runtime_arc(service.sekai_facts.reader())?;
    let projection = service
        .evaluation_execution_lifecycle
        .execute(&manifest, &actor, request.max_total_duration_ms, facts)
        .await?;
    Ok(Response::new(ExecuteEvaluationManifestResponse {
        execution: Some(to_proto_evaluation_execution_projection(&projection)),
    }))
}

/// The wire answer for a finished dataset run.
fn run_response(report: crate::chisei::eval_run::EvalRunReport) -> RunEvalDatasetResponse {
    RunEvalDatasetResponse {
        failure_groups: report
            .failure_groups
            .into_iter()
            .map(|group| EvalFailureGroup {
                dimension: group.dimension.as_str().into(),
                key: group.key,
                trial_code: group.trial_code.unwrap_or_default(),
                count: u32::try_from(group.case_ids.len()).unwrap_or(u32::MAX),
                case_ids: group.case_ids,
            })
            .collect(),
        status: report.status,
        cases_total: report.cases_total as u32,
        spent_micros: report.spent_micros,
        ledger: report
            .results
            .into_iter()
            .map(|result| EvalRunCaseLine {
                case_id: result.case_id,
                passed: result.outcome.passed,
                reason: result.outcome.reason,
                trial_code: result.outcome.trial_code.unwrap_or_default(),
                unmet_metrics: result.outcome.unmet_metrics,
                input_tokens: result.outcome.input_tokens,
                output_tokens: result.outcome.output_tokens,
                cost_micros: result.outcome.cost_micros,
            })
            .collect(),
        unrun_case_ids: report.unrun_cases,
        uncertain_micros: report.uncertain_micros,
        policy_scorer_version: report.policy.scorer_version,
        policy_counts: report
            .policy
            .counts
            .into_iter()
            .map(|(kind, count)| EvalPolicyCount {
                kind: kind.as_str().into(),
                count,
            })
            .collect(),
        policy_violations: report
            .policy
            .violations
            .into_iter()
            .map(|violation| EvalPolicyViolation {
                kind: violation.kind.as_str().into(),
                case_id: violation.case_id,
                receipt_id: violation.receipt_id,
            })
            .collect(),
    }
}

/// Run a recorded dataset (ADR 0153): replay each decided proposal through
/// the agent dry run as the caller and score it against the human decision.
/// Nothing is submitted, so no Action instance, receipt or effect is created.
async fn run_recorded_dataset(
    service: &ChiseiServiceImpl,
    caller: Request<()>,
    spec: crate::chisei::eval_run::EvalRunSpec,
    dataset: crate::chisei::eval_dataset::EvalDataset,
    actor: String,
) -> Result<Response<RunEvalDatasetResponse>, Status> {
    use crate::chisei::eval_dataset::recorded::RecordedEvalDatasetStore;
    use crate::chisei::eval_run::{RUN_CONFLICT, RUN_IN_PROGRESS, run_as};
    use crate::composition::recorded_eval_cases::RecordedCaseExecutor;
    let sekai = service.in_process_sekai_service()?;
    let store = service.db.runtime_arc();
    let report = tokio::task::spawn_blocking(move || {
        let stored = store
            .get_recorded_eval_dataset(&spec.namespace, &spec.dataset, Some(&spec.dataset_version))
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found(crate::chisei::eval_dataset::DATASET_NOT_FOUND))?;
        let executor = RecordedCaseExecutor::prepare(
            &sekai,
            caller,
            &spec.namespace,
            &stored.definition,
            &spec.agent,
        )?;
        run_as(store.as_ref(), &executor, &spec, &dataset, &actor, || {
            chrono::Utc::now().timestamp_millis()
        })
        .map_err(|error| {
            if error == RUN_CONFLICT {
                Status::already_exists(error)
            } else if error == RUN_IN_PROGRESS {
                Status::aborted(error)
            } else {
                Status::internal(error)
            }
        })
    })
    .await
    .map_err(|_| Status::internal("eval run task failed"))??;
    Ok(Response::new(run_response(report)))
}

pub(super) async fn run_eval_dataset(
    service: &ChiseiServiceImpl,
    req: Request<RunEvalDatasetRequest>,
) -> Result<Response<RunEvalDatasetResponse>, Status> {
    use crate::chisei::eval_run::{
        DefinitionCaseExecutor, EVAL_RUN_CONTRACT, EvalRunSpec, RUN_CONFLICT, RUN_IN_PROGRESS,
        run_as,
    };
    let actor = authenticated_actor(&req);
    let context = enterprise_authenticated_context(&req)?.cloned();
    let caller = crate::composition::recorded_eval_cases::caller_of(&req);
    let request = req.into_inner();
    // A tenant context (#3089) writes only its tenant's namespaces; any other
    // caller needs an editor or admin grant.
    match context.as_ref() {
        Some(context) => require_enterprise_namespace(
            service.sekai_facts.reader(),
            context,
            &request.namespace,
            crate::enterprise::NamespaceAction::Write,
        )?,
        None => require_namespace_write_access(
            service.sekai_facts.reader(),
            &actor,
            &request.namespace,
        )?,
    }
    // Binding a run to a release artifact attests that its results are that
    // release's evaluation, so it takes the authority that exports them.
    if !request.artifact_digest.is_empty() {
        super::rpc_model_release_evidence::require_release_admin(
            service,
            &actor,
            context.as_ref(),
        )?;
    }
    let definition = service
        .db
        .get_evaluator_definition(&request.evaluator_definition_id)
        .map_err(Status::internal)?
        .filter(|definition| definition.namespace == request.namespace)
        .ok_or_else(|| Status::not_found("evaluator definition not found"))?;
    let spec = EvalRunSpec {
        contract_version: EVAL_RUN_CONTRACT.into(),
        namespace: request.namespace,
        run_id: request.run_id,
        dataset: request.dataset,
        dataset_version: request.dataset_version,
        agent: request.agent,
        model: request.model,
        tool_version: request.tool_version,
        evaluator_definition_id: definition.definition_id.clone(),
        evaluator_digest: definition.content_digest.clone(),
        concurrency: request.concurrency,
        budget_micros: request.budget_micros,
        max_case_cost_micros: request.max_case_cost_micros,
    };
    spec.validate().map_err(Status::invalid_argument)?;
    let artifact_digest = request.artifact_digest;
    if !artifact_digest.is_empty()
        && !artifact_digest
            .strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(Status::invalid_argument(
            "artifact_digest must be sha256:<64 hex>",
        ));
    }
    let dataset = {
        let (store, spec) = (service.db.runtime_arc(), spec.clone());
        tokio::task::spawn_blocking(move || {
            super::rpc_eval_datasets::resolve_dataset(
                store.as_ref(),
                &spec.namespace,
                &spec.dataset,
                &spec.dataset_version,
            )
        })
        .await
        .map_err(|_| Status::internal("eval dataset task failed"))??
    };
    if crate::chisei::eval_dataset::recorded::is_recorded_dataset(&dataset) {
        if !artifact_digest.is_empty() {
            return Err(Status::failed_precondition(
                "a recorded eval dataset run cannot be bound to a release artifact",
            ));
        }
        return run_recorded_dataset(service, caller, spec, dataset, actor).await;
    }
    let pricing = crate::cost_estimate::pricing_from_env()
        .map_err(|_| Status::failed_precondition("model pricing is misconfigured"))?
        .remove(&spec.model);
    if let Some(policy) = &definition.stochastic_policy
        && !service
            .evaluation_execution_lifecycle
            .stochastic_egress_allowed(policy)
    {
        return Err(Status::failed_precondition(
            evaluation_execution_domain::REASON_STOCHASTIC_EGRESS_DENIED,
        ));
    }
    let (deterministic, stochastic, budget) = service.evaluation_execution_lifecycle.registries();
    let store = service.db.runtime_arc();
    let report = tokio::task::spawn_blocking(move || {
        let executor = DefinitionCaseExecutor {
            definition: &definition,
            deterministic: &deterministic,
            stochastic: &stochastic,
            pricing,
            budget: &budget,
        };
        executor.check(&spec).map_err(Status::failed_precondition)?;
        // Only a run whose evaluator runs on the model can stand for it.
        if !artifact_digest.is_empty() && definition.stochastic_policy.is_none() {
            return Err(Status::failed_precondition(
                "only a run whose evaluator runs on the model can be bound to a release artifact",
            ));
        }
        if !artifact_digest.is_empty() {
            bind_artifact(store.as_ref(), &spec, &artifact_digest)?;
        }
        // Case receipts name the caller, so the operation workspace shows
        // each case to the principal that ran it (#2694).
        run_as(store.as_ref(), &executor, &spec, &dataset, &actor, || {
            chrono::Utc::now().timestamp_millis()
        })
        .map_err(|error| {
            if error == RUN_CONFLICT {
                Status::already_exists(error)
            } else if error == RUN_IN_PROGRESS {
                Status::aborted(error)
            } else {
                Status::internal(error)
            }
        })
    })
    .await
    .map_err(|_| Status::internal("eval run task failed"))??;
    Ok(Response::new(run_response(report)))
}

/// Records a new run bound to the released artifact it evaluates (#1677),
/// atomically with the run itself. A run started without an artifact, by
/// this or an older version, can never be bound later, so its results never
/// become evidence for an artifact; a bound run keeps its artifact.
fn bind_artifact(
    store: &crate::db::runtime_db::RuntimeDb,
    spec: &crate::chisei::eval_run::EvalRunSpec,
    artifact_digest: &str,
) -> Result<(), Status> {
    let (stored, bound) = store
        .put_bound_dataset_run(spec, artifact_digest, chrono::Utc::now().timestamp_millis())
        .map_err(Status::internal)?;
    if stored != *spec {
        return Err(Status::already_exists(
            crate::chisei::eval_run::RUN_CONFLICT,
        ));
    }
    if bound.as_deref() == Some(artifact_digest) {
        Ok(())
    } else {
        Err(Status::already_exists(
            "eval run id is already used without this artifact",
        ))
    }
}

/// Loads two recorded eval dataset runs of `namespace` and compares them
/// (#1677). Returns the comparison, the candidate's spec, and the artifact the
/// candidate is bound to.
pub(super) async fn compare_dataset_runs_bound(
    service: &ChiseiServiceImpl,
    namespace: &str,
    baseline_run_id: &str,
    candidate_run_id: &str,
    gate: crate::chisei::eval_compare::ComparisonGate,
) -> Result<
    (
        crate::chisei::eval_compare::RunComparison,
        crate::chisei::eval_run::EvalRunSpec,
        Option<String>,
    ),
    Status,
> {
    let detailed =
        compare_dataset_runs_detailed(service, namespace, baseline_run_id, candidate_run_id, gate)
            .await?;
    Ok((detailed.comparison, detailed.candidate, detailed.artifact))
}

/// A comparison with the cases behind its counts, read once so the counts and
/// the case list cannot disagree.
pub(super) struct DetailedComparison {
    pub comparison: crate::chisei::eval_compare::RunComparison,
    pub candidate: crate::chisei::eval_run::EvalRunSpec,
    pub artifact: Option<String>,
    /// Every case that did not pass in both runs, in dataset order.
    pub differences: Vec<crate::chisei::eval_compare::CaseDifference>,
}

async fn compare_dataset_runs_detailed(
    service: &ChiseiServiceImpl,
    namespace: &str,
    baseline_run_id: &str,
    candidate_run_id: &str,
    gate: crate::chisei::eval_compare::ComparisonGate,
) -> Result<DetailedComparison, Status> {
    use crate::chisei::eval_compare::{ComparedRun, case_differences, compare_runs};
    use crate::chisei::eval_run::EvalRunStore;
    let store = service.db.runtime_arc();
    let (namespace, baseline_run_id, candidate_run_id) = (
        namespace.to_string(),
        baseline_run_id.to_string(),
        candidate_run_id.to_string(),
    );
    tokio::task::spawn_blocking(move || {
        let runs = store
            .list_dataset_runs(&namespace)
            .map_err(Status::internal)?;
        let spec_of = |run_id: &str| {
            runs.iter()
                .find(|(spec, _)| spec.run_id == run_id)
                .map(|(spec, _)| spec.clone())
                .ok_or_else(|| Status::not_found("eval run not found"))
        };
        let (baseline, candidate) = (spec_of(&baseline_run_id)?, spec_of(&candidate_run_id)?);
        let dataset = super::rpc_eval_datasets::resolve_dataset(
            store.as_ref(),
            &candidate.namespace,
            &candidate.dataset,
            &candidate.dataset_version,
        )?;
        let results = |spec: &crate::chisei::eval_run::EvalRunSpec| {
            store
                .list_dataset_run_cases(&spec.namespace, &spec.run_id)
                .map_err(Status::internal)
        };
        let (before, after) = (results(&baseline)?, results(&candidate)?);
        let baseline_run = ComparedRun {
            spec: &baseline,
            results: &before,
        };
        let candidate_run = ComparedRun {
            spec: &candidate,
            results: &after,
        };
        let comparison = compare_runs(&dataset, baseline_run, candidate_run, gate)
            .map_err(Status::failed_precondition)?;
        let baseline_run = ComparedRun {
            spec: &baseline,
            results: &before,
        };
        let candidate_run = ComparedRun {
            spec: &candidate,
            results: &after,
        };
        let differences = case_differences(&dataset, &baseline_run, &candidate_run);
        let artifact = store
            .dataset_run_artifact(&candidate.namespace, &candidate.run_id)
            .map_err(Status::internal)?;
        Ok(DetailedComparison {
            comparison,
            candidate,
            artifact,
            differences,
        })
    })
    .await
    .map_err(|_| Status::internal("eval comparison task failed"))?
}

/// The gate a request asks for: `alpha` 0 is the default.
pub(super) fn comparison_gate(
    alpha: f64,
    allow_policy_increase: bool,
) -> crate::chisei::eval_compare::ComparisonGate {
    crate::chisei::eval_compare::ComparisonGate {
        alpha: if alpha == 0.0 {
            crate::chisei::eval_compare::DEFAULT_ALPHA
        } else {
            alpha
        },
        block_on_policy_increase: !allow_policy_increase,
    }
}

/// Default and maximum page of `differing_cases`; the plane owns the cap.
const DEFAULT_COMPARISON_CASE_PAGE: usize = 50;
const MAX_COMPARISON_CASE_PAGE: usize = 200;

/// One page of the cases behind a comparison's counts. The page token is the
/// offset into the dataset-ordered list, which the same two runs always
/// produce in the same order.
fn comparison_case_page(
    differences: Vec<crate::chisei::eval_compare::CaseDifference>,
    request: &CompareEvalDatasetRunsRequest,
) -> Result<(Vec<EvalCaseDifference>, String), Status> {
    let offset = if request.page_token.is_empty() {
        0
    } else {
        request
            .page_token
            .parse::<usize>()
            .map_err(|_| Status::invalid_argument("invalid page token"))?
    };
    let limit = match request.case_limit as usize {
        0 => DEFAULT_COMPARISON_CASE_PAGE,
        requested => requested.min(MAX_COMPARISON_CASE_PAGE),
    };
    let mut listed = differences
        .into_iter()
        .filter(|case| request.include_both_failed || case.baseline_passed != case.candidate_passed)
        .skip(offset);
    let page: Vec<_> = listed.by_ref().take(limit).collect();
    let next_page_token = if listed.next().is_some() {
        (offset + page.len()).to_string()
    } else {
        String::new()
    };
    let page = page
        .into_iter()
        .map(|case| EvalCaseDifference {
            case_id: case.case_id,
            tags: case.tags,
            baseline_passed: case.baseline_passed,
            candidate_passed: case.candidate_passed,
            candidate_violations: case
                .candidate_violations
                .into_iter()
                .map(|kind| kind.as_str().to_string())
                .collect(),
        })
        .collect();
    Ok((page, next_page_token))
}

pub(super) async fn compare_eval_dataset_runs(
    service: &ChiseiServiceImpl,
    req: Request<CompareEvalDatasetRunsRequest>,
) -> Result<Response<CompareEvalDatasetRunsResponse>, Status> {
    // Admitted for tenant assertions (#3056).
    require_request_namespace_read(service.sekai_facts.reader(), &req, &req.get_ref().namespace)?;
    let request = req.into_inner();
    let detailed = compare_dataset_runs_detailed(
        service,
        &request.namespace,
        &request.baseline_run_id,
        &request.candidate_run_id,
        comparison_gate(request.alpha, request.allow_policy_increase),
    )
    .await?;
    let comparison = detailed.comparison;
    let (differing_cases, next_page_token) = if request.include_cases {
        comparison_case_page(detailed.differences, &request)?
    } else {
        (Vec::new(), String::new())
    };
    Ok(Response::new(CompareEvalDatasetRunsResponse {
        dataset: comparison.dataset,
        dataset_version: comparison.dataset_version,
        cases: comparison.cases,
        both_passed: comparison.both_passed,
        both_failed: comparison.both_failed,
        regressions: comparison.regressions,
        improvements: comparison.improvements,
        p_value: comparison.p_value,
        alpha: comparison.alpha,
        significant_regression: comparison.significant_regression,
        policy: comparison
            .policy
            .into_iter()
            .map(|delta| EvalPolicyDelta {
                kind: delta.kind,
                baseline: delta.baseline,
                candidate: delta.candidate,
            })
            .collect(),
        policy_increased: comparison.policy_increased,
        verdict: comparison.verdict,
        reasons: comparison.reasons,
        cases_truncated: !next_page_token.is_empty(),
        differing_cases,
        next_page_token,
    }))
}

pub(super) async fn list_eval_dataset_run_trend(
    service: &ChiseiServiceImpl,
    req: Request<ListEvalDatasetRunTrendRequest>,
) -> Result<Response<ListEvalDatasetRunTrendResponse>, Status> {
    use crate::chisei::eval_run::EvalRunStore;
    // Admitted for tenant assertions (#3056).
    require_request_namespace_read(service.sekai_facts.reader(), &req, &req.get_ref().namespace)?;
    let request = req.into_inner();
    let store = service.db.runtime_arc();
    let runs = tokio::task::spawn_blocking(move || {
        store
            .list_dataset_runs(&request.namespace)
            .map_err(Status::internal)?
            .into_iter()
            .filter(|(spec, _)| spec.dataset == request.dataset)
            .map(|(spec, started_at_ms)| {
                let results = store
                    .list_dataset_run_cases(&spec.namespace, &spec.run_id)
                    .map_err(Status::internal)?;
                let point =
                    crate::chisei::eval_compare::trend_point(&spec, started_at_ms, &results);
                Ok(EvalRunTrendPoint {
                    run_id: point.run_id,
                    agent: point.agent,
                    model: point.model,
                    tool_version: point.tool_version,
                    dataset_version: point.dataset_version,
                    started_at_ms: point.started_at_ms,
                    cases_recorded: point.cases_recorded,
                    cases_passed: point.cases_passed,
                    policy: point
                        .policy
                        .into_iter()
                        .map(|(kind, count)| EvalPolicyCount { kind, count })
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, Status>>()
    })
    .await
    .map_err(|_| Status::internal("eval trend task failed"))??;
    Ok(Response::new(ListEvalDatasetRunTrendResponse { runs }))
}

pub(super) async fn cancel_evaluation_execution(
    service: &ChiseiServiceImpl,
    req: Request<CancelEvaluationExecutionRequest>,
) -> Result<Response<CancelEvaluationExecutionResponse>, Status> {
    let actor = authenticated_actor(&req);
    let request = req.into_inner();
    let validated = evaluation_execution_domain::prepare_execution_request(
        evaluation_execution_domain::EvaluationExecutionRequest {
            contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
            executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
            namespace: request.namespace,
            manifest_digest: request.manifest_digest,
            max_total_duration_ms: evaluation_execution_domain::DEFAULT_TOTAL_DURATION_MS,
        },
    )
    .map_err(map_evaluation_resource_error)?;
    require_namespace_write_access(service.sekai_facts.reader(), &actor, &validated.namespace)?;
    let manifest = service
        .db
        .get_evaluation_manifest(&validated.manifest_digest)
        .map_err(Status::internal)?
        .filter(|manifest| manifest.namespace == validated.namespace)
        .ok_or_else(|| Status::not_found("evaluation execution not found"))?;
    let index = service
        .db
        .get_evaluation_execution_index(&validated.manifest_digest)
        .map_err(Status::internal)?
        .filter(|index| index.namespace == validated.namespace)
        .ok_or_else(|| Status::not_found("evaluation execution not found"))?;
    let facts =
        evaluation_manifest_resolution::in_process_facts_runtime_arc(service.sekai_facts.reader())?;
    let projection = service
        .evaluation_execution_lifecycle
        .cancel(&manifest, &index, &actor, facts)
        .await?;
    Ok(Response::new(CancelEvaluationExecutionResponse {
        execution: Some(to_proto_evaluation_execution_projection(&projection)),
    }))
}

/// Lists the routing profiles a namespace may pin. Namespace read access is
/// required; visibility is not permission to route (#1094).
pub(super) async fn list_routing_profiles(
    service: &ChiseiServiceImpl,
    req: Request<ListRoutingProfilesRequest>,
) -> Result<Response<ListRoutingProfilesResponse>, Status> {
    let registry = service.refresh_provider_registry_for_resolution().await?;
    let actor = authenticated_actor(&req);
    let context = enterprise_authenticated_context(&req)?.cloned();
    let namespace = req.into_inner().namespace;
    if namespace.trim().is_empty() || namespace.trim() != namespace {
        return Err(Status::invalid_argument("canonical namespace required"));
    }
    require_execution_namespace_access_with_context(
        service.db.runtime(),
        service.sekai_facts.reader(),
        &service.config,
        &actor,
        context.as_ref(),
        &namespace,
    )?;
    let hosted = hosted_profiles_for(service, &namespace)?;
    let profiles = crate::chisei::routing_profiles::list_routing_profiles(&registry)
        .into_iter()
        .map(|profile| routing_profile_to_proto(profile, None))
        .chain(
            hosted
                .iter()
                .map(|profile| routing_profile_to_proto(profile.entry(), Some(profile))),
        )
        .collect();
    Ok(Response::new(ListRoutingProfilesResponse {
        profiles,
        contract_version: crate::chisei::routing_profiles::ROUTING_PROFILES_CONTRACT.into(),
    }))
}

/// `hosted` carries the customer-hosted fields; provider entries have none.
fn routing_profile_to_proto(
    profile: crate::chisei::routing_profiles::RoutingProfileEntry,
    hosted: Option<&crate::chisei::routing_profiles::HostedRoutingProfile>,
) -> RoutingProfile {
    RoutingProfile {
        profile_id: profile.profile_id,
        mode: profile.mode,
        runtime: profile.runtime,
        model_patterns: profile.model_patterns,
        lifecycle: profile.lifecycle,
        endpoint_origin: hosted
            .map(|hosted| hosted.endpoint_origin.clone())
            .unwrap_or_default(),
        artifact_digest: hosted
            .and_then(|hosted| hosted.artifact_digest.clone())
            .unwrap_or_default(),
        require_runtime_evidence: hosted
            .map(|profile| profile.require_runtime_evidence)
            .unwrap_or(false),
        evidence_provider: hosted
            .map(|profile| profile.evidence_provider.clone())
            .unwrap_or_default(),
        evidence_model: hosted
            .map(|profile| profile.evidence_model.clone())
            .unwrap_or_default(),
        evidence_profile_version: hosted
            .map(|profile| profile.evidence_profile_version.clone())
            .unwrap_or_default(),
        evidence_artifact_digest: hosted
            .map(|profile| profile.evidence_artifact_digest.clone())
            .unwrap_or_default(),
        evidence_endpoint: hosted
            .map(|profile| profile.evidence_endpoint.clone())
            .unwrap_or_default(),
    }
}

/// The namespace's hosted profiles whose origin the operator still allows.
fn hosted_profiles_for(
    service: &ChiseiServiceImpl,
    namespace: &str,
) -> Result<Vec<crate::chisei::routing_profiles::HostedRoutingProfile>, Status> {
    #[cfg(test)]
    HOSTED_PROFILE_LISTS.with(|count| count.set(count.get() + 1));
    let stored = service
        .db
        .list_hosted_routing_profiles(namespace)
        .map_err(|_| Status::internal("routing profiles unavailable"))?;
    Ok(crate::chisei::routing_profiles::admissible_hosted_profiles(
        stored,
        &service.config.routing_endpoint_allowlist,
    ))
}

#[cfg(test)]
thread_local! {
    static HOSTED_PROFILE_LISTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_hosted_profile_list_count() {
    HOSTED_PROFILE_LISTS.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn hosted_profile_list_count() -> usize {
    HOSTED_PROFILE_LISTS.with(|count| count.get())
}

fn routing_profile_admission_status(error: String) -> Status {
    let (code, message) = error.split_once(": ").unwrap_or(("internal", &error));
    match code {
        "invalid_argument" => Status::invalid_argument(message),
        "permission_denied" => Status::permission_denied(message),
        "failed_precondition" => Status::failed_precondition(message),
        _ => Status::internal("routing profile unavailable"),
    }
}

/// Registers a customer-hosted routing profile in one namespace (#1171).
pub(super) async fn put_routing_profile(
    service: &ChiseiServiceImpl,
    req: Request<PutRoutingProfileRequest>,
) -> Result<Response<PutRoutingProfileResponse>, Status> {
    let actor = authenticated_actor(&req);
    let context = enterprise_authenticated_context(&req)?.cloned();
    let request = req.into_inner();
    require_namespace_admin_access(
        service.sekai_facts.reader(),
        &actor,
        context.as_ref(),
        &request.namespace,
    )?;
    let profile = crate::chisei::routing_profiles::admit_hosted_profile(
        crate::chisei::routing_profiles::HostedRoutingProfileInput {
            namespace: request.namespace,
            name: request.name,
            endpoint_url: request.endpoint_url,
            model_patterns: request.model_patterns,
            credential_ref: request.credential_ref,
            artifact_digest: request.artifact_digest,
            require_runtime_evidence: request.require_runtime_evidence,
            evidence_provider: request.evidence_provider,
            evidence_model: request.evidence_model,
            evidence_profile_version: request.evidence_profile_version,
            evidence_artifact_digest: request.evidence_artifact_digest,
            evidence_endpoint: request.evidence_endpoint,
        },
        &service.config.routing_endpoint_allowlist,
        |reference| {
            service
                .config
                .routing_credential_refs
                .iter()
                .any(|known| known == reference)
        },
        &actor,
        chrono::Utc::now().timestamp_millis(),
    )
    .map_err(routing_profile_admission_status)?;
    if profile.require_runtime_evidence {
        crate::chisei::model_release_evidence::identity_from_hosted_profile(&profile)
            .map_err(Status::invalid_argument)?;
    }
    service
        .db
        .put_hosted_routing_profile(&profile)
        .map_err(|_| Status::internal("routing profile unavailable"))?;
    #[cfg(test)]
    {
        let _ = crate::chisei::model_review::set_family_enablement(
            &service.db,
            crate::chisei::model_review::FamilyEnablementRecord {
                namespace: profile.namespace.clone(),
                region_label: String::new(),
                family_id: crate::chisei::routing_profiles::hosted_runtime(&profile),
                status: crate::chisei::model_review::ModelReviewStatus::Enabled,
                actor: actor.clone(),
                reason: "test hosted registration".into(),
                updated_at_ms: profile.registered_at_ms,
            },
        );
    }
    Ok(Response::new(PutRoutingProfileResponse {
        profile: Some(routing_profile_to_proto(profile.entry(), Some(&profile))),
    }))
}

/// Revokes a customer-hosted routing profile; later pins fail closed.
pub(super) async fn revoke_routing_profile(
    service: &ChiseiServiceImpl,
    req: Request<RevokeRoutingProfileRequest>,
) -> Result<Response<RevokeRoutingProfileResponse>, Status> {
    let actor = authenticated_actor(&req);
    let context = enterprise_authenticated_context(&req)?.cloned();
    let request = req.into_inner();
    require_namespace_admin_access(
        service.sekai_facts.reader(),
        &actor,
        context.as_ref(),
        &request.namespace,
    )?;
    let revoked = service
        .db
        .revoke_hosted_routing_profile(
            &request.namespace,
            &request.profile_id,
            chrono::Utc::now().timestamp_millis(),
        )
        .map_err(|_| Status::internal("routing profile unavailable"))?;
    Ok(Response::new(RevokeRoutingProfileResponse { revoked }))
}

/// The registry one planning request resolves against. The namespace's
/// admissible hosted routes are added only when the request can route to a
/// hosted runtime at all (#1185), and only after the caller passed the
/// namespace access check (#1187). Enterprise credentials get none.
fn planning_registry(
    service: &ChiseiServiceImpl,
    registry: crate::provider_profile::ProviderRegistry,
    actor: &str,
    context: Option<&crate::enterprise::AuthenticatedContext>,
    input: &ExecutionInput,
    pin: &str,
) -> Result<
    (
        crate::provider_profile::ProviderRegistry,
        Vec<crate::chisei::routing_profiles::HostedRoutingProfile>,
    ),
    Status,
> {
    if context.is_some()
        || input.namespace.trim().is_empty()
        || !hosted_route_possible(service, input, pin)
    {
        return Ok((registry, Vec::new()));
    }
    require_execution_namespace_access_with_context(
        service.db.runtime(),
        service.sekai_facts.reader(),
        &service.config,
        actor,
        context,
        &input.namespace,
    )?;
    let hosted = hosted_profiles_for(service, &input.namespace)?;
    if hosted.is_empty() {
        return Ok((registry, hosted));
    }
    Ok((
        registry.with_hosted_endpoints(&crate::chisei::routing_profiles::hosted_endpoints(&hosted)),
        hosted,
    ))
}

/// Whether a planning request can resolve to a hosted runtime: it pins or
/// names one, or its namespace policy admits one.
fn hosted_route_possible(service: &ChiseiServiceImpl, input: &ExecutionInput, pin: &str) -> bool {
    use crate::provider_profile::{hosted_provider_of, is_hosted_provider};
    pin.starts_with("hosted:")
        || hosted_provider_of(&input.preferred_model).is_some()
        || hosted_provider_of(&input.route_override).is_some()
        || is_hosted_provider(&input.preferred_runtime)
        || service
            .policy
            .effective_policy(&input.namespace)
            .is_some_and(|policy| {
                policy
                    .allowed_runtimes
                    .iter()
                    .any(|runtime| is_hosted_provider(runtime))
            })
}

/// Registering an endpoint grants nothing: a hosted route needs a namespace
/// policy that names its runtime explicitly (#1171).
fn require_hosted_route_policy(
    service: &ChiseiServiceImpl,
    namespace: &str,
    runtime: &str,
) -> Result<(), Status> {
    if crate::provider_profile::is_hosted_provider(runtime)
        && !service
            .policy
            .effective_policy(namespace)
            .is_some_and(|policy| {
                policy
                    .allowed_runtimes
                    .iter()
                    .any(|allowed| allowed == runtime)
            })
    {
        return Err(Status::failed_precondition(
            "hosted route requires a namespace policy that allows its runtime",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod comparison_case_page_tests {
    use super::*;
    use crate::chisei::eval_compare::CaseDifference;
    use crate::chisei::eval_policy::ViolationKind;

    fn difference(index: usize, baseline: bool, candidate: bool) -> CaseDifference {
        CaseDifference {
            case_id: format!("case-{index}"),
            tags: vec!["smoke".into()],
            baseline_passed: baseline,
            candidate_passed: candidate,
            candidate_violations: vec![ViolationKind::MarkingLeak],
        }
    }

    fn request(limit: u32, token: &str, both_failed: bool) -> CompareEvalDatasetRunsRequest {
        CompareEvalDatasetRunsRequest {
            include_cases: true,
            include_both_failed: both_failed,
            case_limit: limit,
            page_token: token.into(),
            ..Default::default()
        }
    }

    /// Pages follow dataset order, a truncated page names the next one, the
    /// plane caps the limit, and failed-in-both cases appear only on request.
    #[test]
    fn case_pages_are_ordered_bounded_and_filtered() {
        let all: Vec<_> = (0..5)
            .map(|index| difference(index, true, false))
            .chain([difference(5, false, false)])
            .collect();
        let (first, token) = comparison_case_page(all.clone(), &request(2, "", false)).unwrap();
        assert_eq!(
            first
                .iter()
                .map(|case| case.case_id.as_str())
                .collect::<Vec<_>>(),
            ["case-0", "case-1"]
        );
        assert_eq!(token, "2");
        let (last, token) = comparison_case_page(all.clone(), &request(2, "4", false)).unwrap();
        assert_eq!(last.len(), 1, "failed-in-both is not listed by default");
        assert!(token.is_empty());
        let (with_both, _) = comparison_case_page(all.clone(), &request(100, "", true)).unwrap();
        assert_eq!(with_both.len(), 6);
        assert_eq!(with_both[0].candidate_violations, ["marking_leak"]);
        let many: Vec<_> = (0..300)
            .map(|index| difference(index, true, false))
            .collect();
        let (capped, token) = comparison_case_page(many, &request(u32::MAX, "", false)).unwrap();
        assert_eq!(capped.len(), MAX_COMPARISON_CASE_PAGE);
        assert_eq!(token, MAX_COMPARISON_CASE_PAGE.to_string());
        let bad = comparison_case_page(all, &request(2, "nope", false)).unwrap_err();
        assert_eq!(bad.code(), tonic::Code::InvalidArgument);
    }
}
