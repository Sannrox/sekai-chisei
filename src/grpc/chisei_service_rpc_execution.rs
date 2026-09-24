use super::*;

pub(super) async fn plan_execution(
    service: &ChiseiServiceImpl,
    req: Request<PlanExecutionRequest>,
) -> Result<Response<PlanExecutionResponse>, Status> {
    let registry = service.refresh_provider_registry_for_resolution().await?;
    crate::provider_profile::with_provider_registry_snapshot(registry, async {
        let actor = authenticated_actor(&req);
        let context = enterprise_authenticated_context(&req)?.cloned();
        let request = req.into_inner();
        let mut input = request
            .input
            .ok_or(Status::invalid_argument("input required"))?;
        if context.is_some()
            && (!input.route_override.trim().is_empty() || request.gunshi_allocation.is_some())
        {
            return Err(Status::permission_denied(
                "enterprise execution route override or Gunshi allocation binding denied",
            ));
        }
        require_execution_namespace_access_with_context(
            service.db.runtime(),
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
        // A pin is checked against the live catalog after planning, so the
        // listing never acts as a grant (#1094).
        let pinned = request.routing_profile_id.trim();
        if !pinned.is_empty() {
            let hosted = hosted_profiles_for(service, &plan_namespace)?;
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
            .record_planned_operation_with_routing(&plan, &actor, !pinned.is_empty())
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
) -> Result<Response<<ChiseiServiceImpl as ChiseiService>::ExecutePlanStreamStream>, Status> {
    let actor = authenticated_actor(&req);
    let context = enterprise_authenticated_context(&req)?.cloned();
    let requested_plan = req
        .into_inner()
        .plan
        .ok_or(Status::invalid_argument("plan required"))?;
    let stream = service
        .execute_planned_stream(actor, context, requested_plan)
        .await?;
    Ok(Response::new(stream))
}
pub(super) async fn plan_content_execution(
    service: &ChiseiServiceImpl,
    req: Request<PlanContentExecutionRequest>,
) -> Result<Response<PlanContentExecutionResponse>, Status> {
    let registry = service.refresh_provider_registry_for_resolution().await?;
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
        if context.is_some()
            && (!execution.route_override.trim().is_empty() || request.gunshi_allocation.is_some())
        {
            return Err(Status::permission_denied(
                "enterprise execution route override or Gunshi allocation binding denied",
            ));
        }
        require_execution_namespace_access_with_context(
            service.db.runtime(),
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
            .record_planned_operation(execution_plan, &actor)
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
) -> Result<Response<<ChiseiServiceImpl as ChiseiService>::ExecuteContentPlanStreamStream>, Status>
{
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
pub(super) async fn list_kioku_candidates(
    service: &ChiseiServiceImpl,
    req: Request<ListKiokuCandidatesRequest>,
) -> Result<Response<ListKiokuCandidatesResponse>, Status> {
    require_team_namespace_access(
        service.db.runtime(),
        &service.config,
        &req,
        &req.get_ref().namespace,
    )?;
    let actor = authenticated_actor(&req);
    let request = req.into_inner();
    if request.namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace is required"));
    }
    let limit = match request.limit {
        0 => 50,
        1..=100 => request.limit as usize,
        _ => return Err(Status::invalid_argument("limit must not exceed 100")),
    };
    let operation_class = request.operation_class.trim().to_string();
    let page_token = request.page_token.trim();
    let cursor = kioku_candidate_governance::KiokuCandidateGovernance::decode_cursor(
        request.namespace.trim(),
        &operation_class,
        page_token,
    )?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let discovery = kioku_candidate_governance::KiokuCandidateGovernance::new(service.db.clone())
        .discover(kioku_candidate_governance::CandidateDiscoveryCommand {
        namespace: request.namespace.trim().to_string(),
        operation_class: operation_class.clone(),
        actor,
        limit,
        cursor,
        now_ms,
    })?;
    let candidates = discovery
        .memories
        .into_iter()
        .map(|memory| -> Result<KiokuCandidateRecord, Status> {
            let evidence = service
                .db
                .runtime()
                .list_kioku_evidence(&memory.id, memory.version)
                .map_err(Status::internal)?;
            let validation = service
                .db
                .runtime()
                .validate_kioku_candidate(&memory.id, memory.version)
                .map_err(Status::internal)?;
            Ok(KiokuCandidateRecord {
                memory_json: serde_json::to_string(&memory).map_err(|error| {
                    Status::internal(format!("failed to serialize memory: {error}"))
                })?,
                evidence_json: evidence
                    .iter()
                    .map(serde_json::to_string)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| {
                        Status::internal(format!("failed to serialize evidence: {error}"))
                    })?,
                valid: validation.valid,
                validation_errors: validation.errors,
                supporting_evidence: validation.supporting_evidence as u32,
                contradicting_evidence: validation.contradicting_evidence as u32,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next_page_token = if discovery.has_more {
        discovery
            .cursor
            .as_ref()
            .map_or_else(String::new, |cursor| {
                kioku_candidate_governance::KiokuCandidateGovernance::encode_cursor(
                    request.namespace.trim(),
                    &operation_class,
                    cursor,
                )
            })
    } else {
        String::new()
    };
    Ok(Response::new(ListKiokuCandidatesResponse {
        candidates,
        next_page_token,
    }))
}
pub(super) async fn issue_gunshi_recommendations(
    service: &ChiseiServiceImpl,
    req: Request<IssueGunshiRecommendationsRequest>,
) -> Result<Response<IssueGunshiRecommendationsResponse>, Status> {
    let actor = authenticated_actor(&req);
    let response = service.issue_recommendations_from_authenticated(actor, req.into_inner())?;
    Ok(Response::new(response))
}
pub(super) async fn set_gunshi_allocation_policy(
    service: &ChiseiServiceImpl,
    req: Request<SetGunshiAllocationPolicyRequest>,
) -> Result<Response<SetGunshiAllocationPolicyResponse>, Status> {
    let actor = authenticated_actor(&req);
    let response = service.set_allocation_policy_from_authenticated(actor, req.into_inner())?;
    Ok(Response::new(response))
}
pub(super) async fn get_gunshi_allocation_status(
    service: &ChiseiServiceImpl,
    req: Request<GetGunshiAllocationStatusRequest>,
) -> Result<Response<GetGunshiAllocationStatusResponse>, Status> {
    let actor = authenticated_actor(&req);
    let response = service.allocation_status_from_authenticated(actor, req.into_inner())?;
    Ok(Response::new(response))
}
pub(super) async fn review_kioku_memory(
    service: &ChiseiServiceImpl,
    req: Request<ReviewKiokuMemoryRequest>,
) -> Result<Response<ReviewKiokuMemoryResponse>, Status> {
    require_eval_admin(&req)?;
    let actor = authenticated_actor(&req);
    let request = req.into_inner();
    if request.memory_id.trim().is_empty() || request.memory_version == 0 {
        return Err(Status::invalid_argument(
            "memory id and version are required",
        ));
    }
    if request.action == "reassess" {
        if request.reassessment_key.trim().is_empty()
            || request.evidence_basis_json.is_empty()
            || request.evidence_basis_json.len() > 128
        {
            return Err(Status::invalid_argument(
                "reassess requires a key and one to 128 evidence basis records",
            ));
        }
        let evidence_basis = request
            .evidence_basis_json
            .iter()
            .map(|json| {
                serde_json::from_str::<crate::chisei::kioku::KiokuEvidenceBasis>(json).map_err(
                    |error| Status::invalid_argument(format!("invalid evidence basis: {error}")),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let result = kioku_candidate_governance::KiokuCandidateGovernance::new(service.db.clone())
            .review(
                kioku_candidate_governance::CandidateReviewCommand::Reassess {
                    memory_id: request.memory_id,
                    memory_version: request.memory_version,
                    reassessment_key: request.reassessment_key,
                    actor,
                    evidence_basis,
                    now_ms: chrono::Utc::now().timestamp_millis(),
                },
            )?;
        return Ok(Response::new(ReviewKiokuMemoryResponse {
            memory_json: serde_json::to_string(&result.memory)
                .map_err(|error| Status::internal(error.to_string()))?,
            lifecycle_events_json: result
                .lifecycle_events
                .iter()
                .map(serde_json::to_string)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| Status::internal(error.to_string()))?,
            evidence_json: result
                .evidence
                .iter()
                .map(serde_json::to_string)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| Status::internal(error.to_string()))?,
            idempotent: result.idempotent,
        }));
    }
    if request.rationale.trim().is_empty() {
        return Err(Status::invalid_argument("review rationale is required"));
    }
    let result = kioku_candidate_governance::KiokuCandidateGovernance::new(service.db.clone())
        .review(kioku_candidate_governance::CandidateReviewCommand::Human {
            memory_id: request.memory_id,
            memory_version: request.memory_version,
            action: request.action,
            actor,
            rationale: request.rationale,
            now_ms: chrono::Utc::now().timestamp_millis(),
        })?;
    Ok(Response::new(ReviewKiokuMemoryResponse {
        memory_json: serde_json::to_string(&result.memory)
            .map_err(|error| Status::internal(error.to_string()))?,
        lifecycle_events_json: result
            .lifecycle_events
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| Status::internal(error.to_string()))?,
        evidence_json: result
            .evidence
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| Status::internal(error.to_string()))?,
        idempotent: result.idempotent,
    }))
}
pub(super) async fn get_sample_observation(
    service: &ChiseiServiceImpl,
    req: Request<GetSampleObservationRequest>,
) -> Result<Response<GetSampleObservationResponse>, Status> {
    let actor = require_telemetry_reader(&req, &service.config)?;
    let request = req.into_inner();
    let request_id = request.request_id.as_str();
    let namespace = request.namespace.as_str();
    if request_id.trim().is_empty() {
        return Err(Status::invalid_argument("request_id required"));
    }
    if namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    if !matches!(actor.as_str(), "root" | "local") {
        require_namespace_access(service.db.runtime(), &actor, namespace.trim())?;
    }
    let observation = service
        .db
        .runtime()
        .get_sample_observation_in_namespace(request_id, namespace)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("sample observation not found"))?;
    let state = "recorded";
    Ok(Response::new(GetSampleObservationResponse {
        observation: Some(SampleObservationReadback {
            request_id: observation.request_id.clone(),
            namespace: observation.namespace.clone(),
            observation_digest: sample_observation_readback_digest(
                &observation.request_id,
                &observation.namespace,
                state,
                observation.timestamp,
            ),
            state: state.into(),
            observed_at: observation.timestamp,
            read_at: chrono::Utc::now().timestamp_millis(),
        }),
    }))
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
    let actor = authenticated_actor(&req);
    let auth_source = req
        .metadata()
        .get(AUTH_SOURCE_HEADER)
        .and_then(|value| value.to_str().ok());
    let configured_gateway = service
        .config
        .gateway_receipt_principals
        .iter()
        .any(|principal| principal == &actor)
        && auth_source == Some("token");
    if !configured_gateway && !matches!(actor.as_str(), "root" | "local" | "chisei-gateway") {
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
        .runtime()
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
        .runtime()
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
                .runtime()
                .find_gateway_receipt_by_logical_operation_id(operation_id, Some(attempt))
            {
                Ok(Some(receipt)) => Ok(Some(receipt)),
                Ok(None) if attempt == 1 => {
                    service.db.runtime().get_operation_receipt(operation_id)
                }
                Ok(None) => Ok(None),
                Err(error) => Err(error),
            }
        } else {
            let exact = service.db.runtime().get_operation_receipt(operation_id);
            let derived = service
                .db
                .runtime()
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
        let privileged = matches!(actor.as_str(), "root" | "local" | "chisei-gateway");
        if !privileged {
            return Err(Status::permission_denied(
                "opaque request alias lookup requires administrative inspection access",
            ));
        }
        let alias_lookup = || {
            service
                .db
                .runtime()
                .find_operation_receipt_by_lookup_request_id(
                    request_id,
                    (!caller_scope.is_empty()).then_some(caller_scope),
                    None,
                )
        };
        if caller_scope.is_empty() {
            match service
                .db
                .runtime()
                .find_operation_receipt_by_request_id(request_id)
            {
                Ok(Some(receipt)) => Ok(Some(receipt)),
                Ok(None) => alias_lookup(),
                Err(error) => Err(error),
            }
        } else {
            match alias_lookup() {
                Ok(Some(receipt)) => Ok(Some(receipt)),
                Ok(None) => service
                    .db
                    .runtime()
                    .find_operation_receipt_by_request_id(request_id),
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
    })?;
    let mut receipt = match receipt {
        Some(receipt) => receipt,
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
            crate::chisei::cross_store_admission::hop_projection_receipt(operation_id, &commit)
        }
    };
    if receipt.operation_class != "sekai_commit_projection"
        && let Some(lookup) = &service.sekai_commit_lookup
        && let Ok(Some(commit)) = lookup.lookup_commit(&receipt.operation_id)
    {
        crate::chisei::cross_store_admission::project_commit_handles(&mut receipt, &commit);
    }
    if actor != receipt.initiating_actor
            // The UDS interceptor assigns `local`; local socket access is the
            // administrative inspection boundary used by sekaictl. This
            // exception is read-only and is not accepted by mutation RPCs.
            && !matches!(actor.as_str(), "root" | "local" | "chisei-gateway")
    {
        return Err(Status::permission_denied(
            "operation receipt is not visible to this principal",
        ));
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
pub(super) async fn get_quality_trend(
    service: &ChiseiServiceImpl,
    req: Request<GetQualityTrendRequest>,
) -> Result<Response<GetQualityTrendResponse>, Status> {
    let actor = authenticated_actor(&req);
    let request = req.into_inner();
    let namespace = canonical_namespace(&request.namespace)?.to_string();
    require_namespace_access(service.db.runtime(), &actor, &namespace)?;
    let report = crate::quality_trend::query_quality_trends(
        service.db.runtime(),
        &actor,
        &namespace,
        request.since_ms,
        request.until_ms,
    )
    .map_err(map_quality_trend_error)?;
    Ok(Response::new(GetQualityTrendResponse {
        report: Some(quality_trend_report_to_proto(&report)),
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
            .runtime()
            .get_evaluator_definition(&request.definition_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::failed_precondition("evaluator definition not found"))?;
        require_namespace_write_access(service.db.runtime(), &actor, &definition.namespace)?;
        let availability = service
            .db
            .runtime()
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
    require_namespace_write_access(service.db.runtime(), &actor, &definition.namespace)?;
    let definition = service
        .db
        .runtime()
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
    );
    require_namespace_write_access(service.db.runtime(), &actor, &plan.namespace)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let plan = evaluation_plan_domain::prepare_plan(plan, &actor, now_ms)
        .map_err(map_evaluation_resource_error)?;
    if let Some(existing) = service
        .db
        .runtime()
        .get_evaluation_plan(&plan.plan_version_id)
        .map_err(Status::internal)?
    {
        if existing.content_digest != plan.content_digest {
            return Err(Status::already_exists(
                "evaluation plan version already exists with different content",
            ));
        }
        if !evaluation_manifest_resolution::evaluation_plan_visible(
            service.db.runtime(),
            &existing,
            &actor,
        )
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
        &plan,
        &actor,
    )?;
    let plan = service
        .db
        .runtime()
        .put_evaluation_plan(plan, &actor, now_ms)
        .map_err(map_evaluation_resource_error)?;
    Ok(Response::new(PutEvaluationPlanResponse {
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
pub(super) async fn run_lookup_first_promotion_gate(
    service: &ChiseiServiceImpl,
    req: Request<RunLookupFirstPromotionGateRequest>,
) -> Result<Response<RunLookupFirstPromotionGateResponse>, Status> {
    let actor = required_lookup_promotion_admin(&req)?;
    let request = req.into_inner();
    if request.contract_version != lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION {
        return Err(Status::invalid_argument(format!(
            "lookup promotion gate contract must be {}",
            lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION
        )));
    }
    let namespace = canonical_namespace(&request.namespace)?;
    require_namespace_access(service.db.runtime(), &actor, namespace)?;
    if request.suite_json.len() > lookup_first::LOOKUP_FIRST_GATE_MAX_SUITE_BYTES {
        return Err(Status::resource_exhausted(format!(
            "lookup promotion suite exceeds {} bytes",
            lookup_first::LOOKUP_FIRST_GATE_MAX_SUITE_BYTES
        )));
    }
    let suite = lookup_first::parse_lookup_promotion_gate_suite(&request.suite_json)
        .map_err(Status::invalid_argument)?;
    if suite.namespace != namespace {
        return Err(Status::invalid_argument(
            "lookup promotion suite namespace does not match request namespace",
        ));
    }
    for case in &suite.cases {
        require_namespace_access(service.db.runtime(), &case.actor, namespace)?;
    }

    let mut report = lookup_first::run_lookup_promotion_gate(&suite, &service.db)
        .map_err(Status::failed_precondition)?;
    let decision_id = lookup_first::record_lookup_promotion_gate(&service.db, &actor, &report)
        .map_err(Status::internal)?;
    report.audit_decision_id = decision_id;

    Ok(Response::new(RunLookupFirstPromotionGateResponse {
        report: Some(LookupFirstPromotionGateReport {
            contract_version: report.contract_version,
            suite_id: report.suite_id,
            namespace: report.namespace,
            suite_digest: report.suite_digest,
            audit_decision_id: report.audit_decision_id,
            verdict: report.verdict,
            lookup_hits: report.lookup_hits,
            model_path: report.model_path,
            lookup_refusals: report.lookup_refusals,
            passed: report.passed,
            failed: report.failed,
            cases: report
                .cases
                .into_iter()
                .map(|case| LookupFirstPromotionGateCaseResult {
                    id: case.id,
                    answer_path: case.answer_path,
                    lookup_refusal: case.lookup_refusal.unwrap_or_default(),
                    passed: case.passed,
                    detail: case.detail.unwrap_or_default(),
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
    require_namespace_write_access(service.db.runtime(), &actor, &request.namespace)?;
    let manifest = service
        .db
        .runtime()
        .get_evaluation_manifest(&request.manifest_digest)
        .map_err(Status::internal)?
        .filter(|manifest| manifest.namespace == request.namespace)
        .ok_or_else(|| Status::not_found("evaluation manifest not found"))?;
    let projection = service
        .evaluation_execution_lifecycle
        .execute(&manifest, &actor, request.max_total_duration_ms)
        .await?;
    Ok(Response::new(ExecuteEvaluationManifestResponse {
        execution: Some(to_proto_evaluation_execution_projection(&projection)),
    }))
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
    require_namespace_write_access(service.db.runtime(), &actor, &validated.namespace)?;
    let manifest = service
        .db
        .runtime()
        .get_evaluation_manifest(&validated.manifest_digest)
        .map_err(Status::internal)?
        .filter(|manifest| manifest.namespace == validated.namespace)
        .ok_or_else(|| Status::not_found("evaluation execution not found"))?;
    let index = service
        .db
        .runtime()
        .get_evaluation_execution_index(&validated.manifest_digest)
        .map_err(Status::internal)?
        .filter(|index| index.namespace == validated.namespace)
        .ok_or_else(|| Status::not_found("evaluation execution not found"))?;
    let projection = service
        .evaluation_execution_lifecycle
        .cancel(&manifest, &index, &actor)
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
        &service.config,
        &actor,
        context.as_ref(),
        &namespace,
    )?;
    let hosted = hosted_profiles_for(service, &namespace)?;
    let profiles = crate::chisei::routing_profiles::list_routing_profiles(&registry)
        .into_iter()
        .map(|profile| routing_profile_to_proto(profile, String::new()))
        .chain(hosted.into_iter().map(|profile| {
            let origin = profile.endpoint_origin.clone();
            routing_profile_to_proto(profile.entry(), origin)
        }))
        .collect();
    Ok(Response::new(ListRoutingProfilesResponse {
        profiles,
        contract_version: crate::chisei::routing_profiles::ROUTING_PROFILES_CONTRACT.into(),
    }))
}

fn routing_profile_to_proto(
    profile: crate::chisei::routing_profiles::RoutingProfileEntry,
    endpoint_origin: String,
) -> RoutingProfile {
    RoutingProfile {
        profile_id: profile.profile_id,
        mode: profile.mode,
        runtime: profile.runtime,
        model_patterns: profile.model_patterns,
        lifecycle: profile.lifecycle,
        endpoint_origin,
    }
}

/// The namespace's hosted profiles whose origin the operator still allows.
fn hosted_profiles_for(
    service: &ChiseiServiceImpl,
    namespace: &str,
) -> Result<Vec<crate::chisei::routing_profiles::HostedRoutingProfile>, Status> {
    let stored = service
        .db
        .runtime()
        .list_hosted_routing_profiles(namespace)
        .map_err(|_| Status::internal("routing profiles unavailable"))?;
    Ok(crate::chisei::routing_profiles::admissible_hosted_profiles(
        stored,
        &service.config.routing_endpoint_allowlist,
    ))
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
        service.db.runtime(),
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
    service
        .db
        .runtime()
        .put_hosted_routing_profile(&profile)
        .map_err(|_| Status::internal("routing profile unavailable"))?;
    let origin = profile.endpoint_origin.clone();
    Ok(Response::new(PutRoutingProfileResponse {
        profile: Some(routing_profile_to_proto(profile.entry(), origin)),
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
        service.db.runtime(),
        &actor,
        context.as_ref(),
        &request.namespace,
    )?;
    let revoked = service
        .db
        .runtime()
        .revoke_hosted_routing_profile(
            &request.namespace,
            &request.profile_id,
            chrono::Utc::now().timestamp_millis(),
        )
        .map_err(|_| Status::internal("routing profile unavailable"))?;
    Ok(Response::new(RevokeRoutingProfileResponse { revoked }))
}
