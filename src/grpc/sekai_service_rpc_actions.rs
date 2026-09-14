use super::*;

pub(super) async fn put_governed_action_type(
    service: &SekaiServiceImpl,
    req: Request<PutGovernedActionTypeRequest>,
) -> Result<Response<PutGovernedActionTypeResponse>, Status> {
    // Governed Action type registry (#396).
    let principals = caller_principals(&req);
    let inner = req.into_inner();
    let proto = inner
        .r#type
        .ok_or_else(|| Status::invalid_argument("type required"))?;
    let actor = authorize_namespace_action_admin(service, &principals, &proto.namespace)?;
    let domain = from_proto_governed_action_type(proto)?;
    let existing = service
        .db
        .get_governed_action_type(&domain.namespace, &domain.type_id, &domain.version)
        .map_err(Status::internal)?;
    if existing.is_none() {
        domain.validate().map_err(Status::invalid_argument)?;
    }
    let stored = service
        .db
        .put_governed_action_type(domain, &actor, now_millis())
        .map_err(|e| {
            if e.contains("immutable")
                || e.contains("required")
                || e.contains("unknown effect")
                || e.contains("duplicate effect")
                || e.contains("parameter_schema_json")
                || e.contains("must not contain whitespace")
                || e.contains("object_kind")
                || e.contains("object_mutation")
                || e.contains("object binding")
                || e.contains("object_id")
            {
                Status::invalid_argument(e)
            } else {
                Status::internal(e)
            }
        })?;
    Ok(Response::new(PutGovernedActionTypeResponse {
        r#type: Some(to_proto_governed_action_type(&stored)),
    }))
}
pub(super) async fn get_governed_action_type(
    service: &SekaiServiceImpl,
    req: Request<GetGovernedActionTypeRequest>,
) -> Result<Response<GetGovernedActionTypeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    check_team_namespace(&service.db, &principals, &inner.namespace, true)?;
    check_action_admin(
        &service.security,
        &format!("governed_action:{}", inner.namespace),
        &principals,
    )?;
    let stored = service
        .db
        .get_governed_action_type(&inner.namespace, &inner.type_id, &inner.version)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("governed action type not found"))?;
    Ok(Response::new(GetGovernedActionTypeResponse {
        r#type: Some(to_proto_governed_action_type(&stored)),
    }))
}
pub(super) async fn list_governed_action_types(
    service: &SekaiServiceImpl,
    req: Request<ListGovernedActionTypesRequest>,
) -> Result<Response<ListGovernedActionTypesResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    check_team_namespace(&service.db, &principals, &inner.namespace, true)?;
    check_action_admin(
        &service.security,
        &format!("governed_action:{}", inner.namespace),
        &principals,
    )?;
    let type_id = if inner.type_id.trim().is_empty() {
        None
    } else {
        Some(inner.type_id.as_str())
    };
    let types = service
        .db
        .list_governed_action_types(&inner.namespace, type_id, inner.enabled_only)
        .map_err(Status::internal)?
        .iter()
        .map(to_proto_governed_action_type)
        .collect();
    Ok(Response::new(ListGovernedActionTypesResponse { types }))
}
pub(super) async fn set_governed_action_type_enabled(
    service: &SekaiServiceImpl,
    req: Request<SetGovernedActionTypeEnabledRequest>,
) -> Result<Response<SetGovernedActionTypeEnabledResponse>, Status> {
    let principals = caller_principals(&req);
    let inner = req.into_inner();
    let _actor = authorize_namespace_action_admin(service, &principals, &inner.namespace)?;
    let stored = service
        .db
        .set_governed_action_type_enabled(
            &inner.namespace,
            &inner.type_id,
            &inner.version,
            inner.enabled,
            now_millis(),
        )
        .map_err(|e| {
            if e.contains("not found") {
                Status::not_found(e)
            } else {
                Status::internal(e)
            }
        })?;
    Ok(Response::new(SetGovernedActionTypeEnabledResponse {
        r#type: Some(to_proto_governed_action_type(&stored)),
    }))
}
pub(super) async fn submit_action_instance(
    service: &SekaiServiceImpl,
    req: Request<SubmitActionInstanceRequest>,
) -> Result<Response<SubmitActionInstanceResponse>, Status> {
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
    };

    let principals = caller_principals(&req);
    let policy_context = principal_policy_context(&req);
    let tenant_context = request_tenant_context(&service.db, &req)?;
    let header_operation_id = SekaiServiceImpl::catalog_metadata_value(
        &req,
        crate::sekai::operation_correlation::OPERATION_METADATA,
    );
    let mut inner = req.into_inner();
    let namespace = inner.namespace.trim().to_string();
    if namespace.is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    let actor = authorize_action_instance_submit(service, &principals, &namespace)?;
    enforce_namespace_tenant_context(&service.db, tenant_context.as_ref(), &namespace, true)?;
    let operation_id = crate::sekai::operation_correlation::bind_submit_identity(
        header_operation_id.as_deref(),
        &inner.request_id,
    )
    .map_err(Status::invalid_argument)?;
    inner.request_id = operation_id.clone();
    let span = tracing::info_span!(
        "governed_action",
        sekai.operation_id = operation_id.as_str()
    );
    tracing::debug!(
        parent: &span,
        sekai.operation_id = operation_id.as_str(),
        "governed action identity bound"
    );

    let outcome = span.in_scope(|| {
        ActionInstanceAdmission::new(
            &service.db,
            service.budget.as_ref().map(std::convert::AsRef::as_ref),
        )
        .admit(
            ActionInstanceAdmissionRequest {
                namespace,
                type_id: inner.type_id,
                version: inner.version,
                parameters_json: inner.parameters_json,
                idempotency_key: inner.idempotency_key,
                evidence_submission_ids: inner.evidence_submission_ids,
                request_id: inner.request_id,
                ontology_digest: inner.ontology_digest,
                autonomous_envelope_id: String::new(),
                policy_context,
            },
            &actor,
            now_millis(),
        )
        .map_err(|error| match error {
            ActionInstanceAdmissionError::InvalidArgument(message) => {
                Status::invalid_argument(message)
            }
            ActionInstanceAdmissionError::FailedPrecondition(message) => {
                Status::failed_precondition(message)
            }
            ActionInstanceAdmissionError::AlreadyExists(message) => Status::already_exists(message),
            ActionInstanceAdmissionError::Internal(message) => Status::internal(message),
        })
    })?;
    Ok(Response::new(SubmitActionInstanceResponse {
        instance: Some(to_proto_action_instance(&outcome.instance)),
        replay: outcome.replay,
    }))
}
pub(super) async fn describe_object_action(
    service: &SekaiServiceImpl,
    req: Request<DescribeObjectActionRequest>,
) -> Result<Response<DescribeObjectActionResponse>, Status> {
    let principals = caller_principals(&req);
    let policy_context = principal_policy_context(&req);
    let tenant_context = request_tenant_context(&service.db, &req)?;
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let object = visible_action_object(
        service,
        &principals,
        tenant_context.as_ref(),
        &policy_context,
        &inner.namespace,
        &inner.object_id,
    )?;
    let description = crate::sekai::action_describe_preview::describe_object_action(
        &service.db,
        &object,
        &inner.type_id,
        &inner.version,
    )
    .map_err(map_object_action_projection_error)?;
    Ok(Response::new(object_action_description_to_proto(
        description,
    )))
}
pub(super) async fn preview_object_action(
    service: &SekaiServiceImpl,
    req: Request<PreviewObjectActionRequest>,
) -> Result<Response<PreviewObjectActionResponse>, Status> {
    let principals = caller_principals(&req);
    let policy_context = principal_policy_context(&req);
    let tenant_context = request_tenant_context(&service.db, &req)?;
    let actor = authorize_action_instance_submit(service, &principals, &req.get_ref().namespace)?;
    let inner = req.into_inner();
    let object = visible_action_object(
        service,
        &principals,
        tenant_context.as_ref(),
        &policy_context,
        &inner.namespace,
        &inner.object_id,
    )?;
    let preview = crate::sekai::action_describe_preview::preview_object_action(
        &service.db,
        service.budget.as_ref().map(std::convert::AsRef::as_ref),
        crate::sekai::action_describe_preview::ObjectActionPreviewRequest {
            actor: &actor,
            object: &object,
            type_id: &inner.type_id,
            version: &inner.version,
            parameters_json: &inner.parameters_json,
            expected_object_updated_ms: inner.expected_object_updated_ms,
            expected_object_revision: &inner.expected_object_revision,
            evidence_submission_ids: &inner.evidence_submission_ids,
            policy_context: Some(&policy_context),
        },
    )
    .map_err(map_object_action_projection_error)?;
    if preview.outcome == crate::sekai::action_describe_preview::PREVIEW_UNAVAILABLE {
        return Err(Status::permission_denied("object action unavailable"));
    }
    Ok(Response::new(object_action_preview_to_proto(preview)))
}
pub(super) async fn get_action_instance(
    service: &SekaiServiceImpl,
    req: Request<GetActionInstanceRequest>,
) -> Result<Response<GetActionInstanceResponse>, Status> {
    let principals = caller_principals(&req);
    let inner = req.into_inner();
    let stored = if !inner.instance_id.trim().is_empty() {
        service
            .db
            .get_action_instance(&inner.instance_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action instance not found"))?
    } else if !inner.namespace.trim().is_empty() && !inner.idempotency_key.trim().is_empty() {
        service
            .db
            .get_action_instance_by_idempotency(&inner.namespace, &inner.idempotency_key)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action instance not found"))?
    } else {
        return Err(Status::invalid_argument(
            "instance_id or (namespace, idempotency_key) required",
        ));
    };
    authorize_action_instance_read(service, &principals, &stored.namespace)?;
    Ok(Response::new(GetActionInstanceResponse {
        instance: Some(to_proto_action_instance(&stored)),
    }))
}
pub(super) async fn list_action_instances(
    service: &SekaiServiceImpl,
    req: Request<ListActionInstancesRequest>,
) -> Result<Response<ListActionInstancesResponse>, Status> {
    let principals = caller_principals(&req);
    let inner = req.into_inner();
    if inner.namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    authorize_action_instance_read(service, &principals, &inner.namespace)?;
    let type_id = if inner.type_id.trim().is_empty() {
        None
    } else {
        Some(inner.type_id.as_str())
    };
    let status = if inner.status.trim().is_empty() {
        None
    } else {
        Some(inner.status.as_str())
    };
    let limit = if inner.limit == 0 {
        100
    } else {
        inner.limit as usize
    };
    let instances = service
        .db
        .list_action_instances(&inner.namespace, type_id, status, limit)
        .map_err(Status::internal)?
        .iter()
        .map(to_proto_action_instance)
        .collect();
    Ok(Response::new(ListActionInstancesResponse { instances }))
}
pub(super) async fn get_action_effect(
    service: &SekaiServiceImpl,
    req: Request<GetActionEffectRequest>,
) -> Result<Response<GetActionEffectResponse>, Status> {
    let principals = caller_principals(&req);
    let inner = req.into_inner();
    if inner.effect_id.trim().is_empty() {
        return Err(Status::invalid_argument("effect_id required"));
    }
    let stored = service
        .db
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    authorize_action_instance_read(service, &principals, &stored.namespace)?;
    Ok(Response::new(GetActionEffectResponse {
        effect: Some(to_proto_action_effect(&stored)),
    }))
}
pub(super) async fn list_action_effects(
    service: &SekaiServiceImpl,
    req: Request<ListActionEffectsRequest>,
) -> Result<Response<ListActionEffectsResponse>, Status> {
    use crate::sekai::action_effect::EFFECT_STATUS_PENDING;
    use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;

    let principals = caller_principals(&req);
    let inner = req.into_inner();
    let effects = if !inner.instance_id.trim().is_empty() {
        let listed = service
            .db
            .list_action_effects_for_instance(&inner.instance_id)
            .map_err(Status::internal)?;
        if let Some(first) = listed.first() {
            authorize_action_instance_read(service, &principals, &first.namespace)?;
        } else {
            require_authenticated(&principals)?;
        }
        listed
    } else if !inner.namespace.trim().is_empty()
        && (inner.kind.is_empty() || inner.kind == EFFECT_KIND_RUNTIME_DISPATCH)
        && (inner.status.is_empty() || inner.status == EFFECT_STATUS_PENDING)
    {
        authorize_action_instance_read(service, &principals, &inner.namespace)?;
        let limit = if inner.limit == 0 {
            100
        } else {
            inner.limit as usize
        };
        service
            .db
            .list_pending_runtime_dispatch_effects(&inner.namespace, limit)
            .map_err(Status::internal)?
    } else {
        return Err(Status::invalid_argument(
            "instance_id or namespace (pending runtime_dispatch) required",
        ));
    };
    Ok(Response::new(ListActionEffectsResponse {
        effects: effects.iter().map(to_proto_action_effect).collect(),
    }))
}
pub(super) async fn list_claimable_action_work(
    service: &SekaiServiceImpl,
    req: Request<ListClaimableActionWorkRequest>,
) -> Result<Response<ListClaimableActionWorkResponse>, Status> {
    let principals = caller_principals(&req);
    let inner = req.into_inner();
    if inner.namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    authorize_action_instance_read(service, &principals, &inner.namespace)?;
    let runtime = if crate::sekai::action_effect::runtime_id_is_blank(&inner.runtime_id) {
        None
    } else {
        Some(inner.runtime_id.as_str())
    };
    let limit = if inner.limit == 0 {
        100
    } else {
        inner.limit as usize
    };
    let effects = ActionWorkLifecycle::new(&service.db)
        .list_claimable(&inner.namespace, runtime, now_millis(), limit)
        .map_err(action_work_lifecycle_status)?
        .iter()
        .map(to_proto_action_effect)
        .collect();
    Ok(Response::new(ListClaimableActionWorkResponse { effects }))
}
pub(super) async fn claim_action_work(
    service: &SekaiServiceImpl,
    req: Request<ClaimActionWorkRequest>,
) -> Result<Response<ClaimActionWorkResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    if inner.effect_id.trim().is_empty() {
        return Err(Status::invalid_argument("effect_id required"));
    }
    if crate::sekai::action_effect::runtime_id_is_blank(&inner.runtime_id) {
        return Err(Status::invalid_argument("runtime_id required"));
    }
    if inner.request_id.trim().is_empty() {
        return Err(Status::invalid_argument("request_id required"));
    }
    let existing = service
        .db
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    // Claim requires namespace write so only authorized hosts can take work.
    check_team_namespace(&service.db, &principals, &existing.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let claimed = ActionWorkLifecycle::new(&service.db)
        .claim(
            ClaimActionWorkCommand {
                effect_id: &inner.effect_id,
                runtime_id: &inner.runtime_id,
                request_id: &inner.request_id,
                ttl_ms: inner.ttl_ms,
            },
            &actor,
            now_millis(),
        )
        .map_err(action_work_lifecycle_status)?;
    Ok(Response::new(ClaimActionWorkResponse {
        effect: Some(to_proto_action_effect(&claimed.effect)),
        continuation: claimed
            .continuation
            .as_ref()
            .map(to_proto_action_work_continuation),
        park: claimed.park.as_ref().map(to_proto_action_work_park),
    }))
}
pub(super) async fn heartbeat_action_claim(
    service: &SekaiServiceImpl,
    req: Request<HeartbeatActionClaimRequest>,
) -> Result<Response<HeartbeatActionClaimResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let existing = service
        .db
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    check_team_namespace(&service.db, &principals, &existing.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let stored = ActionWorkLifecycle::new(&service.db)
        .heartbeat(
            HeartbeatActionClaimCommand {
                effect_id: &inner.effect_id,
                runtime_id: &inner.runtime_id,
                claim_generation: inner.claim_generation,
                fencing_token: &inner.fencing_token,
                ttl_ms: inner.ttl_ms,
            },
            &actor,
            now_millis(),
        )
        .map_err(action_work_lifecycle_status)?;
    Ok(Response::new(HeartbeatActionClaimResponse {
        effect: Some(to_proto_action_effect(&stored)),
    }))
}
pub(super) async fn ack_action_work(
    service: &SekaiServiceImpl,
    req: Request<AckActionWorkRequest>,
) -> Result<Response<AckActionWorkResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let existing = service
        .db
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    check_team_namespace(&service.db, &principals, &existing.namespace, true)?;
    let now = now_millis();
    let actor = principals.first().cloned().unwrap_or_default();
    let acked = ActionWorkLifecycle::new(&service.db)
        .ack(
            AckActionWorkCommand {
                effect_id: &inner.effect_id,
                runtime_id: &inner.runtime_id,
                claim_generation: inner.claim_generation,
                fencing_token: &inner.fencing_token,
                outcome: &inner.outcome,
                reason: &inner.reason,
                request_id: &inner.request_id,
                checkpoint_store_id: &inner.checkpoint_store_id,
                checkpoint_ref: &inner.checkpoint_ref,
                checkpoint_digest: &inner.checkpoint_digest,
                artifact_json: &inner.artifact_json,
            },
            &actor,
            now,
        )
        .map_err(action_work_lifecycle_status)?;
    Ok(Response::new(AckActionWorkResponse {
        effect: Some(to_proto_action_effect(&acked.effect)),
        park: acked.park.as_ref().map(to_proto_action_work_park),
        replay: acked.replay,
    }))
}
pub(super) async fn report_action_claim_event(
    service: &SekaiServiceImpl,
    req: Request<ReportActionClaimEventRequest>,
) -> Result<Response<ReportActionClaimEventResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let effect = service
        .db
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    check_team_namespace(&service.db, &principals, &effect.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let replay = ActionWorkLifecycle::new(&service.db)
        .report_event(
            ReportActionClaimEventCommand {
                effect_id: &inner.effect_id,
                runtime_id: &inner.runtime_id,
                claim_generation: inner.claim_generation,
                fencing_token: &inner.fencing_token,
                kind: &inner.kind,
                checkpoint_digest: &inner.checkpoint_digest,
                reason_code: &inner.reason_code,
                request_id: &inner.request_id,
            },
            &actor,
            now_millis(),
        )
        .map_err(action_work_lifecycle_status)?;
    Ok(Response::new(ReportActionClaimEventResponse { replay }))
}
pub(super) async fn set_action_policy(
    service: &SekaiServiceImpl,
    req: Request<SetActionPolicyRequest>,
) -> Result<Response<SetActionPolicyResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let policy = req
        .into_inner()
        .policy
        .ok_or(Status::invalid_argument("policy required"))?;
    let domain_policy = from_proto_action_policy(&policy)?;
    check_action_admin(&service.security, &domain_policy.scope, &principals)?;
    service
        .db
        .upsert_action_policy(&domain_policy)
        .map_err(Status::internal)?;
    Ok(Response::new(SetActionPolicyResponse {
        policy: Some(to_proto_action_policy(&domain_policy)),
    }))
}
pub(super) async fn get_action_policy(
    service: &SekaiServiceImpl,
    req: Request<GetActionPolicyRequest>,
) -> Result<Response<GetActionPolicyResponse>, Status> {
    let principals = caller_principals(&req);
    let r = req.into_inner();
    check_action_admin(&service.security, &r.scope, &principals)?;
    let policy = service
        .db
        .get_action_policy(&r.scope)
        .map_err(Status::internal)?;
    Ok(Response::new(GetActionPolicyResponse {
        policy: policy.map(|policy| to_proto_action_policy(&policy)),
    }))
}
pub(super) async fn list_action_policies(
    service: &SekaiServiceImpl,
    req: Request<ListActionPoliciesRequest>,
) -> Result<Response<ListActionPoliciesResponse>, Status> {
    let principals = caller_principals(&req);
    check_action_admin(&service.security, "", &principals)?;
    let policies = service
        .db
        .list_action_policies()
        .map_err(Status::internal)?;
    Ok(Response::new(ListActionPoliciesResponse {
        policies: policies.iter().map(to_proto_action_policy).collect(),
    }))
}
pub(super) async fn get_lineage(
    service: &SekaiServiceImpl,
    req: Request<GetLineageRequest>,
) -> Result<Response<GetLineageResponse>, Status> {
    service.get_visible_lineage(req).await
}
