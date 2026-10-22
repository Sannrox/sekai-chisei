use super::*;
use crate::runtime_token::{ClaimBinding, RuntimeTokenClaims};

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
        .runtime()
        .get_governed_action_type(&domain.namespace, &domain.type_id, &domain.version)
        .map_err(Status::internal)?;
    if existing.is_none() {
        domain.validate().map_err(Status::invalid_argument)?;
    }
    let stored = service
        .db
        .runtime()
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
                || e.contains("system_one")
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
    check_team_namespace(service.db.runtime(), &principals, &inner.namespace, true)?;
    check_action_admin(
        &service.security,
        &format!("governed_action:{}", inner.namespace),
        &principals,
    )?;
    let stored = service
        .db
        .runtime()
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
    check_team_namespace(service.db.runtime(), &principals, &inner.namespace, true)?;
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
        .runtime()
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
        .runtime()
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let header_operation_id = SekaiServiceImpl::catalog_metadata_value(
        &req,
        crate::sekai::operation_correlation::OPERATION_METADATA,
    );
    let catalog_capability = SekaiServiceImpl::catalog_metadata_value(&req, "x-sekai-capability");
    let catalog_namespace = SekaiServiceImpl::catalog_metadata_value(&req, "x-sekai-namespace");
    let mut inner = req.into_inner();
    let namespace = inner.namespace.trim().to_string();
    if namespace.is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    let actor = authorize_action_instance_submit(service, &principals, &namespace)?;
    if let Some(capability_name) = catalog_capability {
        let expected = crate::sekai::capability::action_capability_name(&inner.type_id);
        // MCP v1 binds SubmitActionInstance as `sekai.actions.submit`. Skip
        // the type-specific live catalog check only when that allowlist name
        // is not also the native entry for this type_id.
        if capability_name != "sekai.actions.submit" || capability_name == expected {
            let catalog_namespace = catalog_namespace.unwrap_or_else(|| namespace.clone());
            if catalog_namespace != namespace {
                return Err(Status::invalid_argument(
                    "catalog namespace metadata must match request namespace",
                ));
            }
            let visible = service
                .discoverable_capabilities(&namespace, &principals, tenant_context.as_ref())?
                .into_iter()
                .any(|entry| {
                    entry.name == capability_name
                        && capability_name == expected
                        && entry.action_version == inner.version
                });
            if !visible {
                return Err(Status::failed_precondition("capability unavailable"));
            }
        }
    }
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &namespace,
        true,
    )?;
    enforce_service_principal_action_type(
        service.db.runtime(),
        tenant_context.as_ref(),
        &inner.type_id,
    )?;
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

    let resource_tenant = shared_space_resource_tenant(
        service.db.runtime(),
        tenant_context.as_ref(),
        &namespace,
        crate::enterprise::NamespaceAction::Write,
    )
    .unwrap_or_default();
    let admission_request = ActionInstanceAdmissionRequest {
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
        delegating_actor: tenant_context
            .as_ref()
            .and_then(|context| context.act.clone()),
        budget_already_reserved: false,
        resource_tenant,
    };
    let tenant = acting_tenant(tenant_context.as_ref());
    let machine_credential = freeze_machine_credential(tenant_context.as_ref());
    let outcome = span.in_scope(|| {
        let result = if let Some(clerk) = &service.cross_store {
            clerk.admit(
                admission_request,
                &actor,
                now_millis(),
                tenant,
                machine_credential,
            )
        } else {
            ActionInstanceAdmission::new(service.db.runtime(), None)
                .with_proposal(Some(&crate::chisei::system_one_action::SystemOneProposal))
                .with_tenant(tenant)
                .with_machine_credential(machine_credential)
                .admit(admission_request, &actor, now_millis())
        };
        result.map_err(|error| match error {
            ActionInstanceAdmissionError::InvalidArgument(message) => {
                Status::invalid_argument(message)
            }
            ActionInstanceAdmissionError::FailedPrecondition(message) => {
                Status::failed_precondition(message)
            }
            ActionInstanceAdmissionError::AlreadyExists(message) => Status::already_exists(message),
            ActionInstanceAdmissionError::PermissionDenied(message) => {
                Status::permission_denied(message)
            }
            ActionInstanceAdmissionError::Internal(message) => Status::internal(message),
        })
    })?;
    Ok(Response::new(SubmitActionInstanceResponse {
        instance: Some(to_proto_action_instance(&outcome.instance)),
        replay: outcome.replay,
    }))
}
/// Grant or deny a parked instance (#1084). Every refusal, including an
/// unknown instance, answers `access denied`, so the RPC discloses nothing
/// about instances the caller may not decide.
pub(super) async fn decide_action_instance(
    service: &SekaiServiceImpl,
    req: Request<DecideActionInstanceRequest>,
) -> Result<Response<DecideActionInstanceResponse>, Status> {
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceDecisionRequest,
        DECISION_ACCESS_DENIED,
    };

    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    if let Some(context) = tenant_context.as_ref() {
        context
            .authorize_space_approval()
            .map_err(extension_status)?;
    }
    let access_denied = || Status::permission_denied(DECISION_ACCESS_DENIED);
    // An approval binds to one credentialed subject (#1140). Self-asserted
    // identities from the local or insecure transport, comma-listed
    // principals, and the reserved operator names cannot decide.
    let decider = credentialed_decider(&req, &principals).ok_or_else(access_denied)?;
    let principals = vec![decider.clone()];
    let inner = req.into_inner();
    let instance = service
        .db
        .runtime()
        .get_action_instance(inner.instance_id.trim())
        .map_err(Status::internal)?
        .ok_or_else(access_denied)?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &instance.namespace,
        false,
    )
    .map_err(|_| access_denied())?;
    // ADR 0089: a named approver decides on authentication, tenant, and
    // entitlement alone; namespace Write is not required (#1146). The
    // namespace-admin fallback checks its own standing below.
    let decider_is_namespace_admin =
        authorize_source_type_namespace_admin(service, &principals, &instance.namespace).is_ok();
    let outcome = ActionInstanceAdmission::new(service.db.runtime(), None)
        .with_tenant(acting_tenant(tenant_context.as_ref()))
        .with_machine_credential(freeze_machine_credential(tenant_context.as_ref()))
        .decide(
            ActionInstanceDecisionRequest {
                instance_id: inner.instance_id,
                decision: inner.decision,
                reason: inner.reason,
                decider_principals: principals,
                decider_is_namespace_admin,
                delegating_actor: tenant_context
                    .as_ref()
                    .and_then(|context| context.act.clone()),
            },
            &decider,
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
            ActionInstanceAdmissionError::PermissionDenied(message) => {
                Status::permission_denied(message)
            }
            ActionInstanceAdmissionError::Internal(message) => Status::internal(message),
        })?;
    Ok(Response::new(DecideActionInstanceResponse {
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let object = visible_action_object(
        service,
        &principals,
        tenant_context.as_ref(),
        &policy_context,
        &inner.namespace,
        &inner.object_id,
        crate::enterprise::NamespaceAction::Discover,
    )?;
    let description = crate::sekai::action_describe_preview::describe_object_action(
        service.db.runtime(),
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let actor = authorize_action_instance_submit(service, &principals, &req.get_ref().namespace)?;
    let inner = req.into_inner();
    let object = visible_action_object(
        service,
        &principals,
        tenant_context.as_ref(),
        &policy_context,
        &inner.namespace,
        &inner.object_id,
        crate::enterprise::NamespaceAction::Read,
    )?;
    let type_def = match crate::sekai::action_describe_preview::load_object_bound_type(
        service.db.runtime(),
        &object,
        &inner.type_id,
        &inner.version,
    ) {
        Ok(type_def) => type_def,
        Err(crate::sekai::action_describe_preview::ObjectActionProjectionError::Unavailable) => {
            return Err(Status::permission_denied("object action unavailable"));
        }
        Err(
            crate::sekai::action_describe_preview::ObjectActionProjectionError::InvalidArgument(
                error,
            ),
        ) => return Err(Status::invalid_argument(error)),
    };
    let clerk = service.cross_store.as_ref();
    let budget = clerk.and_then(|clerk| clerk.budget_port());
    let fallback_proposal = crate::chisei::system_one_action::SystemOneProposal;
    let proposal: &dyn crate::sekai::action_ports::ActionProposalPort = match clerk {
        Some(clerk) => clerk.proposal_port(),
        None => &fallback_proposal,
    };
    let admission = crate::sekai::action_describe_preview::preview_object_action_admission(
        service.db.runtime(),
        budget,
        crate::sekai::action_describe_preview::ObjectActionPreviewRequest {
            actor: &actor,
            object: &object,
            type_id: &inner.type_id,
            version: &inner.version,
            parameters_json: "",
            expected_object_updated_ms: inner.expected_object_updated_ms,
            expected_object_revision: &inner.expected_object_revision,
            evidence_submission_ids: &[],
            policy_context: Some(&policy_context),
        },
    )
    .map_err(map_object_action_projection_error)?;
    if admission.outcome == crate::sekai::action_describe_preview::PREVIEW_UNAVAILABLE {
        return Err(Status::permission_denied("object action unavailable"));
    }
    if !crate::sekai::action_describe_preview::allows_function_fill(&admission) {
        let mut proto = object_action_preview_to_proto(admission);
        proto.proposed_parameters_json.clear();
        return Ok(Response::new(proto));
    }
    let mut parameters_json = inner.parameters_json;
    let mut proposed_parameters_json = String::new();
    let mut fill_audit = None;
    if crate::chisei::system_one_action::should_fill(&type_def, &parameters_json) {
        let object_type = service
            .db
            .runtime()
            .get_object_type(&object.kind)
            .ok()
            .flatten();
        let client = chisei_provider::system_one::TypeSafeClient::from_env()
            .map_err(Status::failed_precondition)?;
        let (filled, record) = crate::chisei::system_one_action::fill_proposed_parameters(
            &type_def,
            &object,
            object_type.as_ref(),
            &client,
        )
        .await
        .map_err(|error| {
            if error.contains("system_one") || error.contains("action type has no") {
                Status::failed_precondition(error)
            } else {
                Status::unavailable(error)
            }
        })?;
        fill_audit = Some((
            record,
            crate::chisei::system_one_action::bind_of(&type_def)
                .map(|bind| bind.model.clone())
                .unwrap_or_else(|| "typesafe".into()),
        ));
        parameters_json = filled;
        proposed_parameters_json.clone_from(&parameters_json);
    }
    let preview = crate::sekai::action_describe_preview::preview_object_action(
        service.db.runtime(),
        budget,
        Some(proposal),
        crate::sekai::action_describe_preview::ObjectActionPreviewRequest {
            actor: &actor,
            object: &object,
            type_id: &inner.type_id,
            version: &inner.version,
            parameters_json: &parameters_json,
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
    let mut proto = object_action_preview_to_proto(preview);
    if proto.outcome != crate::sekai::action_describe_preview::PREVIEW_VALID {
        proposed_parameters_json.clear();
    } else if let Some((record, model)) = fill_audit {
        record_system_one_egress_audit(service.db.runtime(), &record, &model, &object.id);
    }
    proto.proposed_parameters_json = proposed_parameters_json;
    Ok(Response::new(proto))
}

fn record_system_one_egress_audit(
    db: &crate::db::runtime_db::RuntimeDb,
    record: &crate::chisei::egress::ContextEgressRecord,
    model: &str,
    request_id: &str,
) {
    let mut evidence = std::collections::HashMap::new();
    evidence.insert("provider".into(), "typesafe".into());
    evidence.insert("model".into(), model.into());
    evidence.insert(
        "included_count".into(),
        record.included_fields.len().to_string(),
    );
    evidence.insert(
        "redacted_count".into(),
        record.redacted_fields.len().to_string(),
    );
    evidence.insert(
        "included_fields".into(),
        serde_json::to_string(&record.included_fields).unwrap_or_else(|_| "[]".into()),
    );
    evidence.insert(
        "redacted_fields".into(),
        serde_json::to_string(&record.redacted_fields).unwrap_or_else(|_| "[]".into()),
    );
    let _ = db.record_decision(&crate::sekai::audit::Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: "chisei.egress".into(),
        action: "preview_object_action".into(),
        reason: "context egress policy applied".into(),
        evidence,
        target_id: request_id.into(),
        outcome: if record.redacted_fields.is_empty() {
            "included".into()
        } else {
            "redacted".into()
        },
    });
}
pub(super) async fn get_action_instance(
    service: &SekaiServiceImpl,
    req: Request<GetActionInstanceRequest>,
) -> Result<Response<GetActionInstanceResponse>, Status> {
    let principals = caller_principals(&req);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let policy_context = principal_policy_context(&req);
    let inner = req.into_inner();
    let stored = if !inner.instance_id.trim().is_empty() {
        service
            .db
            .runtime()
            .get_action_instance(&inner.instance_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action instance not found"))?
    } else if !inner.namespace.trim().is_empty() && !inner.idempotency_key.trim().is_empty() {
        service
            .db
            .runtime()
            .get_action_instance_by_idempotency(&inner.namespace, &inner.idempotency_key)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action instance not found"))?
    } else if !inner.operation_id.trim().is_empty() {
        service
            .db
            .runtime()
            .get_action_instance_by_operation_id(&inner.operation_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action instance not found"))?
    } else {
        return Err(Status::invalid_argument(
            "instance_id, operation_id, or (namespace, idempotency_key) required",
        ));
    };
    authorize_action_instance_read(
        service,
        &principals,
        &stored.namespace,
        tenant_context.as_ref(),
    )?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &stored.namespace,
        false,
    )?;
    authorize_action_instance_visibility(
        service,
        &principals,
        tenant_context.as_ref(),
        &policy_context,
        &stored,
    )?;
    let mut decision_precedents = Vec::new();
    let mut offset = 0_i64;
    const PAGE: i64 = 64;
    if crate::sekai::decision_memory::similar_parameters(
        &stored.parameters_json,
        &stored.parameters_json,
    ) {
        loop {
            let page = service
                .db
                .runtime()
                .list_decision_memory_page(&stored.namespace, &stored.type_id, offset, PAGE)
                .map_err(Status::internal)?;
            if page.is_empty() {
                break;
            }
            let page_len = page.len();
            for memory in page {
                if memory.instance_id == stored.instance_id {
                    continue;
                }
                if !crate::sekai::decision_memory::similar_parameters(
                    &memory.parameters_json,
                    &stored.parameters_json,
                ) {
                    continue;
                }
                let Some(past) = service
                    .db
                    .runtime()
                    .get_action_instance(&memory.instance_id)
                    .map_err(Status::internal)?
                else {
                    continue;
                };
                if authorize_action_instance_visibility(
                    service,
                    &principals,
                    tenant_context.as_ref(),
                    &policy_context,
                    &past,
                )
                .is_err()
                {
                    continue;
                }
                decision_precedents.push(ActionDecisionPrecedent {
                    instance_id: memory.instance_id,
                    outcome: memory.outcome,
                    reason: memory.reason,
                    conditions_json: memory.conditions_json,
                    facts_json: memory.facts_json,
                    decided_by: memory.decided_by,
                    decided_at_ms: memory.decided_at_ms,
                    superseded: memory.superseded,
                });
                if decision_precedents.len() >= crate::sekai::decision_memory::MAX_PRECEDENTS {
                    break;
                }
            }
            if decision_precedents.len() >= crate::sekai::decision_memory::MAX_PRECEDENTS
                || page_len < PAGE as usize
            {
                break;
            }
            offset += PAGE;
            if offset >= crate::sekai::decision_memory::MAX_SCAN_ROWS {
                break;
            }
        }
    }
    Ok(Response::new(GetActionInstanceResponse {
        instance: Some(to_proto_action_instance(&stored)),
        decision_precedents,
    }))
}
pub(super) async fn list_action_instances(
    service: &SekaiServiceImpl,
    req: Request<ListActionInstancesRequest>,
) -> Result<Response<ListActionInstancesResponse>, Status> {
    let principals = caller_principals(&req);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let policy_context = principal_policy_context(&req);
    let inner = req.into_inner();
    if inner.namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    authorize_action_instance_read(
        service,
        &principals,
        &inner.namespace,
        tenant_context.as_ref(),
    )?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &inner.namespace,
        false,
    )?;
    let _ = crate::sekai::action_instance_admission::ActionInstanceAdmission::new(
        service.db.runtime(),
        None,
    )
    .escalate_due(&inner.namespace, now_millis());
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
    let limit = limit.clamp(1, 500);
    let mut offset = 0;
    let mut instances = Vec::new();
    loop {
        let stored = service
            .db
            .runtime()
            .list_action_instances_page(&inner.namespace, type_id, status, 100, offset)
            .map_err(Status::internal)?;
        let exhausted = stored.len() < 100;
        offset += stored.len();
        for instance in &stored {
            match authorize_action_instance_visibility(
                service,
                &principals,
                tenant_context.as_ref(),
                &policy_context,
                instance,
            ) {
                Ok(()) => instances.push(to_proto_action_instance(instance)),
                Err(status)
                    if matches!(
                        status.code(),
                        tonic::Code::PermissionDenied | tonic::Code::NotFound
                    ) => {}
                Err(status) => return Err(status),
            }
            if instances.len() == limit {
                break;
            }
        }
        if exhausted || instances.len() == limit {
            break;
        }
    }
    Ok(Response::new(ListActionInstancesResponse { instances }))
}

fn authorize_action_instance_visibility(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
    instance: &crate::sekai::action_instance::ActionInstance,
) -> Result<(), Status> {
    let denied = || Status::permission_denied("action instance unavailable");
    let definition = service
        .db
        .runtime()
        .get_governed_action_type(&instance.namespace, &instance.type_id, &instance.version)
        .map_err(Status::internal)?;
    let entitled = principal_matches(&instance.principal, principals)
        || authorize_namespace_action_admin(service, principals, &instance.namespace).is_ok()
        || definition.as_ref().is_some_and(|definition| {
            principals
                .iter()
                .any(|principal| definition.approvers.contains(principal))
        });
    if !entitled {
        return Err(denied());
    }
    if let Some(object_id) = action_instance_target_object_id(&instance.parameters_json) {
        let target_exists = service
            .db
            .runtime()
            .get_object(&object_id)
            .map_err(Status::internal)?
            .is_some();
        if target_exists {
            visible_action_object(
                service,
                principals,
                tenant_context,
                policy_context,
                &instance.namespace,
                &object_id,
                crate::enterprise::NamespaceAction::Read,
            )?;
        } else if !definition.as_ref().is_some_and(|definition| {
            definition.object_mutation == crate::sekai::governed_action_type::OBJECT_MUTATION_CREATE
        }) {
            return Err(denied());
        }
    }
    Ok(())
}

fn action_instance_target_object_id(parameters_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()
        .and_then(|value| {
            value
                .get("object_id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
        })
}
fn authorize_action_effect_read(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    effect: &crate::sekai::action_effect::ActionEffect,
) -> Result<(), Status> {
    let instance = service
        .db
        .runtime()
        .get_action_instance(&effect.instance_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::permission_denied("action effect unavailable"))?;
    if instance.namespace != effect.namespace {
        return Err(Status::permission_denied("action effect unavailable"));
    }
    authorize_action_instance_read(service, principals, &instance.namespace, tenant_context)?;
    authorize_action_instance_visibility(
        service,
        principals,
        tenant_context,
        &principal_policy_context_from(principals, tenant_context),
        &instance,
    )
}

pub(super) async fn get_action_effect(
    service: &SekaiServiceImpl,
    req: Request<GetActionEffectRequest>,
) -> Result<Response<GetActionEffectResponse>, Status> {
    let principals = caller_principals(&req);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    if inner.effect_id.trim().is_empty() {
        return Err(Status::invalid_argument("effect_id required"));
    }
    let stored = service
        .db
        .runtime()
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    authorize_action_instance_read(
        service,
        &principals,
        &stored.namespace,
        tenant_context.as_ref(),
    )?;
    authorize_action_effect_read(service, &principals, tenant_context.as_ref(), &stored)?;
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    let effects = if !inner.instance_id.trim().is_empty() {
        let listed = service
            .db
            .runtime()
            .list_action_effects_for_instance(&inner.instance_id)
            .map_err(Status::internal)?;
        if let Some(first) = listed.first() {
            authorize_action_instance_read(
                service,
                &principals,
                &first.namespace,
                tenant_context.as_ref(),
            )?;
        } else {
            require_authenticated(&principals)?;
        }
        listed
    } else if !inner.namespace.trim().is_empty()
        && (inner.kind.is_empty() || inner.kind == EFFECT_KIND_RUNTIME_DISPATCH)
        && (inner.status.is_empty() || inner.status == EFFECT_STATUS_PENDING)
    {
        authorize_action_instance_read(
            service,
            &principals,
            &inner.namespace,
            tenant_context.as_ref(),
        )?;
        let limit = if inner.limit == 0 {
            100
        } else {
            inner.limit as usize
        };
        let limit = limit.clamp(1, 500);
        let mut effects = Vec::new();
        let mut cursor: Option<(i64, String)> = None;
        loop {
            let candidates = service
                .db
                .runtime()
                .list_pending_runtime_dispatch_effects_page(
                    &inner.namespace,
                    100,
                    cursor.as_ref().map(|key| (key.0, key.1.as_str())),
                )
                .map_err(Status::internal)?;
            let exhausted = candidates.len() < 100;
            cursor = candidates
                .last()
                .map(|effect| (effect.created_at_ms, effect.effect_id.clone()));
            for effect in candidates {
                match authorize_action_effect_read(
                    service,
                    &principals,
                    tenant_context.as_ref(),
                    &effect,
                ) {
                    Ok(()) => effects.push(effect),
                    Err(status)
                        if matches!(
                            status.code(),
                            tonic::Code::PermissionDenied | tonic::Code::NotFound
                        ) => {}
                    Err(status) => return Err(status),
                }
                if effects.len() == limit {
                    break;
                }
            }
            if exhausted || effects.len() == limit {
                break;
            }
        }
        effects
    } else {
        return Err(Status::invalid_argument(
            "instance_id or namespace (pending runtime_dispatch) required",
        ));
    };
    let mut visible = Vec::new();
    for effect in &effects {
        match authorize_action_effect_read(service, &principals, tenant_context.as_ref(), effect) {
            Ok(()) => visible.push(to_proto_action_effect(effect)),
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::PermissionDenied | tonic::Code::NotFound
                ) => {}
            Err(status) => return Err(status),
        }
    }
    Ok(Response::new(ListActionEffectsResponse {
        effects: visible,
    }))
}
pub(super) async fn list_claimable_action_work(
    service: &SekaiServiceImpl,
    req: Request<ListClaimableActionWorkRequest>,
) -> Result<Response<ListClaimableActionWorkResponse>, Status> {
    let principals = caller_principals(&req);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    if inner.namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    authorize_action_instance_read(
        service,
        &principals,
        &inner.namespace,
        tenant_context.as_ref(),
    )?;
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
    let now = now_millis();
    let limit = limit.clamp(1, 500);
    let mut effects = Vec::new();
    let mut cursor: Option<(i64, String)> = None;
    loop {
        let candidates = service
            .db
            .runtime()
            .list_claimable_action_work_page(
                &inner.namespace,
                runtime,
                now,
                100,
                cursor.as_ref().map(|key| (key.0, key.1.as_str())),
            )
            .map_err(Status::internal)?;
        let exhausted = candidates.len() < 100;
        cursor = candidates
            .last()
            .map(|effect| (effect.created_at_ms, effect.effect_id.clone()));
        for effect in &candidates {
            if authorize_action_effect_read(service, &principals, tenant_context.as_ref(), effect)
                .is_ok()
            {
                effects.push(to_proto_action_effect(effect));
            }
            if effects.len() == limit {
                break;
            }
        }
        if exhausted || effects.len() == limit {
            break;
        }
    }
    Ok(Response::new(ListClaimableActionWorkResponse { effects }))
}
/// Runtime token for a granted claim (#1507), or empty with zero expiry when
/// the plane has no signing key or the caller has no tenant.
fn runtime_token_for(
    service: &SekaiServiceImpl,
    tenant_context: Option<&RequestEnterpriseContext>,
    effect: &crate::sekai::action_effect::ActionEffect,
    now_ms: i64,
) -> Result<(String, i64), Status> {
    let (Some(authority), Some(context)) =
        (service.runtime_token_authority.as_deref(), tenant_context)
    else {
        return Ok((String::new(), 0));
    };
    if effect.claim_owner.is_empty() || effect.claim_expires_at_ms <= now_ms {
        return Ok((String::new(), 0));
    }
    let binding = ClaimBinding {
        namespace: &effect.namespace,
        effect_id: &effect.effect_id,
        runtime_id: &effect.claim_owner,
        claim_generation: effect.claim_generation,
        claim_expires_at_ms: effect.claim_expires_at_ms,
    };
    let Some(claims) = RuntimeTokenClaims::for_claim(authority, context, binding, now_ms) else {
        return Ok((String::new(), 0));
    };
    let token = claims.sign(authority).map_err(Status::internal)?;
    Ok((token, claims.expires_at_ms))
}

/// Keep claimed work of a service-principal caller, and every follow-up call
/// on it, within the live registration's Action types.
fn enforce_service_principal_effect_type(
    service: &SekaiServiceImpl,
    tenant_context: Option<&RequestEnterpriseContext>,
    effect: &crate::sekai::action_effect::ActionEffect,
) -> Result<(), Status> {
    if service_principal_scope(service.db.runtime(), tenant_context)?.is_none() {
        return Ok(());
    }
    let instance = service
        .db
        .runtime()
        .get_action_instance(&effect.instance_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::permission_denied("action effect unavailable"))?;
    enforce_service_principal_action_type(service.db.runtime(), tenant_context, &instance.type_id)
}

/// Authorize a follow-up call on claimed work: a runtime token must cover
/// this exact claim, and the caller needs namespace write under its tenant.
fn authorize_claimed_work_call(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    runtime_token: Option<&RuntimeTokenClaims>,
    effect: &crate::sekai::action_effect::ActionEffect,
    runtime_id: &str,
    claim_generation: u64,
) -> Result<(), Status> {
    // Bind to the stored claim too, so a token for an earlier generation
    // cannot reach replay paths that return a newer claim's fence.
    if runtime_token.is_some_and(|claims| {
        claims.claim_generation != effect.claim_generation
            || !claims.covers(
                &effect.namespace,
                &effect.effect_id,
                runtime_id,
                claim_generation,
            )
    }) {
        return Err(Status::permission_denied(
            "runtime token does not cover this claim",
        ));
    }
    check_team_namespace(service.db.runtime(), principals, &effect.namespace, true)?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context,
        &effect.namespace,
        true,
    )?;
    enforce_service_principal_effect_type(service, tenant_context, effect)
}

pub(super) async fn claim_action_work(
    service: &SekaiServiceImpl,
    req: Request<ClaimActionWorkRequest>,
) -> Result<Response<ClaimActionWorkResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
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
        .runtime()
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    // Claim requires namespace write so only authorized hosts can take work.
    check_team_namespace(service.db.runtime(), &principals, &existing.namespace, true)?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &existing.namespace,
        true,
    )?;
    enforce_service_principal_effect_type(service, tenant_context.as_ref(), &existing)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let now = now_millis();
    let claimed = ActionWorkLifecycle::new(service.db.runtime())
        .with_agent_ceiling(service.enforce_agent_ceiling)
        .claim(
            ClaimActionWorkCommand {
                effect_id: &inner.effect_id,
                runtime_id: &inner.runtime_id,
                request_id: &inner.request_id,
                ttl_ms: inner.ttl_ms,
            },
            &actor,
            now,
        )
        .map_err(action_work_lifecycle_status)?;
    let (runtime_token, runtime_token_expires_at_ms) =
        runtime_token_for(service, tenant_context.as_ref(), &claimed.effect, now)?;
    Ok(Response::new(ClaimActionWorkResponse {
        effect: Some(to_proto_action_effect(&claimed.effect)),
        continuation: claimed
            .continuation
            .as_ref()
            .map(to_proto_action_work_continuation),
        park: claimed.park.as_ref().map(to_proto_action_work_park),
        runtime_token,
        runtime_token_expires_at_ms,
    }))
}
pub(super) async fn heartbeat_action_claim(
    service: &SekaiServiceImpl,
    req: Request<HeartbeatActionClaimRequest>,
) -> Result<Response<HeartbeatActionClaimResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let runtime_token = req.extensions().get::<RuntimeTokenClaims>().cloned();
    let inner = req.into_inner();
    let existing = service
        .db
        .runtime()
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    authorize_claimed_work_call(
        service,
        &principals,
        tenant_context.as_ref(),
        runtime_token.as_ref(),
        &existing,
        &inner.runtime_id,
        inner.claim_generation,
    )?;
    let actor = principals.first().cloned().unwrap_or_default();
    let now = now_millis();
    let stored = ActionWorkLifecycle::new(service.db.runtime())
        .heartbeat(
            HeartbeatActionClaimCommand {
                effect_id: &inner.effect_id,
                runtime_id: &inner.runtime_id,
                claim_generation: inner.claim_generation,
                fencing_token: &inner.fencing_token,
                ttl_ms: inner.ttl_ms,
            },
            &actor,
            now,
        )
        .map_err(action_work_lifecycle_status)?;
    let (runtime_token, runtime_token_expires_at_ms) =
        runtime_token_for(service, tenant_context.as_ref(), &stored, now)?;
    Ok(Response::new(HeartbeatActionClaimResponse {
        effect: Some(to_proto_action_effect(&stored)),
        runtime_token,
        runtime_token_expires_at_ms,
    }))
}
pub(super) async fn ack_action_work(
    service: &SekaiServiceImpl,
    req: Request<AckActionWorkRequest>,
) -> Result<Response<AckActionWorkResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let runtime_token = req.extensions().get::<RuntimeTokenClaims>().cloned();
    let inner = req.into_inner();
    let existing = service
        .db
        .runtime()
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    authorize_claimed_work_call(
        service,
        &principals,
        tenant_context.as_ref(),
        runtime_token.as_ref(),
        &existing,
        &inner.runtime_id,
        inner.claim_generation,
    )?;
    let actor = principals.first().cloned().unwrap_or_default();
    let instance = service
        .db
        .runtime()
        .get_action_instance(&existing.instance_id)
        .map_err(Status::internal)?;
    if existing.status != crate::sekai::action_effect::EFFECT_STATUS_COMPLETED
        && existing.status != crate::sekai::action_effect::EFFECT_STATUS_FAILED
    {
        let action_type = instance
            .as_ref()
            .map(|instance| instance.type_id.as_str())
            .unwrap_or("");
        let origin = instance
            .as_ref()
            .map(|instance| instance.principal.as_str())
            .unwrap_or("");
        let delegating = instance
            .as_ref()
            .and_then(|instance| instance.delegating_actor.as_deref());
        let supplied_tenant = acting_tenant(tenant_context.as_ref());
        let stored_agent = instance
            .as_ref()
            .is_some_and(|instance| instance.agent_action);
        let actor_agent =
            freeze_actor_is_agent(service.db.runtime(), &actor, tenant_context.as_ref())?;
        let origin_agent = stored_agent
            || crate::sekai::write_freeze::actor_is_agent(
                service.db.runtime(),
                origin,
                delegating,
                false,
            )
            .map_err(Status::internal)?;
        let request_act = tenant_context
            .as_ref()
            .and_then(|context| context.act.as_deref());
        let actor_tenant = crate::sekai::write_freeze::acting_or_registered_tenant(
            service.db.runtime(),
            supplied_tenant,
            &actor,
        )
        .map_err(Status::internal)?;
        let origin_tenant = crate::sekai::write_freeze::acting_or_registered_tenant(
            service.db.runtime(),
            supplied_tenant,
            origin,
        )
        .map_err(Status::internal)?;
        let mut checks = crate::sekai::write_freeze::write_checks_for_actors(
            &existing.namespace,
            actor_tenant.as_ref(),
            &actor,
            request_act,
            action_type,
            actor_agent,
        );
        checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
            &existing.namespace,
            origin_tenant.as_ref(),
            origin,
            delegating,
            action_type,
            origin_agent,
        ));
        let stored_tenant = instance
            .as_ref()
            .map(|instance| instance.admission_tenant.as_str())
            .unwrap_or("");
        if !stored_tenant.is_empty() {
            checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
                &existing.namespace,
                stored_tenant,
                origin,
                delegating,
                action_type,
                origin_agent,
            ));
        }
        let resource_tenant = instance
            .as_ref()
            .map(|instance| instance.resource_tenant.as_str())
            .unwrap_or("");
        if !resource_tenant.is_empty() && resource_tenant != stored_tenant {
            checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
                &existing.namespace,
                resource_tenant,
                origin,
                delegating,
                action_type,
                origin_agent,
            ));
        }
        crate::sekai::write_freeze::refuse_if_frozen_any(service.db.runtime(), &checks)?;
    }
    let now = now_millis();
    let acked = ActionWorkLifecycle::new(service.db.runtime())
        .with_agent_ceiling(service.enforce_agent_ceiling)
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let runtime_token = req.extensions().get::<RuntimeTokenClaims>().cloned();
    let inner = req.into_inner();
    let effect = service
        .db
        .runtime()
        .get_action_effect(&inner.effect_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action effect not found"))?;
    authorize_claimed_work_call(
        service,
        &principals,
        tenant_context.as_ref(),
        runtime_token.as_ref(),
        &effect,
        &inner.runtime_id,
        inner.claim_generation,
    )?;
    let actor = principals.first().cloned().unwrap_or_default();
    let replay = ActionWorkLifecycle::new(service.db.runtime())
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
        .runtime()
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
        .runtime()
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
        .runtime()
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

/// The single subject a token or enterprise credential established for this
/// request, or `None` when the identity is self-asserted or ambiguous.
fn credentialed_decider<T>(req: &Request<T>, principals: &[String]) -> Option<String> {
    let enterprise = req
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
        .is_some();
    let credentialed = enterprise
        || matches!(
            req.metadata()
                .get("x-sekai-auth-source")
                .and_then(|value| value.to_str().ok()),
            Some("token" | "enterprise")
        );
    match principals {
        [subject]
            if credentialed && !matches!(subject.as_str(), "root" | "local" | "anonymous") =>
        {
            Some(subject.clone())
        }
        _ => None,
    }
}

#[cfg(test)]
mod credentialed_decider_tests {
    use super::credentialed_decider;
    use tonic::Request;

    fn request(source: Option<&str>) -> Request<()> {
        let mut request = Request::new(());
        if let Some(source) = source {
            request
                .metadata_mut()
                .insert("x-sekai-auth-source", source.parse().unwrap());
        }
        request
    }

    fn principals(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn only_one_credentialed_subject_may_decide() {
        assert_eq!(
            credentialed_decider(&request(Some("token")), &principals(&["bob"])).as_deref(),
            Some("bob")
        );
        assert_eq!(
            credentialed_decider(&request(Some("enterprise")), &principals(&["bob"])).as_deref(),
            Some("bob")
        );
        // Self-asserted identities: local socket, insecure transport, none.
        for source in [Some("local"), None] {
            assert!(credentialed_decider(&request(source), &principals(&["bob"])).is_none());
        }
        // A comma-listed x-principal never becomes any-of.
        assert!(
            credentialed_decider(&request(Some("token")), &principals(&["mallory", "bob"]))
                .is_none()
        );
        for reserved in ["root", "local", "anonymous"] {
            assert!(
                credentialed_decider(&request(Some("token")), &principals(&[reserved])).is_none()
            );
        }
    }
}
