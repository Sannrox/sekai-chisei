use super::*;

pub(super) async fn acquire_lease(
    service: &SekaiServiceImpl,
    req: Request<AcquireLeaseRequest>,
) -> Result<Response<AcquireLeaseResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let lease = LeaseLifecycle::new(service.db.runtime(), &service.security, &service.site_id)
        .with_policy_context(principal_policy_context_from(
            &principals,
            tenant_context.as_ref(),
        ))
        .acquire(AcquireLeaseCommand {
            namespace: &input.namespace,
            key: &input.key,
            owner: &input.owner,
            ttl_ms: input.ttl_ms,
            request_id: &input.request_id,
            actor: &actor,
            principals: &principals,
            now_ms: now_millis(),
        })
        .map_err(map_lease_lifecycle_error)?;
    Ok(Response::new(AcquireLeaseResponse {
        lease: Some(to_proto_lease(&lease)),
    }))
}
pub(super) async fn get_lease(
    service: &SekaiServiceImpl,
    req: Request<GetLeaseRequest>,
) -> Result<Response<GetLeaseResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, false)?;
    let lease = LeaseLifecycle::new(service.db.runtime(), &service.security, &service.site_id)
        .with_policy_context(principal_policy_context_from(
            &principals,
            tenant_context.as_ref(),
        ))
        .get(GetLeaseCommand {
            namespace: &input.namespace,
            key: &input.key,
            principals: &principals,
        })
        .map_err(map_lease_lifecycle_error)?;
    Ok(Response::new(GetLeaseResponse {
        lease: Some(to_proto_lease(&lease)),
    }))
}
pub(super) async fn refresh_lease(
    service: &SekaiServiceImpl,
    req: Request<RefreshLeaseRequest>,
) -> Result<Response<RefreshLeaseResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let lease = LeaseLifecycle::new(service.db.runtime(), &service.security, &service.site_id)
        .with_policy_context(principal_policy_context_from(
            &principals,
            tenant_context.as_ref(),
        ))
        .refresh(RefreshLeaseCommand {
            namespace: &input.namespace,
            key: &input.key,
            fencing_token: &input.fencing_token,
            ttl_ms: input.ttl_ms,
            request_id: &input.request_id,
            actor: &actor,
            principals: &principals,
            now_ms: now_millis(),
        })
        .map_err(map_lease_lifecycle_error)?;
    Ok(Response::new(RefreshLeaseResponse {
        lease: Some(to_proto_lease(&lease)),
    }))
}
pub(super) async fn release_lease(
    service: &SekaiServiceImpl,
    req: Request<ReleaseLeaseRequest>,
) -> Result<Response<ReleaseLeaseResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let lease = LeaseLifecycle::new(service.db.runtime(), &service.security, &service.site_id)
        .with_policy_context(principal_policy_context_from(
            &principals,
            tenant_context.as_ref(),
        ))
        .release(ReleaseLeaseCommand {
            namespace: &input.namespace,
            key: &input.key,
            fencing_token: &input.fencing_token,
            request_id: &input.request_id,
            actor: &actor,
            principals: &principals,
            now_ms: now_millis(),
        })
        .map_err(map_lease_lifecycle_error)?;
    Ok(Response::new(ReleaseLeaseResponse {
        lease: Some(to_proto_lease(&lease)),
    }))
}
pub(super) async fn takeover_expired_lease(
    service: &SekaiServiceImpl,
    req: Request<TakeoverExpiredLeaseRequest>,
) -> Result<Response<TakeoverExpiredLeaseResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let lease = LeaseLifecycle::new(service.db.runtime(), &service.security, &service.site_id)
        .with_policy_context(principal_policy_context_from(
            &principals,
            tenant_context.as_ref(),
        ))
        .takeover_expired(TakeoverExpiredLeaseCommand {
            namespace: &input.namespace,
            key: &input.key,
            owner: &input.owner,
            expected_fencing_token: &input.expected_fencing_token,
            expected_expires_at_ms: input.expected_expires_at_ms,
            ttl_ms: input.ttl_ms,
            request_id: &input.request_id,
            actor: &actor,
            principals: &principals,
            now_ms: now_millis(),
        })
        .map_err(map_lease_lifecycle_error)?;
    Ok(Response::new(TakeoverExpiredLeaseResponse {
        lease: Some(to_proto_lease(&lease)),
    }))
}
pub(super) async fn apply_source_batch(
    service: &SekaiServiceImpl,
    req: Request<ApplySourceBatchRequest>,
) -> Result<Response<ApplySourceBatchResponse>, Status> {
    let principals = caller_principals(&req);
    let principal = require_single_source_principal(&principals)?.to_string();
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let proto = req
        .into_inner()
        .batch
        .ok_or_else(|| Status::invalid_argument("source batch required"))?;
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &proto.namespace,
        true,
    )?;
    if proto.producer_identity != principal {
        return Err(Status::permission_denied("source producer identity denied"));
    }
    let mut batch = from_proto_source_batch(proto)?;
    batch.producer_identity = principal.clone();
    let authorized_objects = authorize_source_batch_object_policy(
        service.db.runtime(),
        &batch,
        &principals,
        tenant_context.as_ref(),
    )?;
    let policy_generation = object_security_generation(service.db.runtime(), &batch.namespace)?;
    let result = service
        .db
        .runtime()
        .apply_source_batch_with_policy_generation(
            &batch,
            &principal,
            now_millis(),
            Some(&policy_generation),
            Some(&authorized_objects),
        )
        .map_err(map_source_sync_apply_error)?;
    ensure_authoritative_source_result(&result)?;
    Ok(Response::new(ApplySourceBatchResponse {
        result: Some(to_proto_source_batch_result(&result)),
    }))
}
pub(super) async fn get_source_sync_state(
    service: &SekaiServiceImpl,
    req: Request<GetSourceSyncStateRequest>,
) -> Result<Response<GetSourceSyncStateResponse>, Status> {
    let principals = caller_principals(&req);
    require_single_source_principal(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    validate_source_sync_lookup(&input)?;
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    require_admitted_source_type(service.db.runtime(), &input.namespace, &input.type_digest)?;
    let state = service
        .db
        .runtime()
        .get_source_sync_state(&input.namespace, &input.source_instance, &input.type_digest)
        .map_err(|_| Status::internal("source sync state unavailable"))?;
    Ok(Response::new(GetSourceSyncStateResponse {
        found: state.is_some(),
        state: state.as_ref().map(to_proto_source_sync_state),
    }))
}
pub(super) async fn register_source_type_descriptor(
    service: &SekaiServiceImpl,
    req: Request<RegisterSourceTypeDescriptorRequest>,
) -> Result<Response<RegisterSourceTypeDescriptorResponse>, Status> {
    let principals = caller_principals(&req);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    let actor = authorize_source_type_namespace_admin(service, &principals, &input.namespace)?;
    let proposed = crate::sekai::source_type_descriptor::ProposedSourceTypeDescriptor::prepare(
        input.source,
        input.record_kind,
        input.schema_revision,
    )
    .map_err(map_source_type_descriptor_error)?;
    let descriptor = crate::sekai::source_type_descriptor::register_source_type_descriptor(
        service.db.runtime(),
        &actor,
        &input.namespace,
        &proposed,
        now_millis(),
    )
    .map_err(map_source_type_descriptor_error)?;
    Ok(Response::new(RegisterSourceTypeDescriptorResponse {
        descriptor: Some(to_proto_source_type_descriptor(&descriptor)),
    }))
}
pub(super) async fn inspect_source_type_descriptor(
    service: &SekaiServiceImpl,
    req: Request<InspectSourceTypeDescriptorRequest>,
) -> Result<Response<InspectSourceTypeDescriptorResponse>, Status> {
    let principals = caller_principals(&req);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    let actor = authorize_source_type_namespace_admin(service, &principals, &input.namespace)?;
    let descriptor = crate::sekai::source_type_descriptor::inspect_source_type_descriptor(
        service.db.runtime(),
        &actor,
        &input.namespace,
        &input.digest,
    )
    .map_err(map_source_type_descriptor_error)?;
    Ok(Response::new(InspectSourceTypeDescriptorResponse {
        descriptor: Some(to_proto_source_type_descriptor(&descriptor)),
    }))
}
pub(super) async fn retire_source_type_descriptor(
    service: &SekaiServiceImpl,
    req: Request<RetireSourceTypeDescriptorRequest>,
) -> Result<Response<RetireSourceTypeDescriptorResponse>, Status> {
    let principals = caller_principals(&req);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    let actor = authorize_source_type_namespace_admin(service, &principals, &input.namespace)?;
    let descriptor = crate::sekai::source_type_descriptor::retire_source_type_descriptor(
        service.db.runtime(),
        &actor,
        &input.namespace,
        &input.digest,
        now_millis(),
    )
    .map_err(map_source_type_descriptor_error)?;
    Ok(Response::new(RetireSourceTypeDescriptorResponse {
        descriptor: Some(to_proto_source_type_descriptor(&descriptor)),
    }))
}
