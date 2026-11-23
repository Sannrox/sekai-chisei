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
    let cloned = service.clone();
    service
        .spawn_db(move || apply_source_batch_blocking(&cloned, req))
        .await
}

fn apply_source_batch_blocking(
    service: &SekaiServiceImpl,
    req: Request<ApplySourceBatchRequest>,
) -> Result<Response<ApplySourceBatchResponse>, Status> {
    let principals = caller_principals(&req);
    let principal = require_single_source_principal(&principals)?.to_string();
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let operation_id = call_operation_identity(&req, "op-source-batch")?;
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
    let tenant = crate::sekai::write_freeze::acting_or_registered_tenant(
        service.db.runtime(),
        acting_tenant(tenant_context.as_ref()),
        &principal,
    )
    .map_err(Status::internal)?;
    let act = tenant_context
        .as_ref()
        .and_then(|context| context.act.as_deref());
    let agent = freeze_actor_is_agent(service.db.runtime(), &principal, tenant_context.as_ref())?;
    let mut checks = crate::sekai::write_freeze::write_checks_for_actors(
        &proto.namespace,
        tenant.as_ref(),
        &principal,
        act,
        "",
        agent,
    );
    let owner = shared_space_resource_tenant(
        service.db.runtime(),
        tenant_context.as_ref(),
        &proto.namespace,
        crate::enterprise::NamespaceAction::Write,
    );
    if let Some(owner) = owner.as_deref().filter(|owner| *owner != tenant.as_ref()) {
        checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
            &proto.namespace,
            owner,
            &principal,
            act,
            "",
            agent,
        ));
    }
    crate::sekai::write_freeze::refuse_if_frozen_any(service.db.runtime(), &checks)
        .map_err(crate::grpc::write_freeze_status)?;
    if !proto.source_id.is_empty() {
        crate::sekai::source::admit_batch(
            service.db.runtime(),
            &proto.namespace,
            &proto.source,
            &proto.source_instance,
            &proto.source_id,
        )
        .map_err(map_source_sync_apply_error)?;
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
        .apply_source_batch_with_operation(
            &batch,
            &principal,
            now_millis(),
            Some(&policy_generation),
            Some(&authorized_objects),
            Some(&operation_id),
        )
        .map_err(map_source_sync_apply_error)?;
    ensure_authoritative_source_result(&result)?;
    let mut proto_result = to_proto_source_batch_result(&result);
    // A replay reports the identity of the call that opened the transaction.
    fill_operation_ids(service, &batch.namespace, proto_result.transaction.as_mut())?;
    Ok(Response::new(ApplySourceBatchResponse {
        result: Some(proto_result),
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
    let mut proto_state = state.as_ref().map(to_proto_source_sync_state);
    if let Some(state) = proto_state.as_mut() {
        fill_operation_ids(
            service,
            &input.namespace,
            [
                state.open_transaction.as_mut(),
                state.latest_transaction.as_mut(),
                state
                    .last_result
                    .as_mut()
                    .and_then(|result| result.transaction.as_mut()),
            ]
            .into_iter()
            .flatten(),
        )?;
    }
    Ok(Response::new(GetSourceSyncStateResponse {
        found: state.is_some(),
        state: proto_state,
    }))
}

/// Sets `operation_id` on each of `transactions` from the identity recorded
/// when the batch opened (#3087); empty for a batch opened before it was.
fn fill_operation_ids<'a>(
    service: &SekaiServiceImpl,
    namespace: &str,
    transactions: impl IntoIterator<Item = &'a mut SourceBatchTransaction>,
) -> Result<(), Status> {
    let mut transactions: Vec<_> = transactions.into_iter().collect();
    let ids: Vec<&str> = transactions
        .iter()
        .map(|transaction| transaction.transaction_id.as_str())
        .collect();
    let operation_ids = service
        .db
        .runtime()
        .source_batch_operation_ids(namespace, &ids)
        .map_err(|_| Status::internal("source batch identity unavailable"))?;
    for transaction in &mut transactions {
        transaction.operation_id = operation_ids
            .get(&transaction.transaction_id)
            .cloned()
            .unwrap_or_default();
    }
    Ok(())
}
/// Most batch transactions one page returns.
const MAX_BATCH_HISTORY_PAGE: usize = 100;

/// A page token for batch history: the binding and the last row returned,
/// opaque to callers.
#[derive(serde::Serialize, serde::Deserialize)]
struct BatchHistoryToken {
    binding: String,
    opened_at_ms: i64,
    transaction_id: String,
}

fn encode_batch_history_token(token: &BatchHistoryToken) -> Result<String, Status> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    serde_json::to_vec(token)
        .map(|json| URL_SAFE_NO_PAD.encode(json))
        .map_err(|_| Status::internal("page token unavailable"))
}

fn decode_batch_history_token(token: &str) -> Result<BatchHistoryToken, Status> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(token)
        .ok()
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or_else(|| Status::invalid_argument("invalid page_token"))
}

/// A binding's batch transactions, newest first (#1699). Authorized exactly
/// as `GetSourceSyncState`, so a caller it refuses is refused here the same
/// way.
pub(super) async fn list_source_batch_transactions(
    service: &SekaiServiceImpl,
    req: Request<ListSourceBatchTransactionsRequest>,
) -> Result<Response<ListSourceBatchTransactionsResponse>, Status> {
    let principals = caller_principals(&req);
    require_single_source_principal(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    validate_source_sync_lookup(&GetSourceSyncStateRequest {
        namespace: input.namespace.clone(),
        source_instance: input.source_instance.clone(),
        type_digest: input.type_digest.clone(),
    })?;
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    require_admitted_source_type(service.db.runtime(), &input.namespace, &input.type_digest)?;
    let page_size = match input.page_size as usize {
        0 => MAX_BATCH_HISTORY_PAGE,
        size => size.min(MAX_BATCH_HISTORY_PAGE),
    };
    let token = (!input.page_token.is_empty())
        .then(|| decode_batch_history_token(&input.page_token))
        .transpose()?;
    let before = token
        .as_ref()
        .map(|token| crate::db::object_sync::BatchHistoryCursor {
            opened_at_ms: token.opened_at_ms,
            transaction_id: token.transaction_id.clone(),
        });
    // One extra row tells whether another page follows.
    let history = service
        .db
        .runtime()
        .list_source_batch_transactions(
            &input.namespace,
            &input.source_instance,
            &input.type_digest,
            before.as_ref(),
            page_size + 1,
        )
        .map_err(|_| Status::internal("source batch history unavailable"))?;
    let Some(mut history) = history else {
        return Ok(Response::new(ListSourceBatchTransactionsResponse {
            found: false,
            transactions: Vec::new(),
            next_page_token: String::new(),
        }));
    };
    if token
        .as_ref()
        .is_some_and(|token| token.binding != history.binding_id)
    {
        return Err(Status::invalid_argument(
            "page_token belongs to another source binding",
        ));
    }
    let more = history.transactions.len() > page_size;
    history.transactions.truncate(page_size);
    let next_page_token = match (more, history.transactions.last()) {
        (true, Some(last)) => encode_batch_history_token(&BatchHistoryToken {
            binding: history.binding_id.clone(),
            opened_at_ms: last.opened_at_ms,
            transaction_id: last.transaction_id.clone(),
        })?,
        _ => String::new(),
    };
    let mut transactions: Vec<_> = history
        .transactions
        .iter()
        .map(to_proto_source_transaction)
        .collect();
    fill_operation_ids(service, &input.namespace, &mut transactions)?;
    Ok(Response::new(ListSourceBatchTransactionsResponse {
        found: true,
        transactions,
        next_page_token,
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
