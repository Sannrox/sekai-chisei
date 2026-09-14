use super::*;

pub(super) async fn create_object(
    service: &SekaiServiceImpl,
    req: Request<CreateObjectRequest>,
) -> Result<Response<CreateObjectResponse>, Status> {
    let (metadata, extensions, input) = req.into_parts();
    let CreateObjectRequest {
        object,
        lease_precondition,
    } = input;
    let mutation = Request::from_parts(
        metadata,
        extensions,
        GuardedCreateObjectRequest {
            object,
            lease_precondition,
        },
    );
    let response = service.guarded_create_object(mutation).await?;
    Ok(Response::new(CreateObjectResponse {
        object: response.into_inner().object,
    }))
}
pub(super) async fn get_object(
    service: &SekaiServiceImpl,
    req: Request<GetObjectRequest>,
) -> Result<Response<GetObjectResponse>, Status> {
    service.get_visible_object(req).await
}
pub(super) async fn update_object(
    service: &SekaiServiceImpl,
    req: Request<UpdateObjectRequest>,
) -> Result<Response<UpdateObjectResponse>, Status> {
    let (metadata, extensions, input) = req.into_parts();
    let UpdateObjectRequest {
        object,
        lease_precondition,
    } = input;
    let mutation = Request::from_parts(
        metadata,
        extensions,
        GuardedUpdateObjectRequest {
            object,
            lease_precondition,
        },
    );
    let response = service.guarded_update_object(mutation).await?;
    Ok(Response::new(UpdateObjectResponse {
        object: response.into_inner().object,
    }))
}
pub(super) async fn delete_object(
    service: &SekaiServiceImpl,
    req: Request<DeleteObjectRequest>,
) -> Result<Response<DeleteObjectResponse>, Status> {
    let (metadata, extensions, input) = req.into_parts();
    let DeleteObjectRequest {
        id,
        lease_precondition,
    } = input;
    let mutation = Request::from_parts(
        metadata,
        extensions,
        GuardedDeleteObjectRequest {
            id,
            lease_precondition,
        },
    );
    service.guarded_delete_object(mutation).await?;
    Ok(Response::new(DeleteObjectResponse {}))
}
pub(super) async fn list_objects(
    service: &SekaiServiceImpl,
    req: Request<ListObjectsRequest>,
) -> Result<Response<ListObjectsResponse>, Status> {
    service.list_visible_objects(req).await
}
pub(super) async fn evaluate_object_set(
    service: &SekaiServiceImpl,
    req: Request<EvaluateObjectSetRequest>,
) -> Result<Response<EvaluateObjectSetResponse>, Status> {
    service.evaluate_visible_object_set(req).await
}
pub(super) async fn read_object_change_subscription(
    service: &SekaiServiceImpl,
    req: Request<ReadObjectChangeSubscriptionRequest>,
) -> Result<Response<ReadObjectChangeSubscriptionResponse>, Status> {
    service.read_visible_object_change_subscription(req).await
}
pub(super) async fn put_object_security_policy_revision(
    service: &SekaiServiceImpl,
    req: Request<PutObjectSecurityPolicyRevisionRequest>,
) -> Result<Response<PutObjectSecurityPolicyRevisionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(&service.db, &req)?;
    let input = req.into_inner();
    let policy = crate::sekai::object_security::ObjectSecurityPolicy::from_canonical_input(
        &input.canonical_policy_json,
    )
    .map_err(Status::invalid_argument)?;
    enforce_namespace_tenant_context(
        &service.db,
        tenant_context.as_ref(),
        &policy.namespace,
        true,
    )?;
    check_team_namespace(&service.db, &principals, &policy.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let revision = service
        .db
        .put_object_security_policy(&policy, &actor, &input.idempotency_key, now_millis())
        .map_err(map_object_security_error)?;
    Ok(Response::new(PutObjectSecurityPolicyRevisionResponse {
        revision: Some(to_proto_object_security_revision(&revision)),
    }))
}
pub(super) async fn get_object_security_policy_revision(
    service: &SekaiServiceImpl,
    req: Request<GetObjectSecurityPolicyRevisionRequest>,
) -> Result<Response<GetObjectSecurityPolicyRevisionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(&service.db, &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        &service.db,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    check_team_namespace(&service.db, &principals, &input.namespace, false)?;
    let revision = service
        .db
        .get_object_security_policy(&input.namespace, &input.revision_digest)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("not found"))?;
    Ok(Response::new(GetObjectSecurityPolicyRevisionResponse {
        revision: Some(to_proto_object_security_revision(&revision)),
    }))
}
pub(super) async fn activate_object_security_policies(
    service: &SekaiServiceImpl,
    req: Request<ActivateObjectSecurityPoliciesRequest>,
) -> Result<Response<ActivateObjectSecurityPoliciesResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(&service.db, &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(&service.db, tenant_context.as_ref(), &input.namespace, true)?;
    check_team_namespace(&service.db, &principals, &input.namespace, true)?;
    let mut policies = BTreeMap::new();
    for binding in input.policies {
        if binding.kind.trim().is_empty()
            || binding.revision_digest.trim().is_empty()
            || policies
                .insert(binding.kind, binding.revision_digest)
                .is_some()
        {
            return Err(Status::invalid_argument(
                "each policy kind must appear exactly once",
            ));
        }
    }
    let actor = principals.first().cloned().unwrap_or_default();
    let activation = service
        .db
        .activate_object_security_policies(
            &input.namespace,
            &policies,
            &actor,
            &input.idempotency_key,
            now_millis(),
        )
        .map_err(map_object_security_error)?;
    Ok(Response::new(ActivateObjectSecurityPoliciesResponse {
        activation: Some(to_proto_object_security_activation(&activation)),
    }))
}
pub(super) async fn get_object_security_activation(
    service: &SekaiServiceImpl,
    req: Request<GetObjectSecurityActivationRequest>,
) -> Result<Response<GetObjectSecurityActivationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(&service.db, &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        &service.db,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    check_team_namespace(&service.db, &principals, &input.namespace, false)?;
    let activation = service
        .db
        .get_object_security_activation(&input.namespace)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("not found"))?;
    Ok(Response::new(GetObjectSecurityActivationResponse {
        activation: Some(to_proto_object_security_activation(&activation)),
    }))
}
pub(super) async fn put_purpose_authorization(
    service: &SekaiServiceImpl,
    req: Request<PutPurposeAuthorizationRequest>,
) -> Result<Response<PutPurposeAuthorizationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(&service.db, &req)?;
    let authorization = req
        .into_inner()
        .authorization
        .ok_or_else(|| Status::invalid_argument("authorization required"))?;
    enforce_namespace_tenant_context(
        &service.db,
        tenant_context.as_ref(),
        &authorization.namespace,
        true,
    )?;
    check_team_namespace(&service.db, &principals, &authorization.namespace, true)?;
    let mut authorization = from_proto_purpose_authorization(authorization);
    authorization.created_by = principals.first().cloned().unwrap_or_default();
    authorization.created_at_ms = now_millis();
    authorization.revoked_at_ms = 0;
    authorization.prepare().map_err(Status::invalid_argument)?;
    let stored = service
        .db
        .put_purpose_authorization(&authorization)
        .map_err(map_purpose_authorization_error)?;
    Ok(Response::new(PutPurposeAuthorizationResponse {
        authorization: Some(to_proto_purpose_authorization(&stored)),
    }))
}
pub(super) async fn revoke_purpose_authorization(
    service: &SekaiServiceImpl,
    req: Request<RevokePurposeAuthorizationRequest>,
) -> Result<Response<RevokePurposeAuthorizationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let authorization_id = req.into_inner().authorization_id;
    let stored = service
        .db
        .revoke_purpose_authorization(&authorization_id, now_millis())
        .map_err(map_purpose_authorization_error)?;
    Ok(Response::new(RevokePurposeAuthorizationResponse {
        authorization: Some(to_proto_purpose_authorization(&stored)),
    }))
}
pub(super) async fn put_classification_lattice(
    service: &SekaiServiceImpl,
    req: Request<PutClassificationLatticeRequest>,
) -> Result<Response<PutClassificationLatticeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(&service.db, &req)?;
    let lattice = req
        .into_inner()
        .lattice
        .ok_or_else(|| Status::invalid_argument("lattice required"))?;
    enforce_namespace_tenant_context(
        &service.db,
        tenant_context.as_ref(),
        &lattice.namespace,
        true,
    )?;
    check_team_namespace(&service.db, &principals, &lattice.namespace, true)?;
    let lattice = from_proto_classification_lattice(lattice);
    lattice.prepare().map_err(Status::invalid_argument)?;
    let stored = service
        .db
        .put_classification_lattice(
            &lattice,
            principals.first().map(String::as_str).unwrap_or_default(),
            now_millis(),
        )
        .map_err(map_classification_lattice_error)?;
    Ok(Response::new(PutClassificationLatticeResponse {
        lattice: Some(to_proto_classification_lattice(&stored)?),
    }))
}
pub(super) async fn get_classification_lattice(
    service: &SekaiServiceImpl,
    req: Request<GetClassificationLatticeRequest>,
) -> Result<Response<GetClassificationLatticeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(&service.db, &req)?;
    let namespace = req.into_inner().namespace;
    enforce_namespace_tenant_context(&service.db, tenant_context.as_ref(), &namespace, false)?;
    check_team_namespace(&service.db, &principals, &namespace, false)?;
    let lattice = service
        .db
        .get_classification_lattice(&namespace)
        .map_err(map_classification_lattice_error)?
        .ok_or_else(|| Status::not_found("not found"))?;
    Ok(Response::new(GetClassificationLatticeResponse {
        lattice: Some(to_proto_classification_lattice(&lattice)?),
    }))
}
pub(super) async fn find_by_external_id(
    service: &SekaiServiceImpl,
    req: Request<FindByExternalIdRequest>,
) -> Result<Response<GetObjectResponse>, Status> {
    service.find_visible_by_external_id(req).await
}
pub(super) async fn find_by_property(
    service: &SekaiServiceImpl,
    req: Request<FindByPropertyRequest>,
) -> Result<Response<ListObjectsResponse>, Status> {
    service.find_visible_by_property(req).await
}
pub(super) async fn create_link(
    service: &SekaiServiceImpl,
    req: Request<CreateLinkRequest>,
) -> Result<Response<CreateLinkResponse>, Status> {
    service.create_authorized_link(req).await
}
pub(super) async fn delete_link(
    service: &SekaiServiceImpl,
    req: Request<DeleteLinkRequest>,
) -> Result<Response<DeleteLinkResponse>, Status> {
    service.delete_authorized_link(req).await
}
pub(super) async fn get_links(
    service: &SekaiServiceImpl,
    req: Request<GetLinksRequest>,
) -> Result<Response<GetLinksResponse>, Status> {
    service.get_visible_links(req).await
}
pub(super) async fn get_linked_objects(
    service: &SekaiServiceImpl,
    req: Request<GetLinkedObjectsRequest>,
) -> Result<Response<GetLinkedObjectsResponse>, Status> {
    service.get_visible_linked_objects(req).await
}
