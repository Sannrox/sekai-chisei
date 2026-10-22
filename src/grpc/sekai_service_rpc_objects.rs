use super::*;
use std::collections::{BTreeMap, BTreeSet};

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
pub(super) async fn register_object_type_datasource(
    service: &SekaiServiceImpl,
    req: Request<RegisterObjectTypeDatasourceRequest>,
) -> Result<Response<RegisterObjectTypeDatasourceResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    let proto = input
        .datasource
        .ok_or_else(|| Status::invalid_argument("datasource required"))?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &proto.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &proto.namespace, true)?;
    let binding = crate::sekai::object_type_index::ObjectTypeDatasource {
        contract_version: proto.contract_version,
        namespace: proto.namespace,
        kind: proto.kind,
        definition_digest: proto.definition_digest,
        dataset_id: proto.dataset_id,
        key_column: proto.key_column,
        property_mapping: proto.property_mapping.into_iter().collect(),
        hidden_column: proto.hidden_column,
        edits_only: proto.edits_only,
    }
    .prepare()
    .map_err(|error| Status::invalid_argument(error.message()))?;
    service
        .db
        .runtime()
        .register_object_type_datasource(&binding, now_millis())
        .map_err(Status::internal)?;
    Ok(Response::new(RegisterObjectTypeDatasourceResponse {
        datasource: Some(to_proto_datasource(&binding)),
    }))
}
pub(super) async fn reindex_object_type(
    service: &SekaiServiceImpl,
    req: Request<ReindexObjectTypeRequest>,
) -> Result<Response<ReindexObjectTypeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
    let report = service
        .db
        .runtime()
        .apply_object_type_index(
            &input.namespace,
            &input.kind,
            input.full_rebuild,
            now_millis(),
        )
        .map_err(|error| {
            if error.contains("not found") {
                Status::not_found(error)
            } else {
                Status::internal(error)
            }
        })?;
    let status = service
        .db
        .runtime()
        .object_type_index_status(&input.namespace, &input.kind, now_millis())
        .map_err(Status::internal)?;
    Ok(Response::new(ReindexObjectTypeResponse {
        rewritten_keys: report.rewritten_keys,
        skipped_unchanged: report.skipped_unchanged,
        quarantined: report.quarantined,
        quarantine_reason: report.quarantine_reason,
        status: status.as_ref().map(to_proto_index_status),
    }))
}
pub(super) async fn get_object_type_index_status(
    service: &SekaiServiceImpl,
    req: Request<GetObjectTypeIndexStatusRequest>,
) -> Result<Response<GetObjectTypeIndexStatusResponse>, Status> {
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
    let status = service
        .db
        .runtime()
        .object_type_index_status(&input.namespace, &input.kind, now_millis())
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("not found"))?;
    Ok(Response::new(GetObjectTypeIndexStatusResponse {
        status: Some(to_proto_index_status(&status)),
    }))
}
pub(super) async fn put_object_type_index_edit(
    service: &SekaiServiceImpl,
    req: Request<PutObjectTypeIndexEditRequest>,
) -> Result<Response<PutObjectTypeIndexEditResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
    service
        .db
        .runtime()
        .put_object_type_index_edit(&crate::sekai::object_type_index::ObjectTypeIndexEdit {
            namespace: input.namespace,
            kind: input.kind,
            source_key: input.source_key,
            properties: input.properties.into_iter().collect(),
            hidden: input.hidden,
        })
        .map_err(Status::internal)?;
    Ok(Response::new(PutObjectTypeIndexEditResponse {}))
}

fn to_proto_datasource(
    binding: &crate::sekai::object_type_index::ObjectTypeDatasource,
) -> ObjectTypeDatasource {
    ObjectTypeDatasource {
        contract_version: binding.contract_version.clone(),
        namespace: binding.namespace.clone(),
        kind: binding.kind.clone(),
        definition_digest: binding.definition_digest.clone(),
        dataset_id: binding.dataset_id.clone(),
        key_column: binding.key_column.clone(),
        property_mapping: binding.property_mapping.clone().into_iter().collect(),
        hidden_column: binding.hidden_column.clone(),
        edits_only: binding.edits_only,
    }
}

fn to_proto_index_status(
    status: &crate::sekai::object_type_index::ObjectTypeIndexStatus,
) -> ObjectTypeIndexStatus {
    ObjectTypeIndexStatus {
        namespace: status.namespace.clone(),
        kind: status.kind.clone(),
        indexed_at_ms: status.indexed_at_ms,
        member_count: status.member_count,
        stale: status.stale,
        quarantine_reason: status.quarantine_reason.clone(),
        lag_ms: status.lag_ms,
    }
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    let policy = crate::sekai::object_security::ObjectSecurityPolicy::from_canonical_input(
        &input.canonical_policy_json,
    )
    .map_err(Status::invalid_argument)?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &policy.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &policy.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let revision = service
        .db
        .runtime()
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, false)?;
    let revision = service
        .db
        .runtime()
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
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
        .runtime()
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, false)?;
    let activation = service
        .db
        .runtime()
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let authorization = req
        .into_inner()
        .authorization
        .ok_or_else(|| Status::invalid_argument("authorization required"))?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &authorization.namespace,
        true,
    )?;
    check_team_namespace(
        service.db.runtime(),
        &principals,
        &authorization.namespace,
        true,
    )?;
    let mut authorization = from_proto_purpose_authorization(authorization);
    authorization.created_by = principals.first().cloned().unwrap_or_default();
    authorization.created_at_ms = now_millis();
    authorization.revoked_at_ms = 0;
    authorization.prepare().map_err(Status::invalid_argument)?;
    let stored = service
        .db
        .runtime()
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
        .runtime()
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let lattice = req
        .into_inner()
        .lattice
        .ok_or_else(|| Status::invalid_argument("lattice required"))?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &lattice.namespace,
        true,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &lattice.namespace, true)?;
    let lattice = from_proto_classification_lattice(lattice);
    lattice.prepare().map_err(Status::invalid_argument)?;
    let stored = service
        .db
        .runtime()
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let namespace = req.into_inner().namespace;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &namespace, false)?;
    let lattice = service
        .db
        .runtime()
        .get_classification_lattice(&namespace)
        .map_err(map_classification_lattice_error)?
        .ok_or_else(|| Status::not_found("not found"))?;
    Ok(Response::new(GetClassificationLatticeResponse {
        lattice: Some(to_proto_classification_lattice(&lattice)?),
    }))
}

pub(super) async fn simulate_object_policy_change(
    service: &SekaiServiceImpl,
    req: Request<SimulateObjectPolicyChangeRequest>,
) -> Result<Response<SimulateObjectPolicyChangeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, false)?;
    let operation = if input.operation.trim().is_empty() {
        crate::sekai::object_security::ObjectSecurityOperation::Read
    } else {
        crate::sekai::object_security::ObjectSecurityOperation::parse(&input.operation)
            .map_err(Status::invalid_argument)?
    };
    let current_activation = service
        .db
        .runtime()
        .get_object_security_activation(&input.namespace)
        .map_err(map_object_security_error)?;
    let current = snapshot_from_activation(
        service.db.runtime(),
        &input.namespace,
        current_activation.as_ref(),
    )?;
    let mut candidate_policies = BTreeMap::new();
    for binding in &input.candidate_policies {
        if binding.kind.trim().is_empty() || binding.revision_digest.trim().is_empty() {
            return Err(Status::invalid_argument(
                "each candidate policy kind and revision is required",
            ));
        }
        let revision = service
            .db
            .runtime()
            .get_object_security_policy(&input.namespace, &binding.revision_digest)
            .map_err(map_object_security_error)?
            .ok_or_else(|| Status::not_found("candidate policy revision not found"))?;
        let policy = crate::sekai::object_security::ObjectSecurityPolicy::from_canonical_input(
            &revision.canonical_policy_json,
        )
        .map_err(Status::invalid_argument)?;
        if policy.kind != binding.kind {
            return Err(Status::invalid_argument(
                "candidate policy kind does not match stored revision",
            ));
        }
        if candidate_policies
            .insert(binding.kind.clone(), policy)
            .is_some()
        {
            return Err(Status::invalid_argument(
                "each candidate policy kind must appear exactly once",
            ));
        }
    }
    let candidate = crate::sekai::policy_decision::PolicySnapshot {
        namespace: input.namespace.clone(),
        activation_digest: "candidate".into(),
        policies: candidate_policies,
        lattice: current.lattice.clone(),
    };
    let objects = service
        .db
        .runtime()
        .list_objects(&crate::domain::ListFilter {
            namespace: Some(input.namespace.clone()),
            limit: if input.limit > 0 { input.limit } else { 10_000 },
            ..crate::domain::ListFilter::default()
        })
        .map_err(Status::internal)?;
    let mut simulated = Vec::new();
    let named = if input.principals.is_empty() {
        principals.clone()
    } else {
        input.principals.clone()
    };
    for principal in named {
        let authority =
            resolve_principal_authority(service.db.runtime(), std::slice::from_ref(&principal))?;
        simulated.push(crate::sekai::policy_decision::SimulatedPrincipal {
            principal: principal.clone(),
            context: crate::sekai::object_security::PrincipalPolicyContext {
                delegated_subject: None,
                subjects: vec![principal],
                scopes: Vec::new(),
            }
            .normalized(),
            authority,
            purpose: None,
            purpose_authorization: None,
            namespace_granted: true,
        });
    }
    let report = crate::sekai::policy_decision::simulate_policy_change(
        &objects,
        &simulated,
        &current,
        &candidate,
        operation,
        now_millis(),
    )
    .map_err(Status::internal)?;
    Ok(Response::new(SimulateObjectPolicyChangeResponse {
        namespace: report.namespace,
        current_activation_digest: report.current_activation_digest,
        candidate_digest: report.candidate_digest,
        differences: report
            .differences
            .into_iter()
            .map(|diff| PolicySimulationDifference {
                principal: diff.principal,
                object_id: diff.object_id,
                object_kind: diff.object_kind,
                property: diff.property,
                current_outcome: diff.current_outcome.as_str().into(),
                candidate_outcome: diff.candidate_outcome.as_str().into(),
            })
            .collect(),
    }))
}

/// Rebuild a namespace's objects as of a past time and compare each
/// principal's view under the rules in effect then with the candidate rules.
/// Read-only and recorded as a decision. Rules changed after `as_of_ms` fail
/// closed: earlier activations and lattices are not retained.
pub(super) async fn query_counterfactual_view(
    service: &SekaiServiceImpl,
    req: Request<QueryCounterfactualViewRequest>,
) -> Result<Response<QueryCounterfactualViewResponse>, Status> {
    use crate::sekai::counterfactual::{
        CounterfactualInput, MarkingRule, Rules, evaluate_counterfactual, history_covers,
        objects_as_of,
    };
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let db = service.db.runtime();
    let tenant_context = request_tenant_context(db, &req)?;
    let input = req.into_inner();
    if input.namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace is required"));
    }
    if input.as_of_ms <= 0 || input.as_of_ms > now_millis() {
        return Err(Status::invalid_argument("as_of_ms must be a past time"));
    }
    enforce_namespace_tenant_context(db, tenant_context.as_ref(), &input.namespace, false)?;
    check_team_namespace(db, &principals, &input.namespace, false)?;
    let activation = db
        .get_object_security_activation(&input.namespace)
        .map_err(map_object_security_error)?;
    if activation
        .as_ref()
        .is_some_and(|activation| activation.activated_at_ms > input.as_of_ms)
    {
        return Err(Status::failed_precondition(
            "object security policies were activated after as_of_ms; earlier activations are not retained",
        ));
    }
    let actual = snapshot_from_activation(db, &input.namespace, activation.as_ref())?;
    // After the snapshot: a lattice is stamped with the time it is stored, so
    // a replacement between the reads is newer than `as_of_ms` too.
    if db
        .classification_lattice_recorded_at_ms(&input.namespace)
        .map_err(Status::internal)?
        .is_some_and(|recorded_at_ms| recorded_at_ms > input.as_of_ms)
    {
        return Err(Status::failed_precondition(
            "the classification lattice changed after as_of_ms; earlier lattices are not retained",
        ));
    }
    let actual_activated = activation.is_some();

    let mut candidate = actual.clone();
    let mut candidate_kinds = BTreeSet::new();
    for binding in &input.candidate_policies {
        if binding.kind.trim().is_empty() || binding.revision_digest.trim().is_empty() {
            return Err(Status::invalid_argument(
                "each candidate policy kind and revision is required",
            ));
        }
        if !candidate_kinds.insert(binding.kind.clone()) {
            return Err(Status::invalid_argument(
                "each candidate policy kind must appear exactly once",
            ));
        }
        let revision = db
            .get_object_security_policy(&input.namespace, &binding.revision_digest)
            .map_err(map_object_security_error)?
            .ok_or_else(|| Status::not_found("candidate policy revision not found"))?;
        let policy = crate::sekai::object_security::ObjectSecurityPolicy::from_canonical_input(
            &revision.canonical_policy_json,
        )
        .map_err(Status::invalid_argument)?;
        if policy.kind != binding.kind {
            return Err(Status::invalid_argument(
                "candidate policy kind does not match stored revision",
            ));
        }
        candidate.policies.insert(binding.kind.clone(), policy);
    }
    if !candidate_kinds.is_empty() {
        candidate.activation_digest = "candidate".into();
    }
    let marking_rule = match input.candidate_marking_rule {
        Some(rule) => {
            if rule.kind.trim().is_empty() || rule.marking.trim().is_empty() {
                return Err(Status::invalid_argument(
                    "candidate marking rule kind and marking are required",
                ));
            }
            // The change log records an absent property as an empty value, so
            // an empty match value could not be decided for past objects.
            if rule.property_equals.values().any(String::is_empty) {
                return Err(Status::invalid_argument(
                    "candidate marking rule property values must not be empty",
                ));
            }
            crate::sekai::classification_lattice::validate_written_marking_token(
                Some(&rule.marking),
                actual.lattice.as_ref(),
            )
            .map_err(Status::invalid_argument)?;
            Some(MarkingRule {
                kind: rule.kind,
                property_equals: rule.property_equals.into_iter().collect(),
                marking: rule.marking.trim().into(),
            })
        }
        None => None,
    };
    if candidate_kinds.is_empty() && marking_rule.is_none() {
        return Err(Status::invalid_argument(
            "a candidate policy or marking rule is required",
        ));
    }

    let (live, changes) = read_live_objects_and_history(db, &input.namespace)?;
    if !history_covers(&changes, input.as_of_ms) {
        return Err(Status::failed_precondition(
            "as_of_ms predates the retained object history",
        ));
    }
    let mut as_of = objects_as_of(&input.namespace, &live, &changes, input.as_of_ms);
    let selected = |id: &str, kind: &str| {
        (input.kind.is_empty() || kind == input.kind)
            && (input.object_ids.is_empty() || input.object_ids.iter().any(|wanted| wanted == id))
    };
    as_of.objects.retain(|object| {
        !is_reserved_governance_kind(&object.kind)
            && object.kind != markings::PRINCIPAL_PROFILE_KIND
            && selected(&object.id, &object.kind)
    });
    as_of.unreconstructable.retain(|id| {
        changes.iter().any(|mutation| {
            let change = &mutation.change;
            let kind = match change.field.as_str() {
                "_deleted" => change.old_value.split('/').next().unwrap_or_default(),
                "_created" => change.new_value.split('/').next().unwrap_or_default(),
                _ => mutation.object_kind.as_str(),
            };
            change.object_id == *id && selected(id, kind)
        })
    });

    let named = if input.principals.is_empty() {
        principals.clone()
    } else {
        input.principals.clone()
    };
    // Principals are evaluated with their current authority, namespace
    // grants and object ACLs; those are not candidates and keep no history.
    let mut simulated = Vec::new();
    let mut acl_denied = BTreeSet::new();
    for principal in named {
        let one = std::slice::from_ref(&principal);
        let authority = resolve_principal_authority(db, one)?;
        let namespace_granted = check_team_namespace(db, one, &input.namespace, false).is_ok();
        for object in &as_of.objects {
            if !service
                .security
                .can_access(&object.id, &[principal.as_str()])
            {
                acl_denied.insert((principal.clone(), object.id.clone()));
            }
        }
        simulated.push(crate::sekai::policy_decision::SimulatedPrincipal {
            principal: principal.clone(),
            context: crate::sekai::object_security::PrincipalPolicyContext {
                delegated_subject: None,
                subjects: vec![principal],
                scopes: Vec::new(),
            }
            .normalized(),
            authority,
            purpose: None,
            purpose_authorization: None,
            namespace_granted,
        });
    }
    let report = evaluate_counterfactual(CounterfactualInput {
        as_of: &as_of,
        principals: &simulated,
        actual: Rules {
            snapshot: &actual,
            activated: actual_activated,
        },
        candidate: Rules {
            snapshot: &candidate,
            activated: actual_activated || !candidate_kinds.is_empty(),
        },
        marking_rule: marking_rule.as_ref(),
        acl_denied: &acl_denied,
        operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
        as_of_ms: input.as_of_ms,
    })
    .map_err(Status::internal)?;

    let decision_id = format!("counterfactual:{}", uuid::Uuid::new_v4().as_simple());
    db.record_decision(&audit::Decision {
        id: decision_id.clone(),
        timestamp: now_millis(),
        actor: principals.first().cloned().unwrap_or_default(),
        action: "query_counterfactual_view".into(),
        reason: "counterfactual view over recorded history".into(),
        evidence: HashMap::from([
            ("as_of_ms".into(), report.as_of_ms.to_string()),
            ("actual_digest".into(), report.actual_digest.clone()),
            ("candidate_digest".into(), report.candidate_digest.clone()),
            ("input_digest".into(), report.input_digest.clone()),
            ("report_digest".into(), report.report_digest.clone()),
            ("principal_count".into(), report.views.len().to_string()),
        ]),
        target_id: input.namespace.clone(),
        outcome: "allow".into(),
    })
    .map_err(Status::internal)?;

    Ok(Response::new(QueryCounterfactualViewResponse {
        namespace: report.namespace,
        as_of_ms: report.as_of_ms,
        actual_digest: report.actual_digest,
        candidate_digest: report.candidate_digest,
        views: report
            .views
            .into_iter()
            .map(|view| CounterfactualPrincipalView {
                principal: view.principal,
                actual_visible_object_ids: view.actual_visible,
                counterfactual_visible_object_ids: view.counterfactual_visible,
                hidden_object_ids: view.hidden,
                revealed_object_ids: view.revealed,
            })
            .collect(),
        differences: report
            .differences
            .into_iter()
            .map(|diff| PolicySimulationDifference {
                principal: diff.principal,
                object_id: diff.object_id,
                object_kind: diff.object_kind,
                property: diff.property,
                current_outcome: diff.current_outcome.as_str().into(),
                candidate_outcome: diff.candidate_outcome.as_str().into(),
            })
            .collect(),
        unreconstructable_object_ids: report.unreconstructable,
        input_digest: report.input_digest,
        report_digest: report.report_digest,
        decision_id,
    }))
}

/// Read every live object of `namespace` and its recorded change history.
///
/// Offset pages are not one snapshot, so a write while reading could shift a
/// page and drop an unchanged object, and a retention purge could drop later
/// pages of history. The newest and oldest retained change bracket the read;
/// a recorded write or purge in between retries, and a namespace that keeps
/// changing fails closed.
fn read_live_objects_and_history(
    db: &crate::db::runtime_db::RuntimeDb,
    namespace: &str,
) -> Result<
    (
        Vec<crate::domain::Object>,
        Vec<crate::sekai::object_change_subscription::CommittedObjectMutation>,
    ),
    Status,
> {
    use crate::sekai::counterfactual::{MAX_COUNTERFACTUAL_CHANGES, MAX_COUNTERFACTUAL_OBJECTS};
    for _ in 0..3 {
        let watermark = db
            .object_change_watermark(namespace)
            .map_err(Status::internal)?;
        let mut live = Vec::new();
        loop {
            let page = db
                .list_objects(&crate::domain::ListFilter {
                    namespace: Some(namespace.into()),
                    limit: crate::domain::MAX_LIST_LIMIT,
                    offset: live.len() as i32,
                    ..crate::domain::ListFilter::default()
                })
                .map_err(Status::internal)?;
            let full = page.len() == crate::domain::MAX_LIST_LIMIT as usize;
            live.extend(page);
            if live.len() > MAX_COUNTERFACTUAL_OBJECTS {
                return Err(Status::failed_precondition(
                    "namespace has too many objects for a counterfactual view",
                ));
            }
            if !full {
                break;
            }
        }
        let mut changes: Vec<crate::sekai::object_change_subscription::CommittedObjectMutation> =
            Vec::new();
        loop {
            let after = changes.last().map_or(0, |mutation| mutation.seq);
            let page = db
                .list_committed_object_mutations_after(namespace, after, 1_000)
                .map_err(Status::internal)?;
            if page.is_empty() {
                break;
            }
            changes.extend(page);
            if changes.len() > MAX_COUNTERFACTUAL_CHANGES {
                return Err(Status::failed_precondition(
                    "namespace history is too long for a counterfactual view",
                ));
            }
        }
        // Retention deletes the oldest changes; a purge during the read moves
        // the oldest retained sequence past the first one read.
        let oldest = db
            .object_change_oldest_seq(namespace)
            .map_err(Status::internal)?;
        let unchanged = changes.iter().all(|mutation| mutation.seq <= watermark)
            && changes.first().map_or(0, |mutation| mutation.seq) == oldest;
        if unchanged {
            return Ok((live, changes));
        }
    }
    Err(Status::aborted(
        "namespace changed while reading its history; retry the counterfactual view",
    ))
}

pub(super) async fn query_object_policy_audit(
    service: &SekaiServiceImpl,
    req: Request<QueryObjectPolicyAuditRequest>,
) -> Result<Response<QueryObjectPolicyAuditResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, false)?;
    let records = service
        .db
        .runtime()
        .query_policy_decisions(&crate::sekai::policy_decision::PolicyDecisionQuery {
            namespace: input.namespace,
            principal: input.principal,
            object_id: input.object_id,
            from_ms: input.from_ms,
            to_ms: input.to_ms,
            limit: input.limit,
            offset: input.offset,
        })
        .map_err(Status::internal)?;
    let events: Vec<ObjectPolicyAuditEvent> = records
        .iter()
        .map(|record| ObjectPolicyAuditEvent {
            event_id: record.event_id.clone(),
            namespace: record.decision.namespace.clone(),
            object_kind: record.decision.object_kind.clone(),
            object_id: record.decision.object_id.clone(),
            operation: record.decision.operation.clone(),
            principal: record.decision.principal.clone(),
            principal_digest: record.decision.principal_digest.clone(),
            activation_digest: record.decision.activation_digest.clone(),
            policy_revision_digest: record.decision.policy_revision_digest.clone(),
            outcome: record.decision.outcome.as_str().into(),
            denied_by: record
                .decision
                .denied_by
                .map(|layer| layer.as_str().to_string())
                .unwrap_or_default(),
            created_at_ms: record.created_at_ms,
        })
        .collect();
    let export_json =
        serde_json::to_vec(&events).map_err(|error| Status::internal(error.to_string()))?;
    Ok(Response::new(QueryObjectPolicyAuditResponse {
        events,
        export_json,
    }))
}

fn snapshot_from_activation(
    db: &crate::db::runtime_db::RuntimeDb,
    namespace: &str,
    activation: Option<&crate::sekai::object_security::ObjectSecurityActivation>,
) -> Result<crate::sekai::policy_decision::PolicySnapshot, Status> {
    let mut policies = BTreeMap::new();
    let activation_digest = match activation {
        Some(activation) => {
            for (kind, digest) in &activation.policies {
                let revision = db
                    .get_object_security_policy(namespace, digest)
                    .map_err(map_object_security_error)?
                    .ok_or_else(|| {
                        Status::failed_precondition("active policy revision unavailable")
                    })?;
                let policy =
                    crate::sekai::object_security::ObjectSecurityPolicy::from_canonical_input(
                        &revision.canonical_policy_json,
                    )
                    .map_err(|_| {
                        Status::failed_precondition("active policy revision is invalid")
                    })?;
                policies.insert(kind.clone(), policy);
            }
            crate::sekai::object_security::object_security_activation_digest(activation)
                .map_err(Status::internal)?
        }
        None => "legacy".into(),
    };
    Ok(crate::sekai::policy_decision::PolicySnapshot {
        namespace: namespace.into(),
        activation_digest,
        policies,
        lattice: db
            .get_classification_lattice(namespace)
            .map_err(|_| Status::unavailable("classification lattice unavailable"))?,
    })
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

#[cfg(test)]
mod policy_decision_rpc_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
            crate::db::runtime_db::RuntimeDb::Sqlite(Arc::new(
                crate::db::sekai::SekaiDb::new(":memory:").unwrap(),
            )),
        )))
    }

    fn admin<T>(payload: T) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from("local").unwrap());
        req
    }

    fn document(id: &str, owner: &str) -> crate::domain::Object {
        crate::domain::Object {
            id: id.into(),
            kind: "document".into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: format!("doc:{id}"),
            properties: HashMap::from([
                ("owner".into(), owner.into()),
                ("secret".into(), format!("hidden-{id}")),
            ]),
            created: 1,
            updated: 1,
        }
    }

    fn allow_all_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "contract_version": "sekai.object-security-policy/v1",
            "namespace": "acme",
            "kind": "document",
            "rules": [{"operation":"read","predicates":[{"kind":"allow_all"}]}]
        }))
        .unwrap()
    }

    fn owner_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "contract_version": "sekai.object-security-policy/v1",
            "namespace": "acme",
            "kind": "document",
            "rules": [{"operation":"read","predicates":[{"kind":"subject_equals_property","property":"owner"}]}],
            "property_grants": [{"property":"owner","access":"read"}]
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn simulate_and_audit_rpcs_omit_hidden_values() {
        let svc = service();
        svc.db
            .runtime()
            .create_object(&document("doc-a", "alice"))
            .unwrap();
        svc.db
            .runtime()
            .create_object(&document("doc-b", "bob"))
            .unwrap();
        let broad = put_object_security_policy_revision(
            &svc,
            admin(PutObjectSecurityPolicyRevisionRequest {
                canonical_policy_json: allow_all_json(),
                idempotency_key: "put-broad".into(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap();
        let owner = put_object_security_policy_revision(
            &svc,
            admin(PutObjectSecurityPolicyRevisionRequest {
                canonical_policy_json: owner_json(),
                idempotency_key: "put-owner".into(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap();
        activate_object_security_policies(
            &svc,
            admin(ActivateObjectSecurityPoliciesRequest {
                namespace: "acme".into(),
                policies: vec![ObjectSecurityPolicyBinding {
                    kind: "document".into(),
                    revision_digest: broad.revision_digest,
                }],
                idempotency_key: "act-broad".into(),
            }),
        )
        .await
        .unwrap();

        let simulated = simulate_object_policy_change(
            &svc,
            admin(SimulateObjectPolicyChangeRequest {
                namespace: "acme".into(),
                candidate_policies: vec![ObjectSecurityPolicyBinding {
                    kind: "document".into(),
                    revision_digest: owner.revision_digest.clone(),
                }],
                operation: "read".into(),
                principals: vec!["alice".into(), "bob".into()],
                limit: 100,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(
            simulated.differences.iter().any(|diff| {
                diff.principal == "alice" && diff.object_id == "doc-b" && diff.property.is_empty()
            }),
            "{simulated:?}"
        );
        let payload = serde_json::to_string(&simulated.differences).unwrap();
        assert!(!payload.contains("hidden-doc-a"));
        assert!(!payload.contains("hidden-doc-b"));

        activate_object_security_policies(
            &svc,
            admin(ActivateObjectSecurityPoliciesRequest {
                namespace: "acme".into(),
                policies: vec![ObjectSecurityPolicyBinding {
                    kind: "document".into(),
                    revision_digest: owner.revision_digest,
                }],
                idempotency_key: "act-owner".into(),
            }),
        )
        .await
        .unwrap();

        let alice = document("doc-a", "alice");
        enforce_object_operation_access(
            svc.db.runtime(),
            &alice,
            &["alice".into()],
            None,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
            "read-alice",
            None,
        )
        .unwrap();
        let bob_err = enforce_object_operation_access(
            svc.db.runtime(),
            &alice,
            &["bob".into()],
            None,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
            "read-bob",
            None,
        );
        assert!(bob_err.is_err());

        let audit = query_object_policy_audit(
            &svc,
            admin(QueryObjectPolicyAuditRequest {
                namespace: "acme".into(),
                principal: "alice".into(),
                object_id: String::new(),
                from_ms: 0,
                to_ms: 0,
                limit: 20,
                offset: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(
            audit
                .events
                .iter()
                .any(|event| event.principal == "alice" && event.outcome == "allow")
        );
        let export = String::from_utf8(audit.export_json).unwrap();
        assert!(!export.contains("hidden-doc-a"));
        assert!(!export.contains("hidden-doc-b"));
    }

    fn purpose_required_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "contract_version": "sekai.object-security-policy/v1",
            "namespace": "acme",
            "kind": "document",
            "required_purpose": "review",
            "rules": [{"operation":"read","predicates":[{"kind":"allow_all"}]}]
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn compiled_decide_is_live_object_access_authority() {
        let svc = service();
        let alice = document("doc-purpose", "alice");
        svc.db.runtime().create_object(&alice).unwrap();
        let revision = put_object_security_policy_revision(
            &svc,
            admin(PutObjectSecurityPolicyRevisionRequest {
                canonical_policy_json: purpose_required_json(),
                idempotency_key: "put-purpose".into(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap();
        activate_object_security_policies(
            &svc,
            admin(ActivateObjectSecurityPoliciesRequest {
                namespace: "acme".into(),
                policies: vec![ObjectSecurityPolicyBinding {
                    kind: "document".into(),
                    revision_digest: revision.revision_digest,
                }],
                idempotency_key: "act-purpose".into(),
            }),
        )
        .await
        .unwrap();

        let policy = svc
            .db
            .runtime()
            .active_object_policy("acme", "document")
            .unwrap()
            .expect("activated");
        let context = principal_policy_context_from(&["alice".into()], None);
        assert!(
            policy.allows(
                &context,
                &alice,
                crate::sekai::object_security::ObjectSecurityOperation::Read
            ),
            "pre-PDP row evaluator would allow this principal"
        );

        let decision = decide_object_access(
            svc.db.runtime(),
            &alice,
            &["alice".into()],
            None,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
            None,
        )
        .unwrap();
        assert_eq!(
            decision.outcome,
            crate::sekai::policy_decision::PolicyOutcome::Deny
        );
        assert_eq!(
            decision.denied_by,
            Some(crate::sekai::policy_decision::PolicyLayer::Purpose)
        );
        assert_eq!(
            evaluate_active_object_policy(
                svc.db.runtime(),
                &alice,
                &["alice".into()],
                None,
                crate::sekai::object_security::ObjectSecurityOperation::Read,
                None,
            )
            .unwrap(),
            Some(false)
        );
        let err = enforce_object_operation_access(
            svc.db.runtime(),
            &alice,
            &["alice".into()],
            None,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
            "read-purpose",
            None,
        )
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    fn profile(svc: &SekaiServiceImpl, principal: &str, ceiling: &str) {
        let id = format!("profile-{principal}");
        svc.db
            .runtime()
            .create_object(&crate::domain::Object {
                id: id.clone(),
                kind: markings::PRINCIPAL_PROFILE_KIND.into(),
                name: principal.into(),
                namespace: "acme".into(),
                external_id: markings::principal_profile_external_id(principal),
                properties: HashMap::from([
                    (
                        markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        ceiling.into(),
                    ),
                    (
                        markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                        "true".into(),
                    ),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();
        svc.db
            .runtime()
            .create_grant(&crate::sekai::security::Grant {
                id: format!("grant-{id}"),
                object_id: id,
                principal: "root".into(),
                role: crate::sekai::security::Role::Admin,
                created: 0,
                ..Default::default()
            })
            .unwrap();
    }

    fn change(object_id: &str, field: &str, old: &str, new: &str, at: i64) -> audit::ObjectChange {
        audit::ObjectChange {
            id: uuid::Uuid::new_v4().to_string(),
            object_id: object_id.into(),
            field: field.into(),
            old_value: old.into(),
            new_value: new.into(),
            changed_by: "writer".into(),
            timestamp: at,
        }
    }

    /// `doc-fin` was internal at `as_of` and declassified after it, `doc-gone`
    /// existed at `as_of` and was deleted after it.
    fn counterfactual_fixture() -> (SekaiServiceImpl, i64) {
        let svc = service();
        let now = now_millis();
        let as_of = now - 60_000;
        let mut fin = document("doc-fin", "alice");
        fin.properties.insert("team".into(), "finance".into());
        fin.properties.insert(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "public".into(),
        );
        let mut ops = document("doc-ops", "bob");
        ops.properties.insert("team".into(), "ops".into());
        for object in [&fin, &ops] {
            svc.db.runtime().create_object(object).unwrap();
        }
        profile(&svc, "alice", "confidential");
        profile(&svc, "bob", "restricted");
        svc.db
            .runtime()
            .record_object_changes(&[
                change(
                    "doc-fin",
                    "properties.access_marking",
                    "",
                    "internal",
                    as_of - 1_000,
                ),
                change(
                    "doc-gone",
                    "_created",
                    "",
                    "document/doc-gone",
                    as_of - 1_000,
                ),
                change(
                    "doc-fin",
                    "properties.access_marking",
                    "internal",
                    "public",
                    now - 30_000,
                ),
                change(
                    "doc-gone",
                    "_deleted",
                    "document/doc-gone",
                    "",
                    now - 30_000,
                ),
                change("doc-gone", "_namespace", "acme", "", now - 30_000),
            ])
            .unwrap();
        (svc, as_of)
    }

    fn finance_restricted(as_of_ms: i64) -> QueryCounterfactualViewRequest {
        QueryCounterfactualViewRequest {
            namespace: "acme".into(),
            as_of_ms,
            kind: "document".into(),
            candidate_marking_rule: Some(CounterfactualMarkingRule {
                kind: "document".into(),
                property_equals: HashMap::from([("team".into(), "finance".into())]),
                marking: "restricted".into(),
            }),
            principals: vec!["alice".into(), "bob".into()],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn counterfactual_marking_hides_past_objects_from_principals_below_it() {
        let (svc, as_of) = counterfactual_fixture();
        let report = query_counterfactual_view(&svc, admin(finance_restricted(as_of)))
            .await
            .unwrap()
            .into_inner();
        let view = |name: &str| report.views.iter().find(|v| v.principal == name).unwrap();
        // Then, `doc-fin` was internal: both clearances saw it.
        assert_eq!(
            view("alice").actual_visible_object_ids,
            ["doc-fin", "doc-ops"]
        );
        assert_eq!(view("alice").hidden_object_ids, ["doc-fin"]);
        assert_eq!(view("alice").counterfactual_visible_object_ids, ["doc-ops"]);
        assert_eq!(
            view("bob").actual_visible_object_ids,
            ["doc-fin", "doc-ops"]
        );
        assert!(view("bob").hidden_object_ids.is_empty());
        assert!(
            report
                .views
                .iter()
                .all(|v| v.revealed_object_ids.is_empty())
        );
        assert_eq!(report.unreconstructable_object_ids, ["doc-gone"]);
        let payload = serde_json::to_string(&report.differences).unwrap();
        assert!(!payload.contains("hidden-doc-fin"));

        let again = query_counterfactual_view(&svc, admin(finance_restricted(as_of)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(again.report_digest, report.report_digest);
        assert_eq!(again.views, report.views);
        assert_ne!(again.decision_id, report.decision_id);

        let decision = svc
            .db
            .runtime()
            .get_decision(&report.decision_id)
            .unwrap()
            .expect("counterfactual read is recorded");
        assert_eq!(decision.action, "query_counterfactual_view");
        assert_eq!(decision.evidence["report_digest"], report.report_digest);
        // Read-only: live objects are unchanged.
        let live = svc.db.runtime().get_object("doc-fin").unwrap().unwrap();
        assert_eq!(
            live.properties[markings::OBJECT_CLASSIFICATION_PROPERTY],
            "public"
        );
    }

    #[tokio::test]
    async fn counterfactual_view_fails_closed() {
        let (svc, as_of) = counterfactual_fixture();
        let unauthenticated =
            query_counterfactual_view(&svc, Request::new(finance_restricted(as_of)))
                .await
                .unwrap_err();
        assert_eq!(unauthenticated.code(), tonic::Code::Unauthenticated);
        let mut not_admin = Request::new(finance_restricted(as_of));
        not_admin
            .metadata_mut()
            .insert("x-principal", MetadataValue::try_from("alice").unwrap());
        let denied = query_counterfactual_view(&svc, not_admin)
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let no_candidate = query_counterfactual_view(
            &svc,
            admin(QueryCounterfactualViewRequest {
                candidate_marking_rule: None,
                ..finance_restricted(as_of)
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(no_candidate.code(), tonic::Code::InvalidArgument);

        svc.db
            .runtime()
            .put_classification_lattice(
                &crate::sekai::classification_lattice::ClassificationLattice::default_evidence_lattice(
                    "acme",
                ),
                "local",
                now_millis(),
            )
            .unwrap();
        let changed_since = query_counterfactual_view(&svc, admin(finance_restricted(as_of)))
            .await
            .unwrap_err();
        assert_eq!(changed_since.code(), tonic::Code::FailedPrecondition);
    }
}
