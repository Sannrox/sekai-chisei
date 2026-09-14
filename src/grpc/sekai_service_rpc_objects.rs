use super::*;
use std::collections::BTreeMap;

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

pub(super) async fn simulate_object_policy_change(
    service: &SekaiServiceImpl,
    req: Request<SimulateObjectPolicyChangeRequest>,
) -> Result<Response<SimulateObjectPolicyChangeResponse>, Status> {
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
    let operation = if input.operation.trim().is_empty() {
        crate::sekai::object_security::ObjectSecurityOperation::Read
    } else {
        crate::sekai::object_security::ObjectSecurityOperation::parse(&input.operation)
            .map_err(Status::invalid_argument)?
    };
    let current_activation = service
        .db
        .get_object_security_activation(&input.namespace)
        .map_err(map_object_security_error)?;
    let current =
        snapshot_from_activation(&service.db, &input.namespace, current_activation.as_ref())?;
    let mut candidate_policies = BTreeMap::new();
    for binding in &input.candidate_policies {
        if binding.kind.trim().is_empty() || binding.revision_digest.trim().is_empty() {
            return Err(Status::invalid_argument(
                "each candidate policy kind and revision is required",
            ));
        }
        let revision = service
            .db
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
        let authority = resolve_principal_authority(&service.db, std::slice::from_ref(&principal))?;
        simulated.push(crate::sekai::policy_decision::SimulatedPrincipal {
            principal: principal.clone(),
            context: crate::sekai::object_security::PrincipalPolicyContext {
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

pub(super) async fn query_object_policy_audit(
    service: &SekaiServiceImpl,
    req: Request<QueryObjectPolicyAuditRequest>,
) -> Result<Response<QueryObjectPolicyAuditResponse>, Status> {
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
    let records = service
        .db
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
        SekaiServiceImpl::new(Arc::new(crate::db::runtime_db::RuntimeDb::Sqlite(
            Arc::new(crate::db::sekai::SekaiDb::new(":memory:").unwrap()),
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
        svc.db.create_object(&document("doc-a", "alice")).unwrap();
        svc.db.create_object(&document("doc-b", "bob")).unwrap();
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
            &svc.db,
            &alice,
            &["alice".into()],
            None,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
            "read-alice",
        )
        .unwrap();
        let bob_err = enforce_object_operation_access(
            &svc.db,
            &alice,
            &["bob".into()],
            None,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
            "read-bob",
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
        svc.db.create_object(&alice).unwrap();
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
            &svc.db,
            &alice,
            &["alice".into()],
            None,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
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
                &svc.db,
                &alice,
                &["alice".into()],
                None,
                crate::sekai::object_security::ObjectSecurityOperation::Read,
            )
            .unwrap(),
            Some(false)
        );
        let err = enforce_object_operation_access(
            &svc.db,
            &alice,
            &["alice".into()],
            None,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
            "read-purpose",
        )
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }
}
