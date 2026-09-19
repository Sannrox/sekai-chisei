use super::*;

pub(super) async fn create_function(
    service: &SekaiServiceImpl,
    req: Request<CreateFunctionRequest>,
) -> Result<Response<CreateFunctionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    if is_managed_team_principal(service.db.runtime(), &principals)? {
        return Err(Status::permission_denied(
            "team principals cannot create global stored functions",
        ));
    }
    let function = req
        .into_inner()
        .function
        .ok_or(Status::invalid_argument("function required"))?;
    let parsed = from_proto_function(&function);
    service
        .db
        .runtime()
        .create_function(&parsed)
        .map_err(Status::invalid_argument)?;
    Ok(Response::new(CreateFunctionResponse {
        function: Some(to_proto_function(&parsed)),
    }))
}
pub(super) async fn list_functions(
    service: &SekaiServiceImpl,
    req: Request<ListFunctionsRequest>,
) -> Result<Response<ListFunctionsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    if is_managed_team_principal(service.db.runtime(), &principals)? {
        return Err(Status::permission_denied(
            "team principals cannot list global stored functions",
        ));
    }
    let functions = service
        .db
        .runtime()
        .list_functions()
        .map_err(Status::internal)?
        .iter()
        .map(to_proto_function)
        .collect();
    Ok(Response::new(ListFunctionsResponse { functions }))
}
pub(super) async fn invoke_function(
    service: &SekaiServiceImpl,
    req: Request<InvokeFunctionRequest>,
) -> Result<Response<InvokeFunctionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    let function = service
        .db
        .runtime()
        .get_function(&input.name)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("not found"))?;
    crate::sekai::function::validate_function(&function).map_err(Status::invalid_argument)?;
    let budget = input
        .budget
        .map(|budget| crate::sekai::function::FunctionBudget {
            max_time_ms: if budget.max_time_ms == 0 {
                50
            } else {
                budget.max_time_ms
            },
            max_output_bytes: if budget.max_output_bytes == 0 {
                1_048_576
            } else {
                budget.max_output_bytes as usize
            },
            max_steps: if budget.max_steps == 0 {
                32
            } else {
                budget.max_steps
            },
        })
        .unwrap_or_default();
    let host = crate::sekai::function::FunctionHost {
        now_ms: if input.now_ms == 0 {
            now_millis()
        } else {
            input.now_ms
        },
        rng_seed: input.rng_seed,
    };
    let invocation = crate::sekai::function::invoke(
        service.db.runtime(),
        &function,
        &input.params,
        |object| {
            object_passes_security_policy(
                service.db.runtime(),
                object,
                &principals,
                tenant_context.as_ref(),
                crate::sekai::object_security::ObjectSecurityOperation::Read,
                None,
            )
            .map_err(|status| status.message().to_string())
        },
        host,
        budget,
    )
    .map_err(Status::internal)?;
    Ok(Response::new(InvokeFunctionResponse {
        aggregates: invocation.result.aggregates,
        receipt: Some(FunctionReceipt {
            function_name: invocation.receipt.function_name,
            function_digest: invocation.receipt.function_digest,
            now_ms: invocation.receipt.now_ms,
            rng_seed: invocation.receipt.rng_seed,
            elapsed_ms: invocation.receipt.elapsed_ms,
            steps: invocation.receipt.steps,
            budget_exceeded: invocation.receipt.budget_exceeded,
            output_digest: invocation.receipt.output_digest,
        }),
    }))
}
pub(super) async fn create_dataset(
    service: &SekaiServiceImpl,
    req: Request<CreateDatasetRequest>,
) -> Result<Response<CreateDatasetResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let dataset = req
        .into_inner()
        .dataset
        .ok_or(Status::invalid_argument("dataset required"))?;
    let parsed = from_proto_dataset(&dataset);
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &parsed,
        true,
    )?;
    service
        .db
        .runtime()
        .create_dataset(&parsed)
        .map_err(Status::invalid_argument)?;
    Ok(Response::new(CreateDatasetResponse {
        dataset: Some(to_proto_dataset(&parsed)),
    }))
}
pub(super) async fn update_dataset(
    service: &SekaiServiceImpl,
    req: Request<UpdateDatasetRequest>,
) -> Result<Response<UpdateDatasetResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let dataset = req
        .into_inner()
        .dataset
        .ok_or(Status::invalid_argument("dataset required"))?;
    let parsed = from_proto_dataset(&dataset);
    let existing = service
        .db
        .runtime()
        .get_dataset(&parsed.id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &existing,
        true,
    )?;
    if existing.object_id.is_empty() {
        // Unbound system datasets are not ACL-bound. Allow reserved
        // control-plane admins (`root` / UDS transport `local`) and the
        // gateway service principal for `llm_calls` schema convergence.
        // UDS force-local identity must not block sekaictl gateway setup.
        let control_plane_admin = principals
            .iter()
            .any(|principal| matches!(principal.as_str(), "root" | "local"));
        let trusted_gateway = parsed.id == "llm_calls"
            && principals.iter().any(|principal| {
                principal == "chisei-gateway"
                    || service.gateway_schema_principals.contains(principal)
            });
        if !control_plane_admin && !trusted_gateway {
            return Err(Status::permission_denied(
                "unbound dataset updates require control-plane administration or the gateway service principal",
            ));
        }
    }
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &parsed,
        true,
    )?;
    service
        .db
        .runtime()
        .update_dataset(&parsed)
        .map_err(Status::internal)?;
    let updated = service
        .db
        .runtime()
        .get_dataset(&parsed.id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("dataset not found"))?;
    Ok(Response::new(UpdateDatasetResponse {
        dataset: Some(to_proto_dataset(&updated)),
    }))
}
pub(super) async fn list_datasets(
    service: &SekaiServiceImpl,
    req: Request<ListDatasetsRequest>,
) -> Result<Response<ListDatasetsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let datasets = service
        .db
        .runtime()
        .list_datasets()
        .map_err(Status::internal)?
        .into_iter()
        .filter(|dataset| {
            check_dataset_access(
                service.db.runtime(),
                &service.security,
                &principals,
                dataset,
                false,
            )
            .is_ok()
        })
        .collect::<Vec<_>>()
        .iter()
        .map(to_proto_dataset)
        .collect();
    Ok(Response::new(ListDatasetsResponse { datasets }))
}
pub(super) async fn append_rows(
    service: &SekaiServiceImpl,
    req: Request<AppendRowsRequest>,
) -> Result<Response<AppendRowsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let dataset = service
        .db
        .runtime()
        .get_dataset(&inner.dataset_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        true,
    )?;
    let rows: Vec<_> = inner.rows.into_iter().map(|r| r.values).collect();
    let count = service
        .db
        .runtime()
        .append_rows(&inner.dataset_id, &rows)
        .map_err(Status::invalid_argument)?;
    Ok(Response::new(AppendRowsResponse { count }))
}
pub(super) async fn query_rows(
    service: &SekaiServiceImpl,
    req: Request<QueryRowsRequest>,
) -> Result<Response<QueryRowsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let dataset = service
        .db
        .runtime()
        .get_dataset(&inner.dataset_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        false,
    )?;
    let query = inner.query.unwrap_or_default();
    let rows = service
        .db
        .runtime()
        .query_rows(
            &inner.dataset_id,
            &dataset::RowQuery {
                filters: from_proto_row_filters(&query.filters),
                columns: query.columns,
                limit: query.limit,
                offset: query.offset,
            },
        )
        .map_err(Status::internal)?;
    Ok(Response::new(QueryRowsResponse {
        rows: rows.into_iter().map(|values| Row { values }).collect(),
    }))
}
pub(super) async fn create_virtual_table(
    service: &SekaiServiceImpl,
    req: Request<CreateVirtualTableRequest>,
) -> Result<Response<CreateVirtualTableResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let table = req
        .into_inner()
        .table
        .ok_or(Status::invalid_argument("table required"))?;
    let parsed = from_proto_virtual_table(&table);
    let dataset = service
        .db
        .runtime()
        .get_dataset(&parsed.dataset_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        true,
    )?;
    service
        .db
        .runtime()
        .create_virtual_table(&parsed)
        .map_err(Status::invalid_argument)?;
    Ok(Response::new(CreateVirtualTableResponse {
        table: Some(to_proto_virtual_table(&parsed)),
    }))
}
pub(super) async fn list_virtual_tables(
    service: &SekaiServiceImpl,
    req: Request<ListVirtualTablesRequest>,
) -> Result<Response<ListVirtualTablesResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tables = service
        .db
        .runtime()
        .list_virtual_tables()
        .map_err(Status::internal)?
        .into_iter()
        .filter(|table| {
            service
                .db
                .runtime()
                .get_dataset(&table.dataset_id)
                .ok()
                .flatten()
                .map(|dataset| {
                    check_dataset_access(
                        service.db.runtime(),
                        &service.security,
                        &principals,
                        &dataset,
                        false,
                    )
                    .is_ok()
                })
                .unwrap_or(false)
        })
        .collect::<Vec<_>>()
        .iter()
        .map(to_proto_virtual_table)
        .collect();
    Ok(Response::new(ListVirtualTablesResponse { tables }))
}
pub(super) async fn create_grant(
    service: &SekaiServiceImpl,
    req: Request<CreateGrantRequest>,
) -> Result<Response<CreateGrantResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let grant = req
        .into_inner()
        .grant
        .ok_or(Status::invalid_argument("grant required"))?;
    let parsed = from_proto_grant(&grant)?;
    if check_ontology_grant_target(
        service.db.runtime(),
        &service.security,
        &parsed.object_id,
        &principals,
    )? {
        service
            .db
            .runtime()
            .create_grant(&parsed)
            .map_err(Status::invalid_argument)?;
        service.security.add_grant(&parsed);
        return Ok(Response::new(CreateGrantResponse {
            grant: Some(to_proto_grant(&parsed)),
        }));
    }
    let target = service
        .db
        .runtime()
        .get_object(&parsed.object_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::invalid_argument("grant target object does not exist"))?;
    if target.kind == "namespace" {
        require_credential_admin(&principals)?;
    } else {
        check_team_namespace(service.db.runtime(), &principals, &target.namespace, true)?;
    }
    check_object_admin(
        service.db.runtime(),
        &service.security,
        &target,
        &principals,
    )?;
    service
        .db
        .runtime()
        .create_grant(&parsed)
        .map_err(Status::invalid_argument)?;
    service.security.add_grant(&parsed);
    Ok(Response::new(CreateGrantResponse {
        grant: Some(to_proto_grant(&parsed)),
    }))
}
pub(super) async fn delete_grant(
    service: &SekaiServiceImpl,
    req: Request<DeleteGrantRequest>,
) -> Result<Response<DeleteGrantResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let id = req.into_inner().id;
    let existing = service
        .db
        .runtime()
        .get_grant(&id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("grant not found"))?;
    if check_ontology_grant_target(
        service.db.runtime(),
        &service.security,
        &existing.object_id,
        &principals,
    )? {
        let deleted = service
            .db
            .runtime()
            .delete_grant(&id)
            .map_err(Status::internal)?;
        if let Some(grant) = deleted {
            service
                .security
                .remove_grant(&grant.object_id, &grant.principal);
        }
        return Ok(Response::new(DeleteGrantResponse {}));
    }
    let target = service
        .db
        .runtime()
        .get_object(&existing.object_id)
        .map_err(Status::internal)?;
    if target
        .as_ref()
        .is_some_and(|object| object.kind == "namespace")
    {
        require_credential_admin(&principals)?;
    } else if let Some(target) = &target {
        check_team_namespace(service.db.runtime(), &principals, &target.namespace, true)?;
    }
    let target = target.ok_or(Status::not_found("grant target not found"))?;
    check_object_admin(
        service.db.runtime(),
        &service.security,
        &target,
        &principals,
    )?;
    let deleted = service
        .db
        .runtime()
        .delete_grant(&id)
        .map_err(Status::internal)?;
    if let Some(grant) = deleted {
        service
            .security
            .remove_grant(&grant.object_id, &grant.principal);
    }
    Ok(Response::new(DeleteGrantResponse {}))
}
pub(super) async fn list_grants(
    service: &SekaiServiceImpl,
    req: Request<ListGrantsRequest>,
) -> Result<Response<ListGrantsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let object_id = req.into_inner().object_id;
    if check_ontology_grant_target(
        service.db.runtime(),
        &service.security,
        &object_id,
        &principals,
    )? {
        let grants = service
            .db
            .runtime()
            .list_grants(&object_id)
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_grant)
            .collect();
        return Ok(Response::new(ListGrantsResponse { grants }));
    }
    let target = service
        .db
        .runtime()
        .get_object(&object_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("grant target not found"))?;
    if target.kind == "namespace" {
        require_credential_admin(&principals)?;
    } else {
        check_team_namespace(service.db.runtime(), &principals, &target.namespace, true)?;
    }
    check_object_admin(
        service.db.runtime(),
        &service.security,
        &target,
        &principals,
    )?;
    let grants = service
        .db
        .runtime()
        .list_grants(&object_id)
        .map_err(Status::internal)?
        .iter()
        .map(to_proto_grant)
        .collect();
    Ok(Response::new(ListGrantsResponse { grants }))
}
pub(super) async fn check_access(
    service: &SekaiServiceImpl,
    req: Request<CheckAccessRequest>,
) -> Result<Response<CheckAccessResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    check_object_namespace_access(service.db.runtime(), &principals, &inner.object_id, false)?;
    check_read(&service.security, &inner.object_id, &principals)?;
    let refs: Vec<&str> = inner.principals.iter().map(String::as_str).collect();
    Ok(Response::new(CheckAccessResponse {
        allowed: service.security.can_access(&inner.object_id, &refs),
    }))
}
pub(super) async fn ensure_team_namespace(
    service: &SekaiServiceImpl,
    req: Request<EnsureTeamNamespaceRequest>,
) -> Result<Response<EnsureTeamNamespaceResponse>, Status> {
    let principals = caller_principals(&req);
    require_credential_admin(&principals)?;
    let inner = req.into_inner();
    let namespace = validate_credential_principal(&inner.namespace)?;
    let principal = validate_team_principal(&inner.principal)?;
    let role = security::Role::parse(&inner.role)
        .ok_or_else(|| Status::invalid_argument("role must be viewer, editor, or admin"))?;
    let actor = principals.first().map(String::as_str).unwrap_or("root");
    let (namespace, grants) = service
        .db
        .runtime()
        .ensure_team_namespace(&namespace, &principal, role, actor)
        .map_err(Status::internal)?;
    for grant in &grants {
        service.security.add_grant(grant);
    }
    Ok(Response::new(EnsureTeamNamespaceResponse {
        namespace: Some(to_proto_obj(&namespace)),
        grants: grants.iter().map(to_proto_grant).collect(),
    }))
}
pub(super) async fn record_decision(
    service: &SekaiServiceImpl,
    req: Request<RecordDecisionRequest>,
) -> Result<Response<RecordDecisionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let mut decision = req
        .into_inner()
        .decision
        .ok_or_else(|| Status::invalid_argument("decision required"))?;
    decision.actor = principals
        .first()
        .cloned()
        .ok_or(Status::unauthenticated("principal required"))?;
    if decision.target_id.is_empty() {
        if is_managed_team_principal(service.db.runtime(), &principals)? {
            return Err(Status::permission_denied(
                "team decisions require a namespace-bound target object",
            ));
        }
    } else {
        check_object_namespace_access(
            service.db.runtime(),
            &principals,
            &decision.target_id,
            true,
        )?;
        check_write(&service.security, &decision.target_id, &principals)?;
    }
    if decision.id.is_empty() {
        decision.id = uuid::Uuid::new_v4().to_string();
    }
    // Clamp to server time: a client-supplied future timestamp would sit
    // above every later entry in the ledger and pin the purgeable prefix
    // forever (retention would silently stop).
    let now = now_millis();
    if decision.timestamp <= 0 || decision.timestamp > now {
        decision.timestamp = now;
    }
    // Reserved keys: only the server-side attestation binding may claim
    // one, otherwise a caller could dress up an arbitrary decision as
    // policy-attested.
    decision
        .evidence
        .remove(attestation::EVIDENCE_ATTESTATION_ID);
    decision
        .evidence
        .remove(attestation::EVIDENCE_ATTESTATION_HASH);
    service
        .db
        .runtime()
        .record_decision(&audit::Decision {
            id: decision.id.clone(),
            timestamp: decision.timestamp,
            actor: decision.actor.clone(),
            action: decision.action.clone(),
            reason: decision.reason.clone(),
            evidence: decision.evidence.clone(),
            target_id: decision.target_id.clone(),
            outcome: decision.outcome.clone(),
        })
        .map_err(Status::internal)?;
    Ok(Response::new(RecordDecisionResponse {
        decision: Some(decision),
    }))
}
pub(super) async fn list_decisions(
    service: &SekaiServiceImpl,
    req: Request<ListDecisionsRequest>,
) -> Result<Response<ListDecisionsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let visible_limit = if inner.limit > 0 {
        inner.limit as usize
    } else {
        100
    };
    let actor_filter = if inner.actor.is_empty() {
        None
    } else {
        Some(inner.actor.clone())
    };
    let action_filter = if inner.action.is_empty() {
        None
    } else {
        Some(inner.action.clone())
    };
    let target_filter = if inner.target_id.is_empty() {
        None
    } else {
        check_object_namespace_access(service.db.runtime(), &principals, &inner.target_id, false)?;
        check_read(&service.security, &inner.target_id, &principals)?;
        Some(inner.target_id.clone())
    };
    let managed_team_principal = is_managed_team_principal(service.db.runtime(), &principals)?;
    let decisions = scan_visible_page(
        visible_limit,
        0,
        |limit, offset| {
            service.db.runtime().list_decisions(&audit::DecisionFilter {
                actor: actor_filter.clone(),
                action: action_filter.clone(),
                target_id: target_filter.clone(),
                after: inner.after,
                limit,
                offset,
            })
        },
        |decision| {
            if decision.target_id.is_empty() {
                if managed_team_principal {
                    return false;
                }
            } else if check_object_namespace_access(
                service.db.runtime(),
                &principals,
                &decision.target_id,
                false,
            )
            .is_err()
                || check_read(&service.security, &decision.target_id, &principals).is_err()
            {
                return false;
            }
            true
        },
    )
    .map_err(|error| match error {
        VisiblePageError::Fetch(error) => Status::internal(error),
        VisiblePageError::ScanBudgetExhausted => {
            Status::resource_exhausted("decision visibility scan limit exceeded; refine filters")
        }
    })?
    .into_iter()
    .map(|decision| Decision {
        id: decision.id,
        timestamp: decision.timestamp,
        actor: decision.actor,
        action: decision.action,
        reason: decision.reason,
        evidence: decision.evidence,
        target_id: decision.target_id,
        outcome: decision.outcome,
    })
    .collect();
    Ok(Response::new(ListDecisionsResponse { decisions }))
}
pub(super) async fn list_object_changes(
    service: &SekaiServiceImpl,
    req: Request<ListObjectChangesRequest>,
) -> Result<Response<ListObjectChangesResponse>, Status> {
    let principals = caller_principals(&req);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    check_object_namespace_access(service.db.runtime(), &principals, &inner.object_id, false)?;
    check_read(&service.security, &inner.object_id, &principals)?;
    let object = service
        .db
        .runtime()
        .get_object(&inner.object_id)
        .map_err(Status::internal)?;
    match object.as_ref() {
        Some(object) => {
            enforce_namespace_tenant_context(
                service.db.runtime(),
                tenant_context.as_ref(),
                &object.namespace,
                false,
            )
            .map_err(|_| Status::not_found("not found"))?;
            if evaluate_active_object_policy(
                service.db.runtime(),
                object,
                &principals,
                tenant_context.as_ref(),
                crate::sekai::object_security::ObjectSecurityOperation::Read,
                None,
            )? == Some(false)
            {
                return Err(Status::not_found("not found"));
            }
            enforce_object_marking_access(
                service.db.runtime(),
                object,
                &principals,
                &format!("list_object_changes:{}", object.id),
            )?;
        }
        None if tenant_context.is_some() => {
            return Err(Status::not_found("not found"));
        }
        None => {
            // Deleted rows cannot be re-evaluated against the live object.
            // If the inferred namespace is activated, refuse rather than
            // leak field history under ACL-only residual access.
            let activated = match service
                .db
                .runtime()
                .object_change_namespace(&inner.object_id)
            {
                Ok(Some(namespace)) => service
                    .db
                    .runtime()
                    .get_object_security_activation(&namespace)
                    .map_err(|_| Status::unavailable("object authorization unavailable"))?
                    .is_some(),
                Ok(None) => false,
                Err(_) => service
                    .db
                    .runtime()
                    .has_object_security_activations()
                    .map_err(|_| Status::unavailable("object authorization unavailable"))?,
            };
            if activated {
                return Err(Status::not_found("not found"));
            }
        }
    }
    let object_kind = match object.as_ref() {
        Some(object) => Some(object.kind.clone()),
        None => service
            .db
            .runtime()
            .object_change_kind(&inner.object_id)
            .map_err(Status::internal)?,
    };
    let schema = service
        .schema_definitions
        .snapshot()
        .map_err(map_schema_definition_lifecycle_error)?;
    let property_policy = match object.as_ref() {
        Some(object) => service
            .db
            .runtime()
            .active_object_policy(&object.namespace, &object.kind)
            .map_err(|_| Status::unavailable("object authorization unavailable"))?,
        None => None,
    };
    let operation_id = crate::sekai::operation_correlation::operation_ids_for_objects(
        service.db.runtime(),
        &[inner.object_id.clone()].into_iter().collect(),
    )
    .map_err(Status::internal)?
    .remove(&inner.object_id)
    .unwrap_or_default();
    let changes = service
        .db
        .runtime()
        .list_visible_object_changes(&inner.object_id, inner.limit, inner.offset)
        .map_err(Status::internal)?
        .into_iter()
        .map(|change| {
            let mut mapped = if let Some(kind) = object_kind.as_deref() {
                redact_object_change_values(
                    change,
                    &inner.object_id,
                    kind,
                    &schema,
                    &service.security,
                    &principals,
                    property_policy.as_ref(),
                )
            } else {
                ObjectChange {
                    id: change.id,
                    object_id: change.object_id,
                    field: change.field,
                    old_value: change.old_value,
                    new_value: change.new_value,
                    changed_by: change.changed_by,
                    timestamp: change.timestamp,
                    operation_id: String::new(),
                }
            };
            mapped.operation_id = operation_id.clone();
            mapped
        })
        .collect();
    Ok(Response::new(ListObjectChangesResponse { changes }))
}
pub(super) async fn get_attestation(
    service: &SekaiServiceImpl,
    req: Request<GetAttestationRequest>,
) -> Result<Response<GetAttestationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let id = req.into_inner().id;
    if id.trim().is_empty() {
        return Err(Status::invalid_argument("id required"));
    }
    let attestation = service
        .db
        .runtime()
        .get_attestation(&id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("attestation not found"))?;
    // Attestations embed the full policy snapshot; reading policy content
    // is admin-gated like get_action_policy / list_action_policies.
    check_action_admin(&service.security, &attestation.policy_scope, &principals)?;
    Ok(Response::new(GetAttestationResponse {
        attestation: Some(to_proto_attestation(&attestation)),
    }))
}
pub(super) async fn list_attestations(
    service: &SekaiServiceImpl,
    req: Request<ListAttestationsRequest>,
) -> Result<Response<ListAttestationsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let decision_id = (!inner.decision_id.trim().is_empty()).then_some(inner.decision_id);
    let policy_scope = (!inner.policy_scope.trim().is_empty()).then_some(inner.policy_scope);
    // Attestations embed full policy snapshots (admin-gated content).
    // With a scope filter the caller must be admin for that scope; without
    // one, only the scopes the caller administers are returned.
    if let Some(scope) = policy_scope.as_deref() {
        check_action_admin(&service.security, scope, &principals)?;
    }
    // Paginate over *visible* rows: scan the table in batches and apply
    // limit/offset after the admin filter, so partially-privileged
    // callers get stable pages (mirrors list_decisions). A scan cap
    // bounds the work when most rows are invisible to the caller.
    let visible_limit = if inner.limit > 0 {
        inner.limit as usize
    } else {
        100
    };
    let visible_offset = inner.offset.max(0) as usize;
    let attestations = scan_visible_page(
        visible_limit,
        visible_offset,
        |limit, offset| {
            service.db.runtime().list_attestations(
                decision_id.as_deref(),
                policy_scope.as_deref(),
                limit,
                offset,
            )
        },
        |attestation| {
            check_action_admin(&service.security, &attestation.policy_scope, &principals).is_ok()
        },
    )
    .map_err(|error| match error {
        VisiblePageError::Fetch(error) => Status::internal(error),
        VisiblePageError::ScanBudgetExhausted => {
            Status::resource_exhausted("attestation visibility scan limit exceeded; refine filters")
        }
    })?
    .iter()
    .map(to_proto_attestation)
    .collect();
    Ok(Response::new(ListAttestationsResponse { attestations }))
}
pub(super) async fn verify_attestation(
    service: &SekaiServiceImpl,
    req: Request<VerifyAttestationRequest>,
) -> Result<Response<VerifyAttestationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let id = req.into_inner().id;
    if id.trim().is_empty() {
        return Err(Status::invalid_argument("id required"));
    }
    // Verification results expose the replayed decision for a scope's
    // policy; gate like the other attestation reads.
    if let Some(attestation) = service
        .db
        .runtime()
        .get_attestation(&id)
        .map_err(Status::internal)?
    {
        check_action_admin(&service.security, &attestation.policy_scope, &principals)?;
    }
    let report = service
        .db
        .runtime()
        .verify_attestation(&id)
        .map_err(Status::internal)?;
    Ok(Response::new(VerifyAttestationResponse {
        ok: report.ok,
        found: report.found,
        hash_ok: report.hash_ok,
        replay_ok: report.replay_ok,
        replayed_decision: report.replayed_decision,
        decision_linked: report.decision_linked,
        error: report.error,
    }))
}
pub(super) async fn create_credential(
    service: &SekaiServiceImpl,
    req: Request<CreateCredentialRequest>,
) -> Result<Response<CreateCredentialResponse>, Status> {
    credential_admin_actor(service.db.runtime(), &req, "")?;
    let request = req.into_inner();
    let principal = if request.managed_team_principal {
        validate_team_principal(&request.principal)?
    } else {
        validate_new_credential_principal(&request.principal)?
    };
    let existing = service
        .db
        .runtime()
        .list_unbound_credentials(Some(&principal), Some("active"));
    if !existing.map_err(Status::internal)?.is_empty() {
        return Err(Status::already_exists(format!(
            "active credential already exists for {principal:?}; rotate it instead"
        )));
    }
    let token = new_credential_token();
    let token_hash = hash_gateway_key(&token);
    let now = chrono::Utc::now().timestamp_millis();
    let credential = if request.managed_team_principal {
        service
            .db
            .runtime()
            .create_managed_team_credential(&principal, &token_hash, now)
    } else {
        service
            .db
            .runtime()
            .create_principal_credential(&principal, &token_hash, now)
    }
    .map_err(Status::internal)?;
    Ok(Response::new(CreateCredentialResponse {
        token,
        credential: Some(to_proto_credential(credential)),
    }))
}
pub(super) async fn rotate_credential(
    service: &SekaiServiceImpl,
    req: Request<RotateCredentialRequest>,
) -> Result<Response<RotateCredentialResponse>, Status> {
    credential_admin_actor(service.db.runtime(), &req, "")?;
    let request = req.into_inner();
    let principal = if request.managed_team_principal {
        validate_team_principal(&request.principal)?
    } else {
        validate_new_credential_principal(&request.principal)?
    };
    let existing = service
        .db
        .runtime()
        .list_unbound_credentials(Some(&principal), Some("active"));
    if existing.map_err(Status::internal)?.is_empty() {
        return Err(Status::not_found(format!(
            "no active credential for {principal:?}"
        )));
    }
    let token = new_credential_token();
    let token_hash = hash_gateway_key(&token);
    let credential = if request.managed_team_principal {
        service
            .db
            .runtime()
            .rotate_managed_team_credential(&principal, &token_hash)
            .map_err(Status::internal)
    } else {
        service
            .db
            .runtime()
            .rotate_principal_credential(&principal, &token_hash)
            .map_err(Status::internal)
    }?;
    Ok(Response::new(RotateCredentialResponse {
        token,
        credential: Some(to_proto_credential(credential)),
    }))
}
pub(super) async fn revoke_credential(
    service: &SekaiServiceImpl,
    req: Request<RevokeCredentialRequest>,
) -> Result<Response<RevokeCredentialResponse>, Status> {
    credential_admin_actor(service.db.runtime(), &req, "")?;
    let request = req.into_inner();
    let principal = validate_credential_principal(&request.principal)?;
    let credential = service
        .db
        .runtime()
        .revoke_principal_credential(&principal)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found(format!("no active credential for {principal:?}")))?;
    Ok(Response::new(RevokeCredentialResponse {
        credential: Some(to_proto_credential(credential)),
    }))
}
pub(super) async fn list_credentials(
    service: &SekaiServiceImpl,
    req: Request<ListCredentialsRequest>,
) -> Result<Response<ListCredentialsResponse>, Status> {
    credential_admin_actor(service.db.runtime(), &req, "")?;
    let credentials = service
        .db
        .runtime()
        .list_unbound_credentials(None, None)
        .map_err(Status::internal)?
        .into_iter()
        .map(to_proto_credential)
        .collect();
    Ok(Response::new(ListCredentialsResponse { credentials }))
}
pub(super) async fn register_evidence_schema(
    service: &SekaiServiceImpl,
    req: Request<RegisterEvidenceSchemaRequest>,
) -> Result<Response<RegisterEvidenceSchemaResponse>, Status> {
    let principals = caller_principals(&req);
    require_evidence_admin(&service.security, &principals)?;
    let definition = req
        .into_inner()
        .definition
        .ok_or_else(|| Status::invalid_argument("definition required"))?;
    service
        .db
        .runtime()
        .register_evidence_schema(
            &DomainEvidenceSchemaDefinition {
                schema_id: definition.schema_id,
                schema_version: definition.schema_version,
                evidence_type: definition.evidence_type,
                compatible_versions: definition.compatible_versions,
            },
            now_millis(),
        )
        .map_err(Status::invalid_argument)?;
    Ok(Response::new(RegisterEvidenceSchemaResponse {}))
}
pub(super) async fn list_evidence_adapters(
    service: &SekaiServiceImpl,
    req: Request<crate::grpc::pb::sekai::ListEvidenceAdaptersRequest>,
) -> Result<Response<crate::grpc::pb::sekai::ListEvidenceAdaptersResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let registered_only = req.into_inner().registered_only;
    let mut adapters = Vec::new();
    for profile in crate::evidence_adapter_catalog::built_in_evidence_adapters() {
        let schema_registered = service
            .db
            .runtime()
            .is_evidence_schema_registered(&profile.schema_id, &profile.schema_version)
            .map_err(Status::internal)?;
        if registered_only && !schema_registered {
            continue;
        }
        adapters.push(crate::grpc::pb::sekai::EvidenceAdapterProfile {
            adapter_id: profile.adapter_id,
            family: profile.family,
            evidence_type: profile.evidence_type,
            schema_id: profile.schema_id,
            schema_version: profile.schema_version,
            source_type: profile.source_type,
            signal: profile.signal,
            delivery: profile.delivery,
            requires_expiry: profile.requires_expiry,
            reference_example: profile.reference_example,
            description: profile.description,
            schema_registered,
        });
    }
    let families = crate::evidence_adapter_catalog::built_in_evidence_adapter_families()
        .into_iter()
        .filter(|family| {
            !registered_only
                || family.adapter_ids.iter().any(|adapter_id| {
                    adapters
                        .iter()
                        .any(|adapter| adapter.adapter_id == *adapter_id)
                })
        })
        .map(|family| crate::grpc::pb::sekai::EvidenceAdapterFamily {
            family: family.family,
            display_name: family.display_name,
            description: family.description,
            adapter_ids: family.adapter_ids,
        })
        .collect();
    Ok(Response::new(
        crate::grpc::pb::sekai::ListEvidenceAdaptersResponse { adapters, families },
    ))
}
pub(super) async fn submit_evidence(
    service: &SekaiServiceImpl,
    req: Request<SubmitEvidenceRequest>,
) -> Result<Response<SubmitEvidenceResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let envelope = req
        .into_inner()
        .envelope
        .ok_or_else(|| Status::invalid_argument("envelope required"))?;
    let envelope = from_proto_evidence_envelope(envelope)?;
    if !principals.contains(&envelope.producer_identity) {
        return Err(Status::permission_denied(
            "authenticated producer must match envelope attribution",
        ));
    }
    let result = EvidenceAdmissionLifecycle::new(service.db.runtime())
        .admit(&envelope, &envelope.producer_identity, now_millis())
        .map_err(map_evidence_admission_lifecycle_error)?;
    if let Some(object_id) = result
        .projection
        .as_ref()
        .and_then(|projection| projection.evidence_object_id.as_deref())
    {
        for grant in service
            .db
            .runtime()
            .list_grants(object_id)
            .map_err(Status::internal)?
        {
            service.security.add_grant(&grant);
        }
    }
    Ok(Response::new(SubmitEvidenceResponse {
        result: Some(to_proto_evidence_submission_result(result)),
    }))
}
pub(super) async fn get_evidence_submission(
    service: &SekaiServiceImpl,
    req: Request<GetEvidenceSubmissionRequest>,
) -> Result<Response<GetEvidenceSubmissionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let submission_id = req.into_inner().submission_id;
    let submission = service
        .db
        .runtime()
        .get_evidence_submission(&submission_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("evidence submission not found"))?;
    if !can_operate_evidence_submission(&service.security, &submission, &principals) {
        return Err(Status::permission_denied("evidence access denied"));
    }
    let history = service
        .db
        .runtime()
        .evidence_lifecycle_history(&submission_id)
        .map_err(Status::internal)?
        .into_iter()
        .map(|state| state.as_str().to_string())
        .collect();
    Ok(Response::new(GetEvidenceSubmissionResponse {
        submission: Some(to_proto_evidence_submission(&submission)),
        lifecycle_history: history,
    }))
}
pub(super) async fn list_evidence_submissions(
    service: &SekaiServiceImpl,
    req: Request<ListEvidenceSubmissionsRequest>,
) -> Result<Response<ListEvidenceSubmissionsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let is_admin = require_evidence_admin(&service.security, &principals).is_ok();
    let request = req.into_inner();
    let producer_identity = if is_admin {
        optional_nonempty(request.producer_identity)
    } else {
        let requested = optional_nonempty(request.producer_identity);
        if requested
            .as_ref()
            .is_some_and(|producer| !principals.contains(producer))
        {
            return Err(Status::permission_denied("evidence access denied"));
        }
        requested.or_else(|| {
            principals
                .iter()
                .find(|principal| principal.as_str() != "anonymous")
                .cloned()
        })
    };
    let lifecycle_state = if request.lifecycle_state.trim().is_empty() {
        None
    } else {
        Some(
            evidence_domain::EvidenceLifecycleState::parse(request.lifecycle_state.trim())
                .ok_or_else(|| Status::invalid_argument("invalid lifecycle_state"))?,
        )
    };
    let submissions = service
        .db
        .runtime()
        .list_evidence_submissions(&EvidenceSubmissionFilter {
            producer_identity,
            source_instance: optional_nonempty(request.source_instance),
            namespace: optional_nonempty(request.namespace),
            lifecycle_state,
            target_external_id: optional_nonempty(request.target_external_id),
            evidence_type: optional_nonempty(request.evidence_type),
            limit: request.limit,
            offset: request.offset,
        })
        .map_err(Status::internal)?
        .iter()
        .map(to_proto_evidence_submission)
        .collect();
    Ok(Response::new(ListEvidenceSubmissionsResponse {
        submissions,
    }))
}
pub(super) async fn get_provenance_report(
    service: &SekaiServiceImpl,
    req: Request<GetProvenanceReportRequest>,
) -> Result<Response<GetProvenanceReportResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let work_unit_id = req.into_inner().work_unit_id.trim().to_string();
    if work_unit_id.is_empty() {
        return Err(Status::invalid_argument("work_unit_id required"));
    }
    let work_unit = service
        .db
        .runtime()
        .get_work_unit(&work_unit_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("work unit not found"))?;
    check_work_unit_read(
        service.db.runtime(),
        &service.security,
        &work_unit,
        &principals,
    )?;
    let report = crate::provenance::assemble_report(service.db.runtime(), &work_unit_id)
        .map_err(Status::internal)?;
    Ok(Response::new(GetProvenanceReportResponse {
        report: crate::provenance::render_text(&report),
    }))
}
pub(super) async fn put_governed_transform(
    service: &SekaiServiceImpl,
    req: Request<PutGovernedTransformRequest>,
) -> Result<Response<PutGovernedTransformResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let proto = req
        .into_inner()
        .transform
        .ok_or_else(|| Status::invalid_argument("transform required"))?;
    let transform = crate::sekai::governed_transform::GovernedTransform {
        contract_version: proto.contract_version,
        namespace: proto.namespace,
        transform_id: proto.transform_id,
        input_dataset_id: proto.input_dataset_id,
        output_dataset_id: proto.output_dataset_id,
        steps: proto
            .steps
            .into_iter()
            .map(|step| crate::sekai::governed_transform::TransformStep {
                kind: step.kind,
                column: step.column,
                op: step.op,
                value: step.value,
                columns: step.columns,
            })
            .collect(),
        quality_rule: proto.quality_rule,
        definition_digest: proto.definition_digest,
    }
    .prepare()
    .map_err(|error| Status::invalid_argument(error.message()))?;
    service
        .db
        .runtime()
        .put_governed_transform(&transform, now_millis())
        .map_err(Status::internal)?;
    Ok(Response::new(PutGovernedTransformResponse {
        transform: Some(to_proto_transform(&transform)),
    }))
}
pub(super) async fn run_governed_transform(
    service: &SekaiServiceImpl,
    req: Request<RunGovernedTransformRequest>,
) -> Result<Response<RunGovernedTransformResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let input = req.into_inner();
    let run = service
        .db
        .runtime()
        .run_governed_transform(
            &input.namespace,
            &input.transform_id,
            input.incremental,
            now_millis(),
        )
        .map_err(|error| {
            if error.contains("not found") {
                Status::not_found(error)
            } else {
                Status::internal(error)
            }
        })?;
    Ok(Response::new(RunGovernedTransformResponse {
        run: Some(to_proto_transform_run(&run)),
    }))
}
pub(super) async fn get_governed_transform_run(
    service: &SekaiServiceImpl,
    req: Request<GetGovernedTransformRunRequest>,
) -> Result<Response<GetGovernedTransformRunResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let run = service
        .db
        .runtime()
        .get_governed_transform_run(&req.into_inner().run_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("not found"))?;
    Ok(Response::new(GetGovernedTransformRunResponse {
        run: Some(to_proto_transform_run(&run)),
    }))
}

fn to_proto_transform(
    transform: &crate::sekai::governed_transform::GovernedTransform,
) -> GovernedTransform {
    GovernedTransform {
        contract_version: transform.contract_version.clone(),
        namespace: transform.namespace.clone(),
        transform_id: transform.transform_id.clone(),
        input_dataset_id: transform.input_dataset_id.clone(),
        output_dataset_id: transform.output_dataset_id.clone(),
        steps: transform
            .steps
            .iter()
            .map(|step| TransformStep {
                kind: step.kind.clone(),
                column: step.column.clone(),
                op: step.op.clone(),
                value: step.value.clone(),
                columns: step.columns.clone(),
            })
            .collect(),
        quality_rule: transform.quality_rule.clone(),
        definition_digest: transform.definition_digest.clone(),
    }
}

fn to_proto_transform_run(run: &crate::sekai::governed_transform::TransformRun) -> TransformRun {
    TransformRun {
        run_id: run.run_id.clone(),
        namespace: run.namespace.clone(),
        transform_id: run.transform_id.clone(),
        definition_digest: run.definition_digest.clone(),
        input_digest: run.input_digest.clone(),
        output_digest: run.output_digest.clone(),
        last_input_row_id: run.last_input_row_id,
        incremental: run.incremental,
        quarantined: run.quarantined,
        quality_rule: run.quality_rule.clone(),
        rows_in: run.rows_in,
        rows_out: run.rows_out,
        lineage_parent: run.lineage_parent.clone(),
        created_at_ms: run.created_at_ms,
    }
}
