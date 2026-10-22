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
    let parsed = from_proto_function(&function)?;
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
    if crate::sekai::function::has_llm_step(&function)
        && !service
            .db
            .runtime()
            .function_gate_approved(&function)
            .map_err(Status::internal)?
    {
        return Err(Status::failed_precondition(
            crate::sekai::function::LLM_FUNCTION_REQUIRES_GATE,
        ));
    }
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
        structured_json: invocation
            .result
            .structured
            .as_ref()
            .map(|value| serde_json::to_string(value).unwrap_or_else(|_| "{}".into()))
            .unwrap_or_default(),
        receipt: Some(FunctionReceipt {
            function_name: invocation.receipt.function_name,
            function_digest: invocation.receipt.function_digest,
            now_ms: invocation.receipt.now_ms,
            rng_seed: invocation.receipt.rng_seed,
            elapsed_ms: invocation.receipt.elapsed_ms,
            steps: invocation.receipt.steps,
            budget_exceeded: invocation.receipt.budget_exceeded,
            output_digest: invocation.receipt.output_digest,
            prompt_digest: invocation.receipt.prompt_digest,
            model_route: invocation.receipt.model_route,
            input_digest: invocation.receipt.input_digest,
            schema_error: invocation.receipt.schema_error,
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
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
                && catalog_binding_discoverable(
                    service.db.runtime(),
                    &service.security,
                    tenant_context.as_ref(),
                    &dataset.object_id,
                    &principals,
                )
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
pub(super) async fn list_dataset_versions(
    service: &SekaiServiceImpl,
    req: Request<ListDatasetVersionsRequest>,
) -> Result<Response<ListDatasetVersionsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let dataset = service
        .db
        .runtime()
        .get_dataset(&inner.dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        false,
    )?;
    let versions = service
        .db
        .runtime()
        .list_dataset_versions(&inner.dataset_id)
        .map_err(map_dataset_version_error)?;
    let versions = if inner.as_of_ms > 0 {
        versions
            .into_iter()
            .filter(|version| version.created_at_ms <= inner.as_of_ms)
            .collect::<Vec<_>>()
    } else {
        versions
    };
    let version_retention_count = service
        .db
        .runtime()
        .dataset_version_retention(&inner.dataset_id)
        .map_err(Status::internal)?;
    Ok(Response::new(ListDatasetVersionsResponse {
        versions: versions.iter().map(to_proto_dataset_version).collect(),
        version_retention_count,
    }))
}
pub(super) async fn get_dataset_version(
    service: &SekaiServiceImpl,
    req: Request<GetDatasetVersionRequest>,
) -> Result<Response<GetDatasetVersionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let dataset = service
        .db
        .runtime()
        .get_dataset(&inner.dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        false,
    )?;
    let (version, rows) = service
        .db
        .runtime()
        .load_dataset_version(&inner.dataset_id, &inner.version_id, inner.as_of_ms)
        .map_err(map_dataset_version_error)?;
    let version_retention_count = service
        .db
        .runtime()
        .dataset_version_retention(&inner.dataset_id)
        .map_err(Status::internal)?;
    Ok(Response::new(GetDatasetVersionResponse {
        version: Some(to_proto_dataset_version(&version)),
        rows: rows.into_iter().map(|values| Row { values }).collect(),
        version_retention_count,
    }))
}
pub(super) async fn rollback_dataset(
    service: &SekaiServiceImpl,
    req: Request<RollbackDatasetRequest>,
) -> Result<Response<RollbackDatasetResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    let dataset = service
        .db
        .runtime()
        .get_dataset(&inner.dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        true,
    )?;
    let actor = principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let context_tenant = tenant_context
        .as_ref()
        .and_then(|context| {
            context
                .tenant
                .as_ref()
                .map(|tenant| tenant.tenant_id.clone())
        })
        .unwrap_or_default();
    let tenant = if !inner.tenant.is_empty() {
        if !context_tenant.is_empty() && inner.tenant != context_tenant {
            return Err(Status::permission_denied(
                "rollback tenant does not match authenticated tenant",
            ));
        }
        inner.tenant
    } else {
        context_tenant
    };
    let version = service
        .db
        .runtime()
        .rollback_dataset(&crate::sekai::dataset_version::DatasetRollback {
            dataset_id: inner.dataset_id.clone(),
            restore_from_version_id: inner.restore_from_version_id,
            reason: inner.reason,
            actor,
            tenant,
        })
        .map_err(map_dataset_version_error)?;
    let rows = service
        .db
        .runtime()
        .query_dataset_version_rows(&inner.dataset_id, &version.version_id, 0)
        .map_err(map_dataset_version_error)?;
    Ok(Response::new(RollbackDatasetResponse {
        version: Some(to_proto_dataset_version(&version)),
        rows: rows.into_iter().map(|values| Row { values }).collect(),
    }))
}

pub(super) async fn put_dataset_health_check(
    service: &SekaiServiceImpl,
    req: Request<PutDatasetHealthCheckRequest>,
) -> Result<Response<PutDatasetHealthCheckResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let check = inner
        .check
        .ok_or_else(|| Status::invalid_argument("check required"))?;
    let dataset = service
        .db
        .runtime()
        .get_dataset(&check.dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        true,
    )?;
    let parsed = from_proto_health_check(&check);
    service
        .db
        .runtime()
        .put_dataset_health_check(&parsed)
        .map_err(Status::invalid_argument)?;
    let stored = service
        .db
        .runtime()
        .list_dataset_health_checks(&parsed.dataset_id)
        .map_err(Status::internal)?
        .into_iter()
        .find(|item| item.check_id == parsed.check_id)
        .unwrap_or(parsed);
    Ok(Response::new(PutDatasetHealthCheckResponse {
        check: Some(to_proto_health_check(&stored)),
    }))
}

pub(super) async fn list_dataset_health_checks(
    service: &SekaiServiceImpl,
    req: Request<ListDatasetHealthChecksRequest>,
) -> Result<Response<ListDatasetHealthChecksResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let dataset = service
        .db
        .runtime()
        .get_dataset(&inner.dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        false,
    )?;
    let checks = service
        .db
        .runtime()
        .list_dataset_health_checks(&inner.dataset_id)
        .map_err(Status::internal)?;
    Ok(Response::new(ListDatasetHealthChecksResponse {
        checks: checks.iter().map(to_proto_health_check).collect(),
    }))
}

pub(super) async fn list_dataset_health_results(
    service: &SekaiServiceImpl,
    req: Request<ListDatasetHealthResultsRequest>,
) -> Result<Response<ListDatasetHealthResultsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let dataset = service
        .db
        .runtime()
        .get_dataset(&inner.dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        false,
    )?;
    let results = service
        .db
        .runtime()
        .list_dataset_health_results(&inner.dataset_id, &inner.version_id)
        .map_err(Status::internal)?;
    let state = service
        .db
        .runtime()
        .dataset_health_state(&inner.dataset_id)
        .map_err(Status::internal)?;
    Ok(Response::new(ListDatasetHealthResultsResponse {
        results: results.iter().map(to_proto_health_result).collect(),
        last_healthy_version_id: state.last_healthy_version_id,
        quarantined: state.quarantined,
    }))
}

pub(super) async fn run_dataset_health_checks(
    service: &SekaiServiceImpl,
    req: Request<RunDatasetHealthChecksRequest>,
) -> Result<Response<RunDatasetHealthChecksResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let dataset = service
        .db
        .runtime()
        .get_dataset(&inner.dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        true,
    )?;
    let now_ms = if inner.now_ms > 0 {
        inner.now_ms
    } else {
        crate::sekai::dataset_version::now_ms()
    };
    let results = service
        .db
        .runtime()
        .run_dataset_health_checks(&inner.dataset_id, now_ms)
        .map_err(Status::internal)?;
    Ok(Response::new(RunDatasetHealthChecksResponse {
        results: results.iter().map(to_proto_health_result).collect(),
    }))
}

pub(super) async fn list_dataset_alerts(
    service: &SekaiServiceImpl,
    req: Request<ListDatasetAlertsRequest>,
) -> Result<Response<ListDatasetAlertsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let dataset = service
        .db
        .runtime()
        .get_dataset(&inner.dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        false,
    )?;
    let alerts = service
        .db
        .runtime()
        .list_dataset_alerts(&inner.dataset_id)
        .map_err(Status::internal)?;
    Ok(Response::new(ListDatasetAlertsResponse {
        alerts: alerts.iter().map(to_proto_dataset_alert).collect(),
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
fn persist_created_grant(
    service: &SekaiServiceImpl,
    mut parsed: crate::sekai::security::Grant,
    actor: &str,
) -> Result<crate::sekai::security::Grant, Status> {
    let runtime = service.db.runtime();
    let now_ms = crate::sekai::security::unix_now_ms();
    let namespace = runtime
        .get_object(&parsed.object_id)
        .map_err(Status::internal)?
        .map(|object| {
            crate::sekai::security::policy_namespace_for_object(
                &object.kind,
                &object.namespace,
                &object.external_id,
            )
        })
        .filter(|namespace| !namespace.is_empty());
    let policy = match namespace.as_deref() {
        Some(namespace) => runtime
            .namespace_grant_policy(namespace)
            .map_err(Status::internal)?,
        None => None,
    };
    let term = parsed
        .term()
        .prepare(policy.as_ref(), now_ms)
        .map_err(|error| Status::invalid_argument(error.as_str()))?;
    parsed = parsed.with_term(term);
    let renew = runtime
        .list_grants(&parsed.object_id)
        .map_err(Status::internal)?
        .iter()
        .any(|grant| grant.principal == parsed.principal);
    let action = if renew { "grant.renew" } else { "grant.create" };
    let mut evidence = HashMap::new();
    evidence.insert("purpose".into(), parsed.purpose.clone());
    evidence.insert("not_after_ms".into(), parsed.not_after_ms.to_string());
    evidence.insert("exception_reason".into(), parsed.exception_reason.clone());
    evidence.insert("principal".into(), parsed.principal.clone());
    evidence.insert("role".into(), parsed.role.as_str().into());
    evidence.insert("grant_id".into(), parsed.id.clone());
    if let Some(namespace) = namespace {
        evidence.insert("namespace".into(), namespace);
    }
    let receipt_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    runtime
        .create_grant_with_decision(
            &parsed,
            &crate::sekai::audit::Decision {
                id: format!("{action}:{}:{receipt_ns}", parsed.id),
                timestamp: now_ms,
                actor: actor.into(),
                action: action.into(),
                reason: parsed.purpose.clone(),
                evidence,
                target_id: parsed.object_id.clone(),
                outcome: "allowed".into(),
            },
        )
        .map_err(Status::internal)?;
    service.security.add_grant(&parsed);
    Ok(parsed)
}

pub(super) async fn create_grant(
    service: &SekaiServiceImpl,
    req: Request<CreateGrantRequest>,
) -> Result<Response<CreateGrantResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let actor = principals.first().map(String::as_str).unwrap_or_default();
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
        let parsed = persist_created_grant(service, parsed, actor)?;
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
    let parsed = persist_created_grant(service, parsed, actor)?;
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
pub(super) async fn set_write_freeze(
    service: &SekaiServiceImpl,
    req: Request<SetWriteFreezeRequest>,
) -> Result<Response<SetWriteFreezeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let actor = principals.first().map(String::as_str).unwrap_or_default();
    let proto = req
        .into_inner()
        .freeze
        .ok_or_else(|| Status::invalid_argument("freeze required"))?;
    let mut freeze = from_proto_write_freeze(proto);
    if freeze.updated_ms <= 0 {
        freeze.updated_ms = now_millis();
    }
    freeze.validate().map_err(Status::invalid_argument)?;
    let runtime = service.db.runtime();
    let mut evidence = HashMap::new();
    evidence.insert("scope_kind".into(), freeze.scope_kind.clone());
    evidence.insert("scope_value".into(), freeze.scope_value.clone());
    evidence.insert("mode".into(), freeze.mode.clone());
    evidence.insert("enabled".into(), freeze.enabled.to_string());
    runtime
        .set_write_freeze_with_decision(
            &freeze,
            &audit::Decision {
                id: format!(
                    "write_freeze:{}:{}:{}",
                    freeze.scope_kind,
                    freeze.scope_value,
                    uuid::Uuid::new_v4().simple()
                ),
                timestamp: freeze.updated_ms,
                actor: actor.into(),
                action: "write_freeze".into(),
                reason: freeze.reason.clone(),
                evidence,
                target_id: String::new(),
                outcome: if freeze.enabled {
                    "enabled".into()
                } else {
                    "disabled".into()
                },
            },
        )
        .map_err(Status::internal)?;
    Ok(Response::new(SetWriteFreezeResponse {
        freeze: Some(to_proto_write_freeze(&freeze)),
    }))
}
pub(super) async fn list_write_freezes(
    service: &SekaiServiceImpl,
    req: Request<ListWriteFreezesRequest>,
) -> Result<Response<ListWriteFreezesResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let _ = req.into_inner();
    let freezes = service
        .db
        .runtime()
        .list_write_freezes()
        .map_err(Status::internal)?
        .iter()
        .map(to_proto_write_freeze)
        .collect();
    Ok(Response::new(ListWriteFreezesResponse { freezes }))
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
    if service.db.runtime().backend_name() == "postgres" {
        return Err(Status::unavailable(
            "list_visible_object_changes is unavailable on the PostgreSQL community runtime",
        ));
    }
    let inner = req.into_inner();
    check_object_namespace_access(service.db.runtime(), &principals, &inner.object_id, false)?;
    check_read(&service.security, &inner.object_id, &principals)?;
    let object = service
        .db
        .runtime()
        .get_object(&inner.object_id)
        .map_err(Status::internal)?;
    match object.as_ref() {
        // Reserved governance objects, such as comments, carry their own read
        // rules; their raw history is for credential admins only.
        Some(object)
            if is_reserved_governance_kind(&object.kind)
                && require_credential_admin(&principals).is_err() =>
        {
            return Err(Status::not_found("not found"));
        }
        Some(object) => {
            enforce_collaboration_namespace(
                service.db.runtime(),
                tenant_context.as_ref(),
                &object.namespace,
                false,
            )
            .map_err(|_| Status::not_found("not found"))?;
            if !collaboration_object_permitted(
                service.db.runtime(),
                tenant_context.as_ref(),
                object,
                crate::enterprise::NamespaceAction::Read,
            )? {
                return Err(Status::not_found("not found"));
            }
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
            .map_err(map_runtime_store_error)?,
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
    let changes = match visible_collaboration_history_page(
        service.db.runtime(),
        tenant_context.as_ref(),
        object.as_ref(),
        inner.limit,
        inner.offset,
    )? {
        Some(changes) => changes,
        None => service
            .db
            .runtime()
            .list_visible_object_changes(&inner.object_id, inner.limit, inner.offset)
            .map_err(map_runtime_store_error)?,
    }
    .into_iter()
    .map(|change| {
        let mut mapped = if let Some(kind) = object_kind.as_deref() {
            redact_object_change_values(
                change,
                &inner.object_id,
                kind,
                &schema,
                &service.security,
                &principal_policy_context_from(&principals, tenant_context.as_ref()),
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
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let scoped_put = service.db.runtime().enterprise_extension().is_some()
        && tenant_context.as_ref().is_some_and(|context| {
            context.credential_kind == crate::enterprise::CredentialKind::HumanSession
                && context.tenant.is_some()
        });
    if !scoped_put {
        require_credential_admin(&principals)?;
    }
    let proto = req
        .into_inner()
        .transform
        .ok_or_else(|| Status::invalid_argument("transform required"))?;
    let analytical = from_proto_analytical(&proto);
    let isolated_process = from_proto_isolated(&proto);
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
        analytical,
        isolated_process,
        schedule: if proto.schedule_every_ms > 0 {
            Some(crate::sekai::governed_transform::TransformSchedule {
                every_ms: proto.schedule_every_ms,
            })
        } else {
            None
        },
        trigger: if proto.trigger_on_input_commit {
            Some(crate::sekai::governed_transform::TransformTrigger {
                on_input_commit: true,
                debounce_ms: proto.trigger_debounce_ms,
            })
        } else {
            None
        },
    }
    .prepare()
    .map_err(|error| Status::invalid_argument(error.message()))?;
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &transform.namespace,
            true,
        )?;
    }
    if scoped_put {
        check_team_namespace(
            service.db.runtime(),
            &principals,
            &transform.namespace,
            true,
        )?;
        if transform.schedule.is_some() || transform.trigger.is_some() {
            return Err(Status::permission_denied(
                "scoped put cannot schedule or trigger execution",
            ));
        }
        authorize_transform_dataset_reads(
            service,
            &principals,
            tenant_context.as_ref(),
            &transform,
        )?;
    }
    let owner_tenant = tenant_context
        .as_ref()
        .and_then(|context| context.tenant.as_ref())
        .map(|tenant| tenant.tenant_id.as_str())
        .unwrap_or("");
    service
        .db
        .runtime()
        .put_governed_transform_owned(&transform, now_millis(), owner_tenant)
        .map_err(Status::internal)?;
    Ok(Response::new(PutGovernedTransformResponse {
        transform: Some(to_proto_transform(&transform)),
    }))
}

fn preview_response(
    result: crate::sekai::governed_transform::PreviewGovernedTransformResult,
) -> PreviewGovernedTransformResponse {
    PreviewGovernedTransformResponse {
        preview_id: result.preview_id,
        output_schema_json: result.output_schema_json,
        rows: result
            .rows
            .into_iter()
            .map(|values| PreviewGovernedTransformRow { values })
            .collect(),
        inputs: result
            .inputs
            .into_iter()
            .map(|input| PreviewGovernedTransformInputStat {
                alias: input.alias,
                dataset_id: input.dataset_id,
                rows_read: input.rows_read,
            })
            .collect(),
        error: result.error,
    }
}

fn authorize_transform_dataset_reads(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&crate::enterprise::AuthenticatedContext>,
    transform: &crate::sekai::governed_transform::GovernedTransform,
) -> Result<(), Status> {
    let mut dataset_ids: Vec<String> = transform
        .input_bindings()
        .into_iter()
        .map(|(_, dataset_id)| dataset_id)
        .collect();
    if !transform.output_dataset_id.is_empty() {
        dataset_ids.push(transform.output_dataset_id.clone());
    }
    dataset_ids.sort();
    dataset_ids.dedup();
    for dataset_id in dataset_ids {
        authorize_transform_dataset_read(service, principals, tenant_context, &dataset_id)?;
    }
    Ok(())
}

fn authorize_transform_dataset_read(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&crate::enterprise::AuthenticatedContext>,
    dataset_id: &str,
) -> Result<(), Status> {
    let dataset = service
        .db
        .runtime()
        .get_dataset(dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        principals,
        &dataset,
        false,
    )?;
    if !dataset.object_id.is_empty() {
        if let Some(object) = service
            .db
            .runtime()
            .get_object(&dataset.object_id)
            .map_err(Status::internal)?
        {
            if !object_is_visible(
                service.db.runtime(),
                &service.security,
                &object,
                principals,
                tenant_context,
            ) {
                return Err(Status::permission_denied("access denied"));
            }
        }
    }
    Ok(())
}

fn authorize_preview_inputs(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&crate::enterprise::AuthenticatedContext>,
    transform: &crate::sekai::governed_transform::GovernedTransform,
) -> Result<std::collections::HashMap<String, Vec<String>>, Status> {
    let mut column_allowlists = std::collections::HashMap::new();
    for (_, dataset_id) in transform.input_bindings() {
        let dataset = service
            .db
            .runtime()
            .get_dataset(&dataset_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("dataset not found"))?;
        check_dataset_access(
            service.db.runtime(),
            &service.security,
            principals,
            &dataset,
            false,
        )?;
        if !dataset.object_id.is_empty() {
            if let Some(object) = service
                .db
                .runtime()
                .get_object(&dataset.object_id)
                .map_err(Status::internal)?
            {
                if !object_is_visible(
                    service.db.runtime(),
                    &service.security,
                    &object,
                    principals,
                    tenant_context,
                ) {
                    return Err(Status::permission_denied("access denied"));
                }
            }
        }
        if let Some(allowed) = preview_column_allowlist(service, &dataset)? {
            column_allowlists.insert(dataset_id, allowed);
        }
    }
    Ok(column_allowlists)
}

fn retrieve_preview_governed_transform(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&crate::enterprise::AuthenticatedContext>,
    preview_id: &str,
) -> Result<Response<PreviewGovernedTransformResponse>, Status> {
    if !crate::sekai::governed_transform::is_preview_id(preview_id) {
        return Err(Status::invalid_argument(
            "preview_id is not a preview identity",
        ));
    }
    let transform = service
        .db
        .runtime()
        .admitted_isolated_transform(preview_id)
        .map_err(transform_work_status)?
        .ok_or_else(|| Status::not_found("preview not found"))?;
    if let Some(context) = tenant_context {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &transform.namespace,
            false,
        )?;
    }
    check_team_namespace(
        service.db.runtime(),
        principals,
        &transform.namespace,
        false,
    )?;
    let column_allowlists =
        authorize_preview_inputs(service, principals, tenant_context, &transform)?;
    let admitted = service
        .db
        .runtime()
        .get_preview_column_allowlists(preview_id)
        .map_err(Status::internal)?;
    if !crate::sekai::governed_transform::current_preview_auth_covers_admitted(
        &admitted,
        &column_allowlists,
    ) {
        return Err(Status::permission_denied("access denied"));
    }
    let result = service
        .db
        .runtime()
        .get_preview_governed_transform(preview_id)
        .map_err(Status::internal)?
        .unwrap_or(
            crate::sekai::governed_transform::PreviewGovernedTransformResult {
                preview_id: preview_id.to_string(),
                ..Default::default()
            },
        );
    Ok(Response::new(preview_response(result)))
}

pub(super) async fn preview_governed_transform(
    service: &SekaiServiceImpl,
    req: Request<PreviewGovernedTransformRequest>,
) -> Result<Response<PreviewGovernedTransformResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    if !input.preview_id.is_empty() {
        return retrieve_preview_governed_transform(
            service,
            &principals,
            tenant_context.as_ref(),
            &input.preview_id,
        );
    }
    let proto = input
        .transform
        .ok_or_else(|| Status::invalid_argument("transform required"))?;
    let analytical = from_proto_analytical(&proto);
    let isolated_process = from_proto_isolated(&proto);
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
        analytical,
        isolated_process,
        schedule: None,
        trigger: None,
    }
    .prepare()
    .map_err(|error| Status::invalid_argument(error.message()))?;
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &transform.namespace,
            false,
        )?;
    }
    check_team_namespace(
        service.db.runtime(),
        &principals,
        &transform.namespace,
        false,
    )?;
    let row_cap = crate::sekai::governed_transform::resolve_preview_row_cap(input.row_cap)
        .map_err(preview_transform_status)?;
    let column_allowlists =
        authorize_preview_inputs(service, &principals, tenant_context.as_ref(), &transform)?;
    let owner_tenant = tenant_context
        .as_ref()
        .and_then(|context| context.tenant.as_ref())
        .map(|tenant| tenant.tenant_id.as_str())
        .unwrap_or("");
    // Isolated previews admit claimable work and return preview_id immediately.
    // After write-back, the same RPC with that preview_id returns stored rows.
    // GetGovernedTransformRun stays unavailable for preview identities.
    let result = service
        .db
        .runtime()
        .preview_governed_transform(
            &transform,
            row_cap,
            now_millis(),
            owner_tenant,
            &column_allowlists,
        )
        .map_err(preview_transform_status)?;
    Ok(Response::new(preview_response(result)))
}
pub(super) async fn run_governed_transform(
    service: &SekaiServiceImpl,
    req: Request<RunGovernedTransformRequest>,
) -> Result<Response<RunGovernedTransformResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let input = req.into_inner();
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &input.namespace,
            true,
        )?;
    }
    let transform = service
        .db
        .runtime()
        .get_governed_transform(&input.namespace, &input.transform_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("governed transform not found"))?;
    let isolated = transform.isolated_process.is_some();
    let stored_owner = service
        .db
        .runtime()
        .transform_quota_owner(&input.namespace, &input.transform_id)
        .map_err(Status::internal)?;
    let caller_has_tenant = tenant_context
        .as_ref()
        .and_then(|context| context.tenant.as_ref())
        .is_some();
    // Put owner is the tenantless runner/admin fallback. An authenticated
    // caller tenant pays for this Run and cannot spend the Put owner's quota.
    let owner_ctx = if caller_has_tenant {
        tenant_context.clone()
    } else if let Some(tenant_id) = stored_owner.as_deref() {
        Some(crate::provider_credentials::tenant_context(
            tenant_id, "local",
        ))
    } else {
        tenant_context.clone()
    };
    let quota = service.quota_runtime();
    let gate = crate::composition::transform_run_admission::quota_gate(quota.clone());
    let held = if isolated {
        None
    } else {
        admit_tenant_transform(
            quota.as_ref(),
            &gate,
            owner_ctx.as_ref(),
            &format!(
                "transform-run:{}:{}:{}",
                input.namespace,
                input.transform_id,
                now_millis()
            ),
            false,
        )?
    };
    let owner_tenant = owner_ctx
        .as_ref()
        .and_then(|context| context.tenant.as_ref())
        .map(|tenant| tenant.tenant_id.as_str())
        .unwrap_or("");
    let run = match service.db.runtime().run_governed_transform_owned(
        &input.namespace,
        &input.transform_id,
        input.incremental,
        now_millis(),
        owner_tenant,
        &transform.definition_digest,
    ) {
        Ok(run) => run,
        Err(error) => {
            abandon_tenant_transform(service.db.runtime(), &gate, held.as_ref())?;
            return Err(transform_work_status(error));
        }
    };
    if !isolated {
        let recorded = record_tenant_transform_usage(
            quota.as_ref(),
            owner_ctx
                .as_ref()
                .and_then(|context| context.tenant.as_ref())
                .map(|tenant| tenant.tenant_id.as_str()),
            &run,
            &actor,
            now_millis(),
        );
        release_tenant_transform(service.db.runtime(), &gate, &run.run_id, held.as_ref())?;
        if recorded? {
            ack_transform_usage_pending(service.db.runtime(), &run.run_id)?;
        }
    }
    Ok(Response::new(RunGovernedTransformResponse {
        run: Some(to_proto_transform_run(
            &run,
            caller_can_read_run_datasets(service, &principals, &run),
        )),
    }))
}
pub(super) async fn get_governed_transform_run(
    service: &SekaiServiceImpl,
    req: Request<GetGovernedTransformRunRequest>,
) -> Result<Response<GetGovernedTransformRunResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let run = service
        .db
        .runtime()
        .get_governed_transform_run(&req.into_inner().run_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("not found"))?;
    // Another tenant's run reads as missing, not as denied.
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &run.namespace,
            false,
        )
        .map_err(|_| Status::not_found("not found"))?;
    }
    check_team_namespace(service.db.runtime(), &principals, &run.namespace, false)?;
    let reveal = caller_can_read_run_datasets(service, &principals, &run);
    Ok(Response::new(GetGovernedTransformRunResponse {
        run: Some(to_proto_transform_run(&run, reveal)),
    }))
}
pub(super) async fn list_governed_transforms(
    service: &SekaiServiceImpl,
    req: Request<ListGovernedTransformsRequest>,
) -> Result<Response<ListGovernedTransformsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let namespace = req.into_inner().namespace;
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(service.db.runtime(), Some(context), &namespace, false)?;
    }
    check_team_namespace(service.db.runtime(), &principals, &namespace, false)?;
    let transforms = service
        .db
        .runtime()
        .list_governed_transforms(&namespace)
        .map_err(Status::internal)?
        .iter()
        .map(to_proto_transform)
        .collect();
    Ok(Response::new(ListGovernedTransformsResponse { transforms }))
}
pub(super) async fn list_governed_transform_runs(
    service: &SekaiServiceImpl,
    req: Request<ListGovernedTransformRunsRequest>,
) -> Result<Response<ListGovernedTransformRunsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &input.namespace,
            false,
        )?;
    }
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, false)?;
    let limit = if input.limit <= 0 {
        50
    } else {
        i64::from(input.limit.min(MAX_LIST_LIMIT))
    };
    let runs = service
        .db
        .runtime()
        .list_governed_transform_runs(&input.namespace, limit)
        .map_err(Status::internal)?
        .iter()
        .map(|run| {
            let reveal = caller_can_read_run_datasets(service, &principals, run);
            to_proto_transform_run(run, reveal)
        })
        .collect();
    Ok(Response::new(ListGovernedTransformRunsResponse { runs }))
}
pub(super) async fn list_claimable_transform_work(
    service: &SekaiServiceImpl,
    req: Request<ListClaimableTransformWorkRequest>,
) -> Result<Response<ListClaimableTransformWorkResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let input = req.into_inner();
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
    let limit = if input.limit <= 0 {
        50
    } else {
        i64::from(input.limit.min(MAX_LIST_LIMIT))
    };
    let work = service
        .db
        .runtime()
        .list_claimable_transform_work(&input.namespace, now_millis(), limit)
        .map_err(Status::internal)?
        .iter()
        .map(to_proto_transform_work)
        .collect();
    Ok(Response::new(ListClaimableTransformWorkResponse { work }))
}
pub(super) async fn claim_transform_work(
    service: &SekaiServiceImpl,
    req: Request<ClaimTransformWorkRequest>,
) -> Result<Response<ClaimTransformWorkResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &input.namespace,
            true,
        )?;
    }
    let targeted = !input.run_id.trim().is_empty();
    let mut skipped = Vec::new();
    let mut exhausted = false;
    loop {
        let outcome = match service.db.runtime().claim_transform_work_outcome(
            &input.namespace,
            &input.runtime_id,
            &input.run_id,
            input.ttl_ms,
            now_millis(),
            &skipped,
        ) {
            Ok(outcome) => outcome,
            Err(error) => return Err(transform_work_status(error)),
        };
        let quota = service.quota_runtime();
        release_failed_transform_quota(
            service.db.runtime(),
            quota.clone(),
            &outcome.failed_run_ids,
        )?;
        match outcome.claimed {
            Some((mut work, transform)) => {
                // TenantQuotaGate and transform-work live on separate stores.
                // Folding the gate into the claim transaction is out of this slice.
                let owner = if work.tenant_id.trim().is_empty() {
                    tenant_context.clone()
                } else {
                    Some(crate::provider_credentials::tenant_context(
                        &work.tenant_id,
                        "local",
                    ))
                };
                let prior_admission = if work.claim_generation > 1 {
                    match service.db.runtime().reclaim_transform_quota_hold(
                        &work.run_id,
                        work.claim_generation,
                        &work.fencing_token,
                    ) {
                        Ok(Some((tenant_id, reserved_concurrency, held_generation))) => {
                            if reserved_concurrency {
                                if let Err(status) = complete_reserved_transform_quota(
                                    quota.clone(),
                                    &work.run_id,
                                    &tenant_id,
                                ) {
                                    let _ = service.db.runtime().restore_transform_quota_hold(
                                        &work.run_id,
                                        &tenant_id,
                                        true,
                                        held_generation,
                                    );
                                    return Err(status);
                                }
                            }
                            true
                        }
                        Ok(None) => service
                            .db
                            .runtime()
                            .peek_transform_quota_hold(&work.run_id, work.claim_generation)
                            .map_err(Status::internal)?
                            .is_some(),
                        Err(error) => return Err(Status::internal(error)),
                    }
                } else {
                    false
                };
                match admit_claimed_isolated_process(
                    service,
                    quota.as_ref(),
                    owner.as_ref(),
                    &work,
                    prior_admission,
                ) {
                    Ok(held) => {
                        let gate =
                            crate::composition::transform_run_admission::quota_gate(quota.clone());
                        let bind_tenant = held
                            .as_ref()
                            .map(|admission| admission.tenant_id.as_str())
                            .or_else(|| {
                                owner
                                    .as_ref()
                                    .and_then(|context| context.tenant.as_ref())
                                    .map(|tenant| tenant.tenant_id.as_str())
                            });
                        if work.tenant_id.trim().is_empty()
                            && let Some(tenant_id) = bind_tenant
                        {
                            match service.db.runtime().bind_transform_work_tenant(
                                &work.run_id,
                                tenant_id,
                                work.claim_generation,
                                &work.fencing_token,
                            ) {
                                Ok(Some(persisted)) => work.tenant_id = persisted,
                                Ok(None) => {
                                    if let Some(admission) = held.as_ref() {
                                        if prior_admission {
                                            let _ = crate::composition::transform_run_admission::complete_transform_run(
                                            &gate, admission,
                                        );
                                            restore_request_admission_hold(
                                                service.db.runtime(),
                                                &work,
                                                owner.as_ref(),
                                            )?;
                                        } else {
                                            abandon_or_persist_quota_hold(
                                                service.db.runtime(),
                                                &gate,
                                                admission,
                                            )?;
                                        }
                                    }
                                    service
                                        .db
                                        .runtime()
                                        .release_transform_claim(
                                            &work.run_id,
                                            &work.claim_owner,
                                            work.claim_generation,
                                            &work.fencing_token,
                                            now_millis(),
                                            outcome.counted_lease_expiry,
                                        )
                                        .map_err(transform_work_status)?;
                                    return Err(Status::failed_precondition(
                                        crate::sekai::governed_transform::STALE_TRANSFORM_CLAIM,
                                    ));
                                }
                                Err(error) => {
                                    if let Some(admission) = held.as_ref() {
                                        if prior_admission {
                                            let _ = crate::composition::transform_run_admission::complete_transform_run(
                                            &gate, admission,
                                        );
                                            restore_request_admission_hold(
                                                service.db.runtime(),
                                                &work,
                                                owner.as_ref(),
                                            )?;
                                        } else {
                                            abandon_or_persist_quota_hold(
                                                service.db.runtime(),
                                                &gate,
                                                admission,
                                            )?;
                                        }
                                    }
                                    service
                                        .db
                                        .runtime()
                                        .release_transform_claim(
                                            &work.run_id,
                                            &work.claim_owner,
                                            work.claim_generation,
                                            &work.fencing_token,
                                            now_millis(),
                                            outcome.counted_lease_expiry,
                                        )
                                        .map_err(transform_work_status)?;
                                    return Err(Status::internal(error));
                                }
                            }
                        }
                        if let Some(admission) = held {
                            match service.db.runtime().put_transform_quota_hold(
                                &work.run_id,
                                &admission.tenant_id,
                                admission.reserved_concurrency,
                                work.claim_generation,
                                &work.fencing_token,
                            ) {
                                Ok(true) => {}
                                Ok(false) => {
                                    if prior_admission {
                                        crate::composition::transform_run_admission::complete_transform_run(
                                        &gate, &admission,
                                    )
                                    .map_err(map_quota_error)?;
                                        restore_request_admission_hold(
                                            service.db.runtime(),
                                            &work,
                                            owner.as_ref(),
                                        )?;
                                    } else {
                                        abandon_or_persist_quota_hold(
                                            service.db.runtime(),
                                            &gate,
                                            &admission,
                                        )?;
                                    }
                                    service
                                        .db
                                        .runtime()
                                        .release_transform_claim(
                                            &work.run_id,
                                            &work.claim_owner,
                                            work.claim_generation,
                                            &work.fencing_token,
                                            now_millis(),
                                            outcome.counted_lease_expiry,
                                        )
                                        .map_err(transform_work_status)?;
                                    return Err(Status::failed_precondition(
                                        crate::sekai::governed_transform::STALE_TRANSFORM_CLAIM,
                                    ));
                                }
                                Err(error) => {
                                    if prior_admission {
                                        let _ = crate::composition::transform_run_admission::complete_transform_run(
                                        &gate,
                                        &admission,
                                    );
                                        restore_request_admission_hold(
                                            service.db.runtime(),
                                            &work,
                                            owner.as_ref(),
                                        )?;
                                    } else {
                                        abandon_or_persist_quota_hold(
                                            service.db.runtime(),
                                            &gate,
                                            &admission,
                                        )?;
                                    }
                                    service
                                        .db
                                        .runtime()
                                        .release_transform_claim(
                                            &work.run_id,
                                            &work.claim_owner,
                                            work.claim_generation,
                                            &work.fencing_token,
                                            now_millis(),
                                            outcome.counted_lease_expiry,
                                        )
                                        .map_err(transform_work_status)?;
                                    return Err(Status::internal(error));
                                }
                            }
                        }
                    }
                    Err(status) => {
                        if prior_admission {
                            restore_request_admission_hold(
                                service.db.runtime(),
                                &work,
                                owner.as_ref(),
                            )?;
                        }
                        service
                            .db
                            .runtime()
                            .release_transform_claim(
                                &work.run_id,
                                &work.claim_owner,
                                work.claim_generation,
                                &work.fencing_token,
                                now_millis(),
                                outcome.counted_lease_expiry,
                            )
                            .map_err(transform_work_status)?;
                        if status.code() == tonic::Code::ResourceExhausted
                            && !targeted
                            && skipped.len()
                                < crate::sekai::governed_transform::MAX_TRANSFORM_CLAIM_QUOTA_SKIPS
                        {
                            skipped.push(work.run_id.clone());
                            exhausted = true;
                            service
                                .db
                                .runtime()
                                .defer_transform_work(&work.run_id, now_millis())
                                .map_err(Status::internal)?;
                            continue;
                        }
                        return Err(status);
                    }
                }
                return Ok(Response::new(ClaimTransformWorkResponse {
                    work: Some(to_proto_transform_work(&work)),
                    transform: Some(to_proto_transform(&transform)),
                }));
            }
            None => {
                if exhausted {
                    return Err(Status::resource_exhausted("tenant quota exceeded"));
                }
                return Err(Status::not_found("no claimable transform work"));
            }
        }
    }
}
pub(super) async fn heartbeat_transform_claim(
    service: &SekaiServiceImpl,
    req: Request<HeartbeatTransformClaimRequest>,
) -> Result<Response<HeartbeatTransformClaimResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let input = req.into_inner();
    let run = load_transform_run_or_preview(service, &input.run_id)?;
    check_team_namespace(service.db.runtime(), &principals, &run.namespace, true)?;
    let work = service
        .db
        .runtime()
        .heartbeat_transform_work(
            &input.run_id,
            &input.runtime_id,
            input.claim_generation,
            &input.fencing_token,
            input.ttl_ms,
            now_millis(),
        )
        .map_err(transform_work_status)?;
    Ok(Response::new(HeartbeatTransformClaimResponse {
        work: Some(to_proto_transform_work(&work)),
    }))
}
pub(super) async fn read_transform_run_inputs(
    service: &SekaiServiceImpl,
    req: Request<ReadTransformRunInputsRequest>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<
                dyn futures_util::Stream<Item = Result<ReadTransformRunInputsResponse, Status>>
                    + Send,
            >,
        >,
    >,
    Status,
> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let input = req.into_inner();
    let run = load_transform_run_or_preview(service, &input.run_id)?;
    check_team_namespace(service.db.runtime(), &principals, &run.namespace, true)?;
    check_isolated_transform_datasets(service, &principals, &run, false)?;
    let command = crate::sekai::governed_transform::WriteTransformRunCommand {
        run_id: input.run_id,
        runtime_id: input.runtime_id,
        claim_generation: input.claim_generation,
        fencing_token: input.fencing_token,
        partition_key: input.partition_key,
        max_bytes: input.max_bytes,
        ..crate::sekai::governed_transform::WriteTransformRunCommand::default()
    };
    let rows = service
        .db
        .runtime()
        .read_transform_run_input(
            &command,
            &input.alias,
            &input.after_alias,
            input.after_row_id,
            i64::from(input.limit),
            now_millis(),
        )
        .map_err(transform_work_status)?;
    let stream = futures_util::stream::iter(rows.into_iter().map(|row| {
        Ok(ReadTransformRunInputsResponse {
            row: Some(TransformRunInputRow {
                alias: row.alias,
                dataset_id: row.dataset_id,
                row_id: row.row_id,
                values: row.values,
                partition_key: row.partition_key,
            }),
        })
    }));
    Ok(Response::new(Box::pin(stream)))
}
pub(super) async fn write_transform_run_result(
    service: &SekaiServiceImpl,
    req: Request<WriteTransformRunResultRequest>,
) -> Result<Response<WriteTransformRunResultResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let input = req.into_inner();
    let preview = crate::sekai::governed_transform::is_preview_id(&input.run_id);
    let run = load_transform_run_or_preview(service, &input.run_id)?;
    check_team_namespace(service.db.runtime(), &principals, &run.namespace, true)?;
    check_isolated_transform_datasets(service, &principals, &run, !preview)?;
    let command = crate::sekai::governed_transform::WriteTransformRunCommand {
        run_id: input.run_id,
        runtime_id: input.runtime_id,
        claim_generation: input.claim_generation,
        fencing_token: input.fencing_token,
        rows: input.rows.into_iter().map(|row| row.values).collect(),
        output_digest: input.output_digest,
        quarantined: input.quarantined,
        quality_rule: input.quality_rule,
        replaced_partitions: input
            .partitions
            .into_iter()
            .map(
                |partition| crate::sekai::governed_transform::TransformPartitionWrite {
                    partition_key: partition.partition_key,
                    rows: partition.rows.into_iter().map(|row| row.values).collect(),
                },
            )
            .collect(),
        ..crate::sekai::governed_transform::WriteTransformRunCommand::default()
    };
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &run.namespace,
            true,
        )?;
    }
    let claim_generation = command.claim_generation;
    let owner_tenant = service
        .db
        .runtime()
        .transform_work_tenant(&command.run_id)
        .map_err(Status::internal)?;
    let run = service
        .db
        .runtime()
        .write_transform_run(command, now_millis())
        .map_err(transform_work_status)?;
    if preview {
        let hold = service
            .db
            .runtime()
            .take_transform_quota_hold(&run.run_id, Some(claim_generation), false)
            .map_err(Status::internal)?;
        let quota = service.quota_runtime();
        if let Some((tenant_id, true, held_generation)) = hold.as_ref() {
            if let Err(status) = complete_reserved_transform_quota(quota, &run.run_id, tenant_id) {
                let _ = service.db.runtime().restore_transform_quota_hold(
                    &run.run_id,
                    tenant_id,
                    true,
                    *held_generation,
                );
                return Err(status);
            }
        }
        return Ok(Response::new(WriteTransformRunResultResponse {
            run: Some(to_proto_transform_run(&run, true)),
        }));
    }
    // Hold consume and TenantQuotaGate.complete stay on separate stores.
    // Folding them into the write transaction is out of this slice. A crash
    // between take and complete leaves reserved concurrency until the budget
    // period rolls; that window is accepted here. A complete error after
    // take restores the hold so a retry can release concurrency.
    let hold = service
        .db
        .runtime()
        .take_transform_quota_hold(&run.run_id, Some(claim_generation), false)
        .map_err(Status::internal)?;
    let caller_tenant = tenant_context
        .as_ref()
        .and_then(|context| context.tenant.as_ref())
        .map(|tenant| tenant.tenant_id.clone());
    let usage_tenant = hold
        .as_ref()
        .map(|(tenant_id, _, _)| tenant_id.as_str())
        .or(owner_tenant.as_deref())
        .or(caller_tenant.as_deref());
    let quota = service.quota_runtime();
    let completed_at_ms = service
        .db
        .runtime()
        .transform_usage_pending(&run.run_id)
        .map_err(Status::internal)?
        .map(|(_, completed_at_ms)| completed_at_ms)
        .unwrap_or_else(now_millis);
    let usage =
        record_tenant_transform_usage(quota.as_ref(), usage_tenant, &run, &actor, completed_at_ms);
    if let Some((tenant_id, true, held_generation)) = hold.as_ref() {
        if let Err(status) = complete_reserved_transform_quota(quota, &run.run_id, tenant_id) {
            let _ = service.db.runtime().restore_transform_quota_hold(
                &run.run_id,
                tenant_id,
                true,
                *held_generation,
            );
            return Err(status);
        }
    }
    if usage? {
        ack_transform_usage_pending(service.db.runtime(), &run.run_id)?;
    }
    Ok(Response::new(WriteTransformRunResultResponse {
        run: Some(to_proto_transform_run(
            &run,
            caller_can_read_run_datasets(service, &principals, &run),
        )),
    }))
}

pub(super) async fn apply_streaming_transform_batch(
    service: &SekaiServiceImpl,
    req: Request<ApplyStreamingTransformBatchRequest>,
) -> Result<Response<ApplyStreamingTransformBatchResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let input = req.into_inner();
    let run = load_transform_run_or_preview(service, &input.run_id)?;
    check_team_namespace(service.db.runtime(), &principals, &run.namespace, true)?;
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &run.namespace,
            true,
        )?;
    }
    for edit in &input.edits {
        let object_id = edit.object_id.trim();
        if object_id.is_empty() {
            continue;
        }
        let exists = service
            .db
            .runtime()
            .get_object(object_id)
            .map_err(Status::internal)?
            .is_some();
        check_object_acl_with_audit(
            service.db.runtime(),
            &service.security,
            object_id,
            &principals,
            tenant_context.as_ref(),
            if exists {
                crate::sekai::object_security::ObjectSecurityOperation::Update
            } else {
                crate::sekai::object_security::ObjectSecurityOperation::Create
            },
        )?;
    }
    let request = crate::sekai::streaming_transform_apply::StreamingTransformApplyRequest {
        run_id: input.run_id,
        runtime_id: input.runtime_id,
        claim_generation: input.claim_generation,
        fencing_token: input.fencing_token,
        checkpoint: input.checkpoint,
        action_type_id: input.action_type_id,
        action_type_version: input.action_type_version,
        edits: input
            .edits
            .into_iter()
            .map(
                |edit| crate::sekai::streaming_transform_apply::StreamingObjectEdit {
                    object_id: edit.object_id,
                    name: edit.name,
                    properties: edit.properties,
                },
            )
            .collect(),
        input_positions: input
            .input_positions
            .into_iter()
            .map(
                |position| crate::sekai::streaming_transform_apply::StreamingInputPosition {
                    source: position.source,
                    position: position.position,
                },
            )
            .collect(),
    };
    let resource_tenant = shared_space_resource_tenant(
        service.db.runtime(),
        tenant_context.as_ref(),
        &run.namespace,
        crate::enterprise::NamespaceAction::Write,
    )
    .unwrap_or_default();
    let policy_context = principal_policy_context_from(&principals, tenant_context.as_ref());
    let receipt = crate::sekai::streaming_transform_apply::apply(
        service.db.runtime(),
        request,
        now_millis(),
        crate::sekai::streaming_transform_apply::StreamingApplyAuth {
            actor: &actor,
            tenant: acting_tenant(tenant_context.as_ref()),
            resource_tenant: &resource_tenant,
            delegating_actor: tenant_context
                .as_ref()
                .and_then(|context| context.act.as_deref()),
            machine_credential: freeze_machine_credential(tenant_context.as_ref()),
            policy_context: Some(&policy_context),
        },
        |existing, object, create| {
            if let Some(existing) = existing {
                enforce_object_operation_access(
                    service.db.runtime(),
                    existing,
                    &principals,
                    tenant_context.as_ref(),
                    crate::sekai::object_security::ObjectSecurityOperation::Update,
                    &format!("apply_streaming_transform_batch_existing:{}", existing.id),
                    None,
                )
                .map(|_| ())
                .map_err(streaming_object_access_status)?;
            }
            enforce_object_operation_access(
                service.db.runtime(),
                object,
                &principals,
                tenant_context.as_ref(),
                if create {
                    crate::sekai::object_security::ObjectSecurityOperation::Create
                } else {
                    crate::sekai::object_security::ObjectSecurityOperation::Update
                },
                &format!("apply_streaming_transform_batch:{}", object.id),
                None,
            )
            .map(|_| ())
            .map_err(streaming_object_access_status)?;
            enforce_marking_declassify(
                service.db.runtime(),
                existing,
                object,
                &principals,
                tenant_context.as_ref(),
            )
            .map_err(streaming_object_access_status)
        },
    )
    .map_err(streaming_apply_status)?;
    Ok(Response::new(ApplyStreamingTransformBatchResponse {
        receipt: Some(to_proto_streaming_apply_receipt(receipt)),
    }))
}

fn to_proto_streaming_apply_receipt(
    receipt: crate::sekai::streaming_transform_apply::StreamingTransformApplyReceipt,
) -> StreamingTransformApplyReceipt {
    StreamingTransformApplyReceipt {
        run_id: receipt.run_id,
        claim_generation: receipt.claim_generation,
        checkpoint: receipt.checkpoint,
        input_positions: receipt
            .input_positions
            .into_iter()
            .map(|position| StreamingTransformInputPosition {
                source: position.source,
                position: position.position,
            })
            .collect(),
        objects: receipt
            .objects
            .into_iter()
            .map(|object| StreamingTransformObjectVersion {
                object_id: object.object_id,
                version: object.version,
            })
            .collect(),
        transform_version: receipt.transform_version,
        action_type_id: receipt.action_type_id,
        action_type_version: receipt.action_type_version,
        replay: receipt.replay,
    }
}

fn streaming_apply_status(
    error: crate::sekai::streaming_transform_apply::StreamingApplyError,
) -> Status {
    use crate::sekai::streaming_transform_apply::StreamingApplyError;
    match error {
        StreamingApplyError::InvalidArgument(message) => Status::invalid_argument(message),
        StreamingApplyError::FailedPrecondition(message) => Status::failed_precondition(message),
        StreamingApplyError::NotFound(message) => Status::not_found(message),
        StreamingApplyError::PermissionDenied(message) => Status::permission_denied(message),
        StreamingApplyError::Internal(message) => Status::internal(message),
    }
}

fn streaming_object_access_status(
    status: Status,
) -> crate::sekai::streaming_transform_apply::StreamingApplyError {
    use crate::sekai::streaming_transform_apply::StreamingApplyError;
    match status.code() {
        tonic::Code::PermissionDenied => {
            StreamingApplyError::PermissionDenied(status.message().into())
        }
        tonic::Code::FailedPrecondition => {
            StreamingApplyError::FailedPrecondition(status.message().into())
        }
        tonic::Code::InvalidArgument => {
            StreamingApplyError::InvalidArgument(status.message().into())
        }
        tonic::Code::NotFound => StreamingApplyError::NotFound(status.message().into()),
        _ => StreamingApplyError::Internal(status.message().into()),
    }
}

// Authorize the admitted JobSpec dataset bindings. Snapshot rows stay claim-fenced
// to this run; dataset-id reuse under a live claim is outside this check.
fn check_isolated_transform_datasets(
    service: &SekaiServiceImpl,
    principals: &[String],
    run: &crate::sekai::governed_transform::TransformRun,
    write_output: bool,
) -> Result<(), Status> {
    let transform = service
        .db
        .runtime()
        .admitted_isolated_transform(&run.run_id)
        .map_err(transform_work_status)?
        .ok_or_else(|| Status::not_found("admitted transform not found"))?;
    let dataset_ids: Vec<String> = if write_output {
        vec![transform.output_dataset_id]
    } else {
        transform
            .input_bindings()
            .into_iter()
            .map(|(_, dataset_id)| dataset_id)
            .collect()
    };
    for dataset_id in dataset_ids {
        let dataset = service
            .db
            .runtime()
            .get_dataset(&dataset_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("dataset not found"))?;
        check_dataset_access(
            service.db.runtime(),
            &service.security,
            principals,
            &dataset,
            write_output,
        )?;
    }
    Ok(())
}

fn map_quota_error(error: crate::chisei::tenant_quota::TenantQuotaError) -> Status {
    use crate::chisei::tenant_quota::TenantQuotaError;
    match error {
        TenantQuotaError::TenantRequired => Status::unauthenticated(error.to_string()),
        TenantQuotaError::StaleAssignment { .. } => Status::failed_precondition(error.to_string()),
        TenantQuotaError::Exhausted { .. } => Status::resource_exhausted(error.to_string()),
        TenantQuotaError::Storage(message) => Status::internal(message),
    }
}

/// Wall-clock seconds reserved when the isolated-process spec carries no
/// time limit. Matches the runner's default wall clock.
const DEFAULT_ISOLATED_PROCESS_ESTIMATE_SECONDS: i64 = 30;

fn admit_claimed_isolated_process(
    service: &SekaiServiceImpl,
    quota: &crate::db::runtime_db::RuntimeDb,
    owner: Option<&crate::enterprise::AuthenticatedContext>,
    work: &crate::sekai::governed_transform::TransformWork,
    reclaim: bool,
) -> Result<Option<crate::chisei::tenant_quota::TenantQuotaAdmission>, Status> {
    admit_extension_isolated_process(service, owner, work)?;
    admit_tenant_transform(
        quota,
        &crate::composition::transform_run_admission::quota_gate(service.quota_runtime()),
        owner,
        &format!("transform-claim:{}", work.run_id),
        reclaim,
    )
}

fn admit_extension_isolated_process(
    service: &SekaiServiceImpl,
    owner: Option<&crate::enterprise::AuthenticatedContext>,
    work: &crate::sekai::governed_transform::TransformWork,
) -> Result<(), Status> {
    let Some(extension) = service.db.runtime().enterprise_extension() else {
        return Ok(());
    };
    let Some(context) = owner else {
        return Ok(());
    };
    match extension.admit_isolated_process_job(
        context,
        &crate::enterprise::IsolatedProcessJob {
            run_id: work.run_id.clone(),
            namespace: work.namespace.clone(),
            estimated_seconds: DEFAULT_ISOLATED_PROCESS_ESTIMATE_SECONDS,
        },
    ) {
        Ok(()) => Ok(()),
        Err(crate::enterprise::ExtensionError::PermissionDenied) => {
            Err(Status::resource_exhausted("tenant quota exceeded"))
        }
        Err(crate::enterprise::ExtensionError::Unavailable(message)) => {
            Err(Status::unavailable(message))
        }
        Err(_) => Err(Status::permission_denied(
            "isolated-process job not admitted",
        )),
    }
}

fn admit_tenant_transform(
    db: &crate::db::runtime_db::RuntimeDb,
    gate: &crate::chisei::tenant_quota::TenantQuotaGate,
    tenant_context: Option<&crate::enterprise::AuthenticatedContext>,
    run_key: &str,
    reclaim: bool,
) -> Result<Option<crate::chisei::tenant_quota::TenantQuotaAdmission>, Status> {
    let Some(context) = tenant_context else {
        return Ok(None);
    };
    let Some(tenant_id) = context
        .tenant
        .as_ref()
        .map(|tenant| tenant.tenant_id.as_str())
    else {
        return Ok(None);
    };
    let Some(limits) =
        crate::composition::transform_run_admission::configured_limits(db, tenant_id)
            .map_err(Status::internal)?
    else {
        return Ok(None);
    };
    crate::composition::transform_run_admission::admit_transform_run(
        gate, context, &limits, run_key, reclaim,
    )
    .map(Some)
    .map_err(map_quota_error)
}

fn release_tenant_transform(
    db: &crate::db::runtime_db::RuntimeDb,
    gate: &crate::chisei::tenant_quota::TenantQuotaGate,
    run_id: &str,
    held: Option<&crate::chisei::tenant_quota::TenantQuotaAdmission>,
) -> Result<(), Status> {
    let Some(admission) = held else {
        return Ok(());
    };
    match crate::composition::transform_run_admission::complete_transform_run(gate, admission) {
        Ok(()) => Ok(()),
        Err(_) if admission.reserved_concurrency => {
            db.restore_transform_quota_hold(run_id, &admission.tenant_id, true, 0)
                .map_err(Status::internal)?;
            Ok(())
        }
        Err(error) => Err(map_quota_error(error)),
    }
}

fn abandon_or_persist_quota_hold(
    db: &crate::db::runtime_db::RuntimeDb,
    gate: &crate::chisei::tenant_quota::TenantQuotaGate,
    admission: &crate::chisei::tenant_quota::TenantQuotaAdmission,
) -> Result<(), Status> {
    match gate.abandon(admission) {
        Ok(()) => Ok(()),
        Err(failed)
            if failed.remaining.reserved_concurrency
                || failed.remaining.reserved_request
                || failed.remaining.reserved_tokens > 0 =>
        {
            db.restore_abandoned_quota_hold(
                &failed.remaining.idempotency_key,
                &failed.remaining.tenant_id,
                failed.remaining.reserved_concurrency,
                failed.remaining.reserved_request,
                failed.remaining.reserved_tokens,
            )
            .map_err(Status::internal)?;
            Ok(())
        }
        Err(failed) => Err(map_quota_error(failed.error)),
    }
}

fn abandon_tenant_transform(
    db: &crate::db::runtime_db::RuntimeDb,
    gate: &crate::chisei::tenant_quota::TenantQuotaGate,
    held: Option<&crate::chisei::tenant_quota::TenantQuotaAdmission>,
) -> Result<(), Status> {
    let Some(admission) = held else {
        return Ok(());
    };
    abandon_or_persist_quota_hold(db, gate, admission)
}

fn release_failed_transform_quota(
    db: &crate::db::runtime_db::RuntimeDb,
    runtime: std::sync::Arc<crate::db::runtime_db::RuntimeDb>,
    failed_run_ids: &[String],
) -> Result<(), Status> {
    for run_id in failed_run_ids {
        release_claimed_transform_quota(db, runtime.clone(), run_id, None, false)?;
    }
    Ok(())
}

fn release_claimed_transform_quota(
    db: &crate::db::runtime_db::RuntimeDb,
    runtime: std::sync::Arc<crate::db::runtime_db::RuntimeDb>,
    run_id: &str,
    claim_generation: Option<i64>,
    older_than: bool,
) -> Result<bool, Status> {
    let mut released = false;
    loop {
        let Some((tenant_id, reserved_concurrency, held_generation)) = db
            .take_transform_quota_hold(run_id, claim_generation, older_than)
            .map_err(Status::internal)?
        else {
            return Ok(released);
        };
        released = true;
        if reserved_concurrency {
            if let Err(status) =
                complete_reserved_transform_quota(runtime.clone(), run_id, &tenant_id)
            {
                let _ = db.restore_transform_quota_hold(run_id, &tenant_id, true, held_generation);
                return Err(status);
            }
        }
    }
}

fn release_retryable_transform_quota(
    db: &crate::db::runtime_db::RuntimeDb,
    runtime: std::sync::Arc<crate::db::runtime_db::RuntimeDb>,
    run_id: &str,
    claim_generation: i64,
) -> Result<bool, Status> {
    let Some((tenant_id, reserved_concurrency, held_generation, refund_request, refund_tokens)) =
        db.take_retryable_quota_hold(run_id, claim_generation)
            .map_err(Status::internal)?
    else {
        return Ok(false);
    };
    if refund_request || refund_tokens > 0 {
        let admission = crate::chisei::tenant_quota::TenantQuotaAdmission {
            tenant_id: tenant_id.clone(),
            scope_id: crate::chisei::tenant_quota::tenant_scope_id(&tenant_id),
            assignment_version: 1,
            reserved_tokens: refund_tokens,
            reserved_request: refund_request,
            reserved_concurrency,
            idempotency_key: run_id.to_string(),
        };
        match crate::composition::transform_run_admission::quota_gate(runtime.clone())
            .abandon(&admission)
        {
            Ok(()) => return Ok(true),
            Err(failed) => {
                let _ = db.restore_abandoned_quota_hold(
                    run_id,
                    &failed.remaining.tenant_id,
                    failed.remaining.reserved_concurrency,
                    failed.remaining.reserved_request,
                    failed.remaining.reserved_tokens,
                );
                return Err(map_quota_error(failed.error));
            }
        }
    }
    if reserved_concurrency {
        if let Err(status) = complete_reserved_transform_quota(runtime, run_id, &tenant_id) {
            let _ = db.restore_transform_quota_hold(run_id, &tenant_id, true, held_generation);
            return Err(status);
        }
    }
    Ok(true)
}

fn restore_request_admission_hold(
    db: &crate::db::runtime_db::RuntimeDb,
    work: &crate::sekai::governed_transform::TransformWork,
    owner: Option<&crate::enterprise::AuthenticatedContext>,
) -> Result<(), Status> {
    let tenant_id = if !work.tenant_id.trim().is_empty() {
        work.tenant_id.trim()
    } else if let Some(tenant_id) = owner
        .and_then(|context| context.tenant.as_ref())
        .map(|tenant| tenant.tenant_id.as_str())
    {
        tenant_id
    } else {
        return Ok(());
    };
    db.put_transform_quota_hold(
        &work.run_id,
        tenant_id,
        false,
        work.claim_generation,
        &work.fencing_token,
    )
    .map(|_| ())
    .map_err(Status::internal)
}

fn complete_reserved_transform_quota(
    runtime: std::sync::Arc<crate::db::runtime_db::RuntimeDb>,
    run_id: &str,
    tenant_id: &str,
) -> Result<(), Status> {
    let admission = crate::chisei::tenant_quota::TenantQuotaAdmission {
        tenant_id: tenant_id.into(),
        scope_id: crate::chisei::tenant_quota::tenant_scope_id(tenant_id),
        assignment_version: 1,
        reserved_tokens: 0,
        reserved_request: false,
        reserved_concurrency: true,
        idempotency_key: format!("transform-claim:{run_id}"),
    };
    crate::composition::transform_run_admission::complete_transform_run(
        &crate::composition::transform_run_admission::quota_gate(runtime),
        &admission,
    )
    .map_err(map_quota_error)
}

fn record_tenant_transform_usage(
    db: &crate::db::runtime_db::RuntimeDb,
    tenant_id: Option<&str>,
    run: &crate::sekai::governed_transform::TransformRun,
    actor: &str,
    completed_at_ms: i64,
) -> Result<bool, Status> {
    let Some(tenant_id) = tenant_id else {
        return Ok(true);
    };
    match crate::composition::transform_run_admission::record_transform_usage(
        db,
        tenant_id,
        run,
        actor,
        completed_at_ms,
    ) {
        Ok(_) => Ok(true),
        Err(_) => {
            // The run is already durable. Leave the pending row so a later
            // tick can meter it; do not fail the caller for usage persist.
            Ok(false)
        }
    }
}

fn ack_transform_usage_pending(
    db: &crate::db::runtime_db::RuntimeDb,
    run_id: &str,
) -> Result<(), Status> {
    db.take_transform_usage_pending(run_id)
        .map(|_| ())
        .map_err(Status::internal)
}

fn load_transform_run_or_preview(
    service: &SekaiServiceImpl,
    run_id: &str,
) -> Result<crate::sekai::governed_transform::TransformRun, Status> {
    if let Some(run) = service
        .db
        .runtime()
        .get_governed_transform_run(run_id)
        .map_err(Status::internal)?
    {
        return Ok(run);
    }
    if !crate::sekai::governed_transform::is_preview_id(run_id) {
        return Err(Status::not_found("transform run not found"));
    }
    let transform = service
        .db
        .runtime()
        .admitted_isolated_transform(run_id)
        .map_err(transform_work_status)?
        .ok_or_else(|| Status::not_found("admitted transform not found"))?;
    Ok(crate::sekai::governed_transform::TransformRun {
        run_id: run_id.to_string(),
        namespace: transform.namespace,
        transform_id: transform.transform_id,
        definition_digest: transform.definition_digest,
        input_digest: String::new(),
        output_digest: String::new(),
        last_input_row_id: 0,
        incremental: false,
        quarantined: false,
        quality_rule: String::new(),
        rows_in: 0,
        rows_out: 0,
        lineage_parent: String::new(),
        created_at_ms: 0,
        markings_in: String::new(),
        markings_out: String::new(),
        profile: crate::sekai::governed_transform::ISOLATED_CLASS.into(),
        engine: String::new(),
        runtime_image: String::new(),
        dispatch_status: String::new(),
        trigger_cause: String::new(),
        trigger_ref: String::new(),
        input_partitions: Vec::new(),
        output_partitions: Vec::new(),
    })
}

fn preview_column_allowlist(
    service: &SekaiServiceImpl,
    dataset: &crate::sekai::dataset::Dataset,
) -> Result<Option<Vec<String>>, Status> {
    if dataset.object_id.is_empty() {
        return Ok(None);
    }
    let Some(object) = service
        .db
        .runtime()
        .get_object(&dataset.object_id)
        .map_err(Status::internal)?
    else {
        return Ok(None);
    };
    let Some(policy) = service
        .db
        .runtime()
        .active_object_policy(&object.namespace, &object.kind)
        .map_err(|error| {
            if error.starts_with("object_security_denied") {
                Status::permission_denied("access denied")
            } else {
                Status::unavailable("object authorization unavailable")
            }
        })?
    else {
        return Ok(None);
    };
    if !policy.property_grants_enforced() {
        return Ok(None);
    }
    Ok(Some(
        dataset
            .columns
            .iter()
            .map(|column| column.name.clone())
            .filter(|name| {
                policy.allows_property_access(
                    name,
                    crate::sekai::object_security::PropertyGrantAccess::Read,
                )
            })
            .collect(),
    ))
}

fn preview_transform_status(error: String) -> Status {
    if error == crate::sekai::governed_transform::PREVIEW_ROW_CAP
        || error == crate::sekai::transform_engine::BUDGET_TIME
        || error == crate::sekai::transform_engine::BUDGET_MEMORY
    {
        Status::failed_precondition(error)
    } else {
        transform_work_status(error)
    }
}

fn transform_work_status(error: String) -> Status {
    if error == crate::sekai::governed_transform::STALE_TRANSFORM_CLAIM
        || error == crate::sekai::governed_transform::STALE_TRANSFORM_ADMISSION
        || error == crate::sekai::governed_transform::TRANSFORM_DEFINITION_CHANGED
        || error == crate::sekai::governed_transform::PREVIEW_ROW_CAP
        || error == crate::sekai::transform_engine::BUDGET_TIME
        || error == crate::sekai::transform_engine::BUDGET_MEMORY
    {
        Status::failed_precondition(error)
    } else if error == crate::sekai::governed_transform::TRANSFORM_DIGEST_MISMATCH
        || error.contains("required")
    {
        Status::invalid_argument(error)
    } else if error.contains("not found") {
        Status::not_found(error)
    } else {
        Status::internal(error)
    }
}

fn to_proto_transform_work(
    work: &crate::sekai::governed_transform::TransformWork,
) -> TransformWork {
    TransformWork {
        run_id: work.run_id.clone(),
        namespace: work.namespace.clone(),
        transform_id: work.transform_id.clone(),
        definition_digest: work.definition_digest.clone(),
        engine: work.engine.clone(),
        runtime_image: work.runtime_image.clone(),
        status: work.status.clone(),
        claim_owner: work.claim_owner.clone(),
        claim_generation: work.claim_generation,
        fencing_token: work.fencing_token.clone(),
        claim_expires_at_ms: work.claim_expires_at_ms,
        lease_expiries: work.lease_expiries,
        created_at_ms: work.created_at_ms,
        tenant_id: work.tenant_id.clone(),
    }
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
        profile: if transform.is_isolated_process() {
            crate::sekai::governed_transform::ISOLATED_CLASS.into()
        } else if transform.is_analytical() {
            crate::sekai::governed_transform::ANALYTICAL_CLASS.into()
        } else {
            String::new()
        },
        inputs: transform
            .isolated_process
            .as_ref()
            .map(|spec| spec.inputs.as_slice())
            .or_else(|| {
                transform
                    .analytical
                    .as_ref()
                    .map(|spec| spec.inputs.as_slice())
            })
            .unwrap_or(&[])
            .iter()
            .map(|input| TransformInput {
                alias: input.alias.clone(),
                dataset_id: input.dataset_id.clone(),
            })
            .collect(),
        sql: transform
            .analytical
            .as_ref()
            .map(|spec| spec.sql.clone())
            .unwrap_or_default(),
        memory_limit_bytes: transform
            .analytical
            .as_ref()
            .map(|spec| spec.memory_limit_bytes)
            .unwrap_or(0),
        time_limit_ms: transform
            .analytical
            .as_ref()
            .map(|spec| spec.time_limit_ms)
            .unwrap_or(0),
        engine: transform
            .isolated_process
            .as_ref()
            .map(|spec| spec.engine.clone())
            .unwrap_or_default(),
        runtime_image: transform
            .isolated_process
            .as_ref()
            .map(|spec| spec.runtime_image.clone())
            .unwrap_or_default(),
        schedule_every_ms: transform
            .schedule
            .as_ref()
            .map(|schedule| schedule.every_ms)
            .unwrap_or(0),
        trigger_on_input_commit: transform
            .trigger
            .as_ref()
            .is_some_and(|trigger| trigger.on_input_commit),
        trigger_debounce_ms: transform
            .trigger
            .as_ref()
            .map(|trigger| trigger.debounce_ms)
            .unwrap_or(0),
    }
}

fn from_proto_analytical(
    proto: &GovernedTransform,
) -> Option<crate::sekai::governed_transform::AnalyticalSpec> {
    let profile = proto.profile.trim().to_ascii_lowercase();
    if profile == crate::sekai::governed_transform::ISOLATED_CLASS {
        return None;
    }
    let has_spec = profile == crate::sekai::governed_transform::ANALYTICAL_CLASS
        || !proto.sql.trim().is_empty()
        || proto.memory_limit_bytes != 0
        || proto.time_limit_ms != 0
        || (profile != crate::sekai::governed_transform::ISOLATED_CLASS
            && !proto.inputs.is_empty()
            && proto.engine.trim().is_empty()
            && proto.runtime_image.trim().is_empty());
    if !has_spec {
        return None;
    }
    Some(crate::sekai::governed_transform::AnalyticalSpec {
        inputs: proto
            .inputs
            .iter()
            .map(|input| crate::sekai::governed_transform::TransformInput {
                alias: input.alias.clone(),
                dataset_id: input.dataset_id.clone(),
            })
            .collect(),
        sql: proto.sql.clone(),
        memory_limit_bytes: proto.memory_limit_bytes,
        time_limit_ms: proto.time_limit_ms,
    })
}

fn from_proto_isolated(
    proto: &GovernedTransform,
) -> Option<crate::sekai::governed_transform::IsolatedProcessSpec> {
    let profile = proto.profile.trim().to_ascii_lowercase();
    if profile == crate::sekai::governed_transform::ANALYTICAL_CLASS {
        return None;
    }
    let has_spec = profile == crate::sekai::governed_transform::ISOLATED_CLASS
        || !proto.engine.trim().is_empty()
        || !proto.runtime_image.trim().is_empty();
    if !has_spec {
        return None;
    }
    Some(crate::sekai::governed_transform::IsolatedProcessSpec {
        engine: proto.engine.clone(),
        runtime_image: proto.runtime_image.clone(),
        inputs: proto
            .inputs
            .iter()
            .map(|input| crate::sekai::governed_transform::TransformInput {
                alias: input.alias.clone(),
                dataset_id: input.dataset_id.clone(),
            })
            .collect(),
    })
}

fn caller_can_read_run_datasets(
    service: &SekaiServiceImpl,
    principals: &[String],
    run: &crate::sekai::governed_transform::TransformRun,
) -> bool {
    let transform = if run.profile == crate::sekai::governed_transform::ISOLATED_CLASS {
        service
            .db
            .runtime()
            .admitted_isolated_transform(&run.run_id)
            .ok()
            .flatten()
    } else {
        service
            .db
            .runtime()
            .get_governed_transform(&run.namespace, &run.transform_id)
            .ok()
            .flatten()
    };
    let Some(transform) = transform else {
        return false;
    };
    if transform.definition_digest != run.definition_digest {
        return false;
    }
    let mut dataset_ids: Vec<String> = transform
        .input_bindings()
        .into_iter()
        .map(|(_, dataset_id)| dataset_id)
        .collect();
    dataset_ids.push(transform.output_dataset_id);
    for dataset_id in dataset_ids {
        let Ok(Some(dataset)) = service.db.runtime().get_dataset(&dataset_id) else {
            return false;
        };
        if check_dataset_access(
            service.db.runtime(),
            &service.security,
            principals,
            &dataset,
            false,
        )
        .is_err()
        {
            return false;
        }
    }
    true
}

fn to_proto_partition(
    partition: &crate::sekai::governed_transform::TransformPartition,
    reveal_partition_keys: bool,
) -> TransformPartition {
    let identity = if reveal_partition_keys {
        partition.partition_key.clone()
    } else {
        crate::sekai::governed_transform::REDACTED_PARTITION_IDENTITY.into()
    };
    TransformPartition {
        partition_key: identity.clone(),
        digest: if reveal_partition_keys {
            partition.digest.clone()
        } else {
            identity
        },
        rows: partition.rows,
    }
}

fn to_proto_transform_run(
    run: &crate::sekai::governed_transform::TransformRun,
    reveal_partition_keys: bool,
) -> TransformRun {
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
        markings_in: run.markings_in.clone(),
        markings_out: run.markings_out.clone(),
        profile: run.profile.clone(),
        engine: run.engine.clone(),
        runtime_image: run.runtime_image.clone(),
        dispatch_status: run.dispatch_status.clone(),
        trigger_cause: run.trigger_cause.clone(),
        trigger_ref: run.trigger_ref.clone(),
        input_partitions: run
            .input_partitions
            .iter()
            .map(|partition| to_proto_partition(partition, reveal_partition_keys))
            .collect(),
        output_partitions: run
            .output_partitions
            .iter()
            .map(|partition| to_proto_partition(partition, reveal_partition_keys))
            .collect(),
    }
}

pub(super) async fn tick_governed_transforms(
    service: &SekaiServiceImpl,
    req: Request<TickGovernedTransformsRequest>,
) -> Result<Response<TickGovernedTransformsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let now_ms = {
        let requested = req.into_inner().now_ms;
        if requested > 0 {
            requested
        } else {
            now_millis()
        }
    };
    let runtime = service.db.runtime();
    let quota = service.quota_runtime();
    let mut runs = runtime
        .tick_governed_transforms(now_ms)
        .map_err(Status::internal)?;
    let gate = crate::composition::transform_run_admission::quota_gate(quota.clone());
    for (run_id, _, _, generation) in runtime
        .list_retryable_quota_holds()
        .map_err(Status::internal)?
    {
        if let Err(_status) =
            release_retryable_transform_quota(runtime, quota.clone(), &run_id, generation)
        {
            continue;
        }
    }
    for (run_id, tenant_id, completed_at_ms) in runtime
        .list_transform_usage_pending()
        .map_err(Status::internal)?
    {
        let Some(run) = runtime
            .get_governed_transform_run(&run_id)
            .map_err(Status::internal)?
        else {
            let _ = runtime.take_transform_usage_pending(&run_id);
            continue;
        };
        if record_tenant_transform_usage(
            quota.as_ref(),
            Some(tenant_id.as_str()),
            &run,
            &actor,
            completed_at_ms,
        )? {
            ack_transform_usage_pending(runtime, &run_id)?;
        }
    }
    for item in runtime
        .list_due_owned_in_process_transforms(now_ms)
        .map_err(Status::internal)?
    {
        let owner = crate::provider_credentials::tenant_context(&item.tenant_id, "local");
        let held = match admit_tenant_transform(
            quota.as_ref(),
            &gate,
            Some(&owner),
            &format!(
                "transform-tick:{}:{}:{}:{}",
                item.namespace, item.transform_id, item.cause, item.cause_ref
            ),
            false,
        ) {
            Ok(held) => held,
            Err(status) if status.code() == tonic::Code::ResourceExhausted => continue,
            Err(status) => return Err(status),
        };
        match runtime.commit_due_owned_in_process_transform(
            &item.namespace,
            &item.transform_id,
            now_ms,
            &item.tenant_id,
        ) {
            Ok(Some(run)) => {
                let recorded = record_tenant_transform_usage(
                    quota.as_ref(),
                    Some(item.tenant_id.as_str()),
                    &run,
                    &actor,
                    now_ms,
                );
                release_tenant_transform(runtime, &gate, &run.run_id, held.as_ref())?;
                if recorded? {
                    ack_transform_usage_pending(runtime, &run.run_id)?;
                }
                runs.push(run);
            }
            Ok(None) => abandon_tenant_transform(runtime, &gate, held.as_ref())?,
            Err(error) => {
                abandon_tenant_transform(runtime, &gate, held.as_ref())?;
                return Err(Status::internal(error));
            }
        }
    }
    let runs = runs
        .iter()
        .map(|run| {
            let reveal = caller_can_read_run_datasets(service, &principals, run);
            to_proto_transform_run(run, reveal)
        })
        .collect();
    Ok(Response::new(TickGovernedTransformsResponse { runs }))
}

pub(super) async fn get_transform_output_state(
    service: &SekaiServiceImpl,
    req: Request<GetTransformOutputStateRequest>,
) -> Result<Response<GetTransformOutputStateResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let input = req.into_inner();
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, false)?;
    let state = service
        .db
        .runtime()
        .get_transform_output_state(&input.namespace, &input.dataset_id)
        .map_err(Status::internal)?;
    Ok(Response::new(GetTransformOutputStateResponse {
        state: state.map(|state| TransformOutputState {
            namespace: state.namespace,
            dataset_id: state.dataset_id,
            freshness: state.freshness,
            upstream_version: state.upstream_version,
            blocked_run_id: state.blocked_run_id,
            updated_at_ms: state.updated_at_ms,
        }),
    }))
}

pub(super) async fn cancel_governed_transform_run(
    service: &SekaiServiceImpl,
    req: Request<CancelGovernedTransformRunRequest>,
) -> Result<Response<CancelGovernedTransformRunResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let run_id = req.into_inner().run_id;
    let prior = service
        .db
        .runtime()
        .get_governed_transform_run(&run_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("governed transform run not found"))?;
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &prior.namespace,
            true,
        )?;
    }
    let run = service
        .db
        .runtime()
        .cancel_governed_transform_run(&run_id, now_millis())
        .map_err(|error| {
            if error.contains("not found") {
                Status::not_found(error)
            } else {
                Status::internal(error)
            }
        })?;
    release_claimed_transform_quota(
        service.db.runtime(),
        service.quota_runtime(),
        &run.run_id,
        None,
        false,
    )?;
    Ok(Response::new(CancelGovernedTransformRunResponse {
        run: Some(to_proto_transform_run(
            &run,
            caller_can_read_run_datasets(service, &principals, &run),
        )),
    }))
}

fn map_document_error(error: String) -> Status {
    use crate::sekai::document::{
        DOCUMENT_HELD, DOCUMENT_UNAVAILABLE, FORMAT_UNSUPPORTED, REVISION_UNSUPPORTED,
    };
    if error == DOCUMENT_UNAVAILABLE {
        Status::not_found(error)
    } else if error == DOCUMENT_HELD || error == FORMAT_UNSUPPORTED || error == REVISION_UNSUPPORTED
    {
        Status::failed_precondition(error)
    } else {
        Status::invalid_argument(error)
    }
}

fn caller_actor(principals: &[String]) -> Result<&str, Status> {
    require_authenticated(principals)?;
    principals
        .first()
        .map(String::as_str)
        .ok_or_else(|| Status::unauthenticated("principal required"))
}

fn from_proto_content_ref(proto: ContentReference) -> crate::sekai::document::ContentReference {
    crate::sekai::document::ContentReference {
        scheme: proto.scheme,
        digest: proto.digest,
        media_type: proto.media_type,
        byte_length: proto.byte_length,
    }
}

fn to_proto_content_ref(reference: &crate::sekai::document::ContentReference) -> ContentReference {
    ContentReference {
        scheme: reference.scheme.clone(),
        digest: reference.digest.clone(),
        media_type: reference.media_type.clone(),
        byte_length: reference.byte_length,
    }
}

fn from_proto_document(
    proto: GovernedDocument,
) -> Result<crate::sekai::document::GovernedDocument, Status> {
    let content_ref = proto
        .content_ref
        .map(from_proto_content_ref)
        .ok_or_else(|| Status::invalid_argument("content_ref required"))?;
    Ok(crate::sekai::document::GovernedDocument {
        contract_version: proto.contract_version,
        document_id: proto.document_id,
        namespace: proto.namespace,
        owner: proto.owner,
        type_revision: proto.type_revision,
        purpose: proto.purpose,
        classification: proto.classification,
        title: proto.title,
        metadata: proto.metadata.into_iter().collect(),
        content_ref,
        content_digest: proto.content_digest,
        expires_at_ms: proto.expires_at_ms,
        hold_id: proto.hold_id,
        hold_reason: proto.hold_reason,
        admitted_by: proto.admitted_by,
        admitted_at_ms: proto.admitted_at_ms,
        deleted_at_ms: proto.deleted_at_ms,
    })
}

fn to_proto_document(document: &crate::sekai::document::GovernedDocument) -> GovernedDocument {
    GovernedDocument {
        contract_version: document.contract_version.clone(),
        document_id: document.document_id.clone(),
        namespace: document.namespace.clone(),
        owner: document.owner.clone(),
        type_revision: document.type_revision.clone(),
        purpose: document.purpose.clone(),
        classification: document.classification.clone(),
        title: document.title.clone(),
        metadata: document.metadata.clone().into_iter().collect(),
        content_ref: Some(to_proto_content_ref(&document.content_ref)),
        content_digest: document.content_digest.clone(),
        expires_at_ms: document.expires_at_ms,
        hold_id: document.hold_id.clone(),
        hold_reason: document.hold_reason.clone(),
        admitted_by: document.admitted_by.clone(),
        admitted_at_ms: document.admitted_at_ms,
        deleted_at_ms: document.deleted_at_ms,
    }
}

fn from_proto_rendition(
    proto: DocumentRendition,
) -> Result<crate::sekai::document::DocumentRendition, Status> {
    let content_ref = proto
        .content_ref
        .map(from_proto_content_ref)
        .ok_or_else(|| Status::invalid_argument("content_ref required"))?;
    Ok(crate::sekai::document::DocumentRendition {
        namespace: proto.namespace,
        document_id: proto.document_id,
        rendition_id: proto.rendition_id,
        class: proto.class,
        parent_content_digest: proto.parent_content_digest,
        content_ref,
        extractor_id: proto.extractor_id,
        extractor_profile_digest: proto.extractor_profile_digest,
        attached_by: proto.attached_by,
        attached_at_ms: proto.attached_at_ms,
    })
}

fn to_proto_rendition(rendition: &crate::sekai::document::DocumentRendition) -> DocumentRendition {
    DocumentRendition {
        namespace: rendition.namespace.clone(),
        document_id: rendition.document_id.clone(),
        rendition_id: rendition.rendition_id.clone(),
        class: rendition.class.clone(),
        parent_content_digest: rendition.parent_content_digest.clone(),
        content_ref: Some(to_proto_content_ref(&rendition.content_ref)),
        extractor_id: rendition.extractor_id.clone(),
        extractor_profile_digest: rendition.extractor_profile_digest.clone(),
        attached_by: rendition.attached_by.clone(),
        attached_at_ms: rendition.attached_at_ms,
    }
}

fn to_proto_document_view(view: crate::sekai::document::DocumentView) -> DocumentView {
    let has_metadata = view.metadata.is_some();
    let has_renditions = view.renditions.is_some();
    DocumentView {
        contract_version: view.contract_version,
        document_id: view.document_id,
        namespace: view.namespace,
        type_revision: view.type_revision,
        lifecycle: view.lifecycle,
        definition_digest: view.definition_digest,
        content_ref: view.content_ref.as_ref().map(to_proto_content_ref),
        title: view.title,
        metadata: view.metadata.unwrap_or_default().into_iter().collect(),
        purpose: view.purpose,
        classification: view.classification,
        expires_at_ms: view.expires_at_ms,
        hold_id: view.hold_id,
        renditions: view
            .renditions
            .unwrap_or_default()
            .iter()
            .map(to_proto_rendition)
            .collect(),
        has_metadata,
        has_renditions,
    }
}

pub(super) async fn admit_governed_document(
    service: &SekaiServiceImpl,
    req: Request<AdmitGovernedDocumentRequest>,
) -> Result<Response<AdmitGovernedDocumentResponse>, Status> {
    let principals = caller_principals(&req);
    let actor = caller_actor(&principals)?;
    let proto = req
        .into_inner()
        .document
        .ok_or_else(|| Status::invalid_argument("document required"))?;
    let document = from_proto_document(proto)?;
    let admitted = crate::sekai::document::admit_document(
        service.db.runtime(),
        actor,
        &document,
        now_millis(),
    )
    .map_err(map_document_error)?;
    Ok(Response::new(AdmitGovernedDocumentResponse {
        document: Some(to_proto_document(&admitted)),
    }))
}

pub(super) async fn attach_governed_document_rendition(
    service: &SekaiServiceImpl,
    req: Request<AttachGovernedDocumentRenditionRequest>,
) -> Result<Response<AttachGovernedDocumentRenditionResponse>, Status> {
    let principals = caller_principals(&req);
    let actor = caller_actor(&principals)?;
    let proto = req
        .into_inner()
        .rendition
        .ok_or_else(|| Status::invalid_argument("rendition required"))?;
    let rendition = from_proto_rendition(proto)?;
    let attached = crate::sekai::document::attach_rendition(
        service.db.runtime(),
        actor,
        &rendition,
        now_millis(),
    )
    .map_err(map_document_error)?;
    Ok(Response::new(AttachGovernedDocumentRenditionResponse {
        rendition: Some(to_proto_rendition(&attached)),
    }))
}

pub(super) async fn get_governed_document(
    service: &SekaiServiceImpl,
    req: Request<GetGovernedDocumentRequest>,
) -> Result<Response<GetGovernedDocumentResponse>, Status> {
    let principals = caller_principals(&req);
    let actor = caller_actor(&principals)?;
    let input = req.into_inner();
    let view = crate::sekai::document::retrieve_document(
        service.db.runtime(),
        actor,
        &crate::sekai::document::DocumentRetrieve {
            namespace: input.namespace,
            document_id: input.document_id,
            purpose: (!input.purpose.is_empty()).then_some(input.purpose),
            fields: input.fields,
            classification_ceiling: (!input.classification_ceiling.is_empty())
                .then_some(input.classification_ceiling),
        },
        now_millis(),
    )
    .map_err(map_document_error)?;
    Ok(Response::new(GetGovernedDocumentResponse {
        view: Some(to_proto_document_view(view)),
    }))
}

pub(super) async fn hold_governed_document(
    service: &SekaiServiceImpl,
    req: Request<HoldGovernedDocumentRequest>,
) -> Result<Response<HoldGovernedDocumentResponse>, Status> {
    let principals = caller_principals(&req);
    let actor = caller_actor(&principals)?;
    let input = req.into_inner();
    let document = crate::sekai::document::place_hold(
        service.db.runtime(),
        actor,
        &input.namespace,
        &input.document_id,
        &input.hold_id,
        &input.reason,
        now_millis(),
    )
    .map_err(map_document_error)?;
    Ok(Response::new(HoldGovernedDocumentResponse {
        document: Some(to_proto_document(&document)),
    }))
}

pub(super) async fn release_governed_document_hold(
    service: &SekaiServiceImpl,
    req: Request<ReleaseGovernedDocumentHoldRequest>,
) -> Result<Response<ReleaseGovernedDocumentHoldResponse>, Status> {
    let principals = caller_principals(&req);
    let actor = caller_actor(&principals)?;
    let input = req.into_inner();
    let document = crate::sekai::document::release_hold(
        service.db.runtime(),
        actor,
        &input.namespace,
        &input.document_id,
        &input.hold_id,
        now_millis(),
    )
    .map_err(map_document_error)?;
    Ok(Response::new(ReleaseGovernedDocumentHoldResponse {
        document: Some(to_proto_document(&document)),
    }))
}

pub(super) async fn expire_governed_document(
    service: &SekaiServiceImpl,
    req: Request<ExpireGovernedDocumentRequest>,
) -> Result<Response<ExpireGovernedDocumentResponse>, Status> {
    let principals = caller_principals(&req);
    let actor = caller_actor(&principals)?;
    let input = req.into_inner();
    let document = crate::sekai::document::expire_document(
        service.db.runtime(),
        actor,
        &input.namespace,
        &input.document_id,
        now_millis(),
    )
    .map_err(map_document_error)?;
    Ok(Response::new(ExpireGovernedDocumentResponse {
        document: Some(to_proto_document(&document)),
    }))
}

pub(super) async fn delete_governed_document(
    service: &SekaiServiceImpl,
    req: Request<DeleteGovernedDocumentRequest>,
) -> Result<Response<DeleteGovernedDocumentResponse>, Status> {
    let principals = caller_principals(&req);
    let actor = caller_actor(&principals)?;
    let input = req.into_inner();
    let document = crate::sekai::document::delete_document(
        service.db.runtime(),
        actor,
        &input.namespace,
        &input.document_id,
        now_millis(),
    )
    .map_err(map_document_error)?;
    Ok(Response::new(DeleteGovernedDocumentResponse {
        document: Some(to_proto_document(&document)),
    }))
}

// Dataset branches (ADR 0119). The tenant always comes from the caller's
// authenticated context; another tenant's branch reads as missing.

fn branch_status(error: String) -> Status {
    use crate::sekai::dataset_branch as branch;
    match error.as_str() {
        branch::BRANCH_NOT_FOUND | branch::PROPOSAL_NOT_FOUND => Status::not_found(error),
        branch::BRANCH_EXISTS => Status::already_exists(error),
        branch::BRANCH_NAME_INVALID => Status::invalid_argument(error),
        branch::PROPOSAL_SELF_MERGE => Status::permission_denied(error),
        branch::PROPOSAL_NOT_OPEN
        | branch::PROPOSAL_STALE_PARENT
        | branch::PROPOSAL_STALE_BRANCH
        | branch::BRANCH_RUN_ISOLATED
        | branch::BRANCH_RUN_RAISES_MARKING => Status::failed_precondition(error),
        _ if error.starts_with("branch run") => Status::failed_precondition(error),
        _ => map_dataset_version_error(error),
    }
}

fn context_tenant(context: Option<&RequestEnterpriseContext>) -> String {
    context
        .and_then(|context| context.tenant.as_ref())
        .map(|tenant| tenant.tenant_id.clone())
        .unwrap_or_default()
}

/// The caller, its tenant, and the dataset after the read or write check.
fn branch_caller<T: 'static>(
    service: &SekaiServiceImpl,
    req: &Request<T>,
    dataset_id: &str,
    write: bool,
) -> Result<(String, String), Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    let context = request_tenant_context(service.db.runtime(), req)?;
    let tenant = context_tenant(context.as_ref());
    let dataset = service
        .db
        .runtime()
        .get_dataset(dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    // The bound object's namespace must be one the authenticated context
    // may read or write, whatever ACL grants the caller also holds.
    if let Some(context) = context.as_ref()
        && !dataset.object_id.is_empty()
        && let Some(object) = service
            .db
            .runtime()
            .get_object(&dataset.object_id)
            .map_err(Status::internal)?
    {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &object.namespace,
            write,
        )?;
    }
    check_dataset_access(
        service.db.runtime(),
        &service.security,
        &principals,
        &dataset,
        write,
    )?;
    let actor = principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    Ok((actor, tenant))
}

fn to_proto_branch(branch: crate::sekai::dataset_branch::DatasetBranch) -> DatasetBranch {
    DatasetBranch {
        dataset_id: branch.dataset_id,
        name: branch.name,
        base_version_id: branch.base_version_id,
        written: branch.written,
        created_by: branch.created_by,
        created_at_ms: branch.created_at_ms,
    }
}

fn to_proto_proposal(
    proposal: crate::sekai::dataset_branch::DatasetBranchProposal,
) -> DatasetBranchProposal {
    DatasetBranchProposal {
        id: proposal.id,
        dataset_id: proposal.dataset_id,
        branch: proposal.branch,
        parent_version_id: proposal.parent_version_id,
        branch_digest: proposal.branch_digest,
        proposer: proposal.proposer,
        status: proposal.status,
        merged_by: proposal.merged_by,
        merged_version_id: proposal.merged_version_id,
        receipt_id: proposal.receipt_id,
        created_at_ms: proposal.created_at_ms,
        merged_at_ms: proposal.merged_at_ms,
    }
}

pub(super) async fn create_dataset_branch(
    service: &SekaiServiceImpl,
    req: Request<CreateDatasetBranchRequest>,
) -> Result<Response<CreateDatasetBranchResponse>, Status> {
    let dataset_id = req.get_ref().dataset_id.clone();
    let (actor, tenant) = branch_caller(service, &req, &dataset_id, true)?;
    let inner = req.into_inner();
    let branch = service
        .db
        .runtime()
        .create_dataset_branch(&crate::sekai::dataset_branch::CreateDatasetBranch {
            dataset_id,
            name: inner.name,
            from_version_id: inner.from_version_id,
            actor,
            tenant,
        })
        .map_err(branch_status)?;
    Ok(Response::new(CreateDatasetBranchResponse {
        branch: Some(to_proto_branch(branch)),
    }))
}

pub(super) async fn list_dataset_branches(
    service: &SekaiServiceImpl,
    req: Request<ListDatasetBranchesRequest>,
) -> Result<Response<ListDatasetBranchesResponse>, Status> {
    let dataset_id = req.get_ref().dataset_id.clone();
    let (_, tenant) = branch_caller(service, &req, &dataset_id, false)?;
    let branches = service
        .db
        .runtime()
        .list_dataset_branches(&dataset_id)
        .map_err(branch_status)?
        .into_iter()
        .filter(|branch| branch.tenant == tenant)
        .map(to_proto_branch)
        .collect();
    Ok(Response::new(ListDatasetBranchesResponse { branches }))
}

pub(super) async fn delete_dataset_branch(
    service: &SekaiServiceImpl,
    req: Request<DeleteDatasetBranchRequest>,
) -> Result<Response<DeleteDatasetBranchResponse>, Status> {
    let dataset_id = req.get_ref().dataset_id.clone();
    let (_, tenant) = branch_caller(service, &req, &dataset_id, true)?;
    let name = req.into_inner().name;
    service
        .db
        .runtime()
        .delete_dataset_branch(&dataset_id, &name, &tenant)
        .map_err(branch_status)?;
    Ok(Response::new(DeleteDatasetBranchResponse {}))
}

pub(super) async fn compare_dataset_branch(
    service: &SekaiServiceImpl,
    req: Request<CompareDatasetBranchRequest>,
) -> Result<Response<CompareDatasetBranchResponse>, Status> {
    let dataset_id = req.get_ref().dataset_id.clone();
    let (_, tenant) = branch_caller(service, &req, &dataset_id, false)?;
    let name = req.into_inner().name;
    let diff = service
        .db
        .runtime()
        .compare_dataset_branch(&dataset_id, &name, &tenant)
        .map_err(branch_status)?;
    Ok(Response::new(CompareDatasetBranchResponse {
        columns_added: diff.columns_added,
        columns_removed: diff.columns_removed,
        parent_rows: diff.parent_rows,
        branch_rows: diff.branch_rows,
        parent_digest: diff.parent_digest,
        branch_digest: diff.branch_digest,
    }))
}

pub(super) async fn propose_dataset_branch_merge(
    service: &SekaiServiceImpl,
    req: Request<ProposeDatasetBranchMergeRequest>,
) -> Result<Response<ProposeDatasetBranchMergeResponse>, Status> {
    let dataset_id = req.get_ref().dataset_id.clone();
    let (actor, tenant) = branch_caller(service, &req, &dataset_id, true)?;
    let proposal = service
        .db
        .runtime()
        .propose_dataset_branch(&crate::sekai::dataset_branch::ProposeDatasetBranch {
            dataset_id,
            branch: req.into_inner().name,
            actor,
            tenant,
        })
        .map_err(branch_status)?;
    Ok(Response::new(ProposeDatasetBranchMergeResponse {
        proposal: Some(to_proto_proposal(proposal)),
    }))
}

pub(super) async fn merge_dataset_branch(
    service: &SekaiServiceImpl,
    req: Request<MergeDatasetBranchRequest>,
) -> Result<Response<MergeDatasetBranchResponse>, Status> {
    let dataset_id = req.get_ref().dataset_id.clone();
    let (actor, tenant) = branch_caller(service, &req, &dataset_id, true)?;
    let inner = req.into_inner();
    let proposal = service
        .db
        .runtime()
        .merge_dataset_branch(&crate::sekai::dataset_branch::MergeDatasetBranch {
            dataset_id,
            proposal_id: inner.proposal_id,
            actor,
            tenant,
            reason: inner.reason,
        })
        .map_err(branch_status)?;
    Ok(Response::new(MergeDatasetBranchResponse {
        proposal: Some(to_proto_proposal(proposal)),
    }))
}

/// Admitted like a parent run (credential admin, namespace tenant, transform
/// quota gate). A successful run keeps its request charge; a branch run
/// leaves no run receipt, so no usage row is recorded.
pub(super) async fn run_governed_transform_on_branch(
    service: &SekaiServiceImpl,
    req: Request<RunGovernedTransformOnBranchRequest>,
) -> Result<Response<RunGovernedTransformOnBranchResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let input = req.into_inner();
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &input.namespace,
            true,
        )?;
    }
    // Charge the caller's tenant, or for a tenantless operator the stored
    // quota owner, as a parent run does. Branch ownership stays with the
    // caller's tenant.
    let owner_ctx = if tenant_context
        .as_ref()
        .and_then(|context| context.tenant.as_ref())
        .is_some()
    {
        tenant_context.clone()
    } else {
        match service
            .db
            .runtime()
            .transform_quota_owner(&input.namespace, &input.transform_id)
            .map_err(Status::internal)?
        {
            Some(tenant_id) => Some(crate::provider_credentials::tenant_context(
                &tenant_id, "local",
            )),
            None => tenant_context.clone(),
        }
    };
    let quota = service.quota_runtime();
    let gate = crate::composition::transform_run_admission::quota_gate(quota.clone());
    let admission_id = format!(
        "transform-branch-run:{}:{}:{}:{}",
        input.namespace,
        input.transform_id,
        input.branch,
        now_millis()
    );
    let held = admit_tenant_transform(
        quota.as_ref(),
        &gate,
        owner_ctx.as_ref(),
        &admission_id,
        false,
    )?;
    let result = service.db.runtime().run_governed_transform_on_branch(
        &input.namespace,
        &input.transform_id,
        &input.branch,
        &actor,
        &context_tenant(tenant_context.as_ref()),
        now_millis(),
    );
    // A run that wrote its branch keeps its request charge; a failed one is
    // refunded.
    let run = match result {
        Ok(run) => {
            release_tenant_transform(service.db.runtime(), &gate, &admission_id, held.as_ref())?;
            run
        }
        Err(error) => {
            abandon_tenant_transform(service.db.runtime(), &gate, held.as_ref())?;
            return Err(branch_status(error));
        }
    };
    Ok(Response::new(RunGovernedTransformOnBranchResponse {
        output_dataset_id: run.output_dataset_id,
        rows_written: run.rows_written,
        branch_inputs: run.branch_inputs,
        markings_out: run.markings_out,
    }))
}

/// Replay a transform over pinned input versions (#1585). Admitted like a
/// branch run (credential admin, namespace tenant, transform quota gate);
/// the caller must read every input, the stored and candidate alike, and
/// write the output, where the replay branch is created.
pub(super) async fn replay_governed_transform(
    service: &SekaiServiceImpl,
    req: Request<ReplayGovernedTransformRequest>,
) -> Result<Response<ReplayGovernedTransformResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.get_ref().clone();
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &input.namespace,
            true,
        )?;
    }
    let stored = service
        .db
        .runtime()
        .get_governed_transform(&input.namespace, &input.transform_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("governed transform not found"))?;
    let transform =
        crate::db::transform_replay::candidate_or_stored(&stored, &input.definition_json)
            .map_err(Status::invalid_argument)?;
    let mut readable: Vec<String> = stored
        .input_bindings()
        .into_iter()
        .chain(transform.input_bindings())
        .map(|(_, dataset_id)| dataset_id)
        .collect();
    readable.sort();
    readable.dedup();
    for dataset_id in &readable {
        branch_caller(service, &req, dataset_id, false)?;
    }
    let (actor, tenant) = branch_caller(service, &req, &transform.output_dataset_id, true)?;
    // The run, its branch and the diff samples carry whole rows, including
    // fields of older versions; property read grants are not applied to
    // them, so any dataset under enforced grants is refused.
    for dataset_id in readable.iter().chain([&transform.output_dataset_id]) {
        let dataset = service
            .db
            .runtime()
            .get_dataset(dataset_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("dataset not found"))?;
        if preview_column_allowlist(service, &dataset)?.is_some() {
            return Err(Status::failed_precondition(
                crate::sekai::transform_replay::REPLAY_PROPERTY_RESTRICTED,
            ));
        }
    }
    let owner_ctx = if tenant_context
        .as_ref()
        .and_then(|context| context.tenant.as_ref())
        .is_some()
    {
        tenant_context.clone()
    } else {
        match service
            .db
            .runtime()
            .transform_quota_owner(&input.namespace, &input.transform_id)
            .map_err(Status::internal)?
        {
            Some(tenant_id) => Some(crate::provider_credentials::tenant_context(
                &tenant_id, "local",
            )),
            None => tenant_context.clone(),
        }
    };
    let quota = service.quota_runtime();
    let gate = crate::composition::transform_run_admission::quota_gate(quota.clone());
    let admission_id = format!(
        "transform-replay:{}:{}:{}",
        input.namespace,
        input.transform_id,
        uuid::Uuid::new_v4()
    );
    let held = admit_tenant_transform(
        quota.as_ref(),
        &gate,
        owner_ctx.as_ref(),
        &admission_id,
        false,
    )?;
    let result = service.db.runtime().replay_governed_transform(
        &crate::sekai::transform_replay::ReplayTransform {
            namespace: input.namespace,
            transform_id: input.transform_id,
            input_versions: input.input_versions.into_iter().collect(),
            as_of_ms: input.as_of_ms,
            definition_json: input.definition_json,
            baseline_version_id: input.baseline_version_id,
            key_column: input.key_column,
            // The definition whose inputs and output were checked above.
            expected_definition_digest: stored.definition_digest.clone(),
            actor,
            tenant,
        },
        now_millis(),
    );
    let replay = match result {
        Ok(replay) => {
            release_tenant_transform(service.db.runtime(), &gate, &admission_id, held.as_ref())?;
            replay
        }
        Err(error) => {
            abandon_tenant_transform(service.db.runtime(), &gate, held.as_ref())?;
            return Err(branch_status(error));
        }
    };
    Ok(Response::new(ReplayGovernedTransformResponse {
        replay: Some(to_proto_replay(replay)),
    }))
}

/// A replay record, for a caller of its tenant who may read its output and
/// every input; another tenant's reads as missing.
pub(super) async fn get_transform_replay(
    service: &SekaiServiceImpl,
    req: Request<GetTransformReplayRequest>,
) -> Result<Response<GetTransformReplayResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let missing = || Status::not_found(crate::sekai::transform_replay::REPLAY_NOT_FOUND);
    let replay = service
        .db
        .runtime()
        .get_transform_replay(&req.get_ref().id)
        .map_err(Status::internal)?
        .ok_or_else(missing)?;
    let (_, tenant) = branch_caller(service, &req, &replay.output_dataset_id, false)?;
    if tenant != replay.tenant {
        return Err(missing());
    }
    for input in &replay.inputs {
        branch_caller(service, &req, &input.dataset_id, false)?;
    }
    Ok(Response::new(GetTransformReplayResponse {
        replay: Some(to_proto_replay(replay)),
    }))
}

fn to_proto_replay(replay: crate::sekai::transform_replay::TransformReplay) -> TransformReplay {
    let reproduced = replay.diff.reproduced();
    let diff = replay.diff;
    TransformReplay {
        id: replay.id,
        namespace: replay.namespace,
        transform_id: replay.transform_id,
        output_dataset_id: replay.output_dataset_id,
        branch: replay.branch,
        inputs: replay
            .inputs
            .into_iter()
            .map(|input| ReplayInput {
                alias: input.alias,
                dataset_id: input.dataset_id,
                version_id: input.version_id,
                rows: input.rows,
                digest: input.digest,
                columns: input.columns,
            })
            .collect(),
        definition_digest: replay.definition_digest,
        candidate: replay.candidate,
        engine_version: replay.engine_version,
        as_of_ms: replay.as_of_ms,
        baseline_version_id: replay.baseline_version_id,
        non_deterministic: replay.non_deterministic,
        markings_out: replay.markings_out,
        output_digest: replay.output_digest,
        diff: Some(ReplayDiff {
            key_column: diff.key_column,
            columns_added: diff.columns_added,
            columns_removed: diff.columns_removed,
            baseline_rows: diff.baseline_rows,
            replay_rows: diff.replay_rows,
            baseline_digest: diff.baseline_digest,
            replay_digest: diff.replay_digest,
            rows_added: diff.rows_added,
            rows_removed: diff.rows_removed,
            rows_changed: diff.rows_changed,
            changed_keys: diff.changed_keys,
            samples: diff
                .samples
                .into_iter()
                .map(|change| ReplayRowChange {
                    key: change.key,
                    before: change.before.into_iter().collect(),
                    after: change.after.into_iter().collect(),
                })
                .collect(),
            reproduced,
        }),
        downstream: replay
            .downstream
            .into_iter()
            .map(|impact| ReplayDownstream {
                dataset_id: impact.dataset_id,
                via_transform: impact.via_transform,
                object_types: impact.object_types,
            })
            .collect(),
        actor: replay.actor,
        created_at_ms: replay.created_at_ms,
    }
}
