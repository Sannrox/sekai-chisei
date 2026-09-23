use super::*;

pub(super) async fn traverse(
    service: &SekaiServiceImpl,
    req: Request<TraverseRequest>,
) -> Result<Response<TraverseResponse>, Status> {
    service.traverse_visible(req).await
}
pub(super) async fn retrieve_context(
    service: &SekaiServiceImpl,
    req: Request<RetrieveContextRequest>,
) -> Result<Response<RetrieveContextResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let namespace =
        SekaiServiceImpl::catalog_metadata_value(&req, "x-sekai-namespace").unwrap_or_default();
    if !namespace.is_empty() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            tenant_context.as_ref(),
            &namespace,
            false,
        )?;
    }
    let mut receipt_guard = service.begin_semantic_catalog_invocation(
        &req,
        semantic::CAPABILITY_RETRIEVE_CONTEXT,
        &namespace,
        &principals,
    )?;
    let operation_id = receipt_guard
        .as_ref()
        .map(|(operation_id, _)| operation_id.clone());
    let purpose = request_purpose_presentation(&req, &principals);
    let result = service.execute_retrieve_context(
        &principals,
        tenant_context.as_ref(),
        purpose.as_ref(),
        req.into_inner(),
    );
    match result {
        Ok(response) => {
            if let Some((_, guard)) = receipt_guard.as_mut() {
                guard.finalize("allow", "succeeded")?;
            }
            let mut response = Response::new(response);
            if let Some(operation_id) = operation_id.as_deref() {
                response.metadata_mut().insert(
                    "x-sekai-operation-id",
                    operation_id
                        .parse()
                        .map_err(|_| Status::internal("invalid operation id"))?,
                );
            }
            Ok(response)
        }
        Err(status) => Err(status),
    }
}
pub(super) async fn expand_relations(
    service: &SekaiServiceImpl,
    req: Request<ExpandRelationsRequest>,
) -> Result<Response<ExpandRelationsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let namespace = req.get_ref().namespace.trim().to_string();
    if namespace.is_empty() || namespace != req.get_ref().namespace {
        return Err(Status::invalid_argument("canonical namespace required"));
    }
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &namespace, false)?;
    let mut receipt_guard = service.begin_semantic_catalog_invocation(
        &req,
        semantic::CAPABILITY_EXPAND_RELATIONS,
        &namespace,
        &principals,
    )?;
    let operation_id = receipt_guard
        .as_ref()
        .map(|(operation_id, _)| operation_id.clone());
    let purpose = request_purpose_presentation(&req, &principals);
    let inner = req.into_inner();
    let root = inner
        .root
        .ok_or_else(|| Status::invalid_argument("root required"))?;
    let reasoning_mode =
        retrieval::ReasoningMode::parse(&inner.reasoning_mode).map_err(map_retrieval_error)?;
    let retrieved = service.execute_retrieve_context(
        &principals,
        tenant_context.as_ref(),
        purpose.as_ref(),
        RetrieveContextRequest {
            roots: vec![root],
            relations: inner.relations,
            direction: inner.direction,
            max_depth: inner.max_depth,
            max_objects: inner.max_objects,
            max_links: inner.max_links,
            kind_filter: inner.kind_filter,
            reasoning_mode: inner.reasoning_mode,
            max_source_rows: inner.max_source_rows,
            max_derived_rows: inner.max_derived_rows,
            max_derivation_steps: inner.max_derivation_steps,
            max_time_ms: inner.max_time_ms,
            max_explanation_bytes: inner.max_explanation_bytes,
        },
    )?;
    // Keep expansion results inside the requested namespace boundary.
    let candidates = retrieved
        .candidates
        .into_iter()
        .filter(|candidate| {
            candidate
                .object
                .as_ref()
                .is_some_and(|object| object.namespace == namespace || object.namespace.is_empty())
        })
        .collect::<Vec<_>>();
    let visible_ids = candidates
        .iter()
        .filter_map(|candidate| candidate.object.as_ref().map(|object| object.id.as_str()))
        .collect::<std::collections::HashSet<_>>();
    let links = retrieved
        .links
        .into_iter()
        .filter(|link| {
            visible_ids.contains(link.from_id.as_str()) && visible_ids.contains(link.to_id.as_str())
        })
        .collect::<Vec<_>>();
    if let Some((_, guard)) = receipt_guard.as_mut() {
        guard.finalize("allow", "succeeded")?;
    }
    let mut response = Response::new(ExpandRelationsResponse {
        candidates,
        links,
        truncated: retrieved.truncated,
        unresolved_roots: retrieved.unresolved_roots,
        denied_objects: retrieved.denied_objects,
        truncated_objects: retrieved.truncated_objects,
        truncated_links: retrieved.truncated_links,
        truncation_reasons: retrieved.truncation_reasons,
        source_rows: retrieved.source_rows,
        derived_rows: retrieved.derived_rows,
        ontology_revision: retrieved.ontology_revision,
        reasoning_mode: semantic::reasoning_mode_label(reasoning_mode).into(),
        epistemic_descriptor_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
    });
    if let Some(operation_id) = operation_id.as_deref() {
        response.metadata_mut().insert(
            "x-sekai-operation-id",
            operation_id
                .parse()
                .map_err(|_| Status::internal("invalid operation id"))?,
        );
    }
    Ok(response)
}
pub(super) async fn explain_derivation(
    service: &SekaiServiceImpl,
    req: Request<ExplainDerivationRequest>,
) -> Result<Response<ExplainDerivationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let namespace = req.get_ref().namespace.trim().to_string();
    if namespace.is_empty() || namespace != req.get_ref().namespace {
        return Err(Status::invalid_argument("canonical namespace required"));
    }
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &namespace, false)?;
    let mut receipt_guard = service.begin_semantic_catalog_invocation(
        &req,
        semantic::CAPABILITY_EXPLAIN_DERIVATION,
        &namespace,
        &principals,
    )?;
    let operation_id = receipt_guard
        .as_ref()
        .map(|(operation_id, _)| operation_id.clone());
    let purpose = request_purpose_presentation(&req, &principals);
    let inner = req.into_inner();
    let from = inner
        .from
        .ok_or_else(|| Status::invalid_argument("from root required"))?;
    let to = inner
        .to
        .ok_or_else(|| Status::invalid_argument("to root required"))?;
    let to_root = from_proto_context_root(to.clone())?;
    let reasoning_mode =
        retrieval::ReasoningMode::parse(&inner.reasoning_mode).map_err(map_retrieval_error)?;
    let retrieved = service.execute_retrieve_context(
        &principals,
        tenant_context.as_ref(),
        purpose.as_ref(),
        RetrieveContextRequest {
            roots: vec![from],
            relations: inner.relations,
            direction: inner.direction,
            max_depth: if inner.max_depth == 0 {
                retrieval::MAX_DEPTH
            } else {
                inner.max_depth
            },
            max_objects: inner.max_objects,
            max_links: inner.max_links,
            kind_filter: Vec::new(),
            reasoning_mode: inner.reasoning_mode,
            max_source_rows: inner.max_source_rows,
            max_derived_rows: inner.max_derived_rows,
            max_derivation_steps: inner.max_derivation_steps,
            max_time_ms: inner.max_time_ms,
            max_explanation_bytes: inner.max_explanation_bytes,
        },
    )?;

    let mut found_explanation = None;
    for candidate in &retrieved.candidates {
        let Some(object) = candidate.object.as_ref() else {
            continue;
        };
        if object.namespace != namespace && !object.namespace.is_empty() {
            continue;
        }
        let matches = match &to_root {
            retrieval::RetrievalRoot::Object(id) => object.id == *id,
            retrieval::RetrievalRoot::External(external_id) => object.external_id == *external_id,
            retrieval::RetrievalRoot::Link(link_id) => retrieved.links.iter().any(|link| {
                link.id == *link_id && (link.from_id == object.id || link.to_id == object.id)
            }),
        };
        if matches {
            found_explanation = candidate.explanation.clone();
            break;
        }
    }

    let mut evidence_refs = Vec::new();
    if let Some(explanation) = found_explanation.as_ref() {
        evidence_refs.extend(explanation.source_fact_ids.iter().cloned());
        for step in &explanation.steps {
            for fact in &step.source_fact_ids {
                if !evidence_refs.contains(fact) {
                    evidence_refs.push(fact.clone());
                }
            }
        }
    }
    evidence_refs.sort();
    evidence_refs.dedup();

    if let Some((_, guard)) = receipt_guard.as_mut() {
        guard.finalize("allow", "succeeded")?;
    }
    let found = found_explanation.is_some();
    let descriptor = found_explanation.as_ref().map(|explanation| {
        to_proto_epistemic_descriptor(&DomainEpistemicDescriptor::from_graph_projection(
            explanation.derived,
            &explanation.source_fact_ids,
            &explanation.ontology_revision,
            retrieved
                .truncation_reasons
                .iter()
                .any(|reason| reason == "source_rows"),
        ))
    });
    let mut response = Response::new(ExplainDerivationResponse {
        explanation: found_explanation,
        found,
        truncated: retrieved.truncated,
        truncation_reasons: retrieved.truncation_reasons,
        ontology_revision: retrieved.ontology_revision,
        reasoning_mode: semantic::reasoning_mode_label(reasoning_mode).into(),
        evidence_refs,
        descriptor,
    });
    if let Some(operation_id) = operation_id.as_deref() {
        response.metadata_mut().insert(
            "x-sekai-operation-id",
            operation_id
                .parse()
                .map_err(|_| Status::internal("invalid operation id"))?,
        );
    }
    Ok(response)
}
pub(super) async fn discover_capabilities(
    service: &SekaiServiceImpl,
    req: Request<DiscoverCapabilitiesRequest>,
) -> Result<Response<DiscoverCapabilitiesResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let namespace = inner.namespace.trim();
    if namespace.is_empty() || namespace != inner.namespace {
        return Err(Status::invalid_argument("canonical namespace required"));
    }
    let requested_tier = inner.product_tier_filter.trim();
    if !requested_tier.is_empty()
        && !matches!(requested_tier, "all" | "core" | "advanced" | "experimental")
    {
        return Err(Status::invalid_argument(
            "product_tier_filter must be empty or one of all|core|advanced|experimental",
        ));
    }
    let tier_filter = if requested_tier.is_empty() {
        "core"
    } else {
        requested_tier
    };
    let contract_version = capability::negotiate_contract_version(&inner.contract_version)
        .map_err(map_capability_error)?;
    let mut entries = service.discoverable_capabilities(namespace, &principals)?;
    if tier_filter != "all" {
        entries.retain(|entry| {
            let tier = if entry.product_tier.trim().is_empty() {
                "advanced"
            } else {
                entry.product_tier.as_str()
            };
            tier == tier_filter
        });
    }
    let mut context = principals.clone();
    context.sort();
    context.dedup();
    context.insert(0, namespace.to_string());
    context.push(format!("product_tier:{tier_filter}"));
    let canonical_entries = entries
        .iter()
        .map(Message::encode_to_vec)
        .collect::<Vec<_>>();
    let catalog_version = capability::snapshot_version(&context, &canonical_entries);
    let offset =
        capability::resolve_offset(&inner.catalog_version, &inner.page_token, &catalog_version)
            .map_err(map_capability_error)?;
    let page_size = capability::page_size(inner.page_size);
    let end = offset.saturating_add(page_size).min(entries.len());
    let capabilities = entries.get(offset..end).unwrap_or_default().to_vec();
    let next_page_token = capability::next_page_token(&catalog_version, end, entries.len());

    Ok(Response::new(DiscoverCapabilitiesResponse {
        capabilities,
        contract_version: contract_version.to_string(),
        catalog_version,
        next_page_token,
        total_size: entries.len().min(u32::MAX as usize) as u32,
        cache_scope: "authorization_context".into(),
    }))
}
pub(super) async fn get_governed_fact_version(
    service: &SekaiServiceImpl,
    req: Request<GetGovernedFactVersionRequest>,
) -> Result<Response<GetGovernedFactVersionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let object_id = req.into_inner().object_id;
    let object = governed_object_for_read(
        service,
        &principals,
        tenant_context.as_ref(),
        &object_id,
        governed_fact_domain::FACT_KIND,
    )?;
    let fact = governed_fact_domain::fact_from_object(&object).map_err(Status::data_loss)?;
    Ok(Response::new(GetGovernedFactVersionResponse {
        fact: Some(to_proto_governed_fact(&fact)),
    }))
}
pub(super) async fn resolve_invariant_set(
    service: &SekaiServiceImpl,
    req: Request<ResolveInvariantSetRequest>,
) -> Result<Response<ResolveInvariantSetResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &inner.namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, &inner.namespace, false)?;
    let profile_object = governed_object_for_read(
        service,
        &principals,
        tenant_context.as_ref(),
        &governed_fact_domain::profile_object_id(&inner.namespace),
        governed_fact_domain::PROFILE_KIND,
    )?;
    let profile =
        governed_fact_domain::profile_from_object(&profile_object).map_err(Status::data_loss)?;
    let mut visibility_cache = HashMap::new();
    let mut visibility_work = 0;
    let facts = list_visible_governed_objects(
        service,
        &principals,
        &inner.namespace,
        governed_fact_domain::FACT_KIND,
        &mut visibility_cache,
        &mut visibility_work,
    )?
    .iter()
    .map(governed_fact_domain::fact_from_object)
    .collect::<Result<Vec<_>, _>>()
    .map_err(Status::data_loss)?;
    let waivers = list_visible_governed_objects(
        service,
        &principals,
        &inner.namespace,
        governed_fact_domain::WAIVER_KIND,
        &mut visibility_cache,
        &mut visibility_work,
    )?
    .iter()
    .map(governed_fact_domain::waiver_from_object)
    .collect::<Result<Vec<_>, _>>()
    .map_err(Status::data_loss)?;
    let invariant_set = governed_fact_domain::resolve_invariant_set(
        &profile,
        facts,
        waivers,
        &inner.subject_profile,
        &inner.subject_ref,
        inner.evaluation_time_ms,
        inner.max_items as usize,
    )
    .map_err(|error| {
        if error.contains("exceeds") {
            Status::resource_exhausted(error)
        } else if error.contains("history is ambiguous") {
            Status::failed_precondition("governed fact resolution unavailable")
        } else {
            Status::invalid_argument(error)
        }
    })?;
    Ok(Response::new(ResolveInvariantSetResponse {
        invariant_set: Some(to_proto_invariant_set(&invariant_set)),
    }))
}
pub(super) async fn list_schema_types(
    service: &SekaiServiceImpl,
    req: Request<ListSchemaTypesRequest>,
) -> Result<Response<ListSchemaTypesResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let types = service
        .schema_definitions
        .refresh_snapshot()
        .map_err(map_schema_definition_lifecycle_error)?
        .all()
        .iter()
        .filter(|object_type| {
            check_read(
                &service.security,
                &schema_object_id(&object_type.kind),
                &principals,
            )
            .is_ok()
        })
        .map(to_proto_schema_type)
        .collect();
    Ok(Response::new(ListSchemaTypesResponse { types }))
}
pub(super) async fn create_schema_type(
    service: &SekaiServiceImpl,
    req: Request<CreateSchemaTypeRequest>,
) -> Result<Response<CreateSchemaTypeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let object_type = req
        .into_inner()
        .r#type
        .ok_or(Status::invalid_argument("schema type required"))?;
    let parsed = from_proto_schema_type(&object_type)?;
    check_schema_admin(&service.security, &parsed.kind, &principals)?;
    let parsed = service
        .schema_definitions
        .put_definition(parsed)
        .map_err(map_schema_definition_lifecycle_error)?;
    Ok(Response::new(CreateSchemaTypeResponse {
        r#type: Some(to_proto_schema_type(&parsed)),
    }))
}
pub(super) async fn list_ontology_classes(
    service: &SekaiServiceImpl,
    req: Request<ListOntologyClassesRequest>,
) -> Result<Response<ListOntologyClassesResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let classes = service
        .db
        .runtime()
        .list_ontology_classes()
        .map_err(Status::internal)?
        .iter()
        .filter(|class| check_ontology_class_read(&service.security, class, &principals).is_ok())
        .map(to_proto_ontology_class)
        .collect();
    Ok(Response::new(ListOntologyClassesResponse { classes }))
}
pub(super) async fn get_ontology_class(
    service: &SekaiServiceImpl,
    req: Request<GetOntologyClassRequest>,
) -> Result<Response<GetOntologyClassResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let name = req.into_inner().name;
    if name.trim().is_empty() {
        return Err(Status::invalid_argument("class name required"));
    }
    check_read(
        &service.security,
        &ontology_class_object_id(&name),
        &principals,
    )?;
    let class = service
        .db
        .runtime()
        .get_ontology_class(&name)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("ontology class not found"))?;
    check_ontology_class_read(&service.security, &class, &principals)?;
    Ok(Response::new(GetOntologyClassResponse {
        class: Some(to_proto_ontology_class(&class)),
    }))
}
pub(super) async fn create_ontology_class(
    service: &SekaiServiceImpl,
    req: Request<CreateOntologyClassRequest>,
) -> Result<Response<CreateOntologyClassResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let proto = req
        .into_inner()
        .class
        .ok_or(Status::invalid_argument("class required"))?;
    let parsed = from_proto_ontology_class(&proto)?;
    let parsed = service.create_ontology_class_definition(&principals, parsed)?;
    Ok(Response::new(CreateOntologyClassResponse {
        class: Some(to_proto_ontology_class(&parsed)),
    }))
}
pub(super) async fn delete_ontology_class(
    service: &SekaiServiceImpl,
    req: Request<DeleteOntologyClassRequest>,
) -> Result<Response<DeleteOntologyClassResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let name = req.into_inner().name;
    if name.trim().is_empty() {
        return Err(Status::invalid_argument("class name required"));
    }
    service.delete_ontology_class_definition(&principals, &name)?;
    Ok(Response::new(DeleteOntologyClassResponse {}))
}
pub(super) async fn list_ontology_relations(
    service: &SekaiServiceImpl,
    req: Request<ListOntologyRelationsRequest>,
) -> Result<Response<ListOntologyRelationsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let relations = service
        .db
        .runtime()
        .list_ontology_relations()
        .map_err(Status::internal)?
        .iter()
        .filter(|relation| {
            check_ontology_relation_read(&service.security, relation, &principals).is_ok()
        })
        .map(to_proto_ontology_relation)
        .collect();
    Ok(Response::new(ListOntologyRelationsResponse { relations }))
}
pub(super) async fn get_ontology_relation(
    service: &SekaiServiceImpl,
    req: Request<GetOntologyRelationRequest>,
) -> Result<Response<GetOntologyRelationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let name = req.into_inner().name;
    if name.trim().is_empty() {
        return Err(Status::invalid_argument("relation name required"));
    }
    check_read(
        &service.security,
        &ontology_relation_object_id(&name),
        &principals,
    )?;
    let relation = service
        .db
        .runtime()
        .get_ontology_relation(&name)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("ontology relation not found"))?;
    check_ontology_relation_read(&service.security, &relation, &principals)?;
    Ok(Response::new(GetOntologyRelationResponse {
        relation: Some(to_proto_ontology_relation(&relation)),
    }))
}
pub(super) async fn create_ontology_relation(
    service: &SekaiServiceImpl,
    req: Request<CreateOntologyRelationRequest>,
) -> Result<Response<CreateOntologyRelationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let proto = req
        .into_inner()
        .relation
        .ok_or(Status::invalid_argument("relation required"))?;
    let parsed = from_proto_ontology_relation(&proto)?;
    let parsed = service.create_ontology_relation_definition(&principals, parsed)?;
    Ok(Response::new(CreateOntologyRelationResponse {
        relation: Some(to_proto_ontology_relation(&parsed)),
    }))
}
pub(super) async fn delete_ontology_relation(
    service: &SekaiServiceImpl,
    req: Request<DeleteOntologyRelationRequest>,
) -> Result<Response<DeleteOntologyRelationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let name = req.into_inner().name;
    if name.trim().is_empty() {
        return Err(Status::invalid_argument("relation name required"));
    }
    service.delete_ontology_relation_definition(&principals, &name)?;
    Ok(Response::new(DeleteOntologyRelationResponse {}))
}
