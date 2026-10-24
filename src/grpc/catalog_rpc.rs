//! RegisterCatalogEntry (#1559, ADR 0122).

use super::*;
use crate::sekai::catalog::{self, CatalogError, CatalogRegistration, EntryKind};

pub(super) async fn register_catalog_entry(
    service: &SekaiServiceImpl,
    req: Request<RegisterCatalogEntryRequest>,
) -> Result<Response<RegisterCatalogEntryResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let db = service.db.runtime();
    let tenant_context = request_tenant_context(db, &req)?;
    let purpose = request_purpose_presentation(&req, &principals);
    let policy_context = principal_policy_context(&req);
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    refuse_frozen_object_write(
        db,
        &input.namespace,
        &principals,
        tenant_context.as_ref(),
        crate::enterprise::NamespaceAction::Write,
    )?;
    if input.source_system == catalog::ONTOLOGY_SOURCE {
        return Err(Status::invalid_argument(
            "the ontology registers its own object types",
        ));
    }
    let registration = CatalogRegistration {
        entry_kind: EntryKind::parse(&input.entry_kind).map_err(Status::invalid_argument)?,
        namespace: input.namespace,
        source_system: input.source_system,
        source_id: input.source_id,
        display_name: input.display_name,
        description: input.description,
        owners: input.owners,
        steward: input.steward,
        tags: input.tags,
        marking: input.access_marking,
        schema_summary: input.schema_summary,
        freshness_ms: input.freshness_ms,
        deprecated: input.deprecated,
        source_generation: 0,
        binding: match input.binding {
            Some(binding)
                if !binding.kind.is_empty()
                    || !binding.target_id.is_empty()
                    || !binding.source_type_descriptor_id.is_empty() =>
            {
                Some(
                    catalog::CatalogBinding::parse(
                        &binding.kind,
                        &binding.target_id,
                        &binding.source_type_descriptor_id,
                    )
                    .map_err(|error| match error {
                        CatalogError::Invalid(message) => Status::invalid_argument(message),
                        other => Status::internal(format!("{other:?}")),
                    })?,
                )
            }
            _ => None,
        },
    };
    if let Some(binding) = &registration.binding {
        let already_bound = db
            .get_object(&registration.entry_id())
            .ok()
            .flatten()
            .as_ref()
            .and_then(catalog::binding_from_entry)
            .is_some();
        if !already_bound
            && !binding_discoverable_for_caller(
                service,
                &principals,
                tenant_context.as_ref(),
                &registration.namespace,
                binding,
            )
        {
            return Err(Status::invalid_argument(
                "catalog binding target does not exist",
            ));
        }
    }
    let actor = principals.first().cloned().unwrap_or_default();
    let policy_generation = object_security_generation(db, &registration.namespace)?;
    // The stored entry is checked like any object update (ACL, markings,
    // object security policy), and the proposed one like the write it is.
    let authorize = |existing: Option<&domain::Object>, proposed: &mut domain::Object| {
        let denied = |status: Status| CatalogError::Denied(status.message().to_string());
        use crate::sekai::object_security::ObjectSecurityOperation::{Create, Update};
        // Property and value-instance write grants and schema-restricted
        // properties first, for the delegated actor too: they may keep stored
        // values, and every check below then sees what will be persisted.
        enforce_property_grant_mutation(db, existing, proposed).map_err(denied)?;
        let schema = service
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)
            .map_err(denied)?;
        let act = tenant_context
            .as_ref()
            .and_then(|context| context.act.clone());
        for writer in std::iter::once(principals.clone()).chain(act.map(|actor| vec![actor])) {
            if existing.is_some() {
                preserve_redacted_restricted_properties(
                    db,
                    &schema,
                    &service.security,
                    &writer,
                    proposed,
                )
                .map_err(denied)?;
            } else {
                ensure_restricted_create_properties_allowed(
                    &schema,
                    &service.security,
                    &writer,
                    proposed,
                )
                .map_err(denied)?;
            }
        }
        if let Some(existing) = existing {
            check_write(&service.security, &existing.id, &principals).map_err(denied)?;
            // Changing a property an object security policy reads needs the
            // same authority as on any other update.
            ensure_policy_driving_update_allowed(
                db,
                &service.security,
                existing,
                &*proposed,
                &principals,
            )
            .map_err(denied)?;
            if let Some(actor) = tenant_context
                .as_ref()
                .and_then(|context| context.act.as_ref())
            {
                ensure_policy_driving_update_allowed(
                    db,
                    &service.security,
                    existing,
                    &*proposed,
                    std::slice::from_ref(actor),
                )
                .map_err(denied)?;
            }
            enforce_object_operation_access(
                db,
                existing,
                &principals,
                tenant_context.as_ref(),
                Update,
                "register_catalog_entry",
                purpose.as_ref(),
            )
            .map_err(denied)?;
        }
        enforce_object_operation_access(
            db,
            proposed,
            &principals,
            tenant_context.as_ref(),
            if existing.is_some() { Update } else { Create },
            "register_catalog_entry",
            purpose.as_ref(),
        )
        .map_err(denied)?;
        Ok(())
    };
    let registered = catalog::register(
        db,
        registration,
        &actor,
        now_millis(),
        Some(&policy_generation),
        authorize,
    )
    .map_err(|error| match error {
        CatalogError::Invalid(message) => Status::invalid_argument(message),
        CatalogError::Denied(_) => Status::permission_denied("access denied"),
        CatalogError::Conflict | CatalogError::Superseded => {
            Status::failed_precondition("catalog entry changed during registration; retry")
        }
        CatalogError::Storage(message) => {
            if message.starts_with("object_security_denied") {
                Status::permission_denied("access denied")
            } else {
                Status::internal(message)
            }
        }
    })?;
    // The entry is returned only to a caller who may read it, and as a read
    // would show it.
    let readable = object_is_visible_for_purpose(
        db,
        &service.security,
        &registered.entry,
        &principals,
        tenant_context.as_ref(),
        crate::sekai::object_security::ObjectSecurityOperation::Read,
        purpose.as_ref(),
    );
    let shown = if readable {
        Some(to_proto_obj(
            &service.resolve_computed_for_response_with_policy(
                registered.entry,
                &principals,
                Some(&policy_context),
                tenant_context.as_ref(),
                purpose.as_ref(),
            )?,
        ))
    } else {
        None
    };
    Ok(Response::new(RegisterCatalogEntryResponse {
        entry: shown,
        changed: registered.changed,
    }))
}

pub(super) async fn get_catalog_entry_lineage(
    service: &SekaiServiceImpl,
    req: Request<GetCatalogEntryLineageRequest>,
) -> Result<Response<GetCatalogEntryLineageResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let db = service.db.runtime();
    let tenant_context = request_tenant_context(db, &req)?;
    let purpose = request_purpose_presentation(&req, &principals);
    let policy_context = principal_policy_context(&req);
    let input = req.into_inner();
    require_canonical_source_namespace(&input.namespace)?;
    enforce_namespace_tenant_context_for(
        db,
        tenant_context.as_ref(),
        &input.namespace,
        crate::enterprise::NamespaceAction::Discover,
    )?;
    check_team_namespace(db, &principals, &input.namespace, false)?;
    let depth =
        crate::sekai::catalog_lineage::parse_depth(input.depth).map_err(|error| match error {
            CatalogError::Invalid(message) => Status::invalid_argument(message),
            other => Status::internal(format!("{other:?}")),
        })?;
    let (page_size, offset) =
        crate::sekai::catalog_lineage::parse_page(input.page_size, &input.page_token).map_err(
            |error| match error {
                CatalogError::Invalid(message) => Status::invalid_argument(message),
                other => Status::internal(format!("{other:?}")),
            },
        )?;
    let entry = db
        .get_object(&input.entry_id)
        .map_err(|_| Status::internal("catalog entry unavailable"))?
        .ok_or_else(|| Status::not_found("catalog entry unavailable"))?;
    if entry.kind != catalog::CATALOG_ENTRY_KIND || entry.namespace != input.namespace {
        return Err(Status::not_found("catalog entry unavailable"));
    }
    if !object_is_visible_for_purpose(
        db,
        &service.security,
        &entry,
        &principals,
        tenant_context.as_ref(),
        crate::sekai::object_security::ObjectSecurityOperation::Read,
        purpose.as_ref(),
    ) {
        return Err(Status::not_found("catalog entry unavailable"));
    }
    let page = crate::sekai::catalog_lineage::walk_lineage(
        db,
        &entry,
        depth,
        page_size,
        offset,
        |candidate| {
            object_is_visible_for_purpose(
                db,
                &service.security,
                candidate,
                &principals,
                tenant_context.as_ref(),
                crate::sekai::object_security::ObjectSecurityOperation::Read,
                purpose.as_ref(),
            )
        },
        |binding| {
            binding_discoverable_for_caller(
                service,
                &principals,
                tenant_context.as_ref(),
                &input.namespace,
                binding,
            )
        },
    )
    .map_err(|error| match error {
        CatalogError::Invalid(message) => Status::invalid_argument(message),
        CatalogError::Storage(message) => Status::internal(message),
        other => Status::internal(format!("{other:?}")),
    })?;
    let to_node =
        |node: crate::sekai::catalog_lineage::LineageNode| -> Result<CatalogLineageNode, Status> {
            Ok(CatalogLineageNode {
                entry: match node.entry {
                    Some(entry) => Some(to_proto_obj(
                        &service.resolve_computed_for_response_with_policy(
                            entry,
                            &principals,
                            Some(&policy_context),
                            tenant_context.as_ref(),
                            purpose.as_ref(),
                        )?,
                    )),
                    None => None,
                },
                redacted: node.redacted,
                entry_kind: node.entry_kind,
            })
        };
    Ok(Response::new(GetCatalogEntryLineageResponse {
        has_binding: page.has_binding,
        upstream: page
            .upstream
            .into_iter()
            .map(to_node)
            .collect::<Result<Vec<_>, _>>()?,
        downstream: page
            .downstream
            .into_iter()
            .map(to_node)
            .collect::<Result<Vec<_>, _>>()?,
        next_page_token: page.next_page_token,
    }))
}

/// Discover access for a bound core artifact. Datasets use the same bar as
/// `ListDatasets`; other kinds are namespace-scoped existence plus live/published.
fn binding_discoverable_for_caller(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    binding: &catalog::CatalogBinding,
) -> bool {
    if catalog::validate_binding_target(service.db.runtime(), namespace, binding).is_err() {
        return false;
    }
    let db = service.db.runtime();
    match binding.kind {
        catalog::BindingKind::Dataset => {
            let Ok(Some(dataset)) = db.get_dataset(&binding.target_id) else {
                return false;
            };
            check_dataset_access(db, &service.security, principals, &dataset, false).is_ok()
                && catalog_binding_discoverable(
                    db,
                    &service.security,
                    tenant_context,
                    &dataset.object_id,
                    principals,
                )
        }
        catalog::BindingKind::ObjectType => {
            let object_id = definition_member_object_id("object_type", &binding.target_id);
            check_read(&service.security, &object_id, principals).is_ok()
                && catalog_binding_discoverable(
                    db,
                    &service.security,
                    tenant_context,
                    &object_id,
                    principals,
                )
        }
        catalog::BindingKind::Transform | catalog::BindingKind::Source => true,
    }
}

/// Catalog-attributed invocation helpers shared by the semantic RPCs.
impl SekaiServiceImpl {
    pub(super) fn catalog_metadata_value(
        req: &Request<impl prost::Message>,
        key: &str,
    ) -> Option<String> {
        req.metadata()
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    /// MCP link tools send `x-sekai-capability` as `sekai.links.get` /
    /// `sekai.links.create`. Direct gRPC and the HTTP gateway also carry
    /// `x-sekai-namespace`; only the MCP tools bind object ids to it.
    pub(super) fn mcp_link_session_namespace(req: &Request<impl prost::Message>) -> Option<String> {
        match Self::catalog_metadata_value(req, "x-sekai-capability").as_deref() {
            Some("sekai.links.get") | Some("sekai.links.create") => {
                Self::catalog_metadata_value(req, "x-sekai-namespace")
            }
            _ => None,
        }
    }

    /// Begin a receipt-attributed catalog invocation for a semantic capability.
    /// Returns `None` when the caller did not send `x-sekai-capability` (direct RPC).
    /// Live discovery is rechecked; a previously observed catalog is never a grant.
    pub(super) fn begin_semantic_catalog_invocation<'a>(
        &'a self,
        req: &Request<impl prost::Message + 'static>,
        expected_capability: &str,
        namespace: &str,
        principals: &[String],
    ) -> Result<Option<(String, CatalogInvocation<'a>)>, Status> {
        let Some(capability_name) = Self::catalog_metadata_value(req, "x-sekai-capability") else {
            return Ok(None);
        };
        let catalog_namespace = Self::catalog_metadata_value(req, "x-sekai-namespace")
            .unwrap_or_else(|| namespace.to_string());
        if catalog_namespace.is_empty() {
            return Err(Status::invalid_argument(
                "catalog semantic invocation requires namespace",
            ));
        }
        if catalog_namespace != namespace && !namespace.is_empty() {
            return Err(Status::invalid_argument(
                "catalog namespace metadata must match request namespace",
            ));
        }
        let namespace = if namespace.is_empty() {
            catalog_namespace.as_str()
        } else {
            namespace
        };
        let operation_id = Self::catalog_metadata_value(req, "x-sekai-operation-id")
            .unwrap_or_else(|| format!("catalog-invocation-{}", Uuid::new_v4().simple()));
        let catalog_version = Self::catalog_metadata_value(req, "x-sekai-catalog-version");
        let actor = principals.first().cloned().unwrap_or_default();

        let tenant_context = request_tenant_context(self.db.runtime(), req)?;
        let visible = self
            .discoverable_capabilities(namespace, principals, tenant_context.as_ref())?
            .into_iter()
            .any(|entry| entry.name == capability_name && capability_name == expected_capability);
        if !visible {
            CatalogInvocation::record_refusal(
                self.db.runtime(),
                &operation_id,
                namespace,
                &actor,
                &capability_name,
                catalog_version.as_deref(),
                "capability_unavailable",
            )?;
            return Err(Status::failed_precondition("capability unavailable"));
        }

        let invocation = CatalogInvocation::begin(
            self.db.runtime(),
            operation_id.clone(),
            namespace,
            actor,
            capability_name,
            catalog_version,
        )?;
        Ok(Some((operation_id, invocation)))
    }
}
