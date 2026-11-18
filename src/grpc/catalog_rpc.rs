//! RegisterCatalogEntry (#1559, ADR 0122).

use super::*;
use crate::sekai::catalog::{self, CatalogError, CatalogRegistration, EntryKind};
use crate::sekai::catalog_criticality;

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

/// Most outbox rows one `ListCatalogCriticalityOutbox` request reads, however
/// few of them the caller may see.
const MAX_OUTBOX_SCAN_ROWS: usize = 1_000;

/// Collect up to `page_size` visible events, reading at most
/// [`MAX_OUTBOX_SCAN_ROWS`] rows. `accept` maps a row to the event to return,
/// or `None` for a row the caller may not see. A page that ends early on the
/// scan bound still carries a token at the last row read, so the caller resumes
/// after it instead of mistaking the page for the end of the outbox.
fn scan_outbox_page(
    page_size: usize,
    mut page_token: String,
    mut fetch: impl FnMut(&str) -> Result<(Vec<catalog_criticality::CriticalityEvent>, String), Status>,
    mut accept: impl FnMut(
        &catalog_criticality::CriticalityEvent,
    ) -> Result<Option<CatalogCriticalityEvent>, Status>,
) -> Result<(Vec<CatalogCriticalityEvent>, String), Status> {
    let mut visible = Vec::new();
    let mut scanned = 0usize;
    loop {
        let (events, next) = fetch(&page_token)?;
        for event in events {
            scanned += 1;
            visible.extend(accept(&event)?);
            if visible.len() >= page_size || scanned >= MAX_OUTBOX_SCAN_ROWS {
                let token =
                    catalog_criticality::encode_page_token(event.created_at_ms, &event.event_id);
                return Ok((visible, token));
            }
        }
        if next.is_empty() {
            return Ok((visible, String::new()));
        }
        page_token = next;
    }
}

pub(super) async fn list_catalog_criticality_outbox(
    service: &SekaiServiceImpl,
    req: Request<ListCatalogCriticalityOutboxRequest>,
) -> Result<Response<ListCatalogCriticalityOutboxResponse>, Status> {
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
    let page_size =
        crate::sekai::catalog_criticality::clamp_page_size(input.page_size).map_err(|error| {
            match error {
                CatalogError::Invalid(message) => Status::invalid_argument(message),
                other => Status::internal(format!("{other:?}")),
            }
        })?;
    let (events, next_page_token) = scan_outbox_page(
        page_size as usize,
        input.page_token,
        |token| {
            db.list_catalog_criticality_outbox(&input.namespace, page_size, token)
                .map_err(Status::internal)
        },
        |event| {
            let Some(entry) = db
                .get_object(&event.entry_id)
                .map_err(|_| Status::internal("catalog entry unavailable"))?
            else {
                return Ok(None);
            };
            if entry.kind != catalog::CATALOG_ENTRY_KIND || entry.namespace != input.namespace {
                return Ok(None);
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
                return Ok(None);
            }
            let projected = match service.resolve_computed_for_response_with_policy(
                entry,
                &principals,
                Some(&policy_context),
                tenant_context.as_ref(),
                purpose.as_ref(),
            ) {
                Ok(object) => object,
                Err(status) if status.code() == tonic::Code::PermissionDenied => return Ok(None),
                Err(status) => return Err(status),
            };
            let matches_source = projected
                .properties
                .get("source_system")
                .map(String::as_str)
                == Some(event.source_system.as_str())
                && projected.properties.get("source_id").map(String::as_str)
                    == Some(event.source_id.as_str());
            Ok(matches_source.then(|| CatalogCriticalityEvent {
                event_id: event.event_id.clone(),
                namespace: event.namespace.clone(),
                entry_id: event.entry_id.clone(),
                entry_kind: event.entry_kind.clone(),
                source_system: event.source_system.clone(),
                source_id: event.source_id.clone(),
                declared: event.declared.clone(),
                derived: event.derived.clone(),
                effective: event.effective.clone(),
                evidence_digest: event.evidence_digest.clone(),
                created_at_ms: event.created_at_ms,
                seq: event.seq,
            }))
        },
    )?;
    Ok(Response::new(ListCatalogCriticalityOutboxResponse {
        events,
        next_page_token,
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
    pub(super) fn catalog_metadata_value<T>(req: &Request<T>, key: &str) -> Option<String> {
        req.metadata()
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    /// The namespace an MCP session binds object ids to. The MCP link, lineage,
    /// and neighborhood tools send their name as `x-sekai-capability`; direct
    /// gRPC and the HTTP gateway also carry `x-sekai-namespace`, but only these
    /// tools are confined to it.
    pub(super) fn mcp_session_namespace<T>(req: &Request<T>) -> Option<String> {
        match Self::catalog_metadata_value(req, "x-sekai-capability").as_deref() {
            Some(
                "sekai.links.get"
                | "sekai.links.create"
                | "sekai.lineage.get"
                | super::graph_explore_rpc::NEIGHBORHOOD_CAPABILITY,
            ) => Self::catalog_metadata_value(req, "x-sekai-namespace"),
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

#[cfg(test)]
mod outbox_scan_tests {
    use super::*;
    use crate::sekai::catalog_criticality::{CriticalityEvent, decode_page_token};

    fn event(n: i64) -> CriticalityEvent {
        CriticalityEvent {
            event_id: format!("e{n:06}"),
            namespace: "acme".into(),
            entry_id: format!("entry-{n}"),
            entry_kind: "service".into(),
            source_system: "sys".into(),
            source_id: format!("id-{n}"),
            seq: n,
            declared: String::new(),
            derived: String::new(),
            effective: String::new(),
            evidence_digest: String::new(),
            created_at_ms: 1_000_000 - n,
        }
    }

    /// Outbox of `total` rows newest first, served `size` at a time like the store.
    fn fetch_from(
        total: i64,
        size: usize,
        fetched: &std::cell::Cell<usize>,
    ) -> impl FnMut(&str) -> Result<(Vec<CriticalityEvent>, String), Status> + '_ {
        move |token| {
            let start = if token.is_empty() {
                0
            } else {
                let (created, _) = decode_page_token(token).unwrap().unwrap();
                (1_000_000 - created + 1) as usize
            };
            let rows: Vec<_> = (start as i64..total).take(size).map(event).collect();
            fetched.set(fetched.get() + rows.len());
            let next = match rows.last() {
                Some(last) if (start + rows.len()) < total as usize => {
                    catalog_criticality::encode_page_token(last.created_at_ms, &last.event_id)
                }
                _ => String::new(),
            };
            Ok((rows, next))
        }
    }

    fn projected(event: &CriticalityEvent) -> CatalogCriticalityEvent {
        CatalogCriticalityEvent {
            event_id: event.event_id.clone(),
            created_at_ms: event.created_at_ms,
            seq: event.seq,
            ..Default::default()
        }
    }

    #[test]
    fn a_mostly_invisible_outbox_stops_at_the_scan_bound_with_a_resume_token() {
        let fetched = std::cell::Cell::new(0);
        let total = 5_000;
        let (page, token) =
            scan_outbox_page(1, String::new(), fetch_from(total, 10, &fetched), |_| {
                Ok(None)
            })
            .unwrap();
        assert!(page.is_empty());
        assert_eq!(fetched.get(), 1_000);
        let (_, last_event_id) = decode_page_token(&token).unwrap().unwrap();
        assert_eq!(last_event_id, "e000999");

        // The token resumes after the last scanned row and can reach a visible event.
        let visible_at = 1_003;
        let (resumed, _) = scan_outbox_page(1, token, fetch_from(total, 10, &fetched), |event| {
            Ok((event.seq == visible_at).then(|| projected(event)))
        })
        .unwrap();
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].seq, visible_at);
    }

    #[test]
    fn a_short_outbox_ends_with_an_empty_token() {
        let fetched = std::cell::Cell::new(0);
        let (page, token) =
            scan_outbox_page(5, String::new(), fetch_from(3, 10, &fetched), |event| {
                Ok(Some(projected(event)))
            })
            .unwrap();
        assert_eq!(page.len(), 3);
        assert!(token.is_empty());
    }
}
