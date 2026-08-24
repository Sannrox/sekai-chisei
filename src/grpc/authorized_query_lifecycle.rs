//! Authorized graph and object query behind one private interface.
//!
//! The gRPC adapter authenticates the caller and projects protobuf. This module
//! owns tenant, team-namespace, ACL, marking, reserved-kind, computed-property,
//! and restricted-property filtering for get, list, find, links, traverse, and
//! lineage reads.

use super::*;

impl SekaiServiceImpl {
    pub(super) async fn get_visible_object(
        &self,
        req: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let policy_context = principal_policy_context(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let id = req.into_inner().id;
        let obj = self
            .db
            .get_object_with_policy_context(&id, &policy_context)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        let namespace = obj.namespace.clone();
        let visibility = require_visible_read_root(
            &self.db,
            &self.security,
            obj,
            &principals,
            tenant_context.as_ref(),
            &format!("get_object:{id}"),
        );
        let (obj, marking) = match visibility {
            Ok(visible) => visible,
            Err(status) if status.code() == tonic::Code::PermissionDenied => {
                let activated = self
                    .db
                    .get_object_security_activation(&namespace)
                    .map_err(Status::internal)?
                    .is_some();
                return Err(map_direct_read_visibility_error(activated, status));
            }
            Err(status) => return Err(status),
        };
        if marking.decision != markings::MarkingDecision::NotApplicable {
            let actor = principals.first().cloned().unwrap_or_default();
            let mut evidence = HashMap::new();
            if let Some(value) = &marking.object_classification {
                evidence.insert("object_classification".into(), value.clone());
            }
            if let Some(value) = &marking.principal_ceiling {
                evidence.insert("principal_ceiling".into(), value.clone());
            }
            evidence.insert("detail".into(), marking.detail.clone());
            record_marking_or_purpose_decision(
                &self.db,
                &actor,
                "marking.read",
                &obj.id,
                &marking.decision_id,
                "allowed",
                evidence,
            )?;
        }
        let obj = self.resolve_computed_for_response_with_policy(
            obj,
            &principals,
            Some(&policy_context),
            tenant_context.as_ref(),
        )?;
        Ok(Response::new(GetObjectResponse {
            object: Some(to_proto_obj(&obj)),
        }))
    }
    pub(super) async fn list_visible_objects(
        &self,
        req: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let policy_context = principal_policy_context(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let invoked_capability = req
            .metadata()
            .get("x-sekai-capability")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let requested_operation_id = req
            .metadata()
            .get("x-sekai-operation-id")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let catalog_version = req
            .metadata()
            .get("x-sekai-catalog-version")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let input = req.into_inner();
        let mut filter = parse_list_filter(input.filter.unwrap_or_default())?;
        let policy_revision = self
            .db
            .policy_cursor_binding(filter.namespace.as_deref())
            .map_err(Status::internal)?;
        let query_digest = crate::sekai::object_security::list_query_digest(&filter);
        let now_ms = now_millis();
        if !input.page_token.trim().is_empty() {
            let token =
                crate::sekai::object_security::ObjectListPageToken::decode(&input.page_token)
                    .map_err(Status::failed_precondition)?;
            token
                .validate(
                    &policy_context,
                    filter.namespace.as_deref().unwrap_or_default(),
                    &policy_revision,
                    &query_digest,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?;
            filter.offset = token.offset;
        }
        if tenant_context.is_some() {
            let namespace = filter.namespace.as_deref().ok_or_else(|| {
                Status::permission_denied("tenant context requires an explicit namespace filter")
            })?;
            enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), namespace, false)?;
        }
        let operation_id = invoked_capability.as_ref().map(|_| {
            requested_operation_id
                .unwrap_or_else(|| format!("catalog-invocation-{}", Uuid::new_v4().simple()))
        });
        let mut receipt_guard = None;
        if let Some(capability_name) = &invoked_capability {
            let namespace = filter.namespace.as_deref().ok_or_else(|| {
                Status::invalid_argument("catalog invocation requires a namespace filter")
            })?;
            let kind = filter.kind.as_deref().ok_or_else(|| {
                Status::invalid_argument("catalog object query requires a kind filter")
            })?;
            let operation_id = operation_id.as_ref().unwrap();
            let actor = principals.first().cloned().unwrap_or_default();
            receipt_guard = Some(CatalogInvocation::begin(
                &self.db,
                operation_id.clone(),
                namespace,
                actor,
                capability_name.clone(),
                catalog_version.clone(),
            )?);
            let expected = format!("sekai.objects.query.{kind}");
            if capability_name != &expected
                || !self
                    .discoverable_capabilities(namespace, &principals)?
                    .iter()
                    .any(|entry| entry.name == *capability_name)
            {
                return Err(Status::failed_precondition("capability unavailable"));
            }
        }
        if is_managed_team_principal(&self.db, &principals)? {
            let namespace = filter.namespace.as_deref().ok_or_else(|| {
                Status::permission_denied("team principals must filter by namespace")
            })?;
            check_team_namespace(&self.db, &principals, namespace, false)?;
        }
        // Never expose internal governance objects through generic listing.
        if filter
            .kind
            .as_deref()
            .is_some_and(is_reserved_governance_kind)
        {
            return Ok(Response::new(ListObjectsResponse {
                objects: Vec::new(),
                total: 0,
                next_page_token: String::new(),
            }));
        }
        {
            let schema = self
                .schema_definitions
                .snapshot()
                .map_err(map_schema_definition_lifecycle_error)?;
            let mut queried_properties = filter
                .property_filters
                .iter()
                .map(|property_filter| property_filter.key.clone())
                .collect::<Vec<_>>();
            if let Some(order_property) = queried_order_property(&filter.order_by) {
                queried_properties.push(order_property);
            }
            ensure_property_query_allowed(
                &schema,
                &principals,
                filter.kind.as_deref().unwrap_or_default(),
                queried_properties,
            )?;
        }
        // The API now defaults paging at 100 rows when no limit is provided;
        // DB callers using list_objects(&filter) remain unchanged.
        let (objects, total) = list_objects_with_marking(
            &self.db,
            &filter,
            &principals,
            &policy_context,
            tenant_context.as_ref(),
            |objects, principals, tenant_context| {
                self.resolve_computed_for_responses_with_policy(
                    objects,
                    principals,
                    Some(&policy_context),
                    tenant_context,
                )
            },
        )?;
        let next_page_token = if !objects.is_empty() {
            let consumed = filter.offset.saturating_add(objects.len() as i32);
            if consumed < total {
                crate::sekai::object_security::ObjectListPageToken {
                    principal_digest: policy_context.digest(),
                    namespace: filter.namespace.clone().unwrap_or_default(),
                    policy_revision,
                    query_digest,
                    offset: consumed,
                    expiry_ms: now_ms
                        + crate::sekai::object_security::OBJECT_LIST_PAGE_TOKEN_TTL_MS,
                }
                .encode()
                .unwrap_or_default()
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        let mut response = Response::new(ListObjectsResponse {
            objects: objects.iter().map(to_proto_obj).collect(),
            total,
            next_page_token,
        });
        if let (Some(_), Some(operation_id)) =
            (invoked_capability.as_deref(), operation_id.as_deref())
        {
            receipt_guard
                .as_mut()
                .unwrap()
                .finalize("allow", "succeeded")?;
            response.metadata_mut().insert(
                "x-sekai-operation-id",
                operation_id
                    .parse()
                    .map_err(|_| Status::internal("invalid operation id"))?,
            );
        }
        Ok(response)
    }
    pub(super) async fn find_visible_by_external_id(
        &self,
        req: Request<FindByExternalIdRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let policy_context = principal_policy_context(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let external_id = req.into_inner().external_id;
        let candidates = self
            .db
            .find_all_by_external_id(&external_id)
            .map_err(Status::internal)?;
        let mut first_acl_denied = None;
        for candidate in candidates {
            if tenant_context.is_some()
                && !object_is_visible(
                    &self.db,
                    &self.security,
                    &candidate,
                    &principals,
                    tenant_context.as_ref(),
                )
            {
                continue;
            }
            let Some(obj) = self
                .db
                .get_object_with_policy_context(&candidate.id, &policy_context)
                .map_err(Status::internal)?
            else {
                continue;
            };
            let namespace = obj.namespace.clone();
            let visibility = require_visible_read_root(
                &self.db,
                &self.security,
                obj,
                &principals,
                tenant_context.as_ref(),
                &format!("find_by_external_id:{}", candidate.id),
            );
            let (obj, marking) = match visibility {
                Ok(visible) => visible,
                Err(status) if status.code() == tonic::Code::PermissionDenied => {
                    let activated = self
                        .db
                        .get_object_security_activation(&namespace)
                        .map_err(Status::internal)?
                        .is_some();
                    let mapped = map_direct_read_visibility_error(activated, status);
                    if mapped.code() == tonic::Code::NotFound {
                        continue;
                    }
                    first_acl_denied.get_or_insert(mapped);
                    continue;
                }
                Err(status) => return Err(status),
            };
            if marking.decision != markings::MarkingDecision::NotApplicable {
                let actor = principals.first().cloned().unwrap_or_default();
                let mut evidence = HashMap::new();
                if let Some(value) = &marking.object_classification {
                    evidence.insert("object_classification".into(), value.clone());
                }
                if let Some(value) = &marking.principal_ceiling {
                    evidence.insert("principal_ceiling".into(), value.clone());
                }
                evidence.insert("detail".into(), marking.detail.clone());
                record_marking_or_purpose_decision(
                    &self.db,
                    &actor,
                    "marking.read",
                    &obj.id,
                    &marking.decision_id,
                    "allowed",
                    evidence,
                )?;
            }
            let obj = self.resolve_computed_for_response_with_policy(
                obj,
                &principals,
                Some(&policy_context),
                tenant_context.as_ref(),
            )?;
            return Ok(Response::new(GetObjectResponse {
                object: Some(to_proto_obj(&obj)),
            }));
        }
        if let Some(status) = first_acl_denied {
            return Err(status);
        }
        Err(Status::not_found("not found"))
    }
    pub(super) async fn find_visible_by_property(
        &self,
        req: Request<FindByPropertyRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let policy_context = principal_policy_context(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let r = req.into_inner();
        if is_reserved_governance_kind(&r.kind) {
            return Ok(Response::new(ListObjectsResponse {
                objects: Vec::new(),
                total: 0,
                next_page_token: String::new(),
            }));
        }
        {
            let schema = self
                .schema_definitions
                .snapshot()
                .map_err(map_schema_definition_lifecycle_error)?;
            ensure_property_query_allowed(&schema, &principals, &r.kind, [r.key.clone()])?;
        }
        let objs = self
            .db
            .find_by_property_with_policy_context(&r.kind, &r.key, &r.value, Some(&policy_context))
            .map_err(Status::internal)?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        let filtered = self.security.filter_objects(&objs, &refs);
        let filtered = filtered
            .into_iter()
            .filter(|object| {
                object_is_visible(
                    &self.db,
                    &self.security,
                    object,
                    &principals,
                    tenant_context.as_ref(),
                )
            })
            .collect::<Vec<_>>();
        let filtered = self.resolve_computed_for_responses_with_policy(
            filtered.into_iter().cloned().collect(),
            &principals,
            Some(&policy_context),
            tenant_context.as_ref(),
        )?;
        Ok(Response::new(ListObjectsResponse {
            objects: filtered.iter().map(to_proto_obj).collect(),
            total: filtered.len() as i32,
            next_page_token: String::new(),
        }))
    }
    pub(super) async fn get_visible_links(
        &self,
        req: Request<GetLinksRequest>,
    ) -> Result<Response<GetLinksResponse>, Status> {
        let principals = caller_principals(&req);
        let policy_context = principal_policy_context(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        require_authenticated(&principals)?;
        let r = req.into_inner();
        let root = self
            .db
            .get_object_with_policy_context(&r.object_id, &policy_context)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        let (root, _) = require_visible_read_root(
            &self.db,
            &self.security,
            root,
            &principals,
            tenant_context.as_ref(),
            &format!("get_links:{}", r.object_id),
        )?;
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let links = self
            .db
            .get_links(&root.id, &r.relation, &dir)
            .map_err(Status::internal)?;
        let links = links
            .into_iter()
            .filter(|link| {
                [&link.from_id, &link.to_id].into_iter().all(|object_id| {
                    self.db
                        .get_object_with_policy_context(object_id, &policy_context)
                        .ok()
                        .flatten()
                        .is_some_and(|object| {
                            object_is_visible(
                                &self.db,
                                &self.security,
                                &object,
                                &principals,
                                tenant_context.as_ref(),
                            )
                        })
                })
            })
            .collect::<Vec<_>>();
        Ok(Response::new(GetLinksResponse {
            links: links.iter().map(to_proto_link).collect(),
        }))
    }
    pub(super) async fn get_visible_linked_objects(
        &self,
        req: Request<GetLinkedObjectsRequest>,
    ) -> Result<Response<GetLinkedObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let policy_context = principal_policy_context(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let r = req.into_inner();
        let root = self
            .db
            .get_object_with_policy_context(&r.object_id, &policy_context)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        let (root, _) = require_visible_read_root(
            &self.db,
            &self.security,
            root,
            &principals,
            tenant_context.as_ref(),
            &format!("get_linked_objects:{}", r.object_id),
        )?;
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let objs = self
            .db
            .get_linked_objects_with_policy_context(
                &root.id,
                &r.relation,
                &dir,
                Some(&policy_context),
            )
            .map_err(Status::internal)?;
        let objs = objs
            .into_iter()
            .filter(|object| {
                object_is_visible(
                    &self.db,
                    &self.security,
                    object,
                    &principals,
                    tenant_context.as_ref(),
                )
            })
            .collect();
        let objs = self.resolve_computed_for_responses_with_policy(
            objs,
            &principals,
            Some(&policy_context),
            tenant_context.as_ref(),
        )?;
        Ok(Response::new(GetLinkedObjectsResponse {
            objects: objs.iter().map(to_proto_obj).collect(),
        }))
    }
    pub(super) async fn traverse_visible(
        &self,
        req: Request<TraverseRequest>,
    ) -> Result<Response<TraverseResponse>, Status> {
        let principals = caller_principals(&req);
        let policy_context = principal_policy_context(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let q = req
            .into_inner()
            .query
            .ok_or(Status::invalid_argument("query required"))?;
        let mut gq = crate::sekai::query::GraphQuery {
            start_id: q.start_id,
            start_external_id: q.start_external_id,
            relations: q.relations,
            direction: if q.direction == "incoming" {
                domain::Direction::Incoming
            } else {
                domain::Direction::Outgoing
            },
            max_depth: q.max_depth,
            kind_filter: q.kind_filter,
            interface_filter: q.interface_filter,
            property_filter: q.property_filter,
            policy_context: Some(policy_context.clone()),
        };
        let start = if !gq.start_id.is_empty() {
            self.db
                .get_object_with_policy_context(&gq.start_id, &policy_context)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("not found"))?
        } else if !gq.start_external_id.is_empty() {
            let external_id = gq.start_external_id.clone();
            self.db
                .find_all_by_external_id(&external_id)
                .map_err(Status::internal)?
                .into_iter()
                .find_map(|candidate| {
                    if tenant_context.is_some()
                        && !object_is_visible(
                            &self.db,
                            &self.security,
                            &candidate,
                            &principals,
                            tenant_context.as_ref(),
                        )
                    {
                        return None;
                    }
                    self.db
                        .get_object_with_policy_context(&candidate.id, &policy_context)
                        .ok()
                        .flatten()
                })
                .ok_or(Status::not_found("not found"))?
        } else {
            return Err(Status::invalid_argument(
                "start_id or start_external_id required",
            ));
        };
        let start_operation = format!("traverse:{}", start.id);
        let (start, _) = require_visible_read_root(
            &self.db,
            &self.security,
            start,
            &principals,
            tenant_context.as_ref(),
            &start_operation,
        )?;
        gq.start_id = start.id.clone();
        gq.start_external_id.clear();
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        let queried_properties = gq.property_filter.keys().cloned().collect::<Vec<_>>();
        if gq.kind_filter.is_empty() {
            ensure_property_query_allowed(&schema, &principals, "", queried_properties)?;
        } else {
            for kind in &gq.kind_filter {
                ensure_property_query_allowed(
                    &schema,
                    &principals,
                    kind,
                    queried_properties.clone(),
                )?;
            }
        }
        let mut res = crate::sekai::query::traverse(&self.db, &gq, Some(&schema))
            .map_err(Status::internal)?;
        drop(schema);
        res.objects.retain(|object| {
            object_is_visible(
                &self.db,
                &self.security,
                object,
                &principals,
                tenant_context.as_ref(),
            )
        });
        retain_reachable_visible_objects(&start.id, gq.direction, &mut res.objects, &mut res.links);
        res.objects = self.resolve_computed_for_responses_with_policy(
            res.objects,
            &principals,
            Some(&policy_context),
            tenant_context.as_ref(),
        )?;
        Ok(Response::new(TraverseResponse {
            result: Some(GraphResult {
                objects: res.objects.iter().map(to_proto_obj).collect(),
                links: res.links.iter().map(to_proto_link).collect(),
            }),
        }))
    }
    pub(super) async fn get_visible_lineage(
        &self,
        req: Request<GetLineageRequest>,
    ) -> Result<Response<GetLineageResponse>, Status> {
        let principals = caller_principals(&req);
        let policy_context = principal_policy_context(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let r = req.into_inner();
        let root = self
            .db
            .get_object_with_policy_context(&r.object_id, &policy_context)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        let (root, _) = require_visible_read_root(
            &self.db,
            &self.security,
            root,
            &principals,
            tenant_context.as_ref(),
            &format!("get_lineage:{}", r.object_id),
        )?;
        let mut res = self
            .db
            .get_lineage(&root.id, r.max_nodes as usize)
            .map_err(Status::internal)?;
        res.nodes.retain(|node| {
            self.db
                .get_object_with_policy_context(&node.object.id, &policy_context)
                .ok()
                .flatten()
                .is_some()
                && object_is_visible(
                    &self.db,
                    &self.security,
                    &node.object,
                    &principals,
                    tenant_context.as_ref(),
                )
        });
        retain_reachable_visible_lineage(&root.id, &mut res.nodes, &mut res.edges);
        let objects = self.resolve_computed_for_responses_with_policy(
            res.nodes.iter().map(|node| node.object.clone()).collect(),
            &principals,
            Some(&policy_context),
            tenant_context.as_ref(),
        )?;
        let nodes = res
            .nodes
            .iter()
            .zip(objects.iter())
            .map(|(n, object)| LineageNode {
                object: Some(to_proto_obj(object)),
                role: n.role.clone(),
                ephemeral: n.ephemeral,
            })
            .collect::<Vec<_>>();
        let edges = res
            .edges
            .iter()
            .map(|e| LineageEdge {
                from: e.from.clone(),
                to: e.to.clone(),
                relation: e.relation.clone(),
            })
            .collect();
        Ok(Response::new(GetLineageResponse {
            result: Some(LineageResult {
                nodes,
                edges,
                truncated: res.truncated,
            }),
        }))
    }
}
