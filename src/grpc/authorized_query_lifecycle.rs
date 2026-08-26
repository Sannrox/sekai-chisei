//! Authorized graph and object query behind one private interface.
//!
//! The gRPC adapter authenticates the caller and projects protobuf. This module
//! owns tenant, team-namespace, ACL, marking, reserved-kind, computed-property,
//! and restricted-property filtering for get, list, find, links, traverse, and
//! lineage reads.

use super::*;
use std::collections::{BTreeSet, HashSet};

impl SekaiServiceImpl {
    pub(super) async fn get_visible_object(
        &self,
        req: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let policy_context = principal_policy_context(&req);
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let id = req.into_inner().id;
        let obj = self
            .db
            .get_object_with_policy_context(&id, &policy_context)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        let namespace = obj.namespace.clone();
        require_purpose_for_kind(
            &self.db,
            &namespace,
            &obj.kind,
            purpose.as_ref(),
            &format!("get_object:{id}"),
        )?;
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
            purpose.as_ref(),
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
        let purpose = request_purpose_presentation(&req, &principals);
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
        let inner = req.into_inner();
        let page_token = inner.page_token;
        let mut filter = parse_list_filter(inner.filter.unwrap_or_default())?;
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
                queried_properties.clone(),
            )?;
            ensure_property_grant_query_allowed(
                &self.db,
                filter.namespace.as_deref(),
                filter.kind.as_deref(),
                queried_properties,
            )?;
        }
        // Token binds principal policy context, activation, and query. ACL,
        // team, and marking changes are re-applied when the page is served.
        let principal_context_digest =
            crate::sekai::purpose_authorization::purpose_bound_context_digest(
                &policy_context
                    .digest()
                    .map_err(|_| Status::permission_denied("access denied"))?,
                purpose.as_ref().map(|presented| presented.purpose.as_str()),
            )
            .map_err(|_| Status::permission_denied("access denied"))?;
        let query_digest = crate::sekai::object_security::object_query_digest(&filter)
            .map_err(Status::invalid_argument)?;
        let cursor_namespace = filter.namespace.clone().unwrap_or_default();
        let policy_activation_digest = if cursor_namespace.is_empty() {
            "legacy".into()
        } else {
            match self
                .db
                .get_object_security_activation(&cursor_namespace)
                .map_err(Status::internal)?
            {
                Some(activation) => {
                    crate::sekai::object_security::object_security_activation_digest(&activation)
                        .map_err(Status::internal)?
                }
                None => "legacy".into(),
            }
        };
        if !page_token.is_empty() {
            if cursor_namespace.is_empty() || filter.offset != 0 {
                return Err(Status::invalid_argument(
                    "page_token requires a namespace filter and zero offset",
                ));
            }
            let cursor = crate::sekai::object_security::ObjectQueryCursor::decode(
                &page_token,
                &self.object_query_cursor_key,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
            if cursor.principal_context_digest != principal_context_digest
                || cursor.namespace != cursor_namespace
                || cursor.policy_activation_digest != policy_activation_digest
                || cursor.query_digest != query_digest
            {
                return Err(Status::failed_precondition(
                    "object query cursor authority or query has changed",
                ));
            }
            filter.offset = cursor.offset;
        }
        // The API now defaults paging at 100 rows when no limit is provided;
        // DB callers using list_objects(&filter) remain unchanged.
        let (objects, total) = list_objects_with_marking(
            &self.db,
            &filter,
            &principals,
            &policy_context,
            purpose.as_ref(),
            tenant_context.as_ref(),
            |objects, principals, tenant_context| {
                self.resolve_computed_for_responses_with_policy(
                    objects,
                    principals,
                    Some(&policy_context),
                    tenant_context,
                    purpose.as_ref(),
                )
            },
        )?;
        let returned = objects.len() as i32;
        let next_offset = filter.offset.saturating_add(returned);
        let next_page_token = if !cursor_namespace.is_empty() && next_offset < total && returned > 0
        {
            crate::sekai::object_security::ObjectQueryCursor::issue(
                next_offset,
                principal_context_digest,
                cursor_namespace,
                policy_activation_digest,
                query_digest,
                now_millis(),
            )
            .and_then(|cursor| cursor.encode(&self.object_query_cursor_key))
            .map_err(Status::internal)?
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
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let external_id = req.into_inner().external_id;
        let candidates = self
            .db
            .find_all_by_external_id_with_policy_context(&external_id, &policy_context)
            .map_err(Status::internal)?;
        let mut first_acl_denied = None;
        let mut recorded_purposes = HashSet::new();
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
            if !purpose_allows_kind(
                &self.db,
                &namespace,
                &obj.kind,
                purpose.as_ref(),
                &mut recorded_purposes,
            )? {
                continue;
            }
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
                purpose.as_ref(),
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
        let purpose = request_purpose_presentation(&req, &principals);
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
            ensure_property_grant_query_allowed(&self.db, None, Some(&r.kind), [r.key.clone()])?;
        }
        let objs = self
            .db
            .find_by_property_with_policy_context(&r.kind, &r.key, &r.value, &policy_context)
            .map_err(Status::internal)?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        let filtered = self.security.filter_objects(&objs, &refs);
        let mut recorded_purposes = HashSet::new();
        let mut visible = Vec::new();
        for object in filtered {
            if object_is_visible(
                &self.db,
                &self.security,
                object,
                &principals,
                tenant_context.as_ref(),
            ) && purpose_allows_kind(
                &self.db,
                &object.namespace,
                &object.kind,
                purpose.as_ref(),
                &mut recorded_purposes,
            )? {
                visible.push(object.clone());
            }
        }
        let filtered = self.resolve_computed_for_responses_with_policy(
            visible,
            &principals,
            Some(&policy_context),
            tenant_context.as_ref(),
            purpose.as_ref(),
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
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        require_authenticated(&principals)?;
        let r = req.into_inner();
        let root = self
            .db
            .get_object_with_policy_context(&r.object_id, &policy_context)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        require_purpose_for_kind(
            &self.db,
            &root.namespace,
            &root.kind,
            purpose.as_ref(),
            &format!("get_links:{}", r.object_id),
        )?;
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
            .get_links_with_policy_context(&root.id, &r.relation, &dir, &policy_context)
            .map_err(Status::internal)?;
        let mut recorded_purposes = HashSet::new();
        let mut visible_links = Vec::new();
        for link in links {
            let mut keep = true;
            for object_id in [&link.from_id, &link.to_id] {
                let Some(object) = self.db.get_object(object_id).ok().flatten() else {
                    keep = false;
                    break;
                };
                if !object_is_visible(
                    &self.db,
                    &self.security,
                    &object,
                    &principals,
                    tenant_context.as_ref(),
                ) || !purpose_allows_kind(
                    &self.db,
                    &object.namespace,
                    &object.kind,
                    purpose.as_ref(),
                    &mut recorded_purposes,
                )? {
                    keep = false;
                    break;
                }
            }
            if keep {
                visible_links.push(link);
            }
        }
        let links = visible_links;
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
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let r = req.into_inner();
        let root = self
            .db
            .get_object_with_policy_context(&r.object_id, &policy_context)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        require_purpose_for_kind(
            &self.db,
            &root.namespace,
            &root.kind,
            purpose.as_ref(),
            &format!("get_linked_objects:{}", r.object_id),
        )?;
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
            .get_linked_objects_with_policy_context(&root.id, &r.relation, &dir, &policy_context)
            .map_err(Status::internal)?;
        let mut recorded_purposes = HashSet::new();
        let mut visible_objs = Vec::new();
        for object in objs {
            if object_is_visible(
                &self.db,
                &self.security,
                &object,
                &principals,
                tenant_context.as_ref(),
            ) && purpose_allows_kind(
                &self.db,
                &object.namespace,
                &object.kind,
                purpose.as_ref(),
                &mut recorded_purposes,
            )? {
                visible_objs.push(object);
            }
        }
        let objs = visible_objs;
        let objs = self.resolve_computed_for_responses_with_policy(
            objs,
            &principals,
            Some(&policy_context),
            tenant_context.as_ref(),
            purpose.as_ref(),
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
        let purpose = request_purpose_presentation(&req, &principals);
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
        };
        let start = if !gq.start_id.is_empty() {
            self.db
                .get_object_with_policy_context(&gq.start_id, &policy_context)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("not found"))?
        } else if !gq.start_external_id.is_empty() {
            let external_id = gq.start_external_id.clone();
            self.db
                .find_all_by_external_id_with_policy_context(&external_id, &policy_context)
                .map_err(Status::internal)?
                .into_iter()
                .find(|candidate| {
                    object_is_visible(
                        &self.db,
                        &self.security,
                        candidate,
                        &principals,
                        tenant_context.as_ref(),
                    )
                })
                .ok_or(Status::not_found("not found"))?
        } else {
            return Err(Status::invalid_argument(
                "start_id or start_external_id required",
            ));
        };
        let start_operation = format!("traverse:{}", start.id);
        require_purpose_for_kind(
            &self.db,
            &start.namespace,
            &start.kind,
            purpose.as_ref(),
            &start_operation,
        )?;
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
            ensure_property_query_allowed(&schema, &principals, "", queried_properties.clone())?;
            ensure_property_grant_query_allowed(&self.db, None, None, queried_properties)?;
        } else {
            for kind in &gq.kind_filter {
                ensure_property_query_allowed(
                    &schema,
                    &principals,
                    kind,
                    queried_properties.clone(),
                )?;
                ensure_property_grant_query_allowed(
                    &self.db,
                    None,
                    Some(kind),
                    queried_properties.clone(),
                )?;
            }
        }
        let authority = resolve_principal_authority(&self.db, &principals)?;
        let start_lattice = self
            .db
            .get_classification_lattice(&start.namespace)
            .map_err(|_| Status::unavailable("classification lattice unavailable"))?;
        let start_digest = start_lattice
            .as_ref()
            .map(crate::sekai::classification_lattice::ClassificationLattice::digest)
            .transpose()
            .map_err(Status::internal)?;
        let start_path = crate::sekai::classification_lattice::PathClassification {
            namespace: start.namespace.clone(),
            lattice_digest: start_digest,
            token: markings::object_marking_token(&start).map(str::to_string),
        };
        let accumulated = std::cell::RefCell::new(HashMap::from([(
            start.id.clone(),
            BTreeSet::from([start_path]),
        )]));
        let mut res = crate::sekai::query::traverse_with_policy_context(
            &self.db,
            &gq,
            Some(&schema),
            Some(&policy_context),
            Some(&|parent, object| {
                if !purpose_kind_permitted(
                    &self.db,
                    &object.namespace,
                    &object.kind,
                    purpose.as_ref(),
                )
                .map_err(|status| status.to_string())?
                {
                    return Ok(None);
                }
                hop_marking_permitted(&self.db, &authority, &accumulated, parent, object)
            }),
        )
        .map_err(|error| {
            if error.contains("purpose authorization unavailable")
                || error.contains("object authorization unavailable")
            {
                Status::unavailable(error)
            } else {
                Status::internal(error)
            }
        })?;
        drop(schema);
        let mut recorded_purposes = HashSet::new();
        let mut visible_objects = Vec::new();
        for object in res.objects {
            if object_is_visible(
                &self.db,
                &self.security,
                &object,
                &principals,
                tenant_context.as_ref(),
            ) && purpose_allows_kind(
                &self.db,
                &object.namespace,
                &object.kind,
                purpose.as_ref(),
                &mut recorded_purposes,
            )? {
                visible_objects.push(object);
            }
        }
        res.objects = visible_objects;
        retain_reachable_visible_objects(&start.id, gq.direction, &mut res.objects, &mut res.links);
        res.objects = self.resolve_computed_for_responses_with_policy(
            res.objects,
            &principals,
            Some(&policy_context),
            tenant_context.as_ref(),
            purpose.as_ref(),
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
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let r = req.into_inner();
        let root = self
            .db
            .get_object_with_policy_context(&r.object_id, &policy_context)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        require_purpose_for_kind(
            &self.db,
            &root.namespace,
            &root.kind,
            purpose.as_ref(),
            &format!("get_lineage:{}", r.object_id),
        )?;
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
            .get_lineage_with_policy_context(&root.id, r.max_nodes as usize, &policy_context)
            .map_err(Status::internal)?;
        let mut recorded_purposes = HashSet::new();
        let mut visible_nodes = Vec::new();
        for node in res.nodes {
            if object_is_visible(
                &self.db,
                &self.security,
                &node.object,
                &principals,
                tenant_context.as_ref(),
            ) && purpose_allows_kind(
                &self.db,
                &node.object.namespace,
                &node.object.kind,
                purpose.as_ref(),
                &mut recorded_purposes,
            )? {
                visible_nodes.push(node);
            }
        }
        res.nodes = visible_nodes;
        retain_reachable_visible_lineage(&root.id, &mut res.nodes, &mut res.edges);
        let objects = self.resolve_computed_for_responses_with_policy(
            res.nodes.iter().map(|node| node.object.clone()).collect(),
            &principals,
            Some(&policy_context),
            tenant_context.as_ref(),
            purpose.as_ref(),
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

fn hop_marking_permitted(
    db: &RuntimeDb,
    authority: &markings::PrincipalAuthority,
    accumulated: &std::cell::RefCell<
        HashMap<String, BTreeSet<crate::sekai::classification_lattice::PathClassification>>,
    >,
    parent: Option<&domain::Object>,
    object: &domain::Object,
) -> Result<Option<String>, String> {
    if markings::is_trusted_service_principal(&authority.principal) {
        return Ok(Some("trusted".into()));
    }
    let lattice = db.get_classification_lattice(&object.namespace)?;
    let child_digest = lattice
        .as_ref()
        .map(crate::sekai::classification_lattice::ClassificationLattice::digest)
        .transpose()?;
    let parent_paths = parent
        .map(|parent| {
            accumulated
                .borrow()
                .get(&parent.id)
                .cloned()
                .unwrap_or_else(|| {
                    BTreeSet::from([crate::sekai::classification_lattice::PathClassification {
                        namespace: parent.namespace.clone(),
                        lattice_digest: None,
                        token: markings::object_marking_token(parent).map(str::to_string),
                    }])
                })
        })
        .unwrap_or_default();
    let child_token = markings::object_marking_token(object).map(str::to_string);
    let mut added_key = None;
    for parent_path in parent_paths {
        if !crate::sekai::classification_lattice::path_marking_compatible(
            Some(&parent_path),
            &object.namespace,
            child_digest.as_deref(),
            child_token.as_deref(),
        ) {
            continue;
        }
        let inherit = parent_path.namespace == object.namespace;
        let joined = match crate::sekai::classification_lattice::join_marking_tokens(
            lattice.as_ref(),
            inherit.then_some(parent_path.token.as_deref()).flatten(),
            child_token.as_deref(),
        ) {
            Ok(Some(token)) => Some(token),
            Ok(None)
                if inherit
                    && parent_path.token.is_some()
                    && child_token.is_some()
                    && lattice.is_some() =>
            {
                continue;
            }
            Ok(None) => child_token.clone(),
            Err(_) if lattice.is_some() => continue,
            Err(error) => return Err(error),
        };
        let result = crate::sekai::classification_lattice::evaluate_lattice_access(
            "traverse-hop",
            joined.as_deref(),
            authority,
            lattice.as_ref(),
        );
        if result.decision == markings::MarkingDecision::Deny {
            continue;
        }
        let path = crate::sekai::classification_lattice::PathClassification {
            namespace: object.namespace.clone(),
            lattice_digest: child_digest.clone(),
            token: joined,
        };
        let key = path.visit_key();
        if accumulated
            .borrow_mut()
            .entry(object.id.clone())
            .or_default()
            .insert(path)
        {
            added_key = Some(key);
        }
    }
    Ok(added_key)
}
