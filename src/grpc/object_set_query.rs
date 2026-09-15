//! Authorized EvaluateObjectSet over existing list and one-hop traverse.

use super::*;
use crate::sekai::object_set::{
    BoundObjectSet, ObjectSetDescriptor as DomainObjectSetDescriptor, ObjectSetError,
    ObjectSetTraversal as DomainObjectSetTraversal,
};

impl SekaiServiceImpl {
    pub(super) async fn evaluate_visible_object_set(
        &self,
        req: Request<EvaluateObjectSetRequest>,
    ) -> Result<Response<EvaluateObjectSetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let policy_context = principal_policy_context(&req);
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let inner = req.into_inner();
        let descriptor = parse_object_set_descriptor(
            inner
                .descriptor
                .ok_or_else(|| Status::invalid_argument("object-set descriptor required"))?,
        )?;
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &descriptor.namespace,
            false,
        )?;
        check_team_namespace(&self.db, &principals, &descriptor.namespace, false)?;
        authorize_source_sync_namespace(
            self,
            &principals,
            tenant_context.as_ref(),
            &descriptor.namespace,
            false,
        )?;
        if is_reserved_governance_kind(&descriptor.kind)
            || descriptor
                .traversal
                .as_ref()
                .is_some_and(|traversal| is_reserved_governance_kind(&traversal.far_kind))
        {
            return Err(Status::not_found("object set unavailable"));
        }
        let published = self
            .db
            .get_published_definition_revision(&descriptor.namespace)
            .map_err(|_| Status::internal("definition revision unavailable"))?
            .ok_or_else(|| {
                Status::failed_precondition("object set definition revision is stale")
            })?;
        authorize_definition_revision(
            self,
            &principals,
            &published.namespace,
            &published.revision_digest,
            true,
        )?;
        let members = self
            .db
            .get_definition_members(&published.namespace, &published.revision_digest)
            .map_err(|_| Status::internal("definition revision unavailable"))?;
        let bound = descriptor
            .prepare(&published.revision_digest, &members)
            .map_err(map_object_set_error)?;
        {
            let schema = self
                .schema_definitions
                .snapshot()
                .map_err(map_schema_definition_lifecycle_error)?;
            let mut queried_properties = bound
                .filter
                .property_filters
                .iter()
                .map(|property_filter| property_filter.key.clone())
                .collect::<Vec<_>>();
            if let Some(order_property) = queried_order_property(&bound.filter.order_by) {
                queried_properties.push(order_property);
            }
            if let Some(aggregation) = &bound.descriptor.aggregation
                && !aggregation.group_by.is_empty()
            {
                queried_properties.push(aggregation.group_by.clone());
            }
            ensure_property_query_allowed(
                &schema,
                &principals,
                bound.filter.kind.as_deref().unwrap_or_default(),
                queried_properties.clone(),
            )?;
            ensure_property_grant_query_allowed(
                &self.db,
                bound.filter.namespace.as_deref(),
                bound.filter.kind.as_deref(),
                queried_properties,
            )?;
        }
        let principal_context_digest =
            crate::sekai::purpose_authorization::purpose_bound_context_digest(
                &policy_context
                    .digest()
                    .map_err(|_| Status::permission_denied("access denied"))?,
                purpose.as_ref().map(|presented| presented.purpose.as_str()),
            )
            .map_err(|_| Status::permission_denied("access denied"))?;
        let policy_activation_digest = match self
            .db
            .get_object_security_activation(&bound.descriptor.namespace)
            .map_err(Status::internal)?
        {
            Some(activation) => {
                crate::sekai::object_security::object_security_activation_digest(&activation)
                    .map_err(Status::internal)?
            }
            None => "legacy".into(),
        };
        let mut filter = bound.filter.clone();
        if !inner.page_token.is_empty() {
            let cursor = crate::sekai::object_security::ObjectQueryCursor::decode(
                &inner.page_token,
                &self.object_query_cursor_key,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
            if cursor.principal_context_digest != principal_context_digest
                || cursor.namespace != bound.descriptor.namespace
                || cursor.policy_activation_digest != policy_activation_digest
                || cursor.query_digest != bound.query_digest
            {
                return Err(Status::failed_precondition(
                    "object set cursor authority or query has changed",
                ));
            }
            filter.offset = cursor.offset;
        }
        let hops = crate::sekai::object_set::resolved_hops(&bound.descriptor);
        if bound.descriptor.aggregation.is_some() || hops.len() > 1 {
            return self.evaluate_aggregated_object_set(
                &bound,
                &hops,
                &principals,
                tenant_context.as_ref(),
                inner.required_freshness_ms,
                now_millis(),
            );
        }
        if self
            .db
            .get_object_type_datasource(&bound.descriptor.namespace, &bound.descriptor.kind)
            .map_err(Status::internal)?
            .is_some()
        {
            return self.evaluate_indexed_object_set(
                &bound,
                inner.required_freshness_ms,
                filter.offset,
                &principal_context_digest,
                &policy_activation_digest,
                now_millis(),
            );
        }
        let (near, total) = list_objects_with_marking(
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
        let returned = near.len() as i32;
        let members = if bound.descriptor.traversal.is_some() {
            collect_one_hop_members(
                self,
                &bound,
                &near,
                &principals,
                &policy_context,
                tenant_context.as_ref(),
                purpose.as_ref(),
            )?
        } else {
            near
        };
        let next_offset = filter.offset.saturating_add(returned);
        let next_page_token = if next_offset < total && returned > 0 {
            crate::sekai::object_security::ObjectQueryCursor::issue(
                next_offset,
                principal_context_digest,
                bound.descriptor.namespace.clone(),
                policy_activation_digest,
                bound.query_digest.clone(),
                now_millis(),
            )
            .and_then(|cursor| cursor.encode(&self.object_query_cursor_key))
            .map_err(Status::internal)?
        } else {
            String::new()
        };
        Ok(Response::new(EvaluateObjectSetResponse {
            contract_version: bound.descriptor.contract_version.clone(),
            definition_digest: bound.descriptor.definition_digest,
            kind: bound.member_kind,
            members: members.iter().map(to_proto_obj).collect(),
            total,
            next_page_token,
            authority: false,
            aggregates: Vec::new(),
        }))
    }
}

impl SekaiServiceImpl {
    fn evaluate_indexed_object_set(
        &self,
        bound: &BoundObjectSet,
        required_freshness_ms: i64,
        offset: i32,
        principal_context_digest: &str,
        policy_activation_digest: &str,
        now_ms: i64,
    ) -> Result<Response<EvaluateObjectSetResponse>, Status> {
        let status = self
            .db
            .object_type_index_status(&bound.descriptor.namespace, &bound.descriptor.kind, now_ms)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::failed_precondition("object type index is stale"))?;
        if !crate::sekai::object_type_index::freshness_holds(&status, required_freshness_ms) {
            return Err(Status::failed_precondition("object type index is stale"));
        }
        let query = crate::sekai::dataset::RowQuery {
            filters: bound
                .descriptor
                .property_filters
                .iter()
                .map(|filter| crate::sekai::dataset::RowFilter {
                    column: filter.key.clone(),
                    op: filter.op.clone(),
                    value: filter.value.clone(),
                })
                .collect(),
            columns: Vec::new(),
            limit: if bound.descriptor.limit > 0 {
                bound.descriptor.limit
            } else {
                crate::sekai::object_set::DEFAULT_EVALUATE_LIMIT
            },
            offset,
        };
        let members = self
            .db
            .list_visible_index_members(&bound.descriptor.namespace, &bound.descriptor.kind, &query)
            .map_err(Status::internal)?;
        let total = self
            .db
            .count_visible_index_members(&bound.descriptor.namespace, &bound.descriptor.kind)
            .map_err(Status::internal)?;
        let objects: Vec<domain::Object> = members
            .iter()
            .map(|member| domain::Object {
                id: member.object_id.clone(),
                kind: member.kind.clone(),
                name: member.source_key.clone(),
                namespace: member.namespace.clone(),
                external_id: member.source_key.clone(),
                properties: member.properties.clone().into_iter().collect(),
                created: status.indexed_at_ms,
                updated: status.indexed_at_ms,
            })
            .collect();
        let returned = objects.len() as i32;
        let next_offset = offset.saturating_add(returned);
        let next_page_token = if next_offset < total && returned > 0 {
            crate::sekai::object_security::ObjectQueryCursor::issue(
                next_offset,
                principal_context_digest.to_string(),
                bound.descriptor.namespace.clone(),
                policy_activation_digest.to_string(),
                bound.query_digest.clone(),
                now_ms,
            )
            .and_then(|cursor| cursor.encode(&self.object_query_cursor_key))
            .map_err(Status::internal)?
        } else {
            String::new()
        };
        Ok(Response::new(EvaluateObjectSetResponse {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            definition_digest: bound.descriptor.definition_digest.clone(),
            kind: bound.member_kind.clone(),
            members: objects.iter().map(to_proto_obj).collect(),
            total,
            next_page_token,
            authority: false,
            aggregates: Vec::new(),
        }))
    }

    fn require_hop_projection_ready(
        &self,
        bound: &BoundObjectSet,
        hops: &[crate::sekai::object_set::ObjectSetTraversal],
    ) -> Result<(), Status> {
        for hop in hops {
            if !self
                .db
                .hop_projection_ready(&bound.descriptor.namespace, &hop.far_kind)
                .map_err(Status::internal)?
            {
                return Err(Status::failed_precondition(
                    "object index hop projection is stale",
                ));
            }
        }
        Ok(())
    }

    fn hop_projection_paths(
        &self,
        bound: &BoundObjectSet,
        hops: &[crate::sekai::object_set::ObjectSetTraversal],
        roots: &[crate::sekai::object_type_index::ObjectTypeIndexMember],
        meter: &mut crate::sekai::object_set::CostMeter,
    ) -> Result<Vec<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>>, Status> {
        let mut current: Vec<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>> =
            roots.iter().cloned().map(|member| vec![member]).collect();
        for hop in hops {
            let mut parent_keys = std::collections::HashSet::new();
            for path in &current {
                let parent = path.last().expect("path");
                parent_keys.insert(parent.source_key.clone());
                parent_keys.insert(parent.object_id.clone());
            }
            let parent_keys: Vec<String> = parent_keys.into_iter().collect();
            let pairs = self
                .db
                .list_index_join_children(
                    &bound.descriptor.namespace,
                    &hop.far_kind,
                    &hop.join_property,
                    &parent_keys,
                )
                .map_err(Status::internal)?;
            let mut child_keys = std::collections::HashSet::new();
            for (_, source_key) in pairs {
                child_keys.insert(source_key);
            }
            let child_keys: Vec<String> = child_keys.into_iter().collect();
            let children = self
                .db
                .list_index_members_by_keys(&bound.descriptor.namespace, &hop.far_kind, &child_keys)
                .map_err(Status::internal)?;
            meter
                .charge(children.len() as i32)
                .map_err(map_object_set_error)?;
            current = crate::sekai::object_index_engine::join_paths_hash(
                current.iter().map(|path| path.iter().collect()).collect(),
                &children,
                &hop.join_property,
            )
            .into_iter()
            .map(|path| path.into_iter().cloned().collect())
            .collect();
            meter
                .charge(current.len() as i32)
                .map_err(map_object_set_error)?;
        }
        Ok(current)
    }

    fn evaluate_aggregated_object_set(
        &self,
        bound: &BoundObjectSet,
        hops: &[crate::sekai::object_set::ObjectSetTraversal],
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        required_freshness_ms: i64,
        now_ms: i64,
    ) -> Result<Response<EvaluateObjectSetResponse>, Status> {
        let mut meter =
            crate::sekai::object_set::CostMeter::new(bound.descriptor.cost_limit.clone());
        let mut layers = Vec::new();
        let mut kind = bound.descriptor.kind.clone();
        let empty = crate::sekai::dataset::RowQuery::default();
        for (index, hop) in std::iter::once(None)
            .chain(hops.iter().map(Some))
            .enumerate()
        {
            if let Some(hop) = hop {
                kind = hop.far_kind.clone();
            }
            if self
                .db
                .get_object_type_datasource(&bound.descriptor.namespace, &kind)
                .map_err(Status::internal)?
                .is_none()
            {
                return Err(Status::failed_precondition(
                    "object-set aggregation requires an index on every hop kind",
                ));
            }
            let status = self
                .db
                .object_type_index_status(&bound.descriptor.namespace, &kind, now_ms)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("object type index is stale"))?;
            if index == 0
                && !crate::sekai::object_type_index::freshness_holds(&status, required_freshness_ms)
            {
                return Err(Status::failed_precondition("object type index is stale"));
            }
            let load_members = index == 0
                || self.object_index_engine
                    == crate::sekai::object_index_engine::ObjectIndexEngineKind::NestedLoop
                || self.object_index_dual_read;
            if !load_members {
                layers.push(Vec::new());
                continue;
            }
            let query = if index == 0 {
                crate::sekai::dataset::RowQuery {
                    filters: bound
                        .descriptor
                        .property_filters
                        .iter()
                        .map(|filter| crate::sekai::dataset::RowFilter {
                            column: filter.key.clone(),
                            op: filter.op.clone(),
                            value: filter.value.clone(),
                        })
                        .collect(),
                    ..empty.clone()
                }
            } else {
                empty.clone()
            };
            let members = self
                .db
                .list_visible_index_members(&bound.descriptor.namespace, &kind, &query)
                .map_err(Status::internal)?;
            meter
                .charge(members.len() as i32)
                .map_err(map_object_set_error)?;
            layers.push(members);
        }
        if self.object_index_engine
            == crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection
        {
            self.require_hop_projection_ready(bound, hops)?;
        }
        let projected = if self.object_index_engine
            == crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection
        {
            Some(self.hop_projection_paths(bound, hops, &layers[0], &mut meter)?)
        } else {
            None
        };
        let mut paths: Vec<Vec<&crate::sekai::object_type_index::ObjectTypeIndexMember>> =
            layers[0].iter().map(|member| vec![member]).collect();
        if self.object_index_engine
            == crate::sekai::object_index_engine::ObjectIndexEngineKind::NestedLoop
            || self.object_index_dual_read
        {
            for (hop_index, hop) in hops.iter().enumerate() {
                paths = crate::sekai::object_index_engine::join_paths_nested(
                    paths,
                    &layers[hop_index + 1],
                    &hop.join_property,
                );
                if self.object_index_engine
                    == crate::sekai::object_index_engine::ObjectIndexEngineKind::NestedLoop
                {
                    meter
                        .charge(paths.len() as i32)
                        .map_err(map_object_set_error)?;
                }
            }
        }
        if let Some(projected) = projected.as_ref()
            && self.object_index_dual_read
        {
            let projected_sig = crate::sekai::object_index_engine::path_signature(
                &projected
                    .iter()
                    .map(|path| path.iter().collect())
                    .collect::<Vec<Vec<_>>>(),
            );
            if projected_sig != crate::sekai::object_index_engine::path_signature(&paths) {
                return Err(Status::internal(
                    "object index hop-projection dual-read mismatch",
                ));
            }
        }
        let aggregation = bound.descriptor.aggregation.clone().ok_or_else(|| {
            Status::invalid_argument("object-set aggregation required for multi-hop evaluate")
        })?;
        let rows: Vec<(String, Option<f64>)> = if let Some(projected) = projected.as_ref() {
            projected
                .iter()
                .map(|path| aggregate_path_row(&path[0], path.last().expect("path"), &aggregation))
                .collect()
        } else {
            paths
                .iter()
                .map(|path| aggregate_path_row(path[0], path[path.len() - 1], &aggregation))
                .collect()
        };
        let aggregates = crate::sekai::object_set::aggregate_groups(&rows, &aggregation.function)
            .map_err(map_object_set_error)?;
        let _ = (principals, tenant_context);
        Ok(Response::new(EvaluateObjectSetResponse {
            contract_version: bound.descriptor.contract_version.clone(),
            definition_digest: bound.descriptor.definition_digest.clone(),
            kind: bound.member_kind.clone(),
            members: Vec::new(),
            total: aggregates.len() as i32,
            next_page_token: String::new(),
            authority: false,
            aggregates: aggregates
                .into_iter()
                .map(|row| ObjectSetAggregateRow {
                    group_key: row.group_key,
                    value: row.value,
                    count: row.count,
                })
                .collect(),
        }))
    }
}

fn aggregate_path_row(
    root: &crate::sekai::object_type_index::ObjectTypeIndexMember,
    leaf: &crate::sekai::object_type_index::ObjectTypeIndexMember,
    aggregation: &crate::sekai::object_set::ObjectSetAggregation,
) -> (String, Option<f64>) {
    let group = root
        .properties
        .get(&aggregation.group_by)
        .cloned()
        .or_else(|| leaf.properties.get(&aggregation.group_by).cloned())
        .unwrap_or_else(|| root.source_key.clone());
    let value = if aggregation.function.eq_ignore_ascii_case("count") {
        Some(1.0)
    } else {
        leaf.properties
            .get(&aggregation.property)
            .and_then(|raw| raw.parse().ok())
    };
    (group, value)
}

fn parse_object_set_descriptor(
    descriptor: ObjectSetDescriptor,
) -> Result<DomainObjectSetDescriptor, Status> {
    Ok(DomainObjectSetDescriptor {
        contract_version: descriptor.contract_version,
        namespace: descriptor.namespace,
        kind: descriptor.kind,
        definition_digest: descriptor.definition_digest,
        property_filters: descriptor
            .property_filters
            .into_iter()
            .map(|filter| domain::PropertyFilter {
                key: filter.key,
                op: filter.op,
                value: filter.value,
            })
            .collect(),
        order_by: descriptor.order_by,
        descending: descriptor.descending,
        limit: descriptor.limit,
        traversal: descriptor
            .traversal
            .map(|traversal| DomainObjectSetTraversal {
                relation: traversal.relation,
                direction: traversal.direction,
                far_kind: traversal.far_kind,
                join_property: traversal.join_property,
            }),
        hops: descriptor
            .hops
            .into_iter()
            .map(|traversal| DomainObjectSetTraversal {
                relation: traversal.relation,
                direction: traversal.direction,
                far_kind: traversal.far_kind,
                join_property: traversal.join_property,
            })
            .collect(),
        aggregation: descriptor.aggregation.map(|aggregation| {
            crate::sekai::object_set::ObjectSetAggregation {
                function: aggregation.function,
                property: aggregation.property,
                group_by: aggregation.group_by,
            }
        }),
        cost_limit: descriptor
            .cost_limit
            .map(|limit| crate::sekai::object_set::ObjectSetCostLimit {
                max_rows_scanned: limit.max_rows_scanned,
                max_depth: limit.max_depth,
                max_time_ms: limit.max_time_ms,
            })
            .unwrap_or_default(),
    })
}

fn collect_one_hop_members(
    service: &SekaiServiceImpl,
    bound: &BoundObjectSet,
    near: &[domain::Object],
    principals: &[String],
    policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
    tenant_context: Option<&RequestEnterpriseContext>,
    purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
) -> Result<Vec<domain::Object>, Status> {
    let traversal = bound
        .descriptor
        .traversal
        .as_ref()
        .expect("one-hop evaluation requires a declared traversal");
    let direction = if traversal.direction == "incoming" {
        domain::Direction::Incoming
    } else {
        domain::Direction::Outgoing
    };
    let mut seen = HashSet::new();
    let mut recorded_purposes = HashSet::new();
    let mut members = Vec::new();
    for start in near {
        let links = service
            .db
            .get_links_with_policy_context(
                &start.id,
                &traversal.relation,
                &direction,
                policy_context,
            )
            .map_err(Status::internal)?;
        for link in links {
            let target = match direction {
                domain::Direction::Outgoing => &link.to_id,
                domain::Direction::Incoming => &link.from_id,
            };
            if !seen.insert(target.clone()) {
                continue;
            }
            let Some(object) = service
                .db
                .get_object_with_policy_context(target, policy_context)
                .map_err(Status::internal)?
            else {
                continue;
            };
            if object.kind != traversal.far_kind {
                continue;
            }
            if !purpose_kind_permitted(&service.db, &object.namespace, &object.kind, purpose)? {
                continue;
            }
            if !object_is_visible(
                &service.db,
                &service.security,
                &object,
                principals,
                tenant_context,
            ) {
                continue;
            }
            if !purpose_allows_kind(
                &service.db,
                &object.namespace,
                &object.kind,
                purpose,
                &mut recorded_purposes,
            )? {
                continue;
            }
            members.push(object);
        }
    }
    service.resolve_computed_for_responses_with_policy(
        members,
        principals,
        Some(policy_context),
        tenant_context,
        purpose,
    )
}

fn map_object_set_error(error: ObjectSetError) -> Status {
    match error {
        ObjectSetError::InvalidArgument(message) => Status::invalid_argument(message),
        ObjectSetError::Stale(message) => Status::failed_precondition(message),
        ObjectSetError::Unsupported(message) => Status::invalid_argument(message),
        ObjectSetError::LimitExceeded(message) => Status::failed_precondition(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::definition_branch::{
        DefinitionMember, DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };
    use crate::sekai::security;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        SekaiServiceImpl::new(db)
    }

    fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn grant_namespace(svc: &SekaiServiceImpl, namespace: &str, principal: &str) {
        let (_, grants) = svc
            .db
            .ensure_team_namespace(namespace, principal, security::Role::Admin, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
    }

    fn member(namespace: &str, kind: &str, id: &str, json: &str) -> DefinitionMember {
        DefinitionMemberInput {
            member_kind: kind.into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare(namespace)
        .unwrap()
    }

    fn seed_sales_definition(svc: &SekaiServiceImpl) -> String {
        let members = vec![
            member(
                "sales",
                "object_type",
                "Customer",
                r#"{"name":"Customer","properties":{"region":{"type":"string"},"tier":{"type":"integer"}}}"#,
            ),
            member(
                "sales",
                "object_type",
                "Order",
                r#"{"name":"Order","properties":{"status":{"type":"string"}}}"#,
            ),
            member(
                "sales",
                "link_type",
                "placed",
                r#"{"name":"placed","from":"Customer","to":"Order"}"#,
            ),
        ];
        let revision = prepare_revision(
            "sales",
            "",
            members.iter().map(|item| DefinitionRevisionMember {
                member_kind: item.member_kind.clone(),
                member_id: item.member_id.clone(),
                member_digest: item.member_digest.clone(),
            }),
            true,
            "root",
            1,
        )
        .unwrap();
        svc.db
            .seed_published_definition_revision(&revision, &members)
            .unwrap();
        revision.revision_digest
    }

    fn object(
        id: &str,
        kind: &str,
        name: &str,
        properties: &[(&str, &str)],
        created: i64,
    ) -> domain::Object {
        domain::Object {
            id: id.into(),
            kind: kind.into(),
            name: name.into(),
            namespace: "sales".into(),
            external_id: format!("sales:{id}"),
            properties: properties
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
            created,
            updated: created,
        }
    }

    fn seed_customers_and_orders(svc: &SekaiServiceImpl) {
        for item in [
            object(
                "c-eu-2",
                "Customer",
                "North",
                &[("region", "eu"), ("tier", "2")],
                10,
            ),
            object(
                "c-eu-3",
                "Customer",
                "South",
                &[("region", "eu"), ("tier", "3")],
                11,
            ),
            object(
                "c-us-2",
                "Customer",
                "West",
                &[("region", "us"), ("tier", "2")],
                12,
            ),
            object(
                "c-eu-1",
                "Customer",
                "East",
                &[("region", "eu"), ("tier", "1")],
                13,
            ),
        ] {
            svc.db.create_object(&item).unwrap();
        }
        for (id, name, created) in [
            ("o-south", "SO-1", 20),
            ("o-north", "NO-1", 21),
            ("o-west", "WO-1", 22),
        ] {
            svc.db
                .create_object(&object(id, "Order", name, &[("status", "open")], created))
                .unwrap();
        }
        for (id, from, to) in [
            ("l-south", "c-eu-3", "o-south"),
            ("l-north", "c-eu-2", "o-north"),
            ("l-west", "c-us-2", "o-west"),
        ] {
            svc.db
                .create_link(&domain::Link {
                    id: id.into(),
                    from_id: from.into(),
                    to_id: to.into(),
                    relation: "placed".into(),
                    created: 30,
                })
                .unwrap();
        }
    }

    fn descriptor(digest: &str, limit: i32) -> ObjectSetDescriptor {
        ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.into(),
            property_filters: vec![
                PropertyFilter {
                    key: "region".into(),
                    op: "eq".into(),
                    value: "eu".into(),
                },
                PropertyFilter {
                    key: "tier".into(),
                    op: "gte".into(),
                    value: "2".into(),
                },
            ],
            order_by: "property:tier".into(),
            descending: true,
            limit,
            traversal: Some(ObjectSetTraversal {
                relation: "placed".into(),
                direction: "outgoing".into(),
                far_kind: "Order".into(),
                join_property: String::new(),
            }),
            hops: Vec::new(),
            aggregation: None,
            cost_limit: None,
        }
    }

    #[tokio::test]
    async fn evaluate_object_set_filters_pages_and_traverses_without_client_join() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);

        let first = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor(&digest, 1)),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(!first.authority);
        assert_eq!(
            first.contract_version,
            crate::sekai::object_set::CONTRACT_VERSION
        );
        assert_eq!(first.definition_digest, digest);
        assert_eq!(first.kind, "Order");
        assert_eq!(first.total, 2);
        assert_eq!(first.members.len(), 1);
        assert_eq!(first.members[0].id, "o-south");
        assert!(!first.next_page_token.is_empty());

        let second = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor(&digest, 1)),
                    page_token: first.next_page_token,
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second.members.len(), 1);
        assert_eq!(second.members[0].id, "o-north");
        assert!(second.next_page_token.is_empty());
        assert!(!second.members.iter().any(|object| object.id == "o-west"));
    }

    #[tokio::test]
    async fn evaluate_object_set_fails_closed_for_stale_wrong_type_and_hidden_state() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);

        let stale = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor("sha256:deadbeef", 2)),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::FailedPrecondition);

        let mut wrong = descriptor(&digest, 2);
        wrong.property_filters[1].value = "gold".into();
        let typed = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(wrong),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(typed.code(), tonic::Code::InvalidArgument);

        let mut contains = descriptor(&digest, 2);
        contains.property_filters[0].op = "contains".into();
        let unsupported = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(contains),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(unsupported.code(), tonic::Code::InvalidArgument);

        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![
                    crate::sekai::object_security::ObjectSecurityPredicate::PropertyEquals {
                        property: "region".into(),
                        value: "eu".into(),
                    },
                ],
            }],
            property_grants: Some(vec![crate::sekai::object_security::PropertyGrant {
                property: "region".into(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            }]),
            value_instance_grants: None,
            required_purpose: None,
        };
        let customer_revision = svc
            .db
            .put_object_security_policy(&policy, "root", "put-object-set", 1)
            .unwrap();
        let instantiated = svc
            .db
            .list_objects(&domain::ListFilter {
                namespace: Some("sales".into()),
                ..Default::default()
            })
            .unwrap();
        let mut activation =
            BTreeMap::from([("Customer".into(), customer_revision.revision_digest)]);
        for (index, kind) in instantiated
            .iter()
            .map(|object| object.kind.as_str())
            .filter(|kind| *kind != "Customer")
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .enumerate()
        {
            let extra = crate::sekai::object_security::ObjectSecurityPolicy {
                contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION
                    .into(),
                namespace: "sales".into(),
                kind: kind.into(),
                rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                    operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                    predicates: vec![
                        crate::sekai::object_security::ObjectSecurityPredicate::AllowAll,
                    ],
                }],
                property_grants: None,
                value_instance_grants: None,
                required_purpose: None,
            };
            let revision = svc
                .db
                .put_object_security_policy(
                    &extra,
                    "root",
                    &format!("put-object-set-{kind}"),
                    10 + index as i64,
                )
                .unwrap();
            activation.insert(kind.to_string(), revision.revision_digest);
        }
        svc.db
            .activate_object_security_policies(
                "sales",
                &activation,
                "root",
                "activate-object-set",
                40,
            )
            .unwrap();

        let hidden_filter = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor(&digest, 10)),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(hidden_filter.code(), tonic::Code::PermissionDenied);

        let mut region_only = descriptor(&digest, 10);
        region_only.property_filters.truncate(1);
        region_only.order_by.clear();
        region_only.traversal = None;
        let visible = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(region_only),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(visible.total, 3);
        assert!(!visible.members.iter().any(|object| object.id == "c-us-2"));
        assert!(!visible.authority);
    }

    #[tokio::test]
    async fn evaluate_object_set_reads_index_and_fails_closed_on_freshness() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_definition(&svc);
        svc.db
            .create_dataset(&crate::sekai::dataset::Dataset {
                id: "ds-customers".into(),
                name: "customers".into(),
                columns: vec![
                    crate::sekai::dataset::ColumnDef {
                        name: "customer_id".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "region".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "hidden".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                ],
                object_id: String::new(),
                created: 1,
            })
            .unwrap();
        svc.db
            .append_rows(
                "ds-customers",
                &[
                    std::collections::HashMap::from([
                        ("customer_id".into(), "c1".into()),
                        ("region".into(), "eu".into()),
                        ("hidden".into(), "0".into()),
                    ]),
                    std::collections::HashMap::from([
                        ("customer_id".into(), "c-hidden".into()),
                        ("region".into(), "eu".into()),
                        ("hidden".into(), "true".into()),
                    ]),
                ],
            )
            .unwrap();
        svc.register_object_type_datasource(with_named_principal(
            RegisterObjectTypeDatasourceRequest {
                datasource: Some(ObjectTypeDatasource {
                    contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    definition_digest: digest.clone(),
                    dataset_id: "ds-customers".into(),
                    key_column: "customer_id".into(),
                    property_mapping: std::collections::HashMap::from([(
                        "region".into(),
                        "region".into(),
                    )]),
                    hidden_column: "hidden".into(),
                    edits_only: false,
                }),
                idempotency_key: "reg-1".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.reindex_object_type(with_named_principal(
            ReindexObjectTypeRequest {
                namespace: "sales".into(),
                kind: "Customer".into(),
                full_rebuild: true,
            },
            "local",
        ))
        .await
        .unwrap();
        let mut descriptor = descriptor(&digest, 10);
        descriptor.property_filters.clear();
        descriptor.order_by.clear();
        descriptor.traversal = None;
        let page = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor.clone()),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.total, 1);
        assert_eq!(page.members[0].id, "Customer:c1");
        assert!(
            !page
                .members
                .iter()
                .any(|object| object.id.contains("hidden"))
        );
        svc.db
            .update_dataset(&crate::sekai::dataset::Dataset {
                id: "ds-customers".into(),
                name: "customers".into(),
                columns: vec![crate::sekai::dataset::ColumnDef {
                    name: "customer_id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: String::new(),
                created: 1,
            })
            .unwrap();
        let quarantined = svc
            .reindex_object_type(with_named_principal(
                ReindexObjectTypeRequest {
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    full_rebuild: false,
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(quarantined.quarantined);
        let stale = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor),
                    page_token: String::new(),
                    required_freshness_ms: 60_000,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn evaluate_object_set_two_hop_aggregates_without_hidden_leakage() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        let page = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![
                            ObjectSetTraversal {
                                relation: "placed".into(),
                                direction: "outgoing".into(),
                                far_kind: "Order".into(),
                                join_property: "customer_id".into(),
                            },
                            ObjectSetTraversal {
                                relation: "ships".into(),
                                direction: "outgoing".into(),
                                far_kind: "Shipment".into(),
                                join_property: "order_id".into(),
                            },
                        ],
                        aggregation: Some(ObjectSetAggregation {
                            function: "sum".into(),
                            property: "amount".into(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.aggregates.len(), 1);
        assert_eq!(page.aggregates[0].group_key, "eu");
        assert_eq!(page.aggregates[0].value, 10.0);
        assert_eq!(page.aggregates[0].count, 1);
        assert!(page.members.is_empty());
        assert!(!page.authority);

        let mut projected = service();
        grant_namespace(&projected, "sales", "alice");
        grant_namespace(&projected, "sales", "local");
        let digest = seed_sales_with_shipments(&projected);
        seed_indexed_customer_order_shipment(&projected, &digest);
        projected.object_index_engine =
            crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection;
        projected.object_index_dual_read = true;
        let hop_page = projected
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![
                            ObjectSetTraversal {
                                relation: "placed".into(),
                                direction: "outgoing".into(),
                                far_kind: "Order".into(),
                                join_property: "customer_id".into(),
                            },
                            ObjectSetTraversal {
                                relation: "ships".into(),
                                direction: "outgoing".into(),
                                far_kind: "Shipment".into(),
                                join_property: "order_id".into(),
                            },
                        ],
                        aggregation: Some(ObjectSetAggregation {
                            function: "sum".into(),
                            property: "amount".into(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(hop_page.aggregates, page.aggregates);
        assert!(!hop_page.authority);

        let refused = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: page.definition_digest.clone(),
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 1,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(refused.message().contains("max_rows_scanned"));
    }

    fn seed_sales_with_shipments(svc: &SekaiServiceImpl) -> String {
        let members = vec![
            member(
                "sales",
                "object_type",
                "Customer",
                r#"{"name":"Customer","properties":{"region":{"type":"string"}}}"#,
            ),
            member(
                "sales",
                "object_type",
                "Order",
                r#"{"name":"Order","properties":{"customer_id":{"type":"string"}}}"#,
            ),
            member(
                "sales",
                "object_type",
                "Shipment",
                r#"{"name":"Shipment","properties":{"order_id":{"type":"string"},"amount":{"type":"number"}}}"#,
            ),
            member(
                "sales",
                "link_type",
                "placed",
                r#"{"name":"placed","from":"Customer","to":"Order"}"#,
            ),
            member(
                "sales",
                "link_type",
                "ships",
                r#"{"name":"ships","from":"Order","to":"Shipment"}"#,
            ),
        ];
        let revision = prepare_revision(
            "sales",
            "",
            members.iter().map(|item| DefinitionRevisionMember {
                member_kind: item.member_kind.clone(),
                member_id: item.member_id.clone(),
                member_digest: item.member_digest.clone(),
            }),
            true,
            "author",
            1,
        )
        .unwrap();
        svc.db
            .seed_published_definition_revision(&revision, &members)
            .unwrap();
        revision.revision_digest
    }

    fn seed_indexed_customer_order_shipment(svc: &SekaiServiceImpl, digest: &str) {
        index_kind(
            svc,
            digest,
            "Customer",
            "ds-c",
            "customer_id",
            &[("region", "region")],
            vec![
                hashmap(&[("customer_id", "c1"), ("region", "eu"), ("hidden", "0")]),
                hashmap(&[
                    ("customer_id", "c-hidden"),
                    ("region", "eu"),
                    ("hidden", "true"),
                ]),
            ],
        );
        index_kind(
            svc,
            digest,
            "Order",
            "ds-o",
            "order_id",
            &[("customer_id", "customer_id")],
            vec![hashmap(&[
                ("order_id", "o1"),
                ("customer_id", "c1"),
                ("hidden", "0"),
            ])],
        );
        index_kind(
            svc,
            digest,
            "Shipment",
            "ds-s",
            "shipment_id",
            &[("order_id", "order_id"), ("amount", "amount")],
            vec![
                hashmap(&[
                    ("shipment_id", "s1"),
                    ("order_id", "o1"),
                    ("amount", "10"),
                    ("hidden", "0"),
                ]),
                hashmap(&[
                    ("shipment_id", "s-hidden"),
                    ("order_id", "o1"),
                    ("amount", "99"),
                    ("hidden", "true"),
                ]),
            ],
        );
    }

    fn hashmap(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    fn index_kind(
        svc: &SekaiServiceImpl,
        digest: &str,
        kind: &str,
        dataset_id: &str,
        key: &str,
        mapping: &[(&str, &str)],
        rows: Vec<std::collections::HashMap<String, String>>,
    ) {
        let mut columns = vec![key, "hidden"];
        for (_, column) in mapping {
            columns.push(*column);
        }
        columns.sort();
        columns.dedup();
        svc.db
            .create_dataset(&crate::sekai::dataset::Dataset {
                id: dataset_id.into(),
                name: dataset_id.into(),
                columns: columns
                    .iter()
                    .map(|name| crate::sekai::dataset::ColumnDef {
                        name: (*name).into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    })
                    .collect(),
                object_id: String::new(),
                created: 1,
            })
            .unwrap();
        svc.db.append_rows(dataset_id, &rows).unwrap();
        let binding = crate::sekai::object_type_index::ObjectTypeDatasource {
            contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: kind.into(),
            definition_digest: digest.into(),
            dataset_id: dataset_id.into(),
            key_column: key.into(),
            property_mapping: mapping
                .iter()
                .map(|(property, column)| ((*property).into(), (*column).into()))
                .collect(),
            hidden_column: "hidden".into(),
            edits_only: false,
        }
        .prepare()
        .unwrap();
        svc.db
            .register_object_type_datasource(&binding, 10)
            .unwrap();
        svc.db
            .apply_object_type_index("sales", kind, true, 20)
            .unwrap();
    }
}
