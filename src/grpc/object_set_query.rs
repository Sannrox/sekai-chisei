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
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            definition_digest: bound.descriptor.definition_digest,
            kind: bound.member_kind,
            members: members.iter().map(to_proto_obj).collect(),
            total,
            next_page_token,
            authority: false,
        }))
    }
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
            }),
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
            }),
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
}
