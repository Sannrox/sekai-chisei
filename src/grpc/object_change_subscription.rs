//! Authorized ReadObjectChangeSubscription over committed object mutations.

use super::*;
use crate::sekai::event_subscription::SUBSCRIBE_UNAVAILABLE;
use crate::sekai::object_change_subscription::{
    ObjectChangeReadRequest, ObjectChangeScope, authorization_pin, object_matches_filters,
    read_object_change_subscription_with_resolved_objects,
};

impl SekaiServiceImpl {
    pub(super) async fn read_visible_object_change_subscription(
        &self,
        req: Request<ReadObjectChangeSubscriptionRequest>,
    ) -> Result<Response<ReadObjectChangeSubscriptionResponse>, Status> {
        let service = self.clone();
        self.spawn_db(move || service.read_visible_object_change_subscription_blocking(req))
            .await
    }

    fn read_visible_object_change_subscription_blocking(
        &self,
        req: Request<ReadObjectChangeSubscriptionRequest>,
    ) -> Result<Response<ReadObjectChangeSubscriptionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let policy_context = principal_policy_context(&req);
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let actor = principals
            .first()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("authentication required"))?;
        let input = req.into_inner();
        let scope = input
            .scope
            .ok_or_else(|| Status::invalid_argument("object-change scope required"))?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &scope.namespace,
            false,
        )?;
        check_team_namespace(self.db.runtime(), &principals, &scope.namespace, false)?;
        authorize_source_sync_namespace(
            self,
            &principals,
            tenant_context.as_ref(),
            &scope.namespace,
            false,
        )?;
        if is_reserved_governance_kind(&scope.kind) {
            return Err(Status::not_found("object change subscription unavailable"));
        }
        let domain_scope = ObjectChangeScope {
            namespace: scope.namespace.clone(),
            kind: scope.kind.clone(),
            object_ids: scope.object_ids.clone(),
            property_filters: scope
                .property_filters
                .into_iter()
                .map(|filter| domain::PropertyFilter {
                    key: filter.key,
                    op: filter.op,
                    value: filter.value,
                })
                .collect(),
        };
        let scope_filter = domain_scope.clone();
        let activation_id = self
            .db
            .runtime()
            .get_object_security_activation(&domain_scope.namespace)
            .map_err(|_| Status::unavailable("object authorization unavailable"))?
            .map(|activation| activation.activation_id)
            .unwrap_or_else(|| "legacy".into());
        let pin = authorization_pin(&activation_id, &principals)
            .map_err(|_| Status::internal("object-change authorization pin unavailable"))?;
        let now_ms = now_millis();
        let mut recorded_purposes = HashSet::new();
        let mut resolver_error = None;
        let mut visible = Vec::new();
        // Objects are resolved by the ids the change feed names, so a pinned or
        // changed object is checked on its own, never cut off by a listing page.
        // One that is unreadable or outside the scope's filters stays out and
        // its change reads as an invalidation.
        let page = read_object_change_subscription_with_resolved_objects(
            self.db.runtime(),
            &actor,
            &ObjectChangeReadRequest {
                subscription_id: input.subscription_id,
                scope: domain_scope,
                snapshot_revision: input.snapshot_revision,
                limit: input.limit,
                retention_ms: input.retention_ms,
                last_page_digest: input.last_page_digest,
                revoke: input.revoke,
            },
            now_ms,
            &mut visible,
            |object_ids| {
                self.resolve_visible_changed_objects(
                    object_ids,
                    &scope_filter,
                    &principals,
                    &policy_context,
                    purpose.as_ref(),
                    tenant_context.as_ref(),
                    &mut recorded_purposes,
                )
                .map_err(|status| {
                    resolver_error = Some(status);
                    "object change objects unavailable".to_string()
                })
            },
            &pin,
        );
        if let Some(status) = resolver_error {
            return Err(status);
        }
        let page = page.map_err(map_object_change_error)?;
        Ok(Response::new(ReadObjectChangeSubscriptionResponse {
            contract_version: page.contract_version,
            subscription_id: page.subscription_id,
            stream_id: page.stream_id,
            outcome: page.outcome,
            snapshot_revision: page.snapshot_revision,
            generation: page.generation,
            feed_epoch: page.feed_epoch,
            committed_offset: page.committed_offset,
            page_digest: page.page_digest,
            events: page
                .events
                .into_iter()
                .map(|event| ObjectChangeEvent {
                    offset: event.offset,
                    event_id: event.event_id,
                    object_id: event.object_id,
                    kind: event.kind,
                    op: event.op,
                    field: event.field,
                    committed_at_ms: event.committed_at_ms,
                    operation_id: event.operation_id,
                })
                .collect(),
            authority: false,
            disconnect_reason: page.disconnect_reason,
        }))
    }
}

impl SekaiServiceImpl {
    /// The objects among `object_ids` in `scope` that `principals` may read
    /// and that match its property filters, checked one by one as listings
    /// check them. Objects stay raw, as change projection reads them.
    #[allow(clippy::too_many_arguments)]
    fn resolve_visible_changed_objects(
        &self,
        object_ids: &[String],
        scope: &ObjectChangeScope,
        principals: &[String],
        policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
        purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
        tenant_context: Option<&RequestEnterpriseContext>,
        recorded_purposes: &mut HashSet<(String, String)>,
    ) -> Result<Vec<domain::Object>, Status> {
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let objects = self
            .db
            .runtime()
            .list_objects_by_ids_with_policy_context(object_ids, &principal_refs, policy_context)
            .map_err(Status::internal)?;
        let mut visible = Vec::with_capacity(objects.len());
        for object in objects {
            if object.namespace != scope.namespace
                || object.kind != scope.kind
                || !object_matches_filters(scope, &object)
            {
                continue;
            }
            if object_passes_read_checks(
                self.db.runtime(),
                &object,
                principals,
                purpose,
                tenant_context,
                recorded_purposes,
            )? {
                visible.push(object);
            }
        }
        Ok(visible)
    }
}

fn map_object_change_error(error: String) -> Status {
    if error == SUBSCRIBE_UNAVAILABLE
        || error.contains("not admitted")
        || error.contains("unavailable")
    {
        Status::not_found("object change subscription unavailable")
    } else if error.contains("stale")
        || error.contains("retention")
        || error.contains("gap")
        || error.contains("unsupported")
    {
        Status::failed_precondition(error)
    } else if error.contains("required")
        || error.contains("invalid")
        || error.contains("exceeds")
        || error.contains("malformed")
    {
        Status::invalid_argument(error)
    } else {
        Status::failed_precondition(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::object_change_subscription::{
        OP_CREATE, OP_DELETE, OP_UPDATE, OUTCOME_PAGE, OUTCOME_REPLAYED, OUTCOME_RESNAPSHOT,
        OUTCOME_REVOKED,
    };
    use crate::sekai::security;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
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
            .runtime()
            .ensure_team_namespace(namespace, principal, security::Role::Admin, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
    }

    fn proto_customer(id: &str, name: &str, region: &str) -> Object {
        Object {
            id: id.into(),
            kind: "Customer".into(),
            name: name.into(),
            namespace: "sales".into(),
            external_id: format!("sales:{id}"),
            properties: HashMap::from([("region".into(), region.into())]),
            created: 0,
            updated: 0,
        }
    }

    fn scope() -> ObjectChangeSubscriptionScope {
        ObjectChangeSubscriptionScope {
            namespace: "sales".into(),
            kind: "Customer".into(),
            object_ids: Vec::new(),
            property_filters: Vec::new(),
        }
    }

    async fn read(
        svc: &SekaiServiceImpl,
        snapshot: &str,
        revoke: bool,
        last_digest: &str,
    ) -> ReadObjectChangeSubscriptionResponse {
        svc.read_object_change_subscription(with_named_principal(
            ReadObjectChangeSubscriptionRequest {
                subscription_id: "sales-customers".into(),
                scope: Some(scope()),
                snapshot_revision: snapshot.into(),
                limit: 32,
                retention_ms: 0,
                last_page_digest: last_digest.into(),
                revoke,
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
    }

    #[tokio::test]
    async fn snapshot_then_committed_mutations_page_without_authority() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(proto_customer("c-eu", "North", "eu")),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap();

        let first = read(&svc, "", false, "").await;
        assert_eq!(first.outcome, OUTCOME_RESNAPSHOT);
        assert!(!first.authority);
        assert!(!first.snapshot_revision.is_empty());

        let listed = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "Customer".into(),
                        namespace: "sales".into(),
                        limit: 10,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects.len(), 1);

        let empty = read(&svc, &first.snapshot_revision, false, "").await;
        assert_eq!(empty.outcome, OUTCOME_PAGE);
        assert!(empty.events.is_empty());

        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(proto_customer("c-us", "West", "us")),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap();
        let mut updated = listed.objects[0].clone();
        updated.properties.insert("region".into(), "apac".into());
        svc.update_object(with_named_principal(
            UpdateObjectRequest {
                object: Some(updated),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap();
        svc.delete_object(with_named_principal(
            DeleteObjectRequest {
                id: "c-us".into(),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap();

        let page = read(&svc, &first.snapshot_revision, false, "").await;
        assert_eq!(page.outcome, OUTCOME_PAGE);
        assert!(!page.authority);
        let ops: Vec<_> = page
            .events
            .iter()
            .map(|event| (event.object_id.as_str(), event.op.as_str()))
            .collect();
        assert!(ops.contains(&("c-us", OP_CREATE)));
        assert!(ops.iter().any(|(id, op)| *id == "c-eu" && *op == OP_UPDATE));
        assert!(ops.contains(&("c-us", OP_DELETE)));

        let replay = read(&svc, &first.snapshot_revision, false, &page.page_digest).await;
        assert_eq!(replay.outcome, OUTCOME_REPLAYED);
        assert_eq!(replay.committed_offset, page.committed_offset);

        let revoked = read(&svc, &first.snapshot_revision, true, "").await;
        assert_eq!(revoked.outcome, OUTCOME_REVOKED);
    }

    #[tokio::test]
    async fn a_pinned_object_past_the_first_listing_page_gets_filtered_updates() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        // One more readable customer than a listing page holds; the pinned one
        // sorts last by name.
        for index in 0..=domain::MAX_LIST_LIMIT {
            svc.create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(proto_customer(
                        &format!("c-{index:04}"),
                        &format!("customer {index:04}"),
                        "eu",
                    )),
                    lease_precondition: None,
                },
                "alice",
            ))
            .await
            .unwrap();
        }
        let last_index = domain::MAX_LIST_LIMIT;
        let last = format!("c-{last_index:04}");
        let pinned_read = |snapshot: String| {
            svc.read_object_change_subscription(with_named_principal(
                ReadObjectChangeSubscriptionRequest {
                    subscription_id: "last-eu-customer".into(),
                    scope: Some(ObjectChangeSubscriptionScope {
                        object_ids: vec![last.clone()],
                        property_filters: vec![PropertyFilter {
                            key: "region".into(),
                            op: "eq".into(),
                            value: "eu".into(),
                        }],
                        ..scope()
                    }),
                    snapshot_revision: snapshot,
                    limit: 32,
                    ..Default::default()
                },
                "alice",
            ))
        };
        let snapshot = pinned_read(String::new())
            .await
            .unwrap()
            .into_inner()
            .snapshot_revision;

        let mut updated = proto_customer(&last, &format!("customer {last_index:04}"), "eu");
        updated.properties.insert("tier".into(), "gold".into());
        svc.update_object(with_named_principal(
            UpdateObjectRequest {
                object: Some(updated),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap();

        let page = pinned_read(snapshot).await.unwrap().into_inner();
        let events: Vec<_> = page
            .events
            .iter()
            .map(|event| {
                (
                    event.object_id.as_str(),
                    event.op.as_str(),
                    event.field.as_str(),
                )
            })
            .collect();
        assert_eq!(events, [(last.as_str(), OP_UPDATE, "properties.tier")]);
    }
}
