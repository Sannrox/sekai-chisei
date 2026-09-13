//! Authorized ReadObjectChangeSubscription over committed object mutations.

use super::*;
use crate::sekai::event_subscription::SUBSCRIBE_UNAVAILABLE;
use crate::sekai::object_change_subscription::{
    ObjectChangeReadRequest, ObjectChangeScope, authorization_pin, read_object_change_subscription,
};

impl SekaiServiceImpl {
    pub(super) async fn read_visible_object_change_subscription(
        &self,
        req: Request<ReadObjectChangeSubscriptionRequest>,
    ) -> Result<Response<ReadObjectChangeSubscriptionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let policy_context = principal_policy_context(&req);
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let actor = principals
            .first()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("authentication required"))?;
        let input = req.into_inner();
        let scope = input
            .scope
            .ok_or_else(|| Status::invalid_argument("object-change scope required"))?;
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &scope.namespace,
            false,
        )?;
        check_team_namespace(&self.db, &principals, &scope.namespace, false)?;
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
        let filter = domain::ListFilter {
            kind: Some(domain_scope.kind.clone()),
            name: None,
            namespace: Some(domain_scope.namespace.clone()),
            property_filters: domain_scope.property_filters.clone(),
            interface_filter: Vec::new(),
            limit: domain::MAX_LIST_LIMIT,
            offset: 0,
            order_by: "name".into(),
            descending: false,
        };
        let (visible, _) = list_objects_with_marking(
            &self.db,
            &filter,
            &principals,
            &policy_context,
            purpose.as_ref(),
            tenant_context.as_ref(),
            |objects, _, _| Ok(objects),
        )?;
        let visible = if domain_scope.object_ids.is_empty() {
            visible
        } else {
            let pinned: std::collections::BTreeSet<_> =
                domain_scope.object_ids.iter().cloned().collect();
            visible
                .into_iter()
                .filter(|object| pinned.contains(&object.id))
                .collect()
        };
        let activation_id = self
            .db
            .get_object_security_activation(&domain_scope.namespace)
            .map_err(|_| Status::unavailable("object authorization unavailable"))?
            .map(|activation| activation.activation_id)
            .unwrap_or_else(|| "legacy".into());
        let pin = authorization_pin(&activation_id, &principals)
            .map_err(|_| Status::internal("object-change authorization pin unavailable"))?;
        let now_ms = now_millis();
        let page = read_object_change_subscription(
            &self.db,
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
            &visible,
            &pin,
        )
        .map_err(map_object_change_error)?;
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
                })
                .collect(),
            authority: false,
            disconnect_reason: page.disconnect_reason,
        }))
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
}
