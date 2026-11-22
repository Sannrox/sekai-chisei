//! Authorized ReportDefinitionConsumerImpact over registered bindings.

use super::*;
use crate::sekai::definition_consumer_impact::{
    BINDING_KIND, COMPLETENESS_COMPLETE, COMPLETENESS_STALE, COMPLETENESS_UNAVAILABLE,
    MAX_VISIBLE_BINDINGS, any_stale_binding, broken_blocking_bindings, list_blocking_bindings,
    report_consumer_impact,
};

impl SekaiServiceImpl {
    pub(super) async fn report_visible_definition_consumer_impact(
        &self,
        req: Request<ReportDefinitionConsumerImpactRequest>,
    ) -> Result<Response<ReportDefinitionConsumerImpactResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let policy_context = principal_policy_context(&req);
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let input = req.into_inner();
        authorize_source_sync_namespace(
            self,
            &principals,
            tenant_context.as_ref(),
            &input.namespace,
            false,
        )?;
        let (from, from_members, to, to_members) = load_authorized_definition_revisions(
            self,
            &principals,
            &input.namespace,
            &input.from_revision_digest,
            &input.to_revision_digest,
        )?;
        let diff = definition_diff_domain::compare_definition_revisions(
            &from,
            &from_members,
            &to,
            &to_members,
        )
        .map_err(map_definition_write_error)?;
        // Advisory bindings stay visibility-bound and bounded. Blocking ones
        // are disclosed to producers whatever the caller can see (ADR 0067,
        // amended) and are evaluated as the publish gate evaluates them, so
        // they must not consume the advisory cap.
        let mut advisory = Vec::new();
        let mut offset = 0i32;
        loop {
            let filter = domain::ListFilter {
                kind: Some(BINDING_KIND.into()),
                namespace: Some(input.namespace.clone()),
                limit: domain::MAX_LIST_LIMIT,
                offset,
                order_by: "name".into(),
                ..domain::ListFilter::default()
            };
            let (page, _) = list_objects_with_marking(
                self.db.runtime(),
                &filter,
                &principals,
                &policy_context,
                purpose.as_ref(),
                tenant_context.as_ref(),
                |objects, _, _| Ok(objects),
            )
            .map_err(|_| Status::failed_precondition(COMPLETENESS_UNAVAILABLE))?;
            let page_len = page.len();
            for object in page {
                if object
                    .properties
                    .get("blocking")
                    .is_some_and(|value| value == "true")
                {
                    continue;
                }
                advisory.push(object);
                if advisory.len() > MAX_VISIBLE_BINDINGS {
                    break;
                }
            }
            if advisory.len() > MAX_VISIBLE_BINDINGS || page_len < domain::MAX_LIST_LIMIT as usize {
                break;
            }
            offset = offset.saturating_add(page_len as i32);
        }
        let mut report = report_consumer_impact(&diff, &advisory);
        let blocking = list_blocking_bindings(
            |filter| self.db.runtime().list_objects(filter),
            &input.namespace,
        )
        .map_err(|_| Status::failed_precondition(COMPLETENESS_UNAVAILABLE))?;
        if report.completeness == COMPLETENESS_COMPLETE && any_stale_binding(&blocking) {
            report.completeness = COMPLETENESS_STALE.into();
        }
        let compatibility = definition_diff_domain::classify_definition_revision_compatibility(
            &from,
            &from_members,
            &to,
            &to_members,
        )
        .map_err(map_definition_write_error)?;
        report
            .impacts
            .extend(broken_blocking_bindings(&compatibility, &blocking));
        Ok(Response::new(ReportDefinitionConsumerImpactResponse {
            completeness: report.completeness,
            from_revision_digest: report.from_revision_digest,
            to_revision_digest: report.to_revision_digest,
            impacts: report
                .impacts
                .into_iter()
                .map(|impact| DefinitionConsumerImpactPath {
                    owner: impact.owner,
                    resource_identity: impact.resource_identity,
                    member_kind: impact.member_kind,
                    member_id: impact.member_id,
                    property: impact.property,
                    source_locator: impact.source_locator,
                    blocking: impact.blocking,
                })
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput as DomainMemberInput, DefinitionRevisionMember, prepare_revision,
    };
    use crate::sekai::definition_consumer_impact::{
        BINDING_CONTRACT, BINDING_KIND, COMPLETENESS_PARTIAL, DefinitionConsumerBinding,
        binding_digest,
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

    async fn published_customer_pair(
        svc: &SekaiServiceImpl,
        namespace: &str,
        from_json: &str,
        to_json: &str,
    ) -> (String, String) {
        let (_, grants) = svc
            .db
            .runtime()
            .ensure_team_namespace(namespace, "alice", security::Role::Admin, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
        let member = DomainMemberInput {
            member_kind: "object_type".into(),
            member_id: "Customer".into(),
            definition_json: from_json.into(),
            member_digest: String::new(),
        }
        .prepare(namespace)
        .unwrap();
        let revision = prepare_revision(
            namespace,
            "",
            [DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            }],
            true,
            "root",
            1,
        )
        .unwrap();
        svc.db
            .runtime()
            .seed_published_definition_revision(&revision, &[member])
            .unwrap();
        let from = revision.revision_digest;
        svc.create_definition_branch(with_named_principal(
            CreateDefinitionBranchRequest {
                namespace: namespace.into(),
                branch_id: "impact".into(),
                parent_revision_digest: from.clone(),
                idempotency_key: format!("{namespace}-create"),
            },
            "root",
        ))
        .await
        .unwrap();
        let applied = svc
            .apply_definition_branch_edit(with_named_principal(
                ApplyDefinitionBranchEditRequest {
                    namespace: namespace.into(),
                    branch_id: "impact".into(),
                    expected_head_digest: from.clone(),
                    upserts: vec![DefinitionMemberInput {
                        member_kind: "object_type".into(),
                        member_id: "Customer".into(),
                        definition_json: to_json.into(),
                        member_digest: String::new(),
                    }],
                    removals: Vec::new(),
                    idempotency_key: format!("{namespace}-edit"),
                },
                "root",
            ))
            .await
            .unwrap()
            .into_inner();
        (from, applied.revision.unwrap().revision_digest)
    }

    fn consumer_binding(
        namespace: &str,
        id: &str,
        property: &str,
        blocking: bool,
    ) -> domain::Object {
        let mut binding = DefinitionConsumerBinding {
            contract_version: BINDING_CONTRACT.into(),
            owner: format!("owner-{id}"),
            resource_identity: format!("app:{id}"),
            namespace: namespace.into(),
            member_kind: "object_type".into(),
            member_id: "Customer".into(),
            property: property.into(),
            declaration_digest: String::new(),
            source_locator: format!("{id}/src.rs"),
            blocking,
        };
        binding.declaration_digest = binding_digest(&binding);
        let mut properties = HashMap::from([
            ("contract_version".into(), binding.contract_version),
            ("owner".into(), binding.owner),
            ("resource_identity".into(), binding.resource_identity),
            ("member_kind".into(), binding.member_kind),
            ("member_id".into(), binding.member_id),
            ("property".into(), binding.property),
            ("declaration_digest".into(), binding.declaration_digest),
            ("source_locator".into(), binding.source_locator),
        ]);
        if blocking {
            properties.insert("blocking".into(), "true".into());
        }
        domain::Object {
            id: format!("binding-{id}"),
            kind: BINDING_KIND.into(),
            name: format!("binding-{id}"),
            namespace: namespace.into(),
            external_id: format!("{namespace}:binding-{id}"),
            properties,
            created: 1,
            updated: 1,
        }
    }

    #[tokio::test]
    async fn empty_visible_registrations_are_complete_not_proof_of_zero_impact() {
        let svc = service();
        let (_, grants) = svc
            .db
            .runtime()
            .ensure_team_namespace("sales", "alice", security::Role::Admin, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
        let member = DomainMemberInput {
            member_kind: "object_type".into(),
            member_id: "Customer".into(),
            definition_json: r#"{"name":"Customer","properties":{"owner":{"type":"string"}}}"#
                .into(),
            member_digest: String::new(),
        }
        .prepare("sales")
        .unwrap();
        let revision = prepare_revision(
            "sales",
            "",
            [DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            }],
            true,
            "root",
            1,
        )
        .unwrap();
        svc.db
            .runtime()
            .seed_published_definition_revision(&revision, &[member])
            .unwrap();
        let report = svc
            .report_definition_consumer_impact(with_named_principal(
                ReportDefinitionConsumerImpactRequest {
                    namespace: "sales".into(),
                    from_revision_digest: revision.revision_digest.clone(),
                    to_revision_digest: revision.revision_digest,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            report.completeness,
            crate::sekai::definition_consumer_impact::COMPLETENESS_COMPLETE
        );
        assert!(report.impacts.is_empty());
    }

    #[tokio::test]
    async fn blocking_bindings_do_not_overflow_an_advisory_report() {
        let svc = service();
        let namespace = "impact-cap";
        let (from, to) = published_customer_pair(
            &svc,
            namespace,
            r#"{"name":"Customer","properties":["owner"]}"#,
            r#"{"name":"Customer","properties":[]}"#,
        )
        .await;
        for index in 0..MAX_VISIBLE_BINDINGS {
            svc.db
                .runtime()
                .create_object(&consumer_binding(
                    namespace,
                    &format!("b{index:03}"),
                    "unused",
                    true,
                ))
                .unwrap();
        }
        svc.db
            .runtime()
            .create_object(&consumer_binding(namespace, "a000", "owner", false))
            .unwrap();
        let report = svc
            .report_definition_consumer_impact(with_named_principal(
                ReportDefinitionConsumerImpactRequest {
                    namespace: namespace.into(),
                    from_revision_digest: from,
                    to_revision_digest: to,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(report.completeness, COMPLETENESS_COMPLETE);
        assert_eq!(report.impacts.len(), 1);
        assert_eq!(report.impacts[0].resource_identity, "app:a000");
        assert_eq!(report.impacts[0].property, "owner");
        assert!(!report.impacts[0].blocking);
    }

    #[tokio::test]
    async fn advisory_overflow_still_yields_partial() {
        let svc = service();
        let namespace = "impact-overflow";
        let (from, to) = published_customer_pair(
            &svc,
            namespace,
            r#"{"name":"Customer","properties":["owner"]}"#,
            r#"{"name":"Customer","properties":[]}"#,
        )
        .await;
        for index in 0..=MAX_VISIBLE_BINDINGS {
            svc.db
                .runtime()
                .create_object(&consumer_binding(
                    namespace,
                    &format!("a{index:03}"),
                    "owner",
                    false,
                ))
                .unwrap();
        }
        let report = svc
            .report_definition_consumer_impact(with_named_principal(
                ReportDefinitionConsumerImpactRequest {
                    namespace: namespace.into(),
                    from_revision_digest: from,
                    to_revision_digest: to,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(report.completeness, COMPLETENESS_PARTIAL);
        assert!(report.impacts.is_empty());
    }
}
