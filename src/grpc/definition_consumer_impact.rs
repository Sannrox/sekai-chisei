//! Authorized ReportDefinitionConsumerImpact over registered bindings.

use super::*;
use crate::sekai::definition_consumer_impact::{
    BINDING_KIND, COMPLETENESS_UNAVAILABLE, MAX_VISIBLE_BINDINGS, report_consumer_impact,
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
        let filter = domain::ListFilter {
            kind: Some(BINDING_KIND.into()),
            name: None,
            namespace: Some(input.namespace.clone()),
            property_filters: Vec::new(),
            interface_filter: Vec::new(),
            limit: (MAX_VISIBLE_BINDINGS as i32).saturating_add(1),
            offset: 0,
            order_by: "name".into(),
            descending: false,
        };
        let (bindings, _) = list_objects_with_marking(
            self.db.runtime(),
            &filter,
            &principals,
            &policy_context,
            purpose.as_ref(),
            tenant_context.as_ref(),
            |objects, _, _| Ok(objects),
        )
        .map_err(|_| Status::failed_precondition(COMPLETENESS_UNAVAILABLE))?;
        let report = report_consumer_impact(&diff, &bindings);
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
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };
    use crate::sekai::security;
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
        let member = DefinitionMemberInput {
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
}
