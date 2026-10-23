//! GenerateDefinitionChangeBundle (#1691, ADR 0125): diff, migration plan,
//! backfill, and consumer impact for a candidate revision in one read.

use super::*;
use crate::sekai::definition_change_bundle::{
    ChangeHints, PropertyDefault, PropertyRef, PropertyRename, generate_change_bundle,
};

fn hints_from_proto(hints: Option<DefinitionChangeHints>) -> ChangeHints {
    let hints = hints.unwrap_or_default();
    ChangeHints {
        renames: hints
            .renames
            .into_iter()
            .map(|rename| PropertyRename {
                object_type: rename.object_type,
                from: rename.from_property,
                to: rename.to_property,
            })
            .collect(),
        defaults: hints
            .defaults
            .into_iter()
            .map(|default| PropertyDefault {
                object_type: default.object_type,
                property: default.property,
                value: default.value,
            })
            .collect(),
        type_changes: hints
            .type_changes
            .into_iter()
            .map(|property| PropertyRef {
                object_type: property.object_type,
                property: property.property,
            })
            .collect(),
    }
}

impl SekaiServiceImpl {
    pub(super) async fn generate_visible_definition_change_bundle(
        &self,
        req: Request<GenerateDefinitionChangeBundleRequest>,
    ) -> Result<Response<GenerateDefinitionChangeBundleResponse>, Status> {
        let (metadata, extensions, input) = req.into_parts();
        // The impact report runs under the caller's own metadata, so it
        // authorizes the revisions and applies #837 visibility exactly as a
        // direct ReportDefinitionConsumerImpact call would.
        let impact = self
            .report_visible_definition_consumer_impact(Request::from_parts(
                metadata,
                extensions,
                ReportDefinitionConsumerImpactRequest {
                    namespace: input.namespace.clone(),
                    from_revision_digest: input.from_revision_digest.clone(),
                    to_revision_digest: input.to_revision_digest.clone(),
                },
            ))
            .await?
            .into_inner();
        let runtime = self.db.runtime();
        let load = |digest: &str| {
            let revision = runtime
                .get_definition_revision(&input.namespace, digest)
                .map_err(|_| Status::internal("definition revision unavailable"))?
                .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
            let members = runtime
                .get_definition_members(&input.namespace, digest)
                .map_err(|_| Status::internal("definition revision unavailable"))?;
            Ok::<_, Status>((revision, members))
        };
        let (from, from_members) = load(&input.from_revision_digest)?;
        let (to, to_members) = load(&input.to_revision_digest)?;
        let bundle = generate_change_bundle(
            &from,
            &from_members,
            &to,
            &to_members,
            &hints_from_proto(input.hints),
        )
        // The impact call already ran the same diff, so only hints that do
        // not match it fail here.
        .map_err(Status::invalid_argument)?;
        Ok(Response::new(GenerateDefinitionChangeBundleResponse {
            contract_version: bundle.contract_version,
            bundle_digest: bundle.bundle_digest,
            diff: Some(to_proto_definition_revision_diff(&bundle.diff)),
            steps: bundle
                .steps
                .into_iter()
                .map(|step| DefinitionMigrationStep {
                    kind: step.kind,
                    object_type: step.object_type,
                    property: step.property,
                    from_property: step.from_property,
                    default_value: step.default_value,
                    manual: step.manual,
                    reason: step.reason,
                })
                .collect(),
            backfill_contract: bundle.backfill_contract,
            backfill: bundle
                .backfill
                .into_iter()
                .map(|assignment| DefinitionBackfillAssignment {
                    object_type: assignment.object_type,
                    property: assignment.property,
                    mode: assignment.mode,
                    source: assignment.source,
                })
                .collect(),
            impact: Some(impact),
        }))
    }
}
