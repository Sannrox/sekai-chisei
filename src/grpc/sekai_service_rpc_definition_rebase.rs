//! Rebase and archive of definition branches (#2434).
//!
//! A rebase first runs as a dry run. Its outcome names the members the rebase
//! would change, and the caller needs write on each of those before anything
//! is written. A dry run that was asked for, or one that found an unresolved
//! conflict, is the answer.

use super::*;
use crate::sekai::definition_branch_rebase::{
    DefinitionBranchRebaseResult, RebaseChoice, RebaseConflict, RebaseDefinitionBranch,
    RebaseResolution, SetDefinitionBranchArchived,
};

/// Trait routes for the facade's `delegate_rpcs!` list.
impl SekaiServiceImpl {
    pub(super) async fn rebase_definition_branch_rpc(
        &self,
        req: Request<RebaseDefinitionBranchRequest>,
    ) -> Result<Response<RebaseDefinitionBranchResponse>, Status> {
        rebase_definition_branch(self, req).await
    }

    pub(super) async fn set_definition_branch_archived_rpc(
        &self,
        req: Request<SetDefinitionBranchArchivedRequest>,
    ) -> Result<Response<SetDefinitionBranchArchivedResponse>, Status> {
        set_definition_branch_archived(self, req).await
    }
}

async fn rebase_definition_branch(
    service: &SekaiServiceImpl,
    req: Request<RebaseDefinitionBranchRequest>,
) -> Result<Response<RebaseDefinitionBranchResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    let resolutions = input
        .resolutions
        .into_iter()
        .map(|resolution| {
            Ok(RebaseResolution {
                choice: RebaseChoice::parse(&resolution.choice).ok_or_else(|| {
                    Status::invalid_argument(
                        "resolution choice must be keep_branch or take_published",
                    )
                })?,
                member_kind: resolution.member_kind,
                member_id: resolution.member_id,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let request = RebaseDefinitionBranch {
        namespace: input.namespace,
        branch_id: input.branch_id,
        expected_head_digest: input.expected_head_digest,
        onto_published_digest: input.onto_published_digest,
        resolutions,
        dry_run: input.dry_run,
        idempotency_key: input.idempotency_key,
    };
    request.prepare().map_err(Status::invalid_argument)?;
    let runtime = service.db.runtime();
    let branch = runtime
        .get_definition_branch(&request.namespace, &request.branch_id)
        .map_err(|_| Status::internal("definition branch unavailable"))?
        .ok_or_else(|| Status::not_found("definition branch unavailable"))?;
    // The rebased head holds only members of these two revisions.
    authorize_definition_revision(
        service,
        &principals,
        &request.namespace,
        &branch.head_revision_digest,
        false,
    )?;
    authorize_definition_revision(
        service,
        &principals,
        &request.namespace,
        &request.onto_published_digest,
        true,
    )?;
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let dry_run = RebaseDefinitionBranch {
        dry_run: true,
        ..request.clone()
    };
    let planned = rebase_result(
        runtime
            .rebase_definition_branch(&dry_run, actor, now_millis())
            .map_err(map_definition_write_error)?,
    )?;
    for member in &planned.changed_members {
        authorize_definition_member_write(
            service,
            &principals,
            &member.member_kind,
            &member.member_id,
        )?;
    }
    let result = if request.dry_run || planned.applied || !planned.conflicts.is_empty() {
        planned
    } else {
        rebase_result(
            runtime
                .rebase_definition_branch(&request, actor, now_millis())
                .map_err(map_definition_write_error)?,
        )?
    };
    let preview = match &result.revision {
        Some(revision) => Some(rebase_preview(service, &request, &branch, revision)?),
        None => None,
    };
    Ok(Response::new(RebaseDefinitionBranchResponse {
        branch: Some(to_proto_definition_branch(&result.branch)),
        previous_head_digest: result.previous_head_digest,
        revision_digest: result
            .revision
            .map(|revision| revision.revision_digest)
            .unwrap_or_default(),
        preview,
        conflicts: result
            .conflicts
            .into_iter()
            .map(to_proto_conflict)
            .collect(),
        superseded_proposal_ids: result.superseded_proposal_ids,
        applied: result.applied,
    }))
}

fn rebase_result(
    result: definition_branch_domain::DefinitionWriteResult,
) -> Result<DefinitionBranchRebaseResult, Status> {
    match result {
        definition_branch_domain::DefinitionWriteResult::Rebase { result } => Ok(*result),
        _ => Err(Status::internal("definition replay result is invalid")),
    }
}

/// The published head against the rebased head. A rebased head that is
/// not stored yet (a dry run) holds bodies of the branch head or the
/// published revision, so they are read from there.
fn rebase_preview(
    service: &SekaiServiceImpl,
    request: &RebaseDefinitionBranch,
    branch: &definition_branch_domain::DefinitionBranch,
    revision: &definition_branch_domain::DefinitionRevision,
) -> Result<DefinitionRevisionDiff, Status> {
    let runtime = service.db.runtime();
    let unavailable = |_| Status::internal("definition revision unavailable");
    let published = runtime
        .get_definition_revision(&request.namespace, &request.onto_published_digest)
        .map_err(unavailable)?
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    let published_members = runtime
        .get_definition_members(&request.namespace, &published.revision_digest)
        .map_err(unavailable)?;
    let stored = runtime
        .get_definition_revision(&request.namespace, &revision.revision_digest)
        .map_err(unavailable)?
        .is_some();
    let members = if stored {
        runtime
            .get_definition_members(&request.namespace, &revision.revision_digest)
            .map_err(unavailable)?
    } else {
        let head_members = runtime
            .get_definition_members(&request.namespace, &branch.head_revision_digest)
            .map_err(unavailable)?;
        let bodies = head_members
            .iter()
            .chain(&published_members)
            .map(|member| (member.member_digest.as_str(), member))
            .collect::<std::collections::BTreeMap<_, _>>();
        revision
            .members
            .iter()
            .map(|member| {
                bodies
                    .get(member.member_digest.as_str())
                    .map(|body| (*body).clone())
                    .ok_or_else(|| Status::internal("definition revision unavailable"))
            })
            .collect::<Result<Vec<_>, Status>>()?
    };
    let diff = definition_diff_domain::compare_definition_revisions(
        &published,
        &published_members,
        revision,
        &members,
    )
    .map_err(map_definition_write_error)?;
    Ok(to_proto_definition_revision_diff(&diff))
}

fn to_proto_conflict(conflict: RebaseConflict) -> DefinitionRebaseConflict {
    DefinitionRebaseConflict {
        member_kind: conflict.member_kind,
        member_id: conflict.member_id,
        base_member_digest: conflict.base_member_digest,
        branch_member_digest: conflict.branch_member_digest,
        published_member_digest: conflict.published_member_digest,
    }
}

async fn set_definition_branch_archived(
    service: &SekaiServiceImpl,
    req: Request<SetDefinitionBranchArchivedRequest>,
) -> Result<Response<SetDefinitionBranchArchivedResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    let request = SetDefinitionBranchArchived {
        namespace: input.namespace,
        branch_id: input.branch_id,
        archived: input.archived,
        reason: input.reason,
        idempotency_key: input.idempotency_key,
    };
    request.request_digest().map_err(Status::invalid_argument)?;
    let runtime = service.db.runtime();
    let branch = runtime
        .get_definition_branch(&request.namespace, &request.branch_id)
        .map_err(|_| Status::internal("definition branch unavailable"))?
        .ok_or_else(|| Status::not_found("definition branch unavailable"))?;
    authorize_definition_revision(
        service,
        &principals,
        &request.namespace,
        &branch.head_revision_digest,
        false,
    )?;
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let definition_branch_domain::DefinitionWriteResult::SetArchived { result } = runtime
        .set_definition_branch_archived(&request, actor, now_millis())
        .map_err(map_definition_write_error)?
    else {
        return Err(Status::internal("definition replay result is invalid"));
    };
    Ok(Response::new(SetDefinitionBranchArchivedResponse {
        branch: Some(to_proto_definition_branch(&result.branch)),
        closed_proposal_ids: result.closed_proposal_ids,
    }))
}
