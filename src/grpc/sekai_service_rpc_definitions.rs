use super::*;

pub(super) async fn create_definition_branch(
    service: &SekaiServiceImpl,
    req: Request<CreateDefinitionBranchRequest>,
) -> Result<Response<CreateDefinitionBranchResponse>, Status> {
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
    let from_genesis = input.parent_revision_digest.is_empty();
    let parent_revision_digest = if from_genesis {
        definition_genesis(&input.namespace)
            .map_err(Status::invalid_argument)?
            .revision_digest
    } else {
        input.parent_revision_digest
    };
    let request = definition_branch_domain::CreateDefinitionBranch {
        namespace: input.namespace,
        branch_id: input.branch_id,
        parent_revision_digest,
        idempotency_key: input.idempotency_key,
    };
    // The whole request is valid before genesis can become the published head.
    request.validate().map_err(Status::invalid_argument)?;
    if from_genesis {
        seed_definition_genesis(service, &request.namespace)?;
    }
    authorize_definition_revision(
        service,
        &principals,
        &request.namespace,
        &request.parent_revision_digest,
        true,
    )?;
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let result = service
        .db
        .runtime()
        .create_definition_branch(&request, actor, now_millis())
        .map_err(map_definition_write_error)?;
    let definition_branch_domain::DefinitionWriteResult::CreateBranch { branch } = result else {
        return Err(Status::internal("definition replay result is invalid"));
    };
    Ok(Response::new(CreateDefinitionBranchResponse {
        branch: Some(to_proto_definition_branch(&branch)),
    }))
}
pub(super) async fn get_definition_branch(
    service: &SekaiServiceImpl,
    req: Request<GetDefinitionBranchRequest>,
) -> Result<Response<GetDefinitionBranchResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    if input.branch_id.is_empty()
        || input.branch_id.len() > definition_branch_domain::MAX_DEFINITION_ID_BYTES
        || input.branch_id.trim() != input.branch_id
        || input.branch_id.chars().any(char::is_control)
    {
        return Err(Status::invalid_argument("canonical branch_id required"));
    }
    let branch = service
        .db
        .runtime()
        .get_definition_branch(&input.namespace, &input.branch_id)
        .map_err(|_| Status::internal("definition branch unavailable"))?
        .ok_or_else(|| Status::not_found("definition branch unavailable"))?;
    authorize_definition_revision(
        service,
        &principals,
        &branch.namespace,
        &branch.head_revision_digest,
        false,
    )?;
    Ok(Response::new(GetDefinitionBranchResponse {
        branch: Some(to_proto_definition_branch(&branch)),
    }))
}
pub(super) async fn apply_definition_branch_edit(
    service: &SekaiServiceImpl,
    req: Request<ApplyDefinitionBranchEditRequest>,
) -> Result<Response<ApplyDefinitionBranchEditResponse>, Status> {
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
    let request = definition_branch_domain::ApplyDefinitionBranchEdit {
        namespace: input.namespace,
        branch_id: input.branch_id,
        expected_head_digest: input.expected_head_digest,
        upserts: input
            .upserts
            .iter()
            .map(from_proto_definition_member_input)
            .collect(),
        removals: input
            .removals
            .iter()
            .map(from_proto_definition_member_ref)
            .collect(),
        idempotency_key: input.idempotency_key,
    };
    let (upserts, removals, _) = request.prepare().map_err(Status::invalid_argument)?;
    authorize_definition_revision(
        service,
        &principals,
        &request.namespace,
        &request.expected_head_digest,
        false,
    )?;
    for member in &upserts {
        authorize_definition_member_write(
            service,
            &principals,
            &member.member_kind,
            &member.member_id,
        )?;
    }
    for member in &removals {
        authorize_definition_member_write(
            service,
            &principals,
            &member.member_kind,
            &member.member_id,
        )?;
    }
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let result = service
        .db
        .runtime()
        .apply_definition_branch_edit(&request, actor, now_millis())
        .map_err(map_definition_write_error)?;
    let definition_branch_domain::DefinitionWriteResult::ApplyEdit { result } = result else {
        return Err(Status::internal("definition replay result is invalid"));
    };
    Ok(Response::new(ApplyDefinitionBranchEditResponse {
        branch: Some(to_proto_definition_branch(&result.branch)),
        previous_head_digest: result.previous_head_digest,
        revision: Some(to_proto_definition_revision(&result.revision)),
        changed_member_digests: result.changed_member_digests,
    }))
}
pub(super) async fn create_definition_proposal(
    service: &SekaiServiceImpl,
    req: Request<CreateDefinitionProposalRequest>,
) -> Result<Response<CreateDefinitionProposalResponse>, Status> {
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
    let request = definition_proposal_domain::CreateDefinitionProposal {
        namespace: input.namespace,
        branch_id: input.branch_id,
        proposal_id: input.proposal_id,
        base_digest: input.base_digest,
        candidate_digest: input.candidate_digest,
        eval_plan_digests: input.eval_plan_digests,
        named_foreign_digests: input.named_foreign_digests,
        idempotency_key: input.idempotency_key,
    };
    request.prepare().map_err(Status::invalid_argument)?;
    authorize_definition_revision(
        service,
        &principals,
        &request.namespace,
        &request.base_digest,
        true,
    )?;
    authorize_definition_revision(
        service,
        &principals,
        &request.namespace,
        &request.candidate_digest,
        false,
    )?;
    authorize_proposal_member_writes(
        service,
        &principals,
        &request.namespace,
        &request.base_digest,
        &request.candidate_digest,
    )?;
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let result = service
        .db
        .runtime()
        .create_definition_proposal(&request, actor, now_millis())
        .map_err(map_definition_write_error)?;
    let definition_branch_domain::DefinitionWriteResult::CreateProposal { proposal } = result
    else {
        return Err(Status::internal("definition replay result is invalid"));
    };
    Ok(Response::new(CreateDefinitionProposalResponse {
        proposal: Some(to_proto_definition_proposal(&proposal)),
    }))
}
pub(super) async fn get_definition_proposal(
    service: &SekaiServiceImpl,
    req: Request<GetDefinitionProposalRequest>,
) -> Result<Response<GetDefinitionProposalResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    if input.proposal_id.is_empty()
        || input.proposal_id.len() > definition_branch_domain::MAX_DEFINITION_ID_BYTES
        || input.proposal_id.trim() != input.proposal_id
        || input.proposal_id.chars().any(char::is_control)
    {
        return Err(Status::invalid_argument("canonical proposal_id required"));
    }
    let proposal = service
        .db
        .runtime()
        .get_definition_proposal(&input.namespace, &input.proposal_id)
        .map_err(|_| Status::internal("definition proposal unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    authorize_definition_revision(
        service,
        &principals,
        &proposal.namespace,
        &proposal.candidate_digest,
        false,
    )?;
    Ok(Response::new(GetDefinitionProposalResponse {
        proposal: Some(to_proto_definition_proposal(&proposal)),
    }))
}
pub(super) async fn approve_definition_proposal(
    service: &SekaiServiceImpl,
    req: Request<ApproveDefinitionProposalRequest>,
) -> Result<Response<ApproveDefinitionProposalResponse>, Status> {
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
    let request = definition_proposal_domain::ApproveDefinitionProposal {
        namespace: input.namespace,
        proposal_id: input.proposal_id,
        idempotency_key: input.idempotency_key,
    };
    request.request_digest().map_err(Status::invalid_argument)?;
    let proposal = service
        .db
        .runtime()
        .get_definition_proposal(&request.namespace, &request.proposal_id)
        .map_err(|_| Status::internal("definition proposal unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    authorize_proposal_member_writes(
        service,
        &principals,
        &proposal.namespace,
        &proposal.base_digest,
        &proposal.candidate_digest,
    )?;
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let result = service
        .db
        .runtime()
        .approve_definition_proposal(&request, actor, now_millis())
        .map_err(map_definition_write_error)?;
    let definition_branch_domain::DefinitionWriteResult::ApproveProposal { proposal } = result
    else {
        return Err(Status::internal("definition replay result is invalid"));
    };
    Ok(Response::new(ApproveDefinitionProposalResponse {
        proposal: Some(to_proto_definition_proposal(&proposal)),
    }))
}
pub(super) async fn merge_definition_proposal(
    service: &SekaiServiceImpl,
    req: Request<MergeDefinitionProposalRequest>,
) -> Result<Response<MergeDefinitionProposalResponse>, Status> {
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
    let request = definition_proposal_domain::MergeDefinitionProposal {
        namespace: input.namespace,
        proposal_id: input.proposal_id,
        expected_published_digest: input.expected_published_digest,
        idempotency_key: input.idempotency_key,
    };
    request.request_digest().map_err(Status::invalid_argument)?;
    let proposal = service
        .db
        .runtime()
        .get_definition_proposal(&request.namespace, &request.proposal_id)
        .map_err(|_| Status::internal("definition proposal unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    authorize_proposal_member_writes(
        service,
        &principals,
        &proposal.namespace,
        &proposal.base_digest,
        &proposal.candidate_digest,
    )?;
    let has_live_approval = proposal.approvals.iter().any(|approval| {
        let principals = std::slice::from_ref(&approval.actor);
        authorize_source_sync_namespace(
            service,
            principals,
            tenant_context.as_ref(),
            &proposal.namespace,
            true,
        )
        .and_then(|_| {
            authorize_proposal_member_writes(
                service,
                principals,
                &proposal.namespace,
                &proposal.base_digest,
                &proposal.candidate_digest,
            )
        })
        .is_ok()
    });
    if !has_live_approval {
        return Err(Status::failed_precondition(
            "definition write is not current",
        ));
    }
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let result = service
        .db
        .runtime()
        .merge_definition_proposal(&request, actor, now_millis())
        .map_err(map_definition_write_error)?;
    let definition_branch_domain::DefinitionWriteResult::MergeProposal { result } = result else {
        return Err(Status::internal("definition replay result is invalid"));
    };
    Ok(Response::new(MergeDefinitionProposalResponse {
        proposal: Some(to_proto_definition_proposal(&result.proposal)),
        previous_published_digest: result.previous_published_digest,
        published_revision: Some(to_proto_definition_revision(&result.published_revision)),
        receipt_id: result.receipt_id,
    }))
}
pub(super) async fn close_definition_proposal(
    service: &SekaiServiceImpl,
    req: Request<CloseDefinitionProposalRequest>,
) -> Result<Response<CloseDefinitionProposalResponse>, Status> {
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
    let request = definition_proposal_domain::CloseDefinitionProposal {
        namespace: input.namespace,
        proposal_id: input.proposal_id,
        reason_code: input.reason_code,
        idempotency_key: input.idempotency_key,
    };
    request.request_digest().map_err(Status::invalid_argument)?;
    let proposal = service
        .db
        .runtime()
        .get_definition_proposal(&request.namespace, &request.proposal_id)
        .map_err(|_| Status::internal("definition proposal unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    authorize_proposal_member_writes(
        service,
        &principals,
        &proposal.namespace,
        &proposal.base_digest,
        &proposal.candidate_digest,
    )?;
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let result = service
        .db
        .runtime()
        .close_definition_proposal(&request, actor, now_millis())
        .map_err(map_definition_write_error)?;
    let definition_branch_domain::DefinitionWriteResult::CloseProposal { proposal } = result else {
        return Err(Status::internal("definition replay result is invalid"));
    };
    Ok(Response::new(CloseDefinitionProposalResponse {
        proposal: Some(to_proto_definition_proposal(&proposal)),
    }))
}
pub(super) async fn get_published_definition_revision(
    service: &SekaiServiceImpl,
    req: Request<GetPublishedDefinitionRevisionRequest>,
) -> Result<Response<GetPublishedDefinitionRevisionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    let revision = service
        .db
        .runtime()
        .get_published_definition_revision(&input.namespace)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    authorize_definition_revision(
        service,
        &principals,
        &revision.namespace,
        &revision.revision_digest,
        true,
    )?;
    Ok(Response::new(GetPublishedDefinitionRevisionResponse {
        revision: Some(to_proto_definition_revision(&revision)),
    }))
}
pub(super) async fn compare_definition_revisions(
    service: &SekaiServiceImpl,
    req: Request<CompareDefinitionRevisionsRequest>,
) -> Result<Response<CompareDefinitionRevisionsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    let (from, from_members, to, to_members) = load_authorized_definition_revisions(
        service,
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
    Ok(Response::new(CompareDefinitionRevisionsResponse {
        diff: Some(to_proto_definition_revision_diff(&diff)),
    }))
}
pub(super) async fn report_definition_consumer_impact(
    service: &SekaiServiceImpl,
    req: Request<ReportDefinitionConsumerImpactRequest>,
) -> Result<Response<ReportDefinitionConsumerImpactResponse>, Status> {
    service.report_visible_definition_consumer_impact(req).await
}
pub(super) async fn classify_definition_revision_compatibility(
    service: &SekaiServiceImpl,
    req: Request<ClassifyDefinitionRevisionCompatibilityRequest>,
) -> Result<Response<ClassifyDefinitionRevisionCompatibilityResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    let (from, from_members, to, to_members) = load_authorized_definition_revisions(
        service,
        &principals,
        &input.namespace,
        &input.from_revision_digest,
        &input.to_revision_digest,
    )?;
    let compatibility = definition_diff_domain::classify_definition_revision_compatibility(
        &from,
        &from_members,
        &to,
        &to_members,
    )
    .map_err(map_definition_write_error)?;
    Ok(Response::new(
        ClassifyDefinitionRevisionCompatibilityResponse {
            compatibility: Some(to_proto_definition_revision_compatibility(&compatibility)),
        },
    ))
}
pub(super) async fn execute_definition_fact_migration(
    service: &SekaiServiceImpl,
    req: Request<ExecuteDefinitionFactMigrationRequest>,
) -> Result<Response<ExecuteDefinitionFactMigrationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let policy_context = principal_policy_context(&req);
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    let _ = load_authorized_definition_revisions(
        service,
        &principals,
        &input.namespace,
        &input.from_revision_digest,
        &input.to_revision_digest,
    )?;
    let actor = principals.first().cloned().unwrap_or_default();
    let result = service
        .db
        .runtime()
        .execute_definition_fact_migration(
            &crate::sekai::definition_migration::ExecuteFactMigration {
                namespace: input.namespace,
                migration_id: input.migration_id,
                from_revision_digest: input.from_revision_digest,
                to_revision_digest: input.to_revision_digest,
                mode: input.mode,
                idempotency_key: input.idempotency_key,
            },
            &actor,
            &policy_context,
            now_millis(),
        )
        .map_err(map_definition_write_error)?;
    Ok(Response::new(ExecuteDefinitionFactMigrationResponse {
        migration: Some(to_proto_definition_fact_migration(&result)),
    }))
}
pub(super) async fn get_definition_fact_migration(
    service: &SekaiServiceImpl,
    req: Request<GetDefinitionFactMigrationRequest>,
) -> Result<Response<GetDefinitionFactMigrationResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    let result = service
        .db
        .runtime()
        .get_definition_fact_migration(&input.namespace, &input.migration_id)
        .map_err(|_| Status::internal("definition resource unavailable"))?;
    let Some(result) = result else {
        return Err(Status::not_found("definition resource unavailable"));
    };
    match load_authorized_definition_revisions(
        service,
        &principals,
        &result.namespace,
        &result.from_revision_digest,
        &result.to_revision_digest,
    ) {
        Ok(_) => Ok(Response::new(GetDefinitionFactMigrationResponse {
            migration: Some(to_proto_definition_fact_migration(&result)),
        })),
        Err(status) if status.code() == tonic::Code::Internal => Err(status),
        Err(_) => Err(Status::not_found("definition resource unavailable")),
    }
}
pub(super) async fn create_handoff(
    service: &SekaiServiceImpl,
    req: Request<CreateHandoffRequest>,
) -> Result<Response<CreateHandoffResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let proto = inner
        .manifest
        .ok_or(Status::invalid_argument("manifest required"))?;
    check_team_namespace(service.db.runtime(), &principals, &proto.namespace, true)?;
    let creator = principals
        .first()
        .cloned()
        .ok_or(Status::unauthenticated("principal required"))?;
    let manifest = handoff_domain::HandoffManifest {
        schema_version: handoff_domain::HANDOFF_VERSION.into(),
        id: proto.id,
        namespace: proto.namespace,
        parent_operation_id: proto.parent_operation_id,
        parent_attempt_id: proto.parent_attempt_id,
        parent_work_unit_id: proto.parent_work_unit_id,
        references: proto
            .references
            .iter()
            .map(to_domain_handoff_reference)
            .collect(),
        creator_principal: creator,
        intended_principal: proto.intended_principal,
        intended_scope: proto.intended_scope,
        purpose: proto.purpose,
        created_at_ms: proto.created_at_ms,
        expires_at_ms: proto.expires_at_ms,
        digest: proto.digest,
        supersedes_manifest_id: proto.supersedes_manifest_id,
        revoked: false,
    };
    let current_time = now_millis();
    let namespace = manifest.namespace.clone();
    let stored = HandoffLifecycle::new(service.db.runtime())
        .create(
            CreateHandoffCommand {
                manifest,
                request_id: &inner.request_id,
                principals: &principals,
                now_ms: current_time,
            },
            |reference| {
                handoff_reference_available(
                    service,
                    reference,
                    &namespace,
                    &principals,
                    current_time,
                )
                .map_err(|status| HandoffLifecycleError::Storage(status.to_string()))
            },
        )
        .map_err(map_handoff_lifecycle_error)?;
    Ok(Response::new(CreateHandoffResponse {
        manifest: Some(to_proto_handoff(&stored)),
    }))
}
pub(super) async fn revoke_handoff(
    service: &SekaiServiceImpl,
    req: Request<RevokeHandoffRequest>,
) -> Result<Response<RevokeHandoffResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let revoked = HandoffLifecycle::new(service.db.runtime())
        .revoke(RevokeHandoffCommand {
            manifest_id: &inner.manifest_id,
            reason: &inner.reason,
            request_id: &inner.request_id,
            principals: &principals,
            now_ms: now_millis(),
        })
        .map_err(map_handoff_lifecycle_error)?;
    Ok(Response::new(RevokeHandoffResponse {
        manifest: Some(to_proto_handoff(&revoked)),
    }))
}

/// The empty genesis revision every namespace starts from (#1152). It is the
/// same digest everywhere for a namespace, so seeding it is idempotent.
pub(super) fn definition_genesis(
    namespace: &str,
) -> Result<definition_branch_domain::DefinitionRevision, String> {
    definition_branch_domain::prepare_revision(namespace, "", [], true, "genesis", 1)
}

/// Seeds the genesis revision as the published head when the namespace has
/// none. A namespace that already published anything
/// else must branch from that head instead.
fn seed_definition_genesis(service: &SekaiServiceImpl, namespace: &str) -> Result<(), Status> {
    let genesis = definition_genesis(namespace).map_err(Status::invalid_argument)?;
    service
        .db
        .runtime()
        .seed_published_definition_revision(&genesis, &[])
        .map_err(|error| {
            if error.starts_with("stale_published_definition_head") {
                Status::failed_precondition(
                    "namespace already publishes a definition revision; branch from it",
                )
            } else {
                Status::internal("definition revision unavailable")
            }
        })?;
    Ok(())
}
