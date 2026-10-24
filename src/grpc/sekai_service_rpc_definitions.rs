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
pub(super) async fn get_definition_member(
    service: &SekaiServiceImpl,
    req: Request<GetDefinitionMemberRequest>,
) -> Result<Response<GetDefinitionMemberResponse>, Status> {
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
    definition_branch_domain::validate_digest("revision_digest", &input.revision_digest)
        .map_err(Status::invalid_argument)?;
    definition_branch_domain::DefinitionMemberRef {
        member_kind: input.member_kind.clone(),
        member_id: input.member_id.clone(),
    }
    .validate()
    .map_err(Status::invalid_argument)?;
    // Preserve the existing revision-wide grant requirement, including sibling members.
    authorize_definition_revision(
        service,
        &principals,
        &input.namespace,
        &input.revision_digest,
        false,
    )
    .map_err(|status| match status.code() {
        tonic::Code::NotFound => Status::not_found("definition member unavailable"),
        tonic::Code::Internal => Status::internal("definition member unavailable"),
        _ => status,
    })?;
    let revision = service
        .db
        .runtime()
        .get_definition_revision(&input.namespace, &input.revision_digest)
        .map_err(|_| Status::internal("definition member unavailable"))?
        .ok_or_else(|| Status::not_found("definition member unavailable"))?;
    let member = service
        .db
        .runtime()
        .get_definition_member(
            &input.namespace,
            &input.revision_digest,
            &input.member_kind,
            &input.member_id,
        )
        .map_err(|_| Status::internal("definition member unavailable"))?
        .ok_or_else(|| Status::not_found("definition member unavailable"))?;
    Ok(Response::new(GetDefinitionMemberResponse {
        revision_digest: revision.revision_digest,
        member: Some(DefinitionMember {
            contract_version: member.contract_version,
            namespace: member.namespace,
            member_kind: member.member_kind,
            member_id: member.member_id,
            definition_json: member.definition_json,
            member_digest: member.member_digest,
        }),
    }))
}

fn stored_suite_result(
    service: &SekaiServiceImpl,
    suite_id: &str,
    certification_id: &str,
) -> Result<crate::sekai::agent_promotion::StoredSuiteResult, Status> {
    let run = service
        .db
        .runtime()
        .get_eval_run_record(certification_id)
        .map_err(|_| {
            Status::failed_precondition(crate::sekai::agent_promotion::REFUSAL_SUITE_MISSING)
        })?
        .ok_or_else(|| {
            Status::failed_precondition(crate::sekai::agent_promotion::REFUSAL_SUITE_MISSING)
        })?;
    if crate::sekai::agent_dry_run::run_is_dry_run(&run.config_ref, &run.suite_id) {
        return Err(Status::failed_precondition(
            crate::sekai::agent_dry_run::REFUSAL_DRY_RUN,
        ));
    }
    if crate::sekai::agent_shadow::run_is_shadow(&run.config_ref, &run.suite_id) {
        return Err(Status::failed_precondition(
            crate::sekai::agent_shadow::REFUSAL_SHADOW_CERTIFY,
        ));
    }
    if run.suite_id != suite_id {
        return Err(Status::failed_precondition(
            crate::sekai::agent_promotion::REFUSAL_SUITE_MISSING,
        ));
    }
    let passed = !run.results.is_empty() && run.results.iter().all(|result| result.passed);
    Ok(
        crate::sekai::agent_promotion::StoredSuiteResult::from_run_pass(
            &run.suite_id,
            &run.id,
            passed,
        )
        .with_scores(run.results.iter().map(|result| result.score)),
    )
}

/// The published revision's certification: the #1640 regression baseline.
fn published_certification(
    service: &SekaiServiceImpl,
    namespace: &str,
    published: Option<&crate::sekai::definition_branch::DefinitionRevision>,
) -> Result<Option<crate::sekai::agent_promotion::AgentDefinitionCertification>, Status> {
    let Some(published) = published else {
        return Ok(None);
    };
    service
        .db
        .runtime()
        .get_agent_definition_certification(namespace, &published.revision_digest)
        .map_err(|_| Status::internal("definition resource unavailable"))
}

/// #1644: whether every agent of `revision_digest` has an approval policy on
/// each tool that mutates or destroys. The inner error is the refusal
/// (`agent_tool_approval_required:<tool>`); an Action type that cannot be
/// read counts as destructive.
fn agent_tool_approvals(
    service: &SekaiServiceImpl,
    namespace: &str,
    revision_digest: &str,
) -> Result<Result<(), String>, Status> {
    let runtime = service.db.runtime();
    let members = runtime
        .get_definition_members(namespace, revision_digest)
        .map_err(|_| Status::internal("definition resource unavailable"))?;
    let action_types = runtime
        .list_governed_action_types(namespace, None, true)
        .unwrap_or_default();
    Ok(crate::sekai::agent_definition::require_revision_tool_approvals(&members, &action_types))
}

fn map_certification_bind_error(error: String) -> Status {
    if error.starts_with("agent_promotion_self_certification") {
        Status::permission_denied(error)
    } else if error.starts_with("agent_promotion_certification_expiry")
        || error.starts_with("agent_promotion_certification_status")
    {
        Status::invalid_argument(error)
    } else if error.starts_with("agent_promotion_") {
        Status::failed_precondition(error)
    } else {
        Status::invalid_argument(error)
    }
}

fn map_certification_store_error(error: String) -> Status {
    if error.starts_with("agent_promotion_") {
        map_certification_bind_error(error)
    } else {
        Status::internal(error)
    }
}

fn to_proto_definition_certification_gate(
    gate: &crate::sekai::agent_promotion::AgentPromotionGate,
) -> DefinitionCertificationGate {
    DefinitionCertificationGate {
        namespace: gate.namespace.clone(),
        revision_digest: gate.revision_digest.clone(),
        suite_id: gate.suite_id.clone(),
        certification_id: gate.certification_id.clone(),
        certification_status: gate.certification_status.clone(),
        baseline_status: gate.baseline_status.clone(),
        latest_status: gate.latest_status.clone(),
        expires_at_ms: gate.expires_at_ms,
        admitted: gate.admitted,
        refusal: gate.refusal.clone(),
        tools: Vec::new(),
    }
}

/// #1646: every agent member's bound tools with the core's derived effect,
/// so a console never re-derives it.
fn agent_tool_effects(
    service: &SekaiServiceImpl,
    namespace: &str,
    revision_digest: &str,
) -> Result<Vec<crate::grpc::pb::sekai::AgentToolEffect>, Status> {
    let runtime = service.db.runtime();
    let members = runtime
        .get_definition_members(namespace, revision_digest)
        .map_err(|_| Status::internal("definition resource unavailable"))?;
    let action_types = runtime
        .list_governed_action_types(namespace, None, true)
        .unwrap_or_default();
    let mut tools = Vec::new();
    for member in members
        .iter()
        .filter(|member| member.member_kind == crate::sekai::agent_promotion::MEMBER_KIND_AGENT)
    {
        let definition: crate::sekai::agent_definition::AgentDefinition =
            serde_json::from_str(&member.definition_json)
                .map_err(|_| Status::internal("definition resource unavailable"))?;
        for (tool, effect, blocks_publish) in definition.tool_effects(|name| {
            action_types
                .iter()
                .filter(|action| action.type_id == name)
                .cloned()
                .collect()
        }) {
            tools.push(crate::grpc::pb::sekai::AgentToolEffect {
                member_id: member.member_id.clone(),
                kind: tool.kind.clone(),
                name: tool.name.clone(),
                effect: effect.as_str().into(),
                approval_policy: tool.approval_policy.clone().unwrap_or_default(),
                blocks_publish,
            });
        }
    }
    Ok(tools)
}

pub(super) async fn put_definition_certification(
    service: &SekaiServiceImpl,
    req: Request<PutDefinitionCertificationRequest>,
) -> Result<Response<PutDefinitionCertificationResponse>, Status> {
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
    definition_branch_domain::validate_digest("revision_digest", &input.revision_digest)
        .map_err(Status::invalid_argument)?;
    authorize_definition_revision(
        service,
        &principals,
        &input.namespace,
        &input.revision_digest,
        false,
    )?;
    let candidate = service
        .db
        .runtime()
        .get_definition_revision(&input.namespace, &input.revision_digest)
        .map_err(|_| Status::internal("definition resource unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    for member in &candidate.members {
        if member.member_kind != crate::sekai::agent_promotion::MEMBER_KIND_AGENT {
            continue;
        }
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
    let published = service
        .db
        .runtime()
        .get_published_definition_revision(&input.namespace)
        .map_err(|_| Status::internal("definition resource unavailable"))?;
    let lineage = crate::sekai::agent_promotion::certification_lineage(
        &candidate,
        published.as_ref(),
        |digest| {
            service
                .db
                .runtime()
                .get_definition_revision(&input.namespace, digest)
        },
    )
    .map_err(|_| Status::internal("definition resource unavailable"))?;
    let authors = crate::sekai::agent_promotion::agent_change_authors(&lineage);
    if principals
        .iter()
        .any(|principal| authors.contains(principal))
    {
        return Err(Status::permission_denied(
            crate::sekai::agent_promotion::REFUSAL_SELF_CERTIFY,
        ));
    }
    // Binding copies suite identity and pass/fail from a stored run. Merge
    // admits that snapshot; it does not re-run suites.
    let existing = service
        .db
        .runtime()
        .get_agent_definition_certification(&input.namespace, &input.revision_digest)
        .map_err(|_| Status::internal("definition resource unavailable"))?;
    let applying_revoke = existing
        .as_ref()
        .is_some_and(|bound| bound.revoked_at_ms == 0)
        && input.revoked_at_ms > 0;
    let suite = if applying_revoke {
        None
    } else {
        Some(stored_suite_result(
            service,
            &input.suite_id,
            &input.certification_id,
        )?)
    };
    let requested = crate::sekai::agent_promotion::AgentDefinitionCertification {
        namespace: input.namespace,
        revision_digest: input.revision_digest,
        suite_id: input.suite_id,
        certification_id: input.certification_id,
        baseline_status: input.baseline_status,
        latest_status: input.latest_status,
        expires_at_ms: input.expires_at_ms,
        revoked_at_ms: input.revoked_at_ms,
        bound_by: actor.clone(),
        bound_at_ms: now_millis(),
        mean_score_milli: None,
    };
    let certification = crate::sekai::agent_promotion::bind_certification(
        &authors,
        requested,
        existing.as_ref(),
        suite.as_ref(),
    )
    .map_err(map_certification_bind_error)?;
    service
        .db
        .runtime()
        .put_agent_definition_certification(&certification)
        .map_err(map_certification_store_error)?;
    let baseline = published_certification(service, &certification.namespace, published.as_ref())?;
    let gate = certification.gate_against(
        baseline.as_ref(),
        now_millis(),
        crate::sekai::agent_promotion::max_regression_percent(),
    );
    Ok(Response::new(PutDefinitionCertificationResponse {
        gate: Some(DefinitionCertificationGate {
            tools: agent_tool_effects(service, &gate.namespace, &gate.revision_digest)?,
            ..to_proto_definition_certification_gate(&gate)
        }),
    }))
}

pub(super) async fn get_definition_certification_gate(
    service: &SekaiServiceImpl,
    req: Request<GetDefinitionCertificationGateRequest>,
) -> Result<Response<GetDefinitionCertificationGateResponse>, Status> {
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
    definition_branch_domain::validate_digest("revision_digest", &input.revision_digest)
        .map_err(Status::invalid_argument)?;
    authorize_definition_revision(
        service,
        &principals,
        &input.namespace,
        &input.revision_digest,
        false,
    )
    .map_err(|status| match status.code() {
        tonic::Code::NotFound => Status::not_found("definition resource unavailable"),
        tonic::Code::Internal => Status::internal("definition resource unavailable"),
        _ => status,
    })?;
    let candidate = service
        .db
        .runtime()
        .get_definition_revision(&input.namespace, &input.revision_digest)
        .map_err(|_| Status::internal("definition resource unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    let published = service
        .db
        .runtime()
        .get_published_definition_revision(&input.namespace)
        .map_err(|_| Status::internal("definition resource unavailable"))?;
    let from = published
        .as_ref()
        .map(|revision| revision.members.as_slice())
        .unwrap_or(&[]);
    let bound = service
        .db
        .runtime()
        .get_agent_definition_certification(&input.namespace, &input.revision_digest)
        .map_err(|_| Status::internal("definition resource unavailable"))?;
    let baseline = published_certification(service, &input.namespace, published.as_ref())?;
    let mut gate = crate::sekai::agent_promotion::promotion_gate(
        from,
        &candidate.members,
        bound.as_ref(),
        baseline.as_ref(),
        now_millis(),
        &input.namespace,
        &input.revision_digest,
    );
    // The gate reports the same tool-approval refusal merge applies (#1644).
    if gate.admitted
        && let Err(refusal) =
            agent_tool_approvals(service, &input.namespace, &input.revision_digest)?
    {
        gate.admitted = false;
        gate.refusal = refusal;
    }
    Ok(Response::new(GetDefinitionCertificationGateResponse {
        gate: Some(DefinitionCertificationGate {
            tools: agent_tool_effects(service, &gate.namespace, &gate.revision_digest)?,
            ..to_proto_definition_certification_gate(&gate)
        }),
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
        major_revision: input.major_revision,
        migration_plan_digest: input.migration_plan_digest,
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
    let policy_context = principal_policy_context(&req);
    let purpose = request_purpose_presentation(&req, &principals);
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
    // The lint findings the candidate introduces over the base (#1687),
    // judged on the consumers this caller may see; the merge gate judges
    // the same on every consumer.
    let db = service.db.runtime();
    let members = |digest: &str| {
        db.get_definition_members(&proposal.namespace, digest)
            .map_err(|_| Status::internal("definition revision unavailable"))
    };
    let (bindings, lint_complete) = visible_lint_objects(
        service,
        &principals,
        &policy_context,
        purpose.as_ref(),
        tenant_context.as_ref(),
        crate::sekai::definition_consumer_impact::BINDING_KIND,
        Some(&proposal.namespace),
        MAX_LINT_OBJECTS,
    )?;
    let (consumed, consumed_properties) =
        crate::sekai::ontology_lint::consumer_references(&bindings);
    let lint_findings = crate::sekai::ontology_lint::introduced_findings(
        &members(&proposal.base_digest)?,
        &members(&proposal.candidate_digest)?,
        &consumed,
        &consumed_properties,
    );
    Ok(Response::new(GetDefinitionProposalResponse {
        proposal: Some(to_proto_definition_proposal(&proposal)),
        lint_findings: lint_findings
            .into_iter()
            .map(lint_finding_to_proto)
            .collect(),
        lint_complete,
    }))
}
fn refuse_proposal_creator(
    proposal: &definition_proposal_domain::DefinitionProposal,
    actor: &str,
    action: &str,
) -> Result<(), Status> {
    // `root` / `local` are the unix-socket operator identity. One operator
    // creates, approves, and merges on that path. Agent principals cannot.
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    if proposal.created_by == actor {
        return Err(Status::permission_denied(format!(
            "proposal creator cannot {action}"
        )));
    }
    Ok(())
}

/// Approving, merging, or closing discloses both revisions, so the caller
/// must read them as creation and retrieval require (ADR 0111).
fn authorize_proposal_revision_reads(
    service: &SekaiServiceImpl,
    principals: &[String],
    proposal: &definition_proposal_domain::DefinitionProposal,
) -> Result<(), Status> {
    for digest in [&proposal.base_digest, &proposal.candidate_digest] {
        authorize_definition_revision(service, principals, &proposal.namespace, digest, false)?;
    }
    Ok(())
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
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    refuse_proposal_creator(&proposal, actor, "approve")?;
    authorize_proposal_revision_reads(service, &principals, &proposal)?;
    authorize_proposal_member_writes(
        service,
        &principals,
        &proposal.namespace,
        &proposal.base_digest,
        &proposal.candidate_digest,
    )?;
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
/// The checks before a proposal's revision is published (merge, or the last
/// step of a change bundle apply): the actor did not create it, may read both
/// revisions and write the changed members, an approval is still current, and
/// agent tool approvals hold. Returns the acting principal.
pub(super) fn authorize_definition_proposal_merge(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    proposal: &crate::sekai::definition_proposal::DefinitionProposal,
) -> Result<String, Status> {
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    refuse_proposal_creator(proposal, actor, "merge")?;
    authorize_proposal_revision_reads(service, principals, proposal)?;
    authorize_proposal_member_writes(
        service,
        principals,
        &proposal.namespace,
        &proposal.base_digest,
        &proposal.candidate_digest,
    )?;
    let has_live_approval = proposal.approvals.iter().any(|approval| {
        let principals = std::slice::from_ref(&approval.actor);
        authorize_source_sync_namespace(
            service,
            principals,
            tenant_context,
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
    agent_tool_approvals(service, &proposal.namespace, &proposal.candidate_digest)?
        .map_err(Status::failed_precondition)?;
    require_agent_shadow_for_merge(service, proposal)?;
    Ok(actor.clone())
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
        expected_dataset_versions: Vec::new(),
        expected_datasources: Vec::new(),
    };
    request.request_digest().map_err(Status::invalid_argument)?;
    let proposal = service
        .db
        .runtime()
        .get_definition_proposal(&request.namespace, &request.proposal_id)
        .map_err(|_| Status::internal("definition proposal unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    let actor = authorize_definition_proposal_merge(
        service,
        &principals,
        tenant_context.as_ref(),
        &proposal,
    )?;
    let actor = actor.as_str();
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
    authorize_proposal_revision_reads(service, &principals, &proposal)?;
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
pub(super) async fn list_published_definition_revisions(
    service: &SekaiServiceImpl,
    req: Request<ListPublishedDefinitionRevisionsRequest>,
) -> Result<Response<ListPublishedDefinitionRevisionsResponse>, Status> {
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
    definition_proposal_domain::validate_list_published_history_request(
        &input.namespace,
        &input.member_kind,
        &input.member_id,
        &input.page_token,
    )
    .map_err(Status::invalid_argument)?;
    if !input.member_kind.trim().is_empty() {
        authorize_definition_member_read(
            service,
            &principals,
            &input.member_kind,
            &input.member_id,
        )?;
    }
    let (entries, next_page_token) = service
        .db
        .runtime()
        .list_published_definition_revisions(
            &input.namespace,
            &input.member_kind,
            &input.member_id,
            &input.page_token,
            input.page_size,
        )
        .map_err(|error| {
            if error.starts_with("invalid_definition_history_page_token")
                || error.starts_with("definition_history_invalid_member_filter")
                || error.starts_with("canonical ")
            {
                Status::invalid_argument(error)
            } else {
                Status::internal("definition revision unavailable")
            }
        })?;
    Ok(Response::new(ListPublishedDefinitionRevisionsResponse {
        entries: entries
            .into_iter()
            .map(|entry| PublishedDefinitionRevisionHistoryEntry {
                revision_digest: entry.revision_digest,
                previous_published_digest: entry.previous_published_digest,
                proposal_id: entry.proposal_id,
                receipt_id: entry.receipt_id,
                actor: entry.actor,
                published_at_ms: entry.published_at_ms,
            })
            .collect(),
        next_page_token,
    }))
}
pub(super) async fn propose_definition_rollback(
    service: &SekaiServiceImpl,
    req: Request<ProposeDefinitionRollbackRequest>,
) -> Result<Response<ProposeDefinitionRollbackResponse>, Status> {
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
    let published = service
        .db
        .runtime()
        .get_published_definition_revision(&input.namespace)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    authorize_definition_revision(
        service,
        &principals,
        &input.namespace,
        &published.revision_digest,
        true,
    )?;
    let request = definition_proposal_domain::ProposeDefinitionRollback {
        namespace: input.namespace,
        branch_id: input.branch_id,
        proposal_id: input.proposal_id,
        restore_from_digest: input.restore_from_digest,
        expected_published_digest: published.revision_digest.clone(),
        migration_plan_digest: input.migration_plan_digest,
        idempotency_key: input.idempotency_key,
    };
    request.prepare().map_err(Status::invalid_argument)?;
    authorize_definition_revision(
        service,
        &principals,
        &request.namespace,
        &request.restore_from_digest,
        true,
    )?;
    let restore = service
        .db
        .runtime()
        .get_definition_revision(&request.namespace, &request.restore_from_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    for (member_kind, member_id) in
        definition_proposal_domain::changed_member_refs(&published, &restore)
    {
        authorize_definition_member_write(
            service,
            principals.as_slice(),
            &member_kind,
            &member_id,
        )?;
    }
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let result = service
        .db
        .runtime()
        .propose_definition_rollback(&request, actor, now_millis())
        .map_err(map_definition_write_error)?;
    let definition_branch_domain::DefinitionWriteResult::CreateProposal { proposal } = result
    else {
        return Err(Status::internal("definition replay result is invalid"));
    };
    authorize_definition_revision(
        service,
        &principals,
        &proposal.namespace,
        &proposal.base_digest,
        true,
    )?;
    authorize_definition_revision(
        service,
        &principals,
        &proposal.namespace,
        &proposal.candidate_digest,
        false,
    )?;
    authorize_proposal_member_writes(
        service,
        &principals,
        &proposal.namespace,
        &proposal.base_digest,
        &proposal.candidate_digest,
    )?;
    let base = service
        .db
        .runtime()
        .get_definition_revision(&proposal.namespace, &proposal.base_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    let candidate = service
        .db
        .runtime()
        .get_definition_revision(&proposal.namespace, &proposal.candidate_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    let base_members = service
        .db
        .runtime()
        .get_definition_members(&proposal.namespace, &proposal.base_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    let candidate_members = service
        .db
        .runtime()
        .get_definition_members(&proposal.namespace, &proposal.candidate_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    let preview = definition_diff_domain::compare_definition_revisions(
        &base,
        &base_members,
        &candidate,
        &candidate_members,
    )
    .map_err(map_definition_write_error)?;
    Ok(Response::new(ProposeDefinitionRollbackResponse {
        proposal: Some(to_proto_definition_proposal(&proposal)),
        preview: Some(to_proto_definition_revision_diff(&preview)),
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
pub(super) fn seed_definition_genesis(
    service: &SekaiServiceImpl,
    namespace: &str,
) -> Result<(), Status> {
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

pub(super) async fn dry_run_agent(
    service: &SekaiServiceImpl,
    req: Request<DryRunAgentRequest>,
) -> Result<Response<DryRunAgentResponse>, Status> {
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
    definition_branch_domain::validate_digest("revision_digest", &input.revision_digest)
        .map_err(Status::invalid_argument)?;
    definition_branch_domain::DefinitionMemberRef {
        member_kind: crate::sekai::agent_promotion::MEMBER_KIND_AGENT.into(),
        member_id: input.member_id.clone(),
    }
    .validate()
    .map_err(Status::invalid_argument)?;
    authorize_definition_revision(
        service,
        &principals,
        &input.namespace,
        &input.revision_digest,
        false,
    )
    .map_err(|status| match status.code() {
        tonic::Code::NotFound => Status::not_found("definition member unavailable"),
        tonic::Code::Internal => Status::internal("definition member unavailable"),
        _ => status,
    })?;
    let member = service
        .db
        .runtime()
        .get_definition_member(
            &input.namespace,
            &input.revision_digest,
            crate::sekai::agent_promotion::MEMBER_KIND_AGENT,
            &input.member_id,
        )
        .map_err(|_| Status::internal("definition member unavailable"))?
        .ok_or_else(|| Status::not_found("definition member unavailable"))?;
    let definition: crate::sekai::agent_definition::AgentDefinition =
        serde_json::from_str(&member.definition_json)
            .map_err(|_| Status::not_found("definition member unavailable"))?;
    definition
        .validate()
        .map_err(|_| Status::not_found("definition member unavailable"))?;
    let request = crate::sekai::agent_dry_run::DryRunModelRequest {
        namespace: input.namespace.clone(),
        revision_digest: input.revision_digest.clone(),
        member_id: input.member_id.clone(),
        input: input.input,
        instructions: definition.instructions.clone(),
    };
    let reply = match service.dry_run_host.as_ref() {
        Some(host) => host.admit_and_complete(&request),
        None => default_dry_run(service.db.runtime(), &request),
    }
    .map_err(map_dry_run_failure)?;
    let namespace = input.namespace.clone();
    let runtime = service.db.runtime();
    let trace = crate::sekai::agent_dry_run::classify_actions(
        &definition,
        reply,
        |action_type, parameters_json| {
            crate::sekai::agent_dry_run::validate_dry_run_proposed_action(
                runtime,
                &namespace,
                action_type,
                parameters_json,
            )
        },
    );
    let record_id = format!("dry-run-{}", uuid::Uuid::new_v4().simple());
    let record = dry_run_eval_record(
        &input.namespace,
        &input.member_id,
        &input.revision_digest,
        &record_id,
        now_millis(),
        &trace,
    );
    service
        .db
        .runtime()
        .put_eval_run(&record)
        .map_err(Status::internal)?;
    Ok(Response::new(DryRunAgentResponse {
        record_id,
        model_steps: trace
            .model_steps
            .into_iter()
            .map(|(route, output)| DryRunAgentModelStep { route, output })
            .collect(),
        tool_calls: trace
            .tool_calls
            .into_iter()
            .map(|call| DryRunAgentToolCall {
                name: call.name,
                arguments_json: call.arguments_json,
            })
            .collect(),
        actions: trace
            .actions
            .into_iter()
            .map(|action| DryRunAgentAction {
                action_type: action.action_type,
                parameters_json: action.parameters_json,
                disposition: action.disposition,
                reason: action.reason,
            })
            .collect(),
    }))
}

pub(super) async fn run_agent_shadow(
    service: &SekaiServiceImpl,
    req: Request<RunAgentShadowRequest>,
) -> Result<Response<RunAgentShadowResponse>, Status> {
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
    definition_branch_domain::validate_digest(
        "candidate_revision_digest",
        &input.candidate_revision_digest,
    )
    .map_err(Status::invalid_argument)?;
    definition_branch_domain::DefinitionMemberRef {
        member_kind: crate::sekai::agent_promotion::MEMBER_KIND_AGENT.into(),
        member_id: input.member_id.clone(),
    }
    .validate()
    .map_err(Status::invalid_argument)?;
    let envelopes: Vec<crate::sekai::agent_shadow::TriggerEnvelope> = input
        .envelopes
        .into_iter()
        .map(|envelope| crate::sekai::agent_shadow::TriggerEnvelope {
            id: envelope.id,
            input: envelope.input,
        })
        .collect();
    let candidate = load_agent_definition(
        service,
        &principals,
        &input.namespace,
        &input.candidate_revision_digest,
        &input.member_id,
    )?;
    let active_digest = if input.active_revision_digest.is_empty() {
        service
            .db
            .runtime()
            .get_published_definition_revision(&input.namespace)
            .map_err(|_| Status::internal("definition member unavailable"))?
            .ok_or_else(|| Status::not_found("definition member unavailable"))?
            .revision_digest
    } else {
        definition_branch_domain::validate_digest(
            "active_revision_digest",
            &input.active_revision_digest,
        )
        .map_err(Status::invalid_argument)?;
        input.active_revision_digest.clone()
    };
    let active = load_agent_definition(
        service,
        &principals,
        &input.namespace,
        &active_digest,
        &input.member_id,
    )?;
    let runtime = service.db.runtime();
    let namespace = input.namespace.clone();
    let host = ShadowDryRunHost {
        injected: service.dry_run_host.as_deref(),
        runtime,
    };
    let shadow_id = format!("agent-shadow-{}", uuid::Uuid::new_v4().simple());
    let report = crate::sekai::agent_shadow::run_shadow(
        &crate::sekai::agent_shadow::ShadowRun {
            namespace: &input.namespace,
            member_id: &input.member_id,
            active_digest: &active_digest,
            candidate_digest: &input.candidate_revision_digest,
            active: &active,
            candidate: &candidate,
            envelopes: &envelopes,
            require_for_promotion: input.require_for_promotion,
            shadow_id: &shadow_id,
        },
        &host,
        |action_type, parameters_json| {
            crate::sekai::agent_dry_run::validate_dry_run_proposed_action(
                runtime,
                &namespace,
                action_type,
                parameters_json,
            )
        },
    )
    .map_err(map_shadow_failure)?;
    persist_shadow_report(service, &report, now_millis())?;
    if input.require_for_promotion {
        persist_shadow_requirement(service, &input.namespace, now_millis())?;
    }
    Ok(Response::new(RunAgentShadowResponse {
        report: Some(to_proto_shadow_report(&report)),
    }))
}

pub(super) async fn get_agent_shadow_report(
    service: &SekaiServiceImpl,
    req: Request<GetAgentShadowReportRequest>,
) -> Result<Response<GetAgentShadowReportResponse>, Status> {
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
    let report = load_shadow_report(
        service,
        &input.namespace,
        &input.member_id,
        &input.candidate_revision_digest,
        false,
        None,
    )?
    .ok_or_else(|| Status::not_found("agent shadow report unavailable"))?;
    for digest in [
        report.active_revision_digest.as_str(),
        report.candidate_revision_digest.as_str(),
    ] {
        authorize_definition_revision(service, &principals, &report.namespace, digest, false)
            .map_err(|status| match status.code() {
                tonic::Code::NotFound => Status::not_found("agent shadow report unavailable"),
                tonic::Code::Internal => Status::internal("agent shadow report unavailable"),
                _ => status,
            })?;
    }
    Ok(Response::new(GetAgentShadowReportResponse {
        report: Some(to_proto_shadow_report(&report)),
    }))
}

struct ShadowDryRunHost<'a> {
    injected: Option<&'a dyn crate::sekai::agent_dry_run::AgentDryRunHost>,
    runtime: &'a crate::db::runtime_db::RuntimeDb,
}

impl crate::sekai::agent_dry_run::AgentDryRunHost for ShadowDryRunHost<'_> {
    fn admit_and_complete(
        &self,
        request: &crate::sekai::agent_dry_run::DryRunModelRequest,
    ) -> Result<
        crate::sekai::agent_dry_run::DryRunModelReply,
        crate::sekai::agent_dry_run::DryRunFailure,
    > {
        match self.injected {
            Some(host) => host.admit_and_complete(request),
            None => default_dry_run(self.runtime, request),
        }
    }
}

fn map_shadow_failure(error: crate::sekai::agent_shadow::ShadowFailure) -> Status {
    match error {
        crate::sekai::agent_shadow::ShadowFailure::RouteAdmission(reason)
        | crate::sekai::agent_shadow::ShadowFailure::Budget(reason)
        | crate::sekai::agent_shadow::ShadowFailure::Model(reason) => {
            Status::failed_precondition(reason)
        }
    }
}

fn load_agent_definition(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    revision_digest: &str,
    member_id: &str,
) -> Result<crate::sekai::agent_definition::AgentDefinition, Status> {
    authorize_definition_revision(service, principals, namespace, revision_digest, false).map_err(
        |status| match status.code() {
            tonic::Code::NotFound => Status::not_found("definition member unavailable"),
            tonic::Code::Internal => Status::internal("definition member unavailable"),
            _ => status,
        },
    )?;
    let member = service
        .db
        .runtime()
        .get_definition_member(
            namespace,
            revision_digest,
            crate::sekai::agent_promotion::MEMBER_KIND_AGENT,
            member_id,
        )
        .map_err(|_| Status::internal("definition member unavailable"))?
        .ok_or_else(|| Status::not_found("definition member unavailable"))?;
    let definition: crate::sekai::agent_definition::AgentDefinition =
        serde_json::from_str(&member.definition_json)
            .map_err(|_| Status::not_found("definition member unavailable"))?;
    definition
        .validate()
        .map_err(|_| Status::not_found("definition member unavailable"))?;
    Ok(definition)
}

fn persist_shadow_report(
    service: &SekaiServiceImpl,
    report: &crate::sekai::agent_shadow::ShadowReport,
    timestamp: i64,
) -> Result<(), Status> {
    use crate::chisei::eval::{CaseResult, Run};
    let run = Run {
        id: report.shadow_id.clone(),
        suite_id: crate::sekai::agent_shadow::suite_id(&report.namespace, &report.member_id),
        config_ref: crate::sekai::agent_shadow::SHADOW_CONFIG_REF.into(),
        results: vec![CaseResult {
            case_id: report.candidate_revision_digest.clone(),
            passed: report.passing,
            status: "agent_shadow".into(),
            result: serde_json::to_string(report).unwrap_or_else(|_| "{}".into()),
            score: i32::from(report.passing),
            reason: report.verdict_reason.clone(),
            elapsed: report.latency_ms,
        }],
        timestamp,
    };
    service
        .db
        .runtime()
        .put_eval_run(&run)
        .map_err(Status::internal)?;
    Ok(())
}

fn persist_shadow_requirement(
    service: &SekaiServiceImpl,
    namespace: &str,
    timestamp: i64,
) -> Result<(), Status> {
    use crate::chisei::eval::{CaseResult, Run};
    let run = Run {
        id: format!("agent-shadow-required-{}", uuid::Uuid::new_v4().simple()),
        suite_id: crate::sekai::agent_shadow::required_suite_id(namespace),
        config_ref: crate::sekai::agent_shadow::REQUIRED_CONFIG_REF.into(),
        results: vec![CaseResult {
            case_id: namespace.into(),
            passed: true,
            status: "required".into(),
            result: "required".into(),
            score: 1,
            reason: String::new(),
            elapsed: 0,
        }],
        timestamp,
    };
    service
        .db
        .runtime()
        .put_eval_run(&run)
        .map_err(Status::internal)?;
    Ok(())
}

fn eval_runs_relation_missing(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("chisei_eval_runs")
        && (error.contains("no such table") || error.contains("does not exist"))
}

fn list_shadow_eval_runs(
    service: &SekaiServiceImpl,
    suite_id: &str,
) -> Result<Vec<crate::chisei::eval::Run>, Status> {
    match service.db.runtime().list_eval_run_records(suite_id) {
        Ok(runs) => Ok(runs),
        Err(error) if eval_runs_relation_missing(&error) => Ok(Vec::new()),
        Err(error) => Err(Status::internal(error)),
    }
}

fn load_shadow_report(
    service: &SekaiServiceImpl,
    namespace: &str,
    member_id: &str,
    candidate_digest: &str,
    passing_only: bool,
    expected_active: Option<&str>,
) -> Result<Option<crate::sekai::agent_shadow::ShadowReport>, Status> {
    let mut runs = list_shadow_eval_runs(
        service,
        &crate::sekai::agent_shadow::suite_id(namespace, member_id),
    )?;
    runs.sort_by_key(|run| std::cmp::Reverse(run.timestamp));
    for run in runs {
        if !crate::sekai::agent_shadow::run_is_shadow(&run.config_ref, &run.suite_id) {
            continue;
        }
        let Some(result) = run.results.first() else {
            continue;
        };
        if !candidate_digest.is_empty() && result.case_id != candidate_digest {
            continue;
        }
        if let Ok(report) =
            serde_json::from_str::<crate::sekai::agent_shadow::ShadowReport>(&result.result)
        {
            if report.namespace == namespace
                && report.member_id == member_id
                && (!passing_only || report.passing)
                && expected_active
                    .map(|active| report.active_revision_digest == active)
                    .unwrap_or(true)
            {
                return Ok(Some(report));
            }
        }
    }
    Ok(None)
}

fn namespace_requires_agent_shadow(
    service: &SekaiServiceImpl,
    namespace: &str,
) -> Result<bool, Status> {
    let runs = list_shadow_eval_runs(
        service,
        &crate::sekai::agent_shadow::required_suite_id(namespace),
    )?;
    Ok(runs
        .iter()
        .any(|run| crate::sekai::agent_shadow::run_is_shadow(&run.config_ref, &run.suite_id)))
}

fn require_agent_shadow_for_merge(
    service: &SekaiServiceImpl,
    proposal: &crate::sekai::definition_proposal::DefinitionProposal,
) -> Result<(), Status> {
    if !namespace_requires_agent_shadow(service, &proposal.namespace)? {
        return Ok(());
    }
    let candidate = service
        .db
        .runtime()
        .get_definition_revision(&proposal.namespace, &proposal.candidate_digest)
        .map_err(|_| Status::internal("definition resource unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    let base = service
        .db
        .runtime()
        .get_definition_revision(&proposal.namespace, &proposal.base_digest)
        .map_err(|_| Status::internal("definition resource unavailable"))?;
    for member in candidate
        .members
        .iter()
        .filter(|member| member.member_kind == crate::sekai::agent_promotion::MEMBER_KIND_AGENT)
    {
        let expected_active = base.as_ref().and_then(|revision| {
            revision
                .members
                .iter()
                .any(|base_member| {
                    base_member.member_kind == crate::sekai::agent_promotion::MEMBER_KIND_AGENT
                        && base_member.member_id == member.member_id
                })
                .then_some(proposal.base_digest.as_str())
        });
        let report = load_shadow_report(
            service,
            &proposal.namespace,
            &member.member_id,
            &proposal.candidate_digest,
            true,
            expected_active,
        )?;
        crate::sekai::agent_shadow::require_shadow_report(
            true,
            report.as_ref(),
            &proposal.candidate_digest,
            expected_active,
        )
        .map_err(Status::failed_precondition)?;
    }
    Ok(())
}

fn to_proto_shadow_report(report: &crate::sekai::agent_shadow::ShadowReport) -> AgentShadowReport {
    AgentShadowReport {
        contract_version: report.contract_version.clone(),
        namespace: report.namespace.clone(),
        member_id: report.member_id.clone(),
        active_revision_digest: report.active_revision_digest.clone(),
        candidate_revision_digest: report.candidate_revision_digest.clone(),
        shadow_id: report.shadow_id.clone(),
        evaluated: report.evaluated,
        unchanged: report.unchanged,
        differed: report.differed,
        cost_tokens: report.cost_tokens,
        latency_ms: report.latency_ms,
        passing: report.passing,
        verdict_reason: report.verdict_reason.clone(),
        require_for_promotion: report.require_for_promotion,
        samples: report
            .samples
            .iter()
            .map(|sample| AgentShadowSample {
                envelope_id: sample.envelope_id.clone(),
                input: sample.input.clone(),
                active: sample
                    .active
                    .iter()
                    .map(|action| DryRunAgentAction {
                        action_type: action.action_type.clone(),
                        parameters_json: action.parameters_json.clone(),
                        disposition: action.disposition.clone(),
                        reason: action.reason.clone(),
                    })
                    .collect(),
                candidate: sample
                    .candidate
                    .iter()
                    .map(|action| DryRunAgentAction {
                        action_type: action.action_type.clone(),
                        parameters_json: action.parameters_json.clone(),
                        disposition: action.disposition.clone(),
                        reason: action.reason.clone(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn map_dry_run_failure(error: crate::sekai::agent_dry_run::DryRunFailure) -> Status {
    match error {
        crate::sekai::agent_dry_run::DryRunFailure::RouteAdmission(reason)
        | crate::sekai::agent_dry_run::DryRunFailure::Budget(reason)
        | crate::sekai::agent_dry_run::DryRunFailure::Model(reason) => {
            Status::failed_precondition(reason)
        }
    }
}

fn dry_run_eval_record(
    namespace: &str,
    member_id: &str,
    revision_digest: &str,
    record_id: &str,
    timestamp: i64,
    trace: &crate::sekai::agent_dry_run::DryRunTrace,
) -> crate::chisei::eval::Run {
    use crate::chisei::eval::{CaseResult, Run};
    use crate::sekai::agent_dry_run::{
        DISPOSITION_WOULD_SUBMIT, DRY_RUN_CONFIG_REF, DRY_RUN_SUITE_PREFIX,
    };
    let passed = trace
        .actions
        .iter()
        .all(|action| action.disposition == DISPOSITION_WOULD_SUBMIT);
    Run {
        id: record_id.into(),
        suite_id: format!("{DRY_RUN_SUITE_PREFIX}{namespace}:{member_id}"),
        config_ref: DRY_RUN_CONFIG_REF.into(),
        results: vec![CaseResult {
            case_id: revision_digest.into(),
            passed,
            status: "dry_run".into(),
            result: serde_json::to_string(
                &trace
                    .actions
                    .iter()
                    .map(|action| {
                        serde_json::json!({
                            "action_type": action.action_type,
                            "disposition": action.disposition,
                            "reason": action.reason,
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".into()),
            score: i32::from(passed),
            reason: String::new(),
            elapsed: 0,
        }],
        timestamp,
    }
}
fn default_dry_run(
    runtime: &crate::db::runtime_db::RuntimeDb,
    request: &crate::sekai::agent_dry_run::DryRunModelRequest,
) -> Result<crate::sekai::agent_dry_run::DryRunModelReply, crate::sekai::agent_dry_run::DryRunFailure>
{
    use crate::db::chisei_budget::METRIC_TOKENS;
    use crate::sekai::agent_dry_run::DryRunFailure;
    admit_dry_run_route(runtime, &request.namespace)?;
    runtime
        .budget_check_chain(&request.namespace, METRIC_TOKENS, 1, now_millis())
        .map_err(DryRunFailure::Budget)?;
    // Same fail-closed default as Function `RejectLlmHost`: admission and
    // budget run once, then the plane refuses unless a completion host was
    // injected. Do not echo the input or invent Actions as a successful step.
    Err(DryRunFailure::Model(
        crate::sekai::agent_dry_run::REFUSAL_MODEL_UNAVAILABLE.into(),
    ))
}

fn admit_dry_run_route(
    runtime: &crate::db::runtime_db::RuntimeDb,
    namespace: &str,
) -> Result<String, crate::sekai::agent_dry_run::DryRunFailure> {
    use crate::chisei::model_review::{
        ModelReviewStatus, REFUSAL_NOT_ENABLED, effective_review_status,
    };
    use crate::enterprise::ModelIdentity;
    use crate::sekai::agent_dry_run::DryRunFailure;
    let mut families = runtime
        .list_family_enablement_records(namespace)
        .map_err(DryRunFailure::RouteAdmission)?;
    let mut models = runtime
        .list_model_review_records(namespace)
        .map_err(DryRunFailure::RouteAdmission)?;
    if !namespace.is_empty() {
        families.extend(
            runtime
                .list_family_enablement_records("")
                .map_err(DryRunFailure::RouteAdmission)?,
        );
        models.extend(
            runtime
                .list_model_review_records("")
                .map_err(DryRunFailure::RouteAdmission)?,
        );
    }
    let mut families_ids: Vec<String> = families
        .iter()
        .map(|record| record.family_id.clone())
        .collect();
    families_ids.sort();
    families_ids.dedup();
    for family_id in families_ids {
        let identity = ModelIdentity {
            provider: family_id.clone(),
            model: family_id.clone(),
            upstream_model: family_id.clone(),
            profile_version: String::new(),
            artifact_digest: None,
            endpoint: String::new(),
        };
        if effective_review_status(&models, &families, namespace, &identity, "")
            == ModelReviewStatus::Enabled
        {
            return Ok(format!("{family_id}/enabled"));
        }
    }
    Err(DryRunFailure::RouteAdmission(REFUSAL_NOT_ENABLED.into()))
}

/// Objects the lint scans in a namespace; past this the object rules are
/// skipped and the report is partial.
const MAX_LINT_OBJECTS: usize = 2_000;
/// Links read per object and direction, and neighbors authorized in all.
const MAX_LINT_LINKS: usize = 64;
const MAX_LINT_NEIGHBORS: usize = 2_000;
/// Recent instances checked for one the caller may see, per Action type.
const MAX_LINT_INSTANCES: usize = 50;

/// Lints a namespace's published definition (#1454). The caller needs read
/// on the namespace and on every published member; data the lint reads is
/// limited to what the caller may see, so no finding names a hidden object,
/// consumer or principal.
pub(super) async fn get_ontology_lint_report(
    service: &SekaiServiceImpl,
    req: Request<GetOntologyLintReportRequest>,
) -> Result<Response<GetOntologyLintReportResponse>, Status> {
    use crate::sekai::ontology_lint::{LintInput, lint, profile_clearance};

    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let policy_context = principal_policy_context(&req);
    let purpose = request_purpose_presentation(&req, &principals);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let GetOntologyLintReportRequest {
        namespace,
        branch_id,
    } = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &namespace,
        false,
    )?;
    let db = service.db.runtime();
    // A draft branch lints its head; otherwise the published revision.
    let revision_digest = if branch_id.is_empty() {
        db.get_published_definition_revision(&namespace)
            .map_err(|_| Status::internal("definition revision unavailable"))?
            .ok_or_else(|| Status::not_found("no published definition"))?
            .revision_digest
    } else {
        db.get_definition_branch(&namespace, &branch_id)
            .map_err(|_| Status::internal("definition branch unavailable"))?
            .ok_or_else(|| Status::not_found("definition branch unavailable"))?
            .head_revision_digest
    };
    authorize_definition_revision(
        service,
        &principals,
        &namespace,
        &revision_digest,
        branch_id.is_empty(),
    )?;
    let members = db
        .get_definition_members(&namespace, &revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    let visible = |kind: &str, namespace: Option<&str>, cap: usize| {
        visible_lint_objects(
            service,
            &principals,
            &policy_context,
            purpose.as_ref(),
            tenant_context.as_ref(),
            kind,
            namespace,
            cap,
        )
    };

    // The object rules cover instances of the linted revision's object types only.
    let mut objects = Vec::new();
    let mut objects_complete = true;
    for object_type in members.iter().filter(|m| m.member_kind == "object_type") {
        let (found, complete) = visible(
            &object_type.member_id,
            Some(&namespace),
            MAX_LINT_OBJECTS.saturating_sub(objects.len()),
        )?;
        objects.extend(found);
        objects_complete &= complete;
    }
    let ids: std::collections::BTreeSet<&str> =
        objects.iter().map(|object| object.id.as_str()).collect();
    // A link counts only when the caller can see its other end, an object of
    // the namespace of any kind, read with this request's purpose. Reads are
    // bounded per object and across neighbors; an object the bounds leave
    // undecided makes the object rules skip, so no finding is a guess.
    let mut neighbor_reads = 0usize;
    let mut neighbors = std::collections::BTreeMap::<String, bool>::new();
    let mut visible_neighbor = |id: &str| -> Result<Option<bool>, Status> {
        if ids.contains(id) {
            return Ok(Some(true));
        }
        if let Some(known) = neighbors.get(id) {
            return Ok(Some(*known));
        }
        if neighbor_reads == MAX_LINT_NEIGHBORS {
            return Ok(None);
        }
        neighbor_reads += 1;
        let visible = match db
            .get_object_with_policy_context(id, &policy_context)
            .map_err(Status::internal)?
        {
            Some(neighbor) if neighbor.namespace == namespace => require_visible_object_contents(
                db,
                &service.security,
                neighbor,
                &principals,
                tenant_context.as_ref(),
                &format!("ontology_lint:{id}"),
                purpose.as_ref(),
            )
            .is_ok(),
            _ => false,
        };
        neighbors.insert(id.to_string(), visible);
        Ok(Some(visible))
    };
    let mut linked = std::collections::BTreeSet::new();
    if objects_complete {
        'objects: for object in &objects {
            let mut decided = true;
            for direction in [domain::Direction::Outgoing, domain::Direction::Incoming] {
                let links = db
                    .get_links_limited(&object.id, "", &direction, MAX_LINT_LINKS + 1)
                    .map_err(Status::internal)?;
                decided &= links.len() <= MAX_LINT_LINKS;
                for link in links.iter().take(MAX_LINT_LINKS) {
                    let other = if link.from_id == object.id {
                        &link.to_id
                    } else {
                        &link.from_id
                    };
                    if other == &object.id {
                        continue;
                    }
                    match visible_neighbor(other)? {
                        Some(true) => {
                            linked.insert(object.id.clone());
                            continue 'objects;
                        }
                        Some(false) => {}
                        None => decided = false,
                    }
                }
            }
            if !decided {
                objects_complete = false;
                break;
            }
        }
    }
    let (bindings, bindings_complete) = visible(
        crate::sekai::definition_consumer_impact::BINDING_KIND,
        Some(&namespace),
        MAX_LINT_OBJECTS,
    )?;
    let (consumed, consumed_properties) =
        crate::sekai::ontology_lint::consumer_references(&bindings);
    let (entries, entries_complete) = visible(
        crate::sekai::catalog::CATALOG_ENTRY_KIND,
        Some(&namespace),
        MAX_LINT_OBJECTS,
    )?;
    let property = |object: &domain::Object, key: &str| {
        object
            .properties
            .get(key)
            .map(String::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let catalog_owned = entries
        .iter()
        .filter(|entry| {
            property(entry, "source_system") == crate::sekai::catalog::ONTOLOGY_SOURCE
                && property(entry, "entry_kind") == "object_type"
                && !property(entry, "owners").is_empty()
        })
        .map(|entry| property(entry, "source_id"))
        .collect();
    // Action types the caller administers, each with whether it has an
    // instance the caller may see, so neither the registry nor a hidden run
    // shows through.
    let mut action_types = std::collections::BTreeMap::new();
    for action_type in db
        .list_governed_action_types(&namespace, None, true)
        .map_err(Status::internal)?
    {
        if action_types.contains_key(&action_type.type_id)
            || check_action_admin(&service.security, &action_type.type_id, &principals).is_err()
        {
            continue;
        }
        let ran = db
            .list_action_instances(
                &namespace,
                Some(&action_type.type_id),
                None,
                MAX_LINT_INSTANCES,
            )
            .map_err(Status::internal)?
            .iter()
            .any(|instance| {
                super::rpc_actions::authorize_action_instance_visibility(
                    service,
                    &principals,
                    tenant_context.as_ref(),
                    &policy_context,
                    instance,
                )
                .is_ok()
            });
        action_types.insert(action_type.type_id, ran);
    }
    let (profiles, profiles_complete) = visible(
        crate::sekai::markings::PRINCIPAL_PROFILE_KIND,
        None,
        MAX_LINT_OBJECTS,
    )?;
    let report = lint(&LintInput {
        members,
        objects,
        objects_complete,
        linked,
        consumed,
        consumed_properties,
        catalog_owned,
        action_types,
        clearances: profiles.iter().map(profile_clearance).collect(),
    });
    Ok(Response::new(GetOntologyLintReportResponse {
        revision_digest,
        findings: report
            .findings
            .into_iter()
            .map(lint_finding_to_proto)
            .collect(),
        // A capped side scan can only add findings, never hide one, but
        // the report says it is partial.
        complete: report.complete && bindings_complete && entries_complete && profiles_complete,
    }))
}

/// Up to `cap` objects of `kind` the caller may read, as a read would show
/// them, and whether that is all of them. Visibility filtering scans the
/// whole matching population, so a population past the cap is not scanned
/// at all.
#[allow(clippy::too_many_arguments)]
fn visible_lint_objects(
    service: &SekaiServiceImpl,
    principals: &[String],
    policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
    purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    tenant_context: Option<&RequestEnterpriseContext>,
    kind: &str,
    namespace: Option<&str>,
    cap: usize,
) -> Result<(Vec<domain::Object>, bool), Status> {
    let db = service.db.runtime();
    let over_cap = !db
        .list_objects(&domain::ListFilter {
            kind: Some(kind.into()),
            name: None,
            namespace: namespace.map(String::from),
            property_filters: Vec::new(),
            interface_filter: Vec::new(),
            limit: 1,
            offset: i32::try_from(cap).unwrap_or(i32::MAX),
            order_by: "name".into(),
            descending: false,
        })
        .map_err(Status::internal)?
        .is_empty();
    if over_cap {
        return Ok((Vec::new(), false));
    }
    let mut objects = Vec::new();
    loop {
        let filter = domain::ListFilter {
            kind: Some(kind.into()),
            name: None,
            namespace: namespace.map(String::from),
            property_filters: Vec::new(),
            interface_filter: Vec::new(),
            limit: MAX_LIST_LIMIT,
            offset: objects.len() as i32,
            order_by: "name".into(),
            descending: false,
        };
        let (page, _) = list_objects_with_marking(
            db,
            &filter,
            principals,
            policy_context,
            purpose,
            tenant_context,
            // Findings read properties only as a read would show them.
            |objects, principals, tenant_context| {
                service.resolve_computed_for_responses_with_policy(
                    objects,
                    principals,
                    Some(policy_context),
                    tenant_context,
                    purpose,
                )
            },
        )?;
        let last = page.len() < MAX_LIST_LIMIT as usize;
        objects.extend(page);
        if objects.len() > cap {
            objects.truncate(cap);
            return Ok((objects, false));
        }
        if last {
            return Ok((objects, true));
        }
    }
}

fn lint_finding_to_proto(finding: crate::sekai::ontology_lint::LintFinding) -> OntologyLintFinding {
    OntologyLintFinding {
        rule: finding.rule.into(),
        subject_kind: finding.subject_kind.into(),
        subject_id: finding.subject_id,
        property: finding.property,
        severity: finding.severity.into(),
        detail: finding.detail,
        suppressed: finding.suppressed.is_some(),
        suppression_reason: finding.suppressed.unwrap_or_default(),
    }
}
