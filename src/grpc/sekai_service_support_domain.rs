use super::*;

pub(super) fn authorize_source_type_namespace_admin(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
) -> Result<String, Status> {
    require_authenticated(principals)?;
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return principals
            .first()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("principal required"));
    }
    let canonical = namespace.trim();
    if canonical.is_empty() || canonical != namespace {
        return Err(Status::permission_denied("namespace access denied"));
    }
    check_team_namespace(&service.db, principals, canonical, true)?;
    let boundary = service
        .db
        .find_namespace_boundary(canonical)
        .map_err(Status::internal)?;
    let team_managed = boundary.as_ref().is_some_and(|object| {
        object
            .properties
            .get("team_managed")
            .is_some_and(|value| value == "true")
    });
    if !team_managed {
        return Err(Status::permission_denied("namespace access denied"));
    }
    let memberships = team_namespace_memberships(&service.db, principals)?;
    let is_admin = memberships.iter().any(|(member_namespace, role)| {
        member_namespace == canonical && matches!(role, security::Role::Admin)
    });
    if !is_admin {
        return Err(Status::permission_denied("namespace access denied"));
    }
    principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))
}
pub(super) fn authorize_namespace_action_admin(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
) -> Result<String, Status> {
    require_authenticated(principals)?;
    check_team_namespace(&service.db, principals, namespace, true)?;
    check_action_admin(
        &service.security,
        &format!("governed_action:{namespace}"),
        principals,
    )?;
    principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))
}
pub(super) fn to_proto_governed_fact(
    fact: &governed_fact_domain::GovernedFactVersion,
) -> GovernedFactVersion {
    GovernedFactVersion {
        contract_version: fact.input.contract_version.clone(),
        object_id: fact.object_id.clone(),
        namespace: fact.input.namespace.clone(),
        fact_id: fact.input.fact_id.clone(),
        version: fact.input.version.clone(),
        fact_type: fact.input.fact_type.as_str().into(),
        statement: fact.input.statement.clone(),
        applicability: Some(GovernedFactApplicability {
            subject_profiles: fact.input.applicability.subject_profiles.clone(),
            subject_refs: fact.input.applicability.subject_refs.clone(),
        }),
        verification: Some(InvariantVerificationContract {
            predicate_kind: fact.input.verification.predicate_kind.clone(),
            input_schema: fact.input.verification.input_schema.clone(),
            result_schema: fact.input.verification.result_schema.clone(),
            evidence_types: fact.input.verification.evidence_types.clone(),
        }),
        requirement_version_ids: fact.input.requirement_version_ids.clone(),
        evidence_refs: fact.input.evidence_refs.clone(),
        source_ref: fact.input.source_ref.clone(),
        effective_from_ms: fact.input.effective_from_ms,
        supersedes_object_id: fact.input.supersedes_object_id.clone(),
        content_digest: fact.content_digest.clone(),
        created_by: fact.created_by.clone(),
        created_at_ms: fact.created_at_ms,
        access_marking: fact.input.access_marking.clone(),
        status: fact.input.status.clone(),
    }
}
pub(super) fn to_proto_governed_waiver(
    waiver: &governed_fact_domain::GovernedWaiverVersion,
) -> GovernedWaiverVersion {
    GovernedWaiverVersion {
        contract_version: waiver.input.contract_version.clone(),
        object_id: waiver.object_id.clone(),
        namespace: waiver.input.namespace.clone(),
        waiver_id: waiver.input.waiver_id.clone(),
        version: waiver.input.version.clone(),
        invariant_version_ids: waiver.input.invariant_version_ids.clone(),
        applicability: Some(GovernedFactApplicability {
            subject_profiles: waiver.input.applicability.subject_profiles.clone(),
            subject_refs: waiver.input.applicability.subject_refs.clone(),
        }),
        reason: waiver.input.reason.clone(),
        evidence_refs: waiver.input.evidence_refs.clone(),
        source_ref: waiver.input.source_ref.clone(),
        valid_from_ms: waiver.input.valid_from_ms,
        expires_at_ms: waiver.input.expires_at_ms,
        supersedes_object_id: waiver.input.supersedes_object_id.clone(),
        content_digest: waiver.content_digest.clone(),
        created_by: waiver.created_by.clone(),
        created_at_ms: waiver.created_at_ms,
        access_marking: waiver.input.access_marking.clone(),
    }
}
pub(super) fn to_proto_invariant_set(
    invariant_set: &governed_fact_domain::ResolvedInvariantSet,
) -> ResolvedInvariantSet {
    ResolvedInvariantSet {
        contract_version: invariant_set.contract_version.clone(),
        set_id: invariant_set.set_id.clone(),
        set_digest: invariant_set.set_digest.clone(),
        profile_digest: invariant_set.profile_digest.clone(),
        namespace: invariant_set.namespace.clone(),
        subject_profile: invariant_set.subject_profile.clone(),
        subject_ref: invariant_set.subject_ref.clone(),
        evaluation_time_ms: invariant_set.evaluation_time_ms,
        requirements: invariant_set
            .requirements
            .iter()
            .map(to_proto_governed_fact)
            .collect(),
        invariants: invariant_set
            .invariants
            .iter()
            .map(to_proto_governed_fact)
            .collect(),
        waivers: invariant_set
            .waivers
            .iter()
            .map(to_proto_governed_waiver)
            .collect(),
    }
}
pub(super) fn governed_reference_tree_visible(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    object_id: &str,
    visibility_cache: &mut HashMap<String, bool>,
    work: &mut usize,
) -> Result<bool, Status> {
    struct Frame {
        id: String,
        references: Option<Vec<String>>,
        next_reference: usize,
    }

    if let Some(visible) = visibility_cache.get(object_id) {
        return Ok(*visible);
    }
    let mut stack = vec![Frame {
        id: object_id.into(),
        references: None,
        next_reference: 0,
    }];
    let mut active = std::collections::BTreeSet::new();
    while !stack.is_empty() {
        let frame_index = stack.len() - 1;
        let id = stack[frame_index].id.clone();
        if stack[frame_index].references.is_none() {
            if *work >= MAX_GOVERNED_VISIBILITY_WORK {
                return Err(Status::resource_exhausted(
                    "governed reference visibility work exceeds its bound",
                ));
            }
            *work += 1;
            if !active.insert(id.clone()) {
                return Ok(false);
            }
            let object = service.db.get_object(&id).map_err(Status::internal)?;
            let visible = object.as_ref().is_some_and(|object| {
                object.namespace == namespace
                    && check_team_namespace(&service.db, principals, namespace, false).is_ok()
                    && check_read(&service.security, &id, principals).is_ok()
                    && object_passes_marking(&service.db, object, principals).unwrap_or(false)
            });
            if !visible {
                active.remove(&id);
                visibility_cache.insert(id, false);
                stack.pop();
                continue;
            }
            stack[frame_index].references =
                Some(governed_object_references(object.as_ref().unwrap())?);
        }
        let next_reference = stack[frame_index]
            .references
            .as_ref()
            .and_then(|references| references.get(stack[frame_index].next_reference).cloned());
        let Some(reference) = next_reference else {
            active.remove(&id);
            visibility_cache.insert(id, true);
            stack.pop();
            continue;
        };
        match visibility_cache.get(&reference).copied() {
            Some(true) => stack[frame_index].next_reference += 1,
            Some(false) => {
                active.remove(&id);
                visibility_cache.insert(id, false);
                stack.pop();
            }
            None if active.contains(&reference) => return Ok(false),
            None => stack.push(Frame {
                id: reference,
                references: None,
                next_reference: 0,
            }),
        }
    }
    Ok(visibility_cache.get(object_id).copied().unwrap_or(false))
}
pub(super) fn governed_object_references(object: &domain::Object) -> Result<Vec<String>, Status> {
    if object.kind == governed_fact_domain::FACT_KIND {
        let fact = governed_fact_domain::fact_from_object(object).map_err(Status::data_loss)?;
        Ok(fact
            .input
            .requirement_version_ids
            .iter()
            .chain(fact.input.evidence_refs.iter())
            .chain(
                (!fact.input.supersedes_object_id.is_empty())
                    .then_some(&fact.input.supersedes_object_id),
            )
            .cloned()
            .collect())
    } else if object.kind == governed_fact_domain::WAIVER_KIND {
        let waiver = governed_fact_domain::waiver_from_object(object).map_err(Status::data_loss)?;
        Ok(waiver
            .input
            .invariant_version_ids
            .iter()
            .chain(waiver.input.evidence_refs.iter())
            .chain(
                (!waiver.input.supersedes_object_id.is_empty())
                    .then_some(&waiver.input.supersedes_object_id),
            )
            .cloned()
            .collect())
    } else {
        Ok(Vec::new())
    }
}
pub(super) fn governed_object_for_read(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    object_id: &str,
    expected_kind: &str,
) -> Result<domain::Object, Status> {
    let object = service
        .db
        .get_object(object_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("governed fact not found"))?;
    if object.kind != expected_kind
        || enforce_namespace_tenant_context(&service.db, tenant_context, &object.namespace, false)
            .is_err()
        || check_team_namespace(&service.db, principals, &object.namespace, false).is_err()
        || check_read(&service.security, object_id, principals).is_err()
        || !object_passes_marking(&service.db, &object, principals).unwrap_or(false)
    {
        return Err(Status::not_found("governed fact not found"));
    }
    if matches!(
        object.kind.as_str(),
        governed_fact_domain::FACT_KIND | governed_fact_domain::WAIVER_KIND
    ) {
        let mut visibility_cache = HashMap::new();
        let mut visibility_work = 0;
        if !governed_reference_tree_visible(
            service,
            principals,
            &object.namespace,
            object_id,
            &mut visibility_cache,
            &mut visibility_work,
        )? {
            return Err(Status::not_found("governed fact not found"));
        }
    }
    Ok(object)
}
pub(super) fn list_visible_governed_objects(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    kind: &str,
    visibility_cache: &mut HashMap<String, bool>,
    visibility_work: &mut usize,
) -> Result<Vec<domain::Object>, Status> {
    let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    let mut offset = 0i32;
    let mut visible = Vec::new();
    loop {
        let filter = domain::ListFilter {
            kind: Some(kind.into()),
            namespace: Some(namespace.into()),
            limit: domain::MAX_LIST_LIMIT,
            offset,
            ..domain::ListFilter::default()
        };
        let (page, total) = service
            .db
            .list_objects_with_total_for_principals(&filter, &principal_refs, &[])
            .map_err(Status::internal)?;
        if page.is_empty() {
            break;
        }
        offset = offset.saturating_add(page.len() as i32);
        for object in page {
            if object_passes_marking(&service.db, &object, principals).unwrap_or(false)
                && governed_reference_tree_visible(
                    service,
                    principals,
                    namespace,
                    &object.id,
                    visibility_cache,
                    visibility_work,
                )?
            {
                visible.push(object);
                if visible.len() > governed_fact_domain::MAX_FACTS_PER_NAMESPACE {
                    return Err(Status::resource_exhausted(
                        "authorized governed-fact inventory exceeds its bound",
                    ));
                }
            }
        }
        if offset >= total {
            break;
        }
    }
    Ok(visible)
}
pub(super) fn from_proto_governed_action_type(
    proto: crate::grpc::pb::sekai::GovernedActionType,
) -> Result<crate::sekai::governed_action_type::GovernedActionType, Status> {
    let domain = crate::sekai::governed_action_type::GovernedActionType {
        namespace: proto.namespace,
        type_id: proto.type_id,
        version: proto.version,
        description: proto.description,
        parameter_schema_json: proto.parameter_schema_json,
        allowed_effect_kinds: proto.allowed_effect_kinds,
        policy_scope: proto.policy_scope,
        budget_scope: proto.budget_scope,
        object_kind: proto.object_kind,
        object_mutation: proto.object_mutation,
        submission_criteria: proto
            .submission_criteria
            .into_iter()
            .map(from_proto_submission_criterion)
            .collect(),
        declared_effect_kinds: proto.declared_effect_kinds,
        enabled: proto.enabled,
        created_by: proto.created_by,
        created_at_ms: proto.created_at_ms,
        updated_at_ms: proto.updated_at_ms,
        disabled_at_ms: proto.disabled_at_ms,
    };
    Ok(domain)
}
pub(super) fn to_proto_governed_action_type(
    domain: &crate::sekai::governed_action_type::GovernedActionType,
) -> crate::grpc::pb::sekai::GovernedActionType {
    crate::grpc::pb::sekai::GovernedActionType {
        namespace: domain.namespace.clone(),
        type_id: domain.type_id.clone(),
        version: domain.version.clone(),
        description: domain.description.clone(),
        parameter_schema_json: domain.parameter_schema_json.clone(),
        allowed_effect_kinds: domain.allowed_effect_kinds.clone(),
        policy_scope: domain.policy_scope.clone(),
        budget_scope: domain.budget_scope.clone(),
        object_kind: domain.object_kind.clone(),
        object_mutation: domain.object_mutation.clone(),
        submission_criteria: domain
            .submission_criteria
            .iter()
            .map(to_proto_submission_criterion)
            .collect(),
        declared_effect_kinds: domain.declared_effect_kinds.clone(),
        enabled: domain.enabled,
        created_by: domain.created_by.clone(),
        created_at_ms: domain.created_at_ms,
        updated_at_ms: domain.updated_at_ms,
        disabled_at_ms: domain.disabled_at_ms,
    }
}
fn from_proto_submission_criterion(
    proto: crate::grpc::pb::sekai::ActionSubmissionCriterion,
) -> crate::sekai::action_type_criteria::ActionSubmissionCriterion {
    crate::sekai::action_type_criteria::ActionSubmissionCriterion {
        criterion_id: proto.criterion_id,
        kind: proto.kind,
        property: proto.property,
        value: proto.value,
    }
}
fn to_proto_submission_criterion(
    domain: &crate::sekai::action_type_criteria::ActionSubmissionCriterion,
) -> crate::grpc::pb::sekai::ActionSubmissionCriterion {
    crate::grpc::pb::sekai::ActionSubmissionCriterion {
        criterion_id: domain.criterion_id.clone(),
        kind: domain.kind.clone(),
        property: domain.property.clone(),
        value: domain.value.clone(),
    }
}
pub(super) fn to_proto_action_instance(
    domain: &crate::sekai::action_instance::ActionInstance,
) -> crate::grpc::pb::sekai::ActionInstance {
    crate::grpc::pb::sekai::ActionInstance {
        instance_id: domain.instance_id.clone(),
        namespace: domain.namespace.clone(),
        type_id: domain.type_id.clone(),
        version: domain.version.clone(),
        principal: domain.principal.clone(),
        parameters_json: domain.parameters_json.clone(),
        request_digest: domain.request_digest.clone(),
        idempotency_key: domain.idempotency_key.clone(),
        operation_id: domain.operation_id.clone(),
        status: domain.status.clone(),
        deny_reason: domain.deny_reason.clone(),
        evidence_submission_ids: domain.evidence_submission_ids.clone(),
        policy_decision: domain.policy_decision.clone(),
        budget_decision: domain.budget_decision.clone(),
        created_at_ms: domain.created_at_ms,
        decided_at_ms: domain.decided_at_ms,
    }
}
pub(super) fn to_proto_action_effect(
    domain: &crate::sekai::action_effect::ActionEffect,
) -> crate::grpc::pb::sekai::ActionEffect {
    crate::grpc::pb::sekai::ActionEffect {
        effect_id: domain.effect_id.clone(),
        instance_id: domain.instance_id.clone(),
        namespace: domain.namespace.clone(),
        operation_id: domain.operation_id.clone(),
        kind: domain.kind.clone(),
        status: domain.status.clone(),
        payload_json: domain.payload_json.clone(),
        failure_reason: domain.failure_reason.clone(),
        created_at_ms: domain.created_at_ms,
        updated_at_ms: domain.updated_at_ms,
        claim_owner: domain.claim_owner.clone(),
        claim_generation: domain.claim_generation,
        claim_fencing_token: domain.claim_fencing_token.clone(),
        claim_expires_at_ms: domain.claim_expires_at_ms,
        claim_request_id: domain.claim_request_id.clone(),
        park_generation: domain.park_generation,
        active_resolution_id: domain.active_resolution_id.clone(),
        claim_attempt_count: domain.claim_attempt_count,
        lease_expiry_count: domain.lease_expiry_count,
        park_count: domain.park_count,
        lifecycle_state: domain.effective_lifecycle_state().into(),
        retry_policy_version: domain.retry_policy_version.clone(),
        retry_policy_digest: domain.retry_policy_digest.clone(),
        max_claim_attempts: domain.max_claim_attempts,
        max_lease_expiries: domain.max_lease_expiries,
        max_park_cycles: domain.max_park_cycles,
    }
}
pub(super) fn to_proto_action_work_park(
    value: &crate::sekai::parked_work::ActionWorkPark,
) -> ActionWorkPark {
    ActionWorkPark {
        park_id: value.park_id.clone(),
        effect_id: value.effect_id.clone(),
        namespace: value.namespace.clone(),
        operation_id: value.operation_id.clone(),
        park_generation: value.park_generation,
        claim_generation: value.claim_generation,
        checkpoint_ref: value.checkpoint_ref.clone(),
        checkpoint_digest: value.checkpoint_digest.clone(),
        reason: value.reason.clone(),
        parked_by: value.parked_by.clone(),
        parked_at_ms: value.parked_at_ms,
        request_id: value.request_id.clone(),
        request_digest: value.request_digest.clone(),
        checkpoint_store_id: value.checkpoint_store_id.clone(),
    }
}
pub(super) fn to_proto_action_work_continuation(
    value: &crate::sekai::parked_work::ActionWorkContinuation,
) -> ActionWorkContinuation {
    ActionWorkContinuation {
        resolution_id: value.resolution_id.clone(),
        effect_id: value.effect_id.clone(),
        namespace: value.namespace.clone(),
        operation_id: value.operation_id.clone(),
        park_generation: value.park_generation,
        input_json: value.input_json.clone(),
        input_digest: value.input_digest.clone(),
        park_id: value.park_id.clone(),
        resolution_action_id: value.resolution_action_id.clone(),
        resolution_input_id: value.resolution_input_id.clone(),
        reason: value.reason.clone(),
        decided_by: value.decided_by.clone(),
        decided_at_ms: value.decided_at_ms,
        request_id: value.request_id.clone(),
    }
}
pub(super) fn require_single_source_principal(principals: &[String]) -> Result<&str, Status> {
    require_authenticated(principals)?;
    if principals.len() != 1 || principals[0] == "anonymous" {
        return Err(Status::permission_denied(
            "source sync requires exactly one authenticated principal",
        ));
    }
    Ok(&principals[0])
}
pub(super) fn require_canonical_source_namespace(namespace: &str) -> Result<(), Status> {
    if namespace.is_empty()
        || namespace.len() > source_sync_domain::MAX_SOURCE_IDENTIFIER_BYTES
        || namespace.trim() != namespace
        || namespace.chars().any(char::is_control)
    {
        return Err(Status::invalid_argument("canonical namespace required"));
    }
    Ok(())
}
pub(super) fn require_admitted_source_type(
    db: &RuntimeDb,
    namespace: &str,
    type_digest: &str,
) -> Result<(), Status> {
    if type_digest == source_sync_domain::GITHUB_OBJECT_SYNC_TYPE_DIGEST {
        return Ok(());
    }
    match db.get_source_type_descriptor(namespace, type_digest) {
        Ok(Some(stored))
            if stored.status == crate::sekai::source_type_descriptor::STATUS_LIVE
                && stored.digest == type_digest =>
        {
            Ok(())
        }
        _ => Err(Status::failed_precondition(
            "source type revision is not bound",
        )),
    }
}
pub(super) fn validate_source_sync_lookup(input: &GetSourceSyncStateRequest) -> Result<(), Status> {
    require_canonical_source_namespace(&input.namespace)?;
    if input.source_instance.is_empty()
        || input.source_instance.len() > source_sync_domain::MAX_SOURCE_IDENTIFIER_BYTES
        || input.source_instance.trim() != input.source_instance
        || input.source_instance.chars().any(char::is_control)
    {
        return Err(Status::invalid_argument(
            "canonical source instance required",
        ));
    }
    if input.type_digest.is_empty()
        || input.type_digest.len() > source_sync_domain::MAX_SOURCE_IDENTIFIER_BYTES
        || input.type_digest.trim() != input.type_digest
    {
        return Err(Status::failed_precondition(
            "source type revision is not bound",
        ));
    }
    Ok(())
}
pub(super) fn authorize_source_sync_namespace(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    write: bool,
) -> Result<(), Status> {
    require_canonical_source_namespace(namespace)?;
    enforce_namespace_tenant_context(&service.db, tenant_context, namespace, write)?;
    check_team_namespace(&service.db, principals, namespace, write)?;
    let boundary_id = service
        .db
        .find_namespace_boundary(namespace)
        .map_err(|_| Status::internal("namespace authorization unavailable"))?
        .map_or_else(|| format!("namespace:{namespace}"), |object| object.id);
    if write {
        check_write(&service.security, &boundary_id, principals)
    } else {
        check_read(&service.security, &boundary_id, principals)
    }
}
pub(super) fn definition_schema_member_name(member_kind: &str, member_id: &str) -> String {
    match member_kind {
        "object_type" => member_id.into(),
        "interface_type" => format!("interface:{member_id}"),
        "link_type" => format!("link:{member_id}"),
        "control" => format!("control:{member_id}"),
        _ => format!("{member_kind}:{member_id}"),
    }
}
pub(super) fn definition_member_object_id(member_kind: &str, member_id: &str) -> String {
    match member_kind {
        "action_type" => action_object_id(member_id),
        "ontology_class" => ontology_class_object_id(member_id),
        "ontology_relation" => ontology_relation_object_id(member_id),
        _ => schema_object_id(&definition_schema_member_name(member_kind, member_id)),
    }
}
pub(super) fn authorize_definition_member_read(
    service: &SekaiServiceImpl,
    principals: &[String],
    member_kind: &str,
    member_id: &str,
) -> Result<(), Status> {
    check_read(
        &service.security,
        &definition_member_object_id(member_kind, member_id),
        principals,
    )
    .map_err(|_| Status::not_found("definition revision unavailable"))
}
pub(super) fn authorize_definition_member_write(
    service: &SekaiServiceImpl,
    principals: &[String],
    member_kind: &str,
    member_id: &str,
) -> Result<(), Status> {
    match member_kind {
        "action_type" => check_action_admin(&service.security, member_id, principals),
        "ontology_class" => check_ontology_admin(
            &service.security,
            &ontology_class_object_id(member_id),
            principals,
        ),
        "ontology_relation" => check_ontology_admin(
            &service.security,
            &ontology_relation_object_id(member_id),
            principals,
        ),
        _ => check_schema_admin(
            &service.security,
            &definition_schema_member_name(member_kind, member_id),
            principals,
        ),
    }
}
pub(super) fn authorize_definition_revision(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    revision_digest: &str,
    require_published: bool,
) -> Result<(), Status> {
    let revision = service
        .db
        .get_definition_revision(namespace, revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .filter(|revision| !require_published || revision.published)
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    let members = service
        .db
        .get_definition_members(namespace, &revision.revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    if members.len() != revision.members.len() {
        return Err(Status::internal("definition revision unavailable"));
    }
    for member in members {
        authorize_definition_member_read(
            service,
            principals,
            &member.member_kind,
            &member.member_id,
        )?;
    }
    Ok(())
}
pub(super) fn load_authorized_definition_revisions(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    from_revision_digest: &str,
    to_revision_digest: &str,
) -> Result<
    (
        definition_branch_domain::DefinitionRevision,
        Vec<definition_branch_domain::DefinitionMember>,
        definition_branch_domain::DefinitionRevision,
        Vec<definition_branch_domain::DefinitionMember>,
    ),
    Status,
> {
    definition_branch_domain::validate_digest("from_revision_digest", from_revision_digest)
        .map_err(Status::invalid_argument)?;
    definition_branch_domain::validate_digest("to_revision_digest", to_revision_digest)
        .map_err(Status::invalid_argument)?;
    authorize_definition_revision(service, principals, namespace, from_revision_digest, false)?;
    authorize_definition_revision(service, principals, namespace, to_revision_digest, false)?;
    let from = service
        .db
        .get_definition_revision(namespace, from_revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    let to = service
        .db
        .get_definition_revision(namespace, to_revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    let from_members = service
        .db
        .get_definition_members(namespace, &from.revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    let to_members = service
        .db
        .get_definition_members(namespace, &to.revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    Ok((from, from_members, to, to_members))
}
pub(super) fn from_proto_definition_member_input(
    member: &DefinitionMemberInput,
) -> definition_branch_domain::DefinitionMemberInput {
    definition_branch_domain::DefinitionMemberInput {
        member_kind: member.member_kind.clone(),
        member_id: member.member_id.clone(),
        definition_json: member.definition_json.clone(),
        member_digest: member.member_digest.clone(),
    }
}
pub(super) fn from_proto_definition_member_ref(
    member: &DefinitionMemberRef,
) -> definition_branch_domain::DefinitionMemberRef {
    definition_branch_domain::DefinitionMemberRef {
        member_kind: member.member_kind.clone(),
        member_id: member.member_id.clone(),
    }
}
pub(super) fn to_proto_definition_branch(
    branch: &definition_branch_domain::DefinitionBranch,
) -> DefinitionBranch {
    DefinitionBranch {
        contract_version: branch.contract_version.clone(),
        namespace: branch.namespace.clone(),
        branch_id: branch.branch_id.clone(),
        base_revision_digest: branch.base_revision_digest.clone(),
        head_revision_digest: branch.head_revision_digest.clone(),
        created_by: branch.created_by.clone(),
        created_at_ms: branch.created_at_ms,
        updated_at_ms: branch.updated_at_ms,
        pin_digest: definition_branch_domain::branch_pin_digest(branch),
    }
}
pub(super) fn to_proto_definition_revision_diff(
    diff: &definition_diff_domain::DefinitionRevisionDiff,
) -> DefinitionRevisionDiff {
    DefinitionRevisionDiff {
        from_revision_digest: diff.from_revision_digest.clone(),
        to_revision_digest: diff.to_revision_digest.clone(),
        diff_digest: diff.diff_digest.clone(),
        added: diff
            .added
            .iter()
            .map(to_proto_definition_member_change)
            .collect(),
        removed: diff
            .removed
            .iter()
            .map(to_proto_definition_member_change)
            .collect(),
        changed: diff
            .changed
            .iter()
            .map(to_proto_definition_member_change)
            .collect(),
    }
}
pub(super) fn to_proto_definition_member_change(
    change: &definition_diff_domain::DefinitionMemberChange,
) -> DefinitionMemberChange {
    DefinitionMemberChange {
        member_kind: change.member_kind.clone(),
        member_id: change.member_id.clone(),
        from_member_digest: change.from_member_digest.clone(),
        to_member_digest: change.to_member_digest.clone(),
        added_properties: change.added_properties.clone(),
        removed_properties: change.removed_properties.clone(),
        changed_properties: change.changed_properties.clone(),
    }
}
pub(super) fn to_proto_definition_revision_compatibility(
    report: &definition_diff_domain::DefinitionRevisionCompatibility,
) -> DefinitionRevisionCompatibility {
    DefinitionRevisionCompatibility {
        from_revision_digest: report.from_revision_digest.clone(),
        to_revision_digest: report.to_revision_digest.clone(),
        compatibility_digest: report.compatibility_digest.clone(),
        class: report.class.clone(),
        reasons: report
            .reasons
            .iter()
            .map(to_proto_definition_compatibility_reason)
            .collect(),
        diff: Some(to_proto_definition_revision_diff(&report.diff)),
    }
}
pub(super) fn to_proto_definition_fact_migration(
    result: &crate::sekai::definition_migration::FactMigrationResult,
) -> DefinitionFactMigration {
    DefinitionFactMigration {
        contract_version: result.contract_version.clone(),
        namespace: result.namespace.clone(),
        migration_id: result.migration_id.clone(),
        from_revision_digest: result.from_revision_digest.clone(),
        to_revision_digest: result.to_revision_digest.clone(),
        compatibility_digest: result.compatibility_digest.clone(),
        compatibility_class: result.compatibility_class.clone(),
        mode: result.mode.clone(),
        status: result.status.clone(),
        checkpoint_object_id: result.checkpoint_object_id.clone(),
        affected_count: result.affected_count,
        migrated_count: result.migrated_count,
        blocked_count: result.blocked_count,
        blocked: result
            .blocked
            .iter()
            .map(|block| DefinitionFactMigrationBlock {
                object_id: block.object_id.clone(),
                reason_code: block.reason_code.clone(),
            })
            .collect(),
        objects: result
            .objects
            .iter()
            .map(|object| DefinitionFactMigrationObject {
                object_id: object.object_id.clone(),
                kind: object.kind.clone(),
                outcome: object.outcome.clone(),
                stripped_properties: object.stripped_properties.clone(),
            })
            .collect(),
        actor: result.actor.clone(),
        created_at_ms: result.created_at_ms,
        updated_at_ms: result.updated_at_ms,
        result_digest: result.result_digest.clone(),
    }
}
pub(super) fn to_proto_definition_compatibility_reason(
    reason: &definition_diff_domain::DefinitionCompatibilityReason,
) -> DefinitionCompatibilityReason {
    DefinitionCompatibilityReason {
        class: reason.class.clone(),
        member_kind: reason.member_kind.clone(),
        member_id: reason.member_id.clone(),
        code: reason.code.clone(),
        property: reason.property.clone(),
    }
}
pub(super) fn to_proto_definition_revision(
    revision: &definition_branch_domain::DefinitionRevision,
) -> DefinitionRevision {
    DefinitionRevision {
        contract_version: revision.contract_version.clone(),
        namespace: revision.namespace.clone(),
        revision_digest: revision.revision_digest.clone(),
        parent_revision_digest: revision.parent_revision_digest.clone(),
        members: revision
            .members
            .iter()
            .map(|member| DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            })
            .collect(),
        published: revision.published,
        created_by: revision.created_by.clone(),
        created_at_ms: revision.created_at_ms,
    }
}
pub(super) fn map_definition_write_error(error: String) -> Status {
    if error.starts_with("definition_revision_not_found")
        || error.starts_with("definition_branch_not_found")
        || error.starts_with("definition_member_not_found")
        || error.starts_with("definition_proposal_not_found")
        || error.starts_with("fact_migration_not_found")
    {
        Status::not_found("definition resource unavailable")
    } else if error.starts_with("stale_definition_branch_head")
        || error.starts_with("stale_definition_proposal_candidate")
        || error.starts_with("stale_published_definition_head")
        || error.starts_with("definition_proposal_not_open")
        || error.starts_with("definition_proposal_missing_approval")
        || error.starts_with("definition_proposal_no_change")
        || error.starts_with("foreign_authority_is_not_a_grant")
        || error.starts_with("incompatible_definition_proposal_candidate")
        || error.starts_with("definition_revision_conflict")
        || error.starts_with("stale_definition_revision")
        || error.starts_with("fact_migration_unknown")
        || error.starts_with("fact_migration_unapproved")
        || error.starts_with("fact_migration_no_change")
        || error.starts_with("fact_migration_unsupported_mode")
        || error.starts_with("fact_migration_not_committed")
        || error.starts_with("fact_migration_revision_mismatch")
        || error.starts_with("fact_migration_rollback_denied")
        || error.starts_with("object_security_denied")
        || error.starts_with("fact_migration_limit")
    {
        Status::failed_precondition("definition write is not current")
    } else if let Some(gate) = error.strip_prefix("compatibility_gate:") {
        Status::failed_precondition(format!("compatibility_gate:{gate}"))
    } else if error.starts_with("unknown_definition_construct") {
        Status::failed_precondition("definition compare encountered an unknown construct")
    } else if error.starts_with("definition_edit_no_change") {
        Status::failed_precondition("definition edit has no effect")
    } else if error.starts_with("definition_idempotency_conflict")
        || error.starts_with("definition_branch_conflict")
        || error.starts_with("definition_proposal_conflict")
        || error.starts_with("immutable_definition_")
    {
        Status::already_exists("definition write conflicts with durable state")
    } else if error.starts_with("definition_proposal_invalid_close_reason") {
        Status::invalid_argument("definition close reason is invalid")
    } else {
        Status::internal("definition write unavailable")
    }
}
pub(super) fn to_proto_definition_proposal(
    proposal: &definition_proposal_domain::DefinitionProposal,
) -> DefinitionProposal {
    DefinitionProposal {
        contract_version: proposal.contract_version.clone(),
        namespace: proposal.namespace.clone(),
        branch_id: proposal.branch_id.clone(),
        proposal_id: proposal.proposal_id.clone(),
        base_digest: proposal.base_digest.clone(),
        candidate_digest: proposal.candidate_digest.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        eval_plan_digests: proposal.eval_plan_digests.clone(),
        named_foreign_digests: proposal.named_foreign_digests.clone(),
        approvals: proposal
            .approvals
            .iter()
            .map(|approval| DefinitionProposalApproval {
                actor: approval.actor.clone(),
                approved_at_ms: approval.approved_at_ms,
            })
            .collect(),
        status: proposal.status.clone(),
        created_by: proposal.created_by.clone(),
        created_at_ms: proposal.created_at_ms,
        updated_at_ms: proposal.updated_at_ms,
        receipt_id: proposal.receipt_id.clone(),
        close_reason_code: proposal.close_reason_code.clone(),
    }
}
pub(super) fn authorize_proposal_member_writes(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    base_digest: &str,
    candidate_digest: &str,
) -> Result<(), Status> {
    let base = service
        .db
        .get_definition_revision(namespace, base_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    let candidate = service
        .db
        .get_definition_revision(namespace, candidate_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    for (member_kind, member_id) in
        definition_proposal_domain::changed_member_refs(&base, &candidate)
    {
        authorize_definition_member_write(service, principals, &member_kind, &member_id)?;
    }
    Ok(())
}
pub(super) fn from_proto_source_batch(
    batch: SourceBatch,
) -> Result<source_sync_domain::SourceBatch, Status> {
    let delivery = batch
        .delivery
        .map(|delivery| {
            let mode = match SourceDeliveryMode::try_from(delivery.mode) {
                Ok(SourceDeliveryMode::Snapshot) => {
                    source_sync_domain::SourceDeliveryMode::Snapshot
                }
                Ok(SourceDeliveryMode::ChangeFeed) => {
                    source_sync_domain::SourceDeliveryMode::ChangeFeed
                }
                Ok(SourceDeliveryMode::Unspecified) | Err(_) => {
                    return Err(Status::invalid_argument("source delivery mode is invalid"));
                }
            };
            Ok(source_sync_domain::SourceDeliveryWindow {
                mode,
                sync_generation: delivery.sync_generation,
                source_feed_epoch: delivery.source_feed_epoch,
                offset_start: delivery.offset_start,
                offset_end: delivery.offset_end,
                snapshot_complete: delivery.snapshot_complete,
            })
        })
        .transpose()?;
    Ok(source_sync_domain::SourceBatch {
        contract_version: batch.contract_version,
        namespace: batch.namespace,
        producer_identity: batch.producer_identity,
        source: batch.source,
        source_instance: batch.source_instance,
        family: batch.family,
        adapter_id: batch.adapter_id,
        adapter_version: batch.adapter_version,
        type_digest: batch.type_digest,
        current_cursor: batch.current_cursor,
        proposed_next_cursor: batch.proposed_next_cursor,
        idempotency_key: batch.idempotency_key,
        batch_digest: batch.batch_digest,
        collected_at_ms: batch.collected_at_ms,
        records: batch
            .records
            .into_iter()
            .map(|record| source_sync_domain::SourceRecord {
                source: record.source,
                source_instance: record.source_instance,
                external_id: record.external_id,
                source_version: record.source_version,
                type_name: record.type_name,
                display_name: record.display_name,
                payload_digest: record.payload_digest,
                properties: record.properties.into_iter().collect(),
                deleted: record.deleted,
                observed_at_ms: record.observed_at_ms,
                source_sequence: record.source_sequence,
            })
            .collect(),
        delivery,
    })
}
pub(super) fn source_batch_status(status: source_sync_domain::SourceBatchStatus) -> &'static str {
    status.as_str()
}
pub(super) fn source_operation_outcome(
    outcome: source_sync_domain::OperationOutcome,
) -> &'static str {
    match outcome {
        source_sync_domain::OperationOutcome::Success => "success",
        source_sync_domain::OperationOutcome::Denial => "denial",
        source_sync_domain::OperationOutcome::Unavailable => "unavailable",
        source_sync_domain::OperationOutcome::Partial => "partial",
        source_sync_domain::OperationOutcome::Unknown => "unknown",
    }
}
pub(super) fn proto_source_delivery_mode(
    mode: Option<source_sync_domain::SourceDeliveryMode>,
) -> i32 {
    match mode {
        None => SourceDeliveryMode::Unspecified as i32,
        Some(source_sync_domain::SourceDeliveryMode::Snapshot) => {
            SourceDeliveryMode::Snapshot as i32
        }
        Some(source_sync_domain::SourceDeliveryMode::ChangeFeed) => {
            SourceDeliveryMode::ChangeFeed as i32
        }
    }
}
pub(super) fn to_proto_source_binding(
    binding: &source_sync_domain::SourceBinding,
) -> SourceBinding {
    SourceBinding {
        binding_id: binding.binding_id.clone(),
        namespace: binding.namespace.clone(),
        producer_identity: binding.producer_identity.clone(),
        source: binding.source.clone(),
        source_instance: binding.source_instance.clone(),
        family: binding.family.clone(),
        adapter_id: binding.adapter_id.clone(),
        adapter_version: binding.adapter_version.clone(),
        type_digest: binding.type_digest.clone(),
        created_at_ms: binding.created_at_ms,
        active: binding.active,
    }
}
pub(super) fn to_proto_source_transaction(
    transaction: &source_sync_domain::SourceBatchTransaction,
) -> SourceBatchTransaction {
    SourceBatchTransaction {
        transaction_id: transaction.transaction_id.clone(),
        binding_id: transaction.binding_id.clone(),
        namespace: transaction.namespace.clone(),
        producer_identity: transaction.producer_identity.clone(),
        idempotency_key: transaction.idempotency_key.clone(),
        batch_digest: transaction.batch_digest.clone(),
        current_cursor: transaction.current_cursor.clone(),
        proposed_next_cursor: transaction.proposed_next_cursor.clone(),
        status: source_batch_status(transaction.status).into(),
        outcome: source_operation_outcome(transaction.outcome).into(),
        opened_at_ms: transaction.opened_at_ms,
        closed_at_ms: transaction.closed_at_ms,
        reason: transaction.reason.clone(),
        contract_version: transaction.contract_version.clone(),
        delivery_mode: proto_source_delivery_mode(transaction.delivery_mode),
        sync_generation: transaction.sync_generation,
        source_feed_epoch: transaction.source_feed_epoch.clone(),
        offset_start: transaction.offset_start,
        offset_end: transaction.offset_end,
        snapshot_complete: transaction.snapshot_complete,
    }
}
pub(super) fn to_proto_source_checkpoint(
    checkpoint: &source_sync_domain::SourceCheckpoint,
) -> SourceCheckpoint {
    SourceCheckpoint {
        binding_id: checkpoint.binding_id.clone(),
        namespace: checkpoint.namespace.clone(),
        cursor: checkpoint.cursor.clone(),
        committed_batch_digest: checkpoint.committed_batch_digest.clone(),
        advanced_at_ms: checkpoint.advanced_at_ms,
        contract_version: checkpoint.contract_version.clone(),
        delivery_mode: proto_source_delivery_mode(checkpoint.delivery_mode),
        sync_generation: checkpoint.sync_generation,
        source_feed_epoch: checkpoint.source_feed_epoch.clone(),
        committed_offset: checkpoint.committed_offset,
    }
}
pub(super) fn to_proto_synced_object(object: &source_sync_domain::SyncedObject) -> SyncedObject {
    SyncedObject {
        object_id: object.object_id.clone(),
        type_name: object.type_name.clone(),
        source_id: object.source_id.clone(),
        source_version: object.source_version.clone(),
        payload_digest: object.payload_digest.clone(),
        properties: object.properties.clone().into_iter().collect(),
        tombstoned: object.tombstoned,
        type_digest: object.type_digest.clone(),
    }
}
pub(super) fn to_proto_source_record_result(
    result: &source_sync_domain::SourceRecordResult,
) -> SourceRecordResult {
    let (decision, object) = match &result.decision {
        source_sync_domain::SyncDecision::Upsert(object) => ("upsert", Some(object)),
        source_sync_domain::SyncDecision::Tombstone(object) => ("tombstone", Some(object)),
        source_sync_domain::SyncDecision::Conflict { .. } => ("conflict", None),
        source_sync_domain::SyncDecision::Reject { .. } => ("reject", None),
    };
    let lineage = object.map(|object| SourceRecordLineage {
        type_digest: object.type_digest.clone(),
        source_id: object.source_id.clone(),
        dataset_id: crate::sekai::object_lineage::dataset_id_for(
            &object.type_digest,
            &object.type_name,
        ),
        object_id: object.object_id.clone(),
    });
    SourceRecordResult {
        transaction_id: result.transaction_id.clone(),
        source_id: result.source_id.clone(),
        source_version: result.source_version.clone(),
        decision: decision.into(),
        outcome: source_operation_outcome(result.outcome).into(),
        reason: result.reason.clone(),
        object: object.map(to_proto_synced_object),
        lineage,
        source_sequence: result.source_sequence,
    }
}
pub(super) fn to_proto_source_generation(
    generation: &source_sync_domain::SourceSyncGeneration,
) -> SourceSyncGeneration {
    let status = match generation.status {
        source_sync_domain::SourceSyncGenerationStatus::Snapshotting => {
            SourceSyncGenerationStatus::Snapshotting
        }
        source_sync_domain::SourceSyncGenerationStatus::Active => {
            SourceSyncGenerationStatus::Active
        }
        source_sync_domain::SourceSyncGenerationStatus::RecoveryRequired => {
            SourceSyncGenerationStatus::RecoveryRequired
        }
        source_sync_domain::SourceSyncGenerationStatus::Superseded => {
            SourceSyncGenerationStatus::Superseded
        }
    };
    SourceSyncGeneration {
        binding_id: generation.binding_id.clone(),
        sync_generation: generation.sync_generation,
        status: status as i32,
        delivery_mode: proto_source_delivery_mode(Some(generation.delivery_mode)),
        source_feed_epoch: generation.source_feed_epoch.clone(),
        committed_offset: generation.committed_offset,
        reason: generation.reason.clone(),
        created_at_ms: generation.created_at_ms,
        updated_at_ms: generation.updated_at_ms,
    }
}
pub(super) fn to_proto_source_batch_result(
    result: &source_sync_domain::SourceBatchResult,
) -> SourceBatchResult {
    SourceBatchResult {
        transaction: Some(to_proto_source_transaction(&result.transaction)),
        records: result
            .records
            .iter()
            .map(to_proto_source_record_result)
            .collect(),
        checkpoint_advanced: result.checkpoint_advanced,
    }
}
pub(super) fn to_proto_source_sync_state(
    state: &source_sync_domain::SourceSyncState,
) -> SourceSyncState {
    SourceSyncState {
        binding: Some(to_proto_source_binding(&state.binding)),
        checkpoint: state.checkpoint.as_ref().map(to_proto_source_checkpoint),
        open_transaction: state
            .open_transaction
            .as_ref()
            .map(to_proto_source_transaction),
        last_result: state.last_result.as_ref().map(to_proto_source_batch_result),
        updated_at_ms: state.updated_at_ms,
        current_generation: state
            .current_generation
            .as_ref()
            .map(to_proto_source_generation),
        latest_transaction: state
            .latest_transaction
            .as_ref()
            .map(to_proto_source_transaction),
    }
}
pub(super) fn ensure_authoritative_source_result(
    result: &source_sync_domain::SourceBatchResult,
) -> Result<(), Status> {
    let committed_success = result.transaction.status
        == source_sync_domain::SourceBatchStatus::Committed
        && result.transaction.outcome == source_sync_domain::OperationOutcome::Success
        && result.checkpoint_advanced
        && result.records.iter().all(|record| {
            record.outcome == source_sync_domain::OperationOutcome::Success
                && !matches!(
                    record.decision,
                    source_sync_domain::SyncDecision::Conflict { .. }
                        | source_sync_domain::SyncDecision::Reject { .. }
                )
        });
    let quarantined_denial = result.transaction.status
        == source_sync_domain::SourceBatchStatus::Quarantined
        && result.transaction.outcome == source_sync_domain::OperationOutcome::Denial
        && !result.checkpoint_advanced
        && result.records.iter().all(|record| {
            record.outcome == source_sync_domain::OperationOutcome::Denial
                && matches!(
                    record.decision,
                    source_sync_domain::SyncDecision::Reject { .. }
                )
        });
    if committed_success || quarantined_denial {
        Ok(())
    } else {
        Err(Status::internal(
            "source sync returned a non-authoritative execution result",
        ))
    }
}
pub(super) fn authorize_source_batch_object_policy(
    db: &RuntimeDb,
    batch: &crate::sekai::object_sync::SourceBatch,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
) -> Result<Vec<domain::Object>, Status> {
    let context = principal_policy_context_from(principals, tenant_context);
    let mut authorized = Vec::new();
    for record in &batch.records {
        let source_id = if batch.type_digest == source_sync_domain::GITHUB_OBJECT_SYNC_TYPE_DIGEST {
            record.source_id()
        } else {
            format!(
                "{}:{}#{}/{}",
                batch.source, batch.source_instance, record.type_name, record.external_id
            )
        };
        for existing in db
            .find_all_by_external_id(&source_id)
            .map_err(|_| Status::unavailable("object authorization unavailable"))?
        {
            if existing.namespace != batch.namespace {
                continue;
            }
            match db.active_object_policy(&existing.namespace, &existing.kind) {
                Ok(None) => {}
                Ok(Some(policy)) => {
                    if !policy.allows(
                        &context,
                        &existing,
                        crate::sekai::object_security::ObjectSecurityOperation::Sync,
                    ) {
                        return Err(Status::permission_denied("access denied"));
                    }
                }
                Err(error) if error.starts_with("object_security_denied") => {
                    return Err(Status::permission_denied("access denied"));
                }
                Err(_) => return Err(Status::unavailable("object authorization unavailable")),
            }
            authorized.push(existing);
        }
        let mut properties = record
            .properties
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<std::collections::HashMap<_, _>>();
        properties.insert("sync_source".into(), record.source.clone());
        properties.insert(
            "sync_source_instance".into(),
            record.source_instance.clone(),
        );
        properties.insert("sync_source_id".into(), source_id.clone());
        properties.insert("sync_source_version".into(), record.source_version.clone());
        properties.insert("sync_payload_digest".into(), record.payload_digest.clone());
        properties.insert("sync_type_digest".into(), batch.type_digest.clone());
        properties.insert("sync_tombstoned".into(), record.deleted.to_string());
        let object = domain::Object {
            id: source_id.clone(),
            kind: record.type_name.clone(),
            name: record.display_name.clone(),
            namespace: batch.namespace.clone(),
            external_id: source_id,
            properties,
            created: 1,
            updated: 1,
        };
        match db.active_object_policy(&object.namespace, &object.kind) {
            Ok(None) => {}
            Ok(Some(policy)) => {
                if !policy.allows(
                    &context,
                    &object,
                    crate::sekai::object_security::ObjectSecurityOperation::Sync,
                ) {
                    return Err(Status::permission_denied("access denied"));
                }
                if policy.property_grants_enforced() {
                    for property in record.properties.keys() {
                        if !policy.allows_property_access(
                            property,
                            crate::sekai::object_security::PropertyGrantAccess::Write,
                        ) {
                            return Err(Status::permission_denied("access denied"));
                        }
                    }
                }
                if policy.value_instance_grants_enforced() {
                    for (property, value) in &record.properties {
                        if !policy.allows_value_instance_access(
                            &object.id,
                            property,
                            value,
                            crate::sekai::object_security::PropertyGrantAccess::Write,
                        ) {
                            return Err(Status::permission_denied("access denied"));
                        }
                    }
                }
            }
            Err(error) if error.starts_with("object_security_denied") => {
                return Err(Status::permission_denied("access denied"));
            }
            Err(_) => return Err(Status::unavailable("object authorization unavailable")),
        }
    }
    Ok(authorized)
}
pub(super) fn map_source_sync_apply_error(error: String) -> Status {
    let code = error
        .split_once(':')
        .map_or(error.as_str(), |(code, _)| code)
        .trim();
    match code {
        "producer_identity_mismatch" | "binding_producer_conflict" => {
            Status::permission_denied("source producer identity denied")
        }
        "unsupported_version" | "unsupported_adapter" => {
            Status::failed_precondition("source sync contract version is unsupported")
        }
        "unbound_type_revision" => Status::failed_precondition("source type revision is not bound"),
        "idempotency_conflict" | "replay_identity_conflict" | "source_identity_conflict" => {
            Status::already_exists("source sync identity conflict")
        }
        "stale_cursor"
        | "foreign_cursor"
        | "open_transaction_conflict"
        | "overlapping_range"
        | "missing_range" => Status::aborted("source checkpoint conflict"),
        "object_changed_since_authorization" => {
            Status::failed_precondition(crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION)
        }
        "batch_aborted"
        | "inactive_binding"
        | "binding_source_conflict"
        | "binding_type_conflict"
        | "binding_contract_conflict"
        | "type_identity_conflict"
        | "source_revision_conflict"
        | "ambiguous_identity_state"
        | "orphaned_open_transaction"
        | "missing_open_transaction"
        | "legacy_batch_after_v2"
        | "generation_conflict"
        | "feed_epoch_conflict"
        | "phase_conflict"
        | "recovery_required" => Status::failed_precondition("source sync state conflict"),
        "canonicalization_failed"
        | "foreign_source"
        | "foreign_family"
        | "invalid_timestamp"
        | "record_bounds"
        | "ambiguous_record_identity"
        | "batch_digest_mismatch"
        | "mixed_source_identity"
        | "unsupported_record_type"
        | "property_bounds"
        | "invalid_property_key"
        | "secret_like_text"
        | "invalid_identifier"
        | "invalid_source_instance"
        | "invalid_external_id"
        | "cursor_bounds"
        | "text_bounds"
        | "invalid_digest"
        | "reserved_property"
        | "missing_delivery_metadata"
        | "unexpected_delivery_metadata"
        | "invalid_sync_generation"
        | "invalid_snapshot_metadata"
        | "missing_feed_epoch"
        | "invalid_change_feed_metadata"
        | "missing_delivery_range"
        | "invalid_delivery_range"
        | "unexpected_source_sequence"
        | "missing_source_sequence"
        | "duplicate_source_sequence"
        | "reordered_source_sequence"
        | "noncontiguous_source_sequence"
        | "invalid_feed_epoch"
        | "delivery_position_out_of_range"
        | "invalid_record" => Status::invalid_argument("invalid source batch"),
        "storage_error" => Status::internal("source sync storage failure"),
        _ => Status::internal("source sync unavailable"),
    }
}
pub(super) fn visible_action_object(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
    namespace: &str,
    object_id: &str,
) -> Result<crate::domain::Object, Status> {
    let unavailable = || Status::permission_denied("object action unavailable");
    let namespace = namespace.trim();
    let object_id = object_id.trim();
    if namespace.is_empty() || object_id.is_empty() {
        return Err(Status::invalid_argument(
            "namespace and object_id are required",
        ));
    }
    let object = service
        .db
        .get_object_with_policy_context(object_id, policy_context)
        .map_err(Status::internal)?
        .ok_or_else(unavailable)?;
    if object.namespace != namespace {
        return Err(unavailable());
    }
    require_visible_read_root(
        &service.db,
        &service.security,
        object,
        principals,
        tenant_context,
        &format!("object_action:{object_id}"),
        None,
    )
    .map(|(object, _)| object)
    .map_err(|_| unavailable())
}
pub(super) fn map_object_action_projection_error(
    error: crate::sekai::action_describe_preview::ObjectActionProjectionError,
) -> Status {
    match error {
        crate::sekai::action_describe_preview::ObjectActionProjectionError::Unavailable => {
            Status::permission_denied("object action unavailable")
        }
        crate::sekai::action_describe_preview::ObjectActionProjectionError::InvalidArgument(
            message,
        ) => Status::invalid_argument(message),
    }
}
pub(super) fn object_action_description_to_proto(
    description: crate::sekai::action_describe_preview::ObjectActionDescription,
) -> DescribeObjectActionResponse {
    DescribeObjectActionResponse {
        namespace: description.namespace,
        object_id: description.object_id,
        object_updated_ms: description.object_updated_ms,
        object_revision: description.object_revision,
        type_id: description.type_id,
        version: description.version,
        parameter_schema_json: description.parameter_schema_json,
        allowed_effect_kinds: description.allowed_effect_kinds,
        object_kind: description.object_kind,
        object_mutation: description.object_mutation,
        enabled: description.enabled,
        preview_supported: description.preview_supported,
        compensation: description.compensation,
        submission_criteria: description
            .submission_criteria
            .iter()
            .map(to_proto_submission_criterion)
            .collect(),
        declared_effect_kinds: description.declared_effect_kinds,
    }
}
pub(super) fn object_action_preview_to_proto(
    preview: crate::sekai::action_describe_preview::ObjectActionPreview,
) -> PreviewObjectActionResponse {
    PreviewObjectActionResponse {
        outcome: preview.outcome,
        reason_code: preview.reason_code,
        request_digest: preview.request_digest,
        object_revision: preview.object_revision,
        object_updated_ms: preview.object_updated_ms,
        type_id: preview.type_id,
        version: preview.version,
        policy_decision: preview.policy_decision,
        budget_decision: preview.budget_decision,
        approval_state: preview.approval_state,
        compensation: preview.compensation,
        failing_criterion: preview.failing_criterion,
    }
}
pub(super) fn authorize_action_instance_submit(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
) -> Result<String, Status> {
    require_authenticated(principals)?;
    check_team_namespace(&service.db, principals, namespace, true)?;
    principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))
}
pub(super) fn authorize_action_instance_read(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
) -> Result<(), Status> {
    require_authenticated(principals)?;
    check_team_namespace(&service.db, principals, namespace, false)?;
    Ok(())
}

#[cfg(test)]
mod definition_write_error_tests {
    use super::*;

    #[test]
    fn not_descendant_candidate_is_failed_precondition_not_already_exists() {
        let status = map_definition_write_error(
            "incompatible_definition_proposal_candidate: candidate is not a descendant of the pinned base"
                .into(),
        );
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_ne!(status.code(), tonic::Code::AlreadyExists);
    }

    #[test]
    fn fact_migration_revision_mismatch_is_failed_precondition() {
        let status = map_definition_write_error(
            "fact_migration_revision_mismatch: rollback must name the stored parent and candidate"
                .into(),
        );
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_ne!(status.code(), tonic::Code::Internal);
    }

    #[test]
    fn compatibility_gate_is_failed_precondition_and_names_the_kind() {
        let status = map_definition_write_error("compatibility_gate:function".into());
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "compatibility_gate:function");
        assert_ne!(status.code(), tonic::Code::Internal);
    }
}
