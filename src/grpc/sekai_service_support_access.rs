use super::*;

pub(super) fn map_capability_error(error: capability::CatalogError) -> Status {
    match error {
        capability::CatalogError::UnsupportedContractVersion => {
            Status::failed_precondition("unsupported capability catalog contract version")
        }
        capability::CatalogError::CatalogVersionUnavailable => {
            Status::aborted("capability catalog version unavailable")
        }
        capability::CatalogError::InvalidPageToken => {
            Status::invalid_argument("invalid capability catalog page token")
        }
    }
}
pub(super) fn caller_principals(req: &Request<impl std::any::Any>) -> Vec<String> {
    if let Some(context) = req
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        return vec![context.principal.subject.clone()];
    }
    req.metadata()
        .get("x-principal")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            let principals = v
                .split(',')
                .map(str::trim)
                .filter(|principal| !principal.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            if principals.is_empty() {
                vec!["anonymous".to_string()]
            } else {
                principals
            }
        })
        .unwrap_or_else(|| vec!["anonymous".to_string()])
}
pub(super) fn require_authenticated(principals: &[String]) -> Result<(), Status> {
    if principals.is_empty() || principals.iter().all(|principal| principal == "anonymous") {
        return Err(Status::unauthenticated("principal required"));
    }
    Ok(())
}
pub(super) fn require_evidence_admin(
    security: &SecurityChecker,
    principals: &[String],
) -> Result<(), Status> {
    let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("evidence", &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("evidence admin required"))
}
pub(super) fn can_operate_evidence_submission(
    security: &SecurityChecker,
    submission: &DomainEvidenceSubmissionRecord,
    principals: &[String],
) -> bool {
    principals
        .iter()
        .any(|principal| principal == &submission.producer_identity)
        || require_evidence_admin(security, principals).is_ok()
}
pub(super) fn parse_evidence_classification(
    value: &str,
) -> Result<evidence_domain::EvidenceClassification, Status> {
    match value.trim() {
        "public" => Ok(evidence_domain::EvidenceClassification::Public),
        "internal" => Ok(evidence_domain::EvidenceClassification::Internal),
        "confidential" => Ok(evidence_domain::EvidenceClassification::Confidential),
        "restricted" => Ok(evidence_domain::EvidenceClassification::Restricted),
        _ => Err(Status::invalid_argument("invalid evidence classification")),
    }
}
pub(super) fn parse_evidence_intent(
    value: &str,
) -> Result<evidence_domain::EvidenceIntent, Status> {
    match value.trim() {
        "upsert" => Ok(evidence_domain::EvidenceIntent::Upsert),
        "retract" => Ok(evidence_domain::EvidenceIntent::Retract),
        "mark_stale" => Ok(evidence_domain::EvidenceIntent::MarkStale),
        _ => Err(Status::invalid_argument("invalid evidence intent")),
    }
}
pub(super) fn parse_evidence_signal(
    value: &str,
) -> Result<evidence_domain::EvidenceSignal, Status> {
    match value.trim() {
        "acceptance" => Ok(evidence_domain::EvidenceSignal::Acceptance),
        "verification" => Ok(evidence_domain::EvidenceSignal::Verification),
        "delivery" => Ok(evidence_domain::EvidenceSignal::Delivery),
        "regression" => Ok(evidence_domain::EvidenceSignal::Regression),
        "resource_use" => Ok(evidence_domain::EvidenceSignal::ResourceUse),
        "operational_health" => Ok(evidence_domain::EvidenceSignal::OperationalHealth),
        "other" => Ok(evidence_domain::EvidenceSignal::Other),
        _ => Err(Status::invalid_argument("invalid evidence signal")),
    }
}
pub(super) fn parse_schema_compatibility(
    value: &str,
) -> Result<evidence_domain::SchemaCompatibility, Status> {
    match value.trim() {
        "exact" => Ok(evidence_domain::SchemaCompatibility::Exact),
        "backward_compatible" => Ok(evidence_domain::SchemaCompatibility::BackwardCompatible),
        _ => Err(Status::invalid_argument(
            "invalid evidence schema compatibility",
        )),
    }
}
pub(super) fn optional_nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}
pub(super) fn from_proto_evidence_envelope(
    envelope: EvidenceEnvelope,
) -> Result<evidence_domain::EvidenceEnvelope, Status> {
    let confidence_bps = u16::try_from(envelope.confidence_bps)
        .map_err(|_| Status::invalid_argument("confidence_bps out of range"))?;
    let content = serde_json::from_slice(&envelope.content_json)
        .map_err(|_| Status::invalid_argument("content_json must contain valid JSON"))?;
    let causality = envelope
        .causality
        .map(|causality| evidence_domain::EvidenceCausality {
            operation_id: optional_nonempty(causality.operation_id),
            parent_operation_id: optional_nonempty(causality.parent_operation_id),
            attempt_id: optional_nonempty(causality.attempt_id),
            model_call_id: optional_nonempty(causality.model_call_id),
            subject_references: causality.subject_references,
            trace_context: causality.trace_context.into_iter().collect(),
        });
    Ok(evidence_domain::EvidenceEnvelope {
        contract_version: envelope.contract_version,
        source_type: envelope.source_type,
        source_instance: envelope.source_instance,
        source_record_id: envelope.source_record_id,
        source_version: envelope.source_version,
        source_sequence: envelope.source_sequence,
        target: evidence_domain::EvidenceTarget {
            namespace: envelope.namespace,
            object_external_id: envelope.target_external_id,
            object_kind: envelope.target_kind,
        },
        evidence_type: envelope.evidence_type,
        signal: parse_evidence_signal(&envelope.signal)?,
        schema_id: envelope.schema_id,
        schema_version: envelope.schema_version,
        schema_compatibility: parse_schema_compatibility(&envelope.schema_compatibility)?,
        observed_at_ms: envelope.observed_at_ms,
        collected_at_ms: envelope.collected_at_ms,
        expires_at_ms: envelope.expires_at_ms,
        content,
        relationships: envelope
            .relationships
            .into_iter()
            .map(|relationship| evidence_domain::EvidenceRelationship {
                relation: relationship.relation,
                target_source_type: relationship.target_source_type,
                target_source_instance: relationship.target_source_instance,
                target_source_record_id: relationship.target_source_record_id,
            })
            .collect(),
        producer_identity: envelope.producer_identity,
        confidence_bps,
        classification: parse_evidence_classification(&envelope.classification)?,
        provenance: envelope.provenance.into_iter().collect(),
        idempotency_key: envelope.idempotency_key,
        content_digest: envelope.content_digest,
        intent: parse_evidence_intent(&envelope.intent)?,
        causality,
    })
}
#[cfg(test)]
pub(super) fn evidence_content_is_readable(state: evidence_domain::EvidenceLifecycleState) -> bool {
    matches!(
        state,
        evidence_domain::EvidenceLifecycleState::Available
            | evidence_domain::EvidenceLifecycleState::Superseded
            | evidence_domain::EvidenceLifecycleState::Retracted
            | evidence_domain::EvidenceLifecycleState::Stale
    )
}
pub(super) fn to_proto_evidence_submission(
    submission: &DomainEvidenceSubmissionRecord,
) -> EvidenceSubmissionRecord {
    EvidenceSubmissionRecord {
        id: submission.id.clone(),
        producer_identity: submission.producer_identity.clone(),
        source_type: submission.source_type.clone(),
        source_instance: submission.source_instance.clone(),
        source_record_id: submission.source_record_id.clone(),
        source_version: submission.source_version.clone(),
        source_sequence: submission.source_sequence,
        namespace: submission.namespace.clone(),
        target_external_id: submission.target_external_id.clone(),
        target_kind: submission.target_kind.clone(),
        evidence_type: submission.evidence_type.clone(),
        schema_id: submission.schema_id.clone(),
        schema_version: submission.schema_version.clone(),
        content_digest: submission.content_digest.clone(),
        classification: submission.classification.as_str().into(),
        intent: match submission.intent {
            evidence_domain::EvidenceIntent::Upsert => "upsert",
            evidence_domain::EvidenceIntent::Retract => "retract",
            evidence_domain::EvidenceIntent::MarkStale => "mark_stale",
        }
        .into(),
        lifecycle_state: submission.lifecycle_state.as_str().into(),
        rejection_code: submission.rejection_code.clone().unwrap_or_default(),
        rejection_summary: submission.rejection_summary.clone().unwrap_or_default(),
        observed_at_ms: submission.observed_at_ms,
        collected_at_ms: submission.collected_at_ms,
        expires_at_ms: submission.expires_at_ms,
        received_at_ms: submission.received_at_ms,
        updated_at_ms: submission.updated_at_ms,
        descriptor: Some(to_proto_epistemic_descriptor(
            &DomainEpistemicDescriptor::from_external_evidence(submission),
        )),
    }
}
pub(super) fn to_proto_epistemic_descriptor(
    descriptor: &DomainEpistemicDescriptor,
) -> EpistemicDescriptor {
    debug_assert!(descriptor.validate().is_ok());
    EpistemicDescriptor {
        contract_version: descriptor.contract_version.clone(),
        origin_class: descriptor.origin_class.as_str().into(),
        evidence_status: descriptor.evidence_status.as_str().into(),
        lifecycle_status: descriptor.lifecycle_status.as_str().into(),
        producer_confidence_bps: descriptor.producer_confidence_bps.map(u32::from),
        confidence_basis: descriptor.confidence_basis.clone().unwrap_or_default(),
        observed_at_ms: descriptor.observed_at_ms,
        derivation_ref: descriptor.derivation_ref.clone().unwrap_or_default(),
        source_refs: descriptor.source_refs.clone(),
        source_digests: descriptor.source_digests.clone(),
        source_row_count: descriptor.source_row_count,
        source_rows_truncated: descriptor.source_rows_truncated,
        supporting_evidence_count: descriptor.supporting_evidence_count,
        contradicting_evidence_count: descriptor.contradicting_evidence_count,
    }
}
pub(super) fn to_proto_evidence_submission_result(
    outcome: EvidenceAdmissionOutcome,
) -> EvidenceSubmissionResult {
    EvidenceSubmissionResult {
        submission: Some(to_proto_evidence_submission(&outcome.submission)),
        admitted: outcome.admitted,
        deduplicated: outcome.deduplicated,
        projected: outcome
            .projection
            .is_some_and(|projection| projection.projected),
    }
}
pub(super) fn map_evidence_admission_lifecycle_error(
    error: EvidenceAdmissionLifecycleError,
) -> Status {
    match error {
        EvidenceAdmissionLifecycleError::Admission(_) => {
            Status::internal("evidence admission failed")
        }
        EvidenceAdmissionLifecycleError::Rejection(_) => {
            Status::internal("evidence rejection failed")
        }
        EvidenceAdmissionLifecycleError::Projection(_) => {
            Status::internal("evidence projection failed")
        }
        EvidenceAdmissionLifecycleError::ExecutionRecording(error) => {
            Status::failed_precondition(error)
        }
        EvidenceAdmissionLifecycleError::ResultResolution(error) => Status::internal(error),
    }
}
pub(super) fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
pub(super) fn check_read(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_access(object_id, &refs) {
        return Err(Status::permission_denied("access denied"));
    }
    Ok(())
}
pub(super) fn resolve_principal_authority(
    db: &RuntimeDb,
    principals: &[String],
) -> Result<markings::PrincipalAuthority, Status> {
    let primary = principals.first().map(String::as_str).unwrap_or_default();
    if let Some(trusted) = markings::trusted_service_authority(primary) {
        return Ok(trusted);
    }
    let external_id = markings::principal_profile_external_id(primary);
    // Prefer an explicit kind-matched sealed profile over any colliding
    // external_id on ordinary objects (external IDs are indexed, not unique).
    let candidates = db
        .find_all_by_external_id(&external_id)
        .map_err(Status::internal)?;
    let mut trusted = Vec::new();
    for object in &candidates {
        if object.kind != markings::PRINCIPAL_PROFILE_KIND {
            continue;
        }
        if object
            .properties
            .get(markings::PRINCIPAL_PROFILE_SEALED_PROPERTY)
            .is_none_or(|value| value != "true")
        {
            continue;
        }
        let grants = db.list_grants(&object.id).map_err(Status::internal)?;
        if grants
            .iter()
            .any(|grant| matches!(grant.role, security::Role::Admin))
        {
            trusted.push(object);
        }
    }
    if trusted.len() > 1 {
        return Err(Status::failed_precondition(
            "multiple trusted principal profiles found; resolve duplicates before marking checks",
        ));
    }
    markings::principal_authority_from_profile(primary, trusted.first().copied())
        .map_err(Status::internal)
}
pub(super) fn load_classification_lattice(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<Option<crate::sekai::classification_lattice::ClassificationLattice>, Status> {
    db.get_classification_lattice(namespace)
        .map_err(|_| Status::unavailable("classification lattice unavailable"))
}
pub(super) fn object_passes_marking(
    db: &RuntimeDb,
    object: &domain::Object,
    principals: &[String],
) -> Result<bool, Status> {
    if markings::object_marking_token(object).is_none() {
        return Ok(true);
    }
    let lattice = load_classification_lattice(db, &object.namespace)?;
    let authority = resolve_principal_authority(db, principals)?;
    let result = crate::sekai::classification_lattice::evaluate_lattice_access(
        "visibility",
        markings::object_marking_token(object),
        &authority,
        lattice.as_ref(),
    );
    Ok(result.decision != markings::MarkingDecision::Deny)
}
pub(super) fn object_is_visible(
    db: &RuntimeDb,
    security: &SecurityChecker,
    object: &domain::Object,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
) -> bool {
    object_is_visible_for(
        db,
        security,
        object,
        principals,
        tenant_context,
        crate::sekai::object_security::ObjectSecurityOperation::Read,
    )
}
pub(super) fn object_is_visible_for(
    db: &RuntimeDb,
    security: &SecurityChecker,
    object: &domain::Object,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    operation: crate::sekai::object_security::ObjectSecurityOperation,
) -> bool {
    !is_reserved_governance_kind(&object.kind)
        && check_team_namespace(db, principals, &object.namespace, false).is_ok()
        && enforce_namespace_tenant_context(db, tenant_context, &object.namespace, false).is_ok()
        && check_read(security, &object.id, principals).is_ok()
        && object_passes_security_policy(db, object, principals, tenant_context, operation)
            .unwrap_or(false)
}
pub(super) fn object_security_generation(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<String, Status> {
    Ok(db
        .get_object_security_activation(namespace)
        .map_err(|_| Status::unavailable("object authorization unavailable"))?
        .map(|activation| activation.activation_id)
        .unwrap_or_else(|| "legacy".into()))
}
pub(super) fn evaluate_active_object_policy(
    db: &RuntimeDb,
    object: &domain::Object,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    operation: crate::sekai::object_security::ObjectSecurityOperation,
) -> Result<Option<bool>, Status> {
    Ok(Some(
        decide_object_access(db, object, principals, tenant_context, operation)?.outcome
            == crate::sekai::policy_decision::PolicyOutcome::Allow,
    ))
}
pub(super) fn object_passes_security_policy(
    db: &RuntimeDb,
    object: &domain::Object,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    operation: crate::sekai::object_security::ObjectSecurityOperation,
) -> Result<bool, Status> {
    if is_reserved_governance_kind(&object.kind) {
        return object_passes_marking(db, object, principals);
    }
    Ok(
        decide_object_access(db, object, principals, tenant_context, operation)?.outcome
            == crate::sekai::policy_decision::PolicyOutcome::Allow,
    )
}
pub(super) fn enforce_object_operation_access(
    db: &RuntimeDb,
    object: &domain::Object,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    operation: crate::sekai::object_security::ObjectSecurityOperation,
    operation_id: &str,
) -> Result<markings::MarkingCheckResult, Status> {
    let decision = decide_object_access(db, object, principals, tenant_context, operation)?;
    let record = crate::sekai::policy_decision::PolicyDecisionRecord {
        event_id: format!("{operation_id}:{}", uuid::Uuid::new_v4().as_simple()),
        decision: decision.clone(),
        created_at_ms: now_millis(),
    };
    db.record_policy_decision(&record)
        .map_err(|_| Status::unavailable("policy decision audit unavailable"))?;
    if decision.outcome != crate::sekai::policy_decision::PolicyOutcome::Allow {
        return Err(Status::permission_denied("access denied"));
    }
    enforce_object_marking_access(db, object, principals, operation_id)
}

pub(super) fn decide_object_access(
    db: &RuntimeDb,
    object: &domain::Object,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    operation: crate::sekai::object_security::ObjectSecurityOperation,
) -> Result<crate::sekai::policy_decision::PolicyDecision, Status> {
    let policy = match db.active_object_policy(&object.namespace, &object.kind) {
        Ok(policy) => policy,
        Err(error) if error.starts_with("object_security_denied") => {
            return Ok(crate::sekai::policy_decision::PolicyDecision {
                contract_version: crate::sekai::policy_decision::POLICY_DECISION_CONTRACT.into(),
                namespace: object.namespace.clone(),
                object_kind: object.kind.clone(),
                object_id: object.id.clone(),
                operation: operation.as_str().into(),
                principal: principals.first().cloned().unwrap_or_default(),
                principal_digest: String::new(),
                activation_digest: String::new(),
                policy_revision_digest: String::new(),
                outcome: crate::sekai::policy_decision::PolicyOutcome::Deny,
                denied_by: Some(crate::sekai::policy_decision::PolicyLayer::ObjectRow),
            });
        }
        Err(_) => return Err(Status::unavailable("object authorization unavailable")),
    };
    let lattice = load_classification_lattice(db, &object.namespace)?;
    let authority = resolve_principal_authority(db, principals)?;
    let context = principal_policy_context_from(principals, tenant_context);
    let activation = db
        .get_object_security_activation(&object.namespace)
        .map_err(|_| Status::unavailable("object authorization unavailable"))?;
    let activation_digest = match activation.as_ref() {
        Some(activation) => {
            crate::sekai::object_security::object_security_activation_digest(activation)
                .unwrap_or_else(|_| "legacy".into())
        }
        None => "legacy".into(),
    };
    let compiled = crate::sekai::policy_decision::compile_object_access(
        crate::sekai::policy_decision::PolicyCompileRequest {
            namespace: &object.namespace,
            kind: &object.kind,
            operation,
            context: &context,
            authority: &authority,
            lattice: lattice.as_ref(),
            policy: policy.as_ref(),
            activation_digest: &activation_digest,
            purpose: None,
            purpose_authorization: None,
            now_ms: now_millis(),
            namespace_granted: true,
        },
    )
    .map_err(Status::internal)?;
    Ok(compiled.decide(object))
}
pub(super) fn ensure_policy_driving_update_allowed(
    db: &RuntimeDb,
    security: &SecurityChecker,
    before: &domain::Object,
    after: &domain::Object,
    principals: &[String],
) -> Result<(), Status> {
    let mut properties = std::collections::BTreeSet::<String>::new();
    let mut saw_active_policy = false;
    for (namespace, kind) in [
        (before.namespace.as_str(), before.kind.as_str()),
        (after.namespace.as_str(), after.kind.as_str()),
    ] {
        if let Some(policy) = db
            .active_object_policy(namespace, kind)
            .map_err(|_| Status::unavailable("object security policy unavailable"))?
        {
            saw_active_policy = true;
            properties.extend(policy.policy_driving_properties());
        }
    }
    if !saw_active_policy {
        return Ok(());
    }
    if before.kind != after.kind || before.namespace != after.namespace {
        return check_object_admin(db, security, before, principals);
    }
    let changes_policy_input = properties
        .iter()
        .any(|property| before.properties.get(property) != after.properties.get(property));
    if !changes_policy_input {
        return Ok(());
    }
    check_object_admin(db, security, before, principals)
}
pub(super) fn check_object_admin(
    db: &RuntimeDb,
    security: &SecurityChecker,
    object: &domain::Object,
    principals: &[String],
) -> Result<(), Status> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(());
    }
    let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    if security.can_admin(&object.id, &refs) {
        return Ok(());
    }
    let memberships = team_namespace_memberships(db, principals)?;
    if memberships
        .iter()
        .any(|(namespace, role)| namespace == &object.namespace && *role == security::Role::Admin)
    {
        return Ok(());
    }
    Err(Status::permission_denied("admin access denied"))
}
pub(super) fn map_direct_read_visibility_error(activated: bool, status: Status) -> Status {
    if activated && status.code() == tonic::Code::PermissionDenied {
        Status::not_found("not found")
    } else {
        status
    }
}
/// Single-object read root: reserved kinds are observationally missing, tenant
/// mismatches are missing, and ACL/team/marking failures stay fail-closed.
pub(super) fn require_visible_read_root(
    db: &RuntimeDb,
    security: &SecurityChecker,
    object: domain::Object,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    operation_id: &str,
) -> Result<(domain::Object, markings::MarkingCheckResult), Status> {
    if is_reserved_governance_kind(&object.kind) {
        return Err(Status::not_found("not found"));
    }
    enforce_namespace_tenant_context(db, tenant_context, &object.namespace, false)
        .map_err(|_| Status::not_found("not found"))?;
    check_team_namespace(db, principals, &object.namespace, false)?;
    check_read(security, &object.id, principals)?;
    if let Some(allowed) = evaluate_active_object_policy(
        db,
        &object,
        principals,
        tenant_context,
        crate::sekai::object_security::ObjectSecurityOperation::Read,
    )
    .map_err(|_| Status::not_found("not found"))?
    {
        if !allowed {
            return Err(Status::not_found("not found"));
        }
    }
    let marking = enforce_object_marking_access(db, &object, principals, operation_id)?;
    Ok((object, marking))
}
pub(super) fn retain_reachable_visible_objects(
    start_id: &str,
    direction: domain::Direction,
    objects: &mut Vec<domain::Object>,
    links: &mut Vec<domain::Link>,
) {
    let mut visible = objects
        .iter()
        .map(|object| object.id.clone())
        .collect::<std::collections::HashSet<_>>();
    visible.insert(start_id.to_string());
    let mut adjacency = HashMap::<String, Vec<String>>::new();
    for link in links.iter() {
        if !visible.contains(&link.from_id) || !visible.contains(&link.to_id) {
            continue;
        }
        match direction {
            domain::Direction::Outgoing => adjacency
                .entry(link.from_id.clone())
                .or_default()
                .push(link.to_id.clone()),
            domain::Direction::Incoming => adjacency
                .entry(link.to_id.clone())
                .or_default()
                .push(link.from_id.clone()),
        }
    }
    let mut reachable = std::collections::HashSet::from([start_id.to_string()]);
    let mut stack = vec![start_id.to_string()];
    while let Some(id) = stack.pop() {
        let Some(next) = adjacency.get(&id) else {
            continue;
        };
        for neighbor in next {
            if reachable.insert(neighbor.clone()) {
                stack.push(neighbor.clone());
            }
        }
    }
    objects.retain(|object| reachable.contains(&object.id));
    let object_ids = objects
        .iter()
        .map(|object| object.id.as_str())
        .collect::<std::collections::HashSet<_>>();
    links.retain(|link| {
        object_ids.contains(link.from_id.as_str()) && object_ids.contains(link.to_id.as_str())
    });
}
pub(super) fn retain_reachable_visible_lineage(
    start_id: &str,
    nodes: &mut Vec<crate::sekai::lineage::LineageNode>,
    edges: &mut Vec<crate::sekai::lineage::LineageEdge>,
) {
    let mut visible = nodes
        .iter()
        .map(|node| node.object.id.clone())
        .collect::<std::collections::HashSet<_>>();
    visible.insert(start_id.to_string());
    let mut adjacency = HashMap::<String, Vec<String>>::new();
    for edge in edges.iter() {
        if !visible.contains(&edge.from) || !visible.contains(&edge.to) {
            continue;
        }
        adjacency
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
        adjacency
            .entry(edge.to.clone())
            .or_default()
            .push(edge.from.clone());
    }
    let mut reachable = std::collections::HashSet::from([start_id.to_string()]);
    let mut stack = vec![start_id.to_string()];
    while let Some(id) = stack.pop() {
        let Some(next) = adjacency.get(&id) else {
            continue;
        };
        for neighbor in next {
            if reachable.insert(neighbor.clone()) {
                stack.push(neighbor.clone());
            }
        }
    }
    nodes.retain(|node| reachable.contains(&node.object.id));
    edges.retain(|edge| reachable.contains(&edge.from) && reachable.contains(&edge.to));
}
/// ACL-visible list with marking filter, exact marking-visible totals, and
/// offset/limit applied over the filtered set.
pub(super) fn list_objects_with_marking<F>(
    db: &RuntimeDb,
    filter: &domain::ListFilter,
    principals: &[String],
    policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
    purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    tenant_context: Option<&RequestEnterpriseContext>,
    resolve: F,
) -> Result<(Vec<domain::Object>, i32), Status>
where
    F: FnOnce(
        Vec<domain::Object>,
        &[String],
        Option<&RequestEnterpriseContext>,
    ) -> Result<Vec<domain::Object>, Status>,
{
    let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    let requested_limit = if filter.limit <= 0 {
        domain::DEFAULT_LIST_LIMIT as usize
    } else {
        (filter.limit as usize).min(domain::MAX_LIST_LIMIT as usize)
    };
    let requested_offset = filter.offset.max(0) as usize;
    let mut scan_offset = 0i32;
    let mut visible_index = 0usize;
    let mut collected = Vec::new();
    let mut visible_total = 0i32;
    let mut recorded_purposes = HashSet::new();
    loop {
        let mut scan_filter = filter.clone();
        scan_filter.offset = scan_offset;
        scan_filter.limit = domain::MAX_LIST_LIMIT;
        let (page, principal_total) = db
            .list_objects_with_total_for_policy_context(
                &scan_filter,
                &principal_refs,
                RESERVED_GOVERNANCE_KINDS,
                policy_context,
            )
            .map_err(Status::internal)?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len() as i32;
        for object in page {
            if !object_passes_marking(db, &object, principals).unwrap_or(false) {
                continue;
            }
            if !purpose_allows_kind(
                db,
                &object.namespace,
                &object.kind,
                purpose,
                &mut recorded_purposes,
            )? {
                continue;
            }
            if visible_index >= requested_offset && collected.len() < requested_limit {
                collected.push(object);
            }
            visible_index = visible_index.saturating_add(1);
            visible_total = visible_total.saturating_add(1);
        }
        scan_offset = scan_offset.saturating_add(page_len);
        if scan_offset >= principal_total {
            break;
        }
    }
    let objects = resolve(collected, principals, tenant_context)?;
    Ok((objects, visible_total))
}
pub(super) fn validate_principal_profile_object(obj: &Object) -> Result<(), Status> {
    if obj.kind != markings::PRINCIPAL_PROFILE_KIND {
        return Ok(());
    }
    let expected = markings::principal_profile_external_id(&obj.name);
    if obj.external_id != expected {
        return Err(Status::invalid_argument(format!(
            "principal_profile external_id must be {expected}"
        )));
    }
    if obj
        .properties
        .contains_key(markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY)
        || obj
            .properties
            .contains_key(markings::PRINCIPAL_ALLOWED_PURPOSES_PROPERTY)
    {
        let domain = from_proto_obj(obj);
        markings::principal_authority_from_profile(&obj.name, Some(&domain))
            .map_err(Status::invalid_argument)?;
    }
    Ok(())
}
pub(super) fn enforce_object_marking_access(
    db: &RuntimeDb,
    object: &domain::Object,
    principals: &[String],
    operation_id: &str,
) -> Result<markings::MarkingCheckResult, Status> {
    if markings::object_marking_token(object).is_none() {
        return Ok(markings::MarkingCheckResult {
            decision: markings::MarkingDecision::NotApplicable,
            decision_id: format!(
                "marking:{operation_id}:{}",
                uuid::Uuid::new_v4().as_simple()
            ),
            object_classification: None,
            principal_ceiling: None,
            detail: "object has no classification marking".into(),
        });
    }
    let lattice = load_classification_lattice(db, &object.namespace)?;
    let authority = resolve_principal_authority(db, principals)?;
    let result = crate::sekai::classification_lattice::evaluate_lattice_access(
        operation_id,
        markings::object_marking_token(object),
        &authority,
        lattice.as_ref(),
    );
    if result.decision == markings::MarkingDecision::Deny {
        // Generic denial — do not leak marking details to unauthorized callers.
        return Err(Status::permission_denied("access denied"));
    }
    Ok(result)
}
pub(super) fn record_marking_or_purpose_decision(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    target_id: &str,
    decision_id: &str,
    outcome: &str,
    evidence: HashMap<String, String>,
) -> Result<(), Status> {
    db.record_decision(&audit::Decision {
        id: decision_id.into(),
        timestamp: now_millis(),
        actor: actor.into(),
        action: action.into(),
        reason: "classification marking / purpose gate".into(),
        evidence,
        target_id: target_id.into(),
        outcome: outcome.into(),
    })
    .map_err(Status::internal)
}
pub(super) fn check_write(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_write(object_id, &refs) {
        return Err(Status::permission_denied("write denied"));
    }
    Ok(())
}
pub(super) fn validate_object_kind_change_access(
    db: &RuntimeDb,
    security: &SecurityChecker,
    principals: &[String],
    existing: &domain::Object,
    updated: &domain::Object,
) -> Result<(), Status> {
    if existing.kind == updated.kind {
        return Ok(());
    }
    let ontology = db.load_ontology_registry().map_err(Status::internal)?;
    let mut linked = db
        .get_links(&updated.id, "", &domain::Direction::Outgoing)
        .map_err(Status::internal)?;
    linked.extend(
        db.get_links(&updated.id, "", &domain::Direction::Incoming)
            .map_err(Status::internal)?,
    );
    for link in linked {
        if ontology
            .constraints_for_mapped_relation(&link.relation)
            .is_empty()
        {
            continue;
        }
        for endpoint_id in [&link.from_id, &link.to_id] {
            if endpoint_id == &updated.id {
                continue;
            }
            let endpoint = db
                .get_object(endpoint_id)
                .map_err(Status::internal)?
                .ok_or(Status::failed_precondition("link endpoint unavailable"))?;
            check_team_namespace(db, principals, &endpoint.namespace, false)?;
            check_read(security, &endpoint.id, principals)?;
        }
        if ontology
            .constraints_for_mapped_relation(&link.relation)
            .into_iter()
            .any(|constraint| {
                let introduces_domain_violation = link.from_id == updated.id
                    && ontology.kind_satisfies_class(&existing.kind, &constraint.domain)
                    && !ontology.kind_satisfies_class(&updated.kind, &constraint.domain);
                let introduces_range_violation = link.to_id == updated.id
                    && ontology.kind_satisfies_class(&existing.kind, &constraint.range)
                    && !ontology.kind_satisfies_class(&updated.kind, &constraint.range);
                introduces_domain_violation || introduces_range_violation
            })
        {
            return Err(Status::failed_precondition(
                "link endpoints violate ontology constraint",
            ));
        }
    }
    Ok(())
}
pub(super) fn check_object_namespace_access(
    db: &RuntimeDb,
    principals: &[String],
    object_id: &str,
    write: bool,
) -> Result<(), Status> {
    let namespace = match db.get_object(object_id).map_err(Status::internal)? {
        Some(object) => Some(object.namespace),
        None => db
            .object_change_namespace(object_id)
            .map_err(Status::internal)?,
    };
    match namespace {
        Some(namespace) => check_team_namespace(db, principals, &namespace, write),
        None if is_managed_team_principal(db, principals)? => {
            Err(Status::permission_denied("namespace access denied"))
        }
        None => Ok(()),
    }
}
pub(super) fn team_namespace_memberships(
    db: &RuntimeDb,
    principals: &[String],
) -> Result<Vec<(String, security::Role)>, Status> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(Vec::new());
    }
    let mut memberships = Vec::new();
    for principal in principals {
        memberships.extend(
            db.list_namespace_roles_for_principal(principal)
                .map_err(Status::internal)?,
        );
    }
    Ok(memberships)
}
pub(super) fn is_managed_team_principal(
    db: &RuntimeDb,
    principals: &[String],
) -> Result<bool, Status> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(false);
    }
    for principal in principals {
        if db.is_team_principal(principal).map_err(Status::internal)? {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(super) fn check_team_namespace(
    db: &RuntimeDb,
    principals: &[String],
    namespace: &str,
    write: bool,
) -> Result<(), Status> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(());
    }
    let canonical = namespace.trim();
    if canonical.is_empty() || canonical != namespace {
        return if is_managed_team_principal(db, principals)? {
            Err(Status::permission_denied(
                "team principals require a canonical namespace",
            ))
        } else {
            Ok(())
        };
    }
    let boundary = db
        .find_namespace_boundary(canonical)
        .map_err(Status::internal)?;
    let team_managed_namespace = boundary.as_ref().is_some_and(|object| {
        object
            .properties
            .get("team_managed")
            .is_some_and(|value| value == "true")
    });
    if !team_managed_namespace && !is_managed_team_principal(db, principals)? {
        return Ok(());
    }
    let memberships = team_namespace_memberships(db, principals)?;
    let authorized = memberships.iter().any(|(member_namespace, role)| {
        member_namespace == canonical
            && (!write || matches!(role, security::Role::Editor | security::Role::Admin))
    });
    if authorized {
        Ok(())
    } else {
        Err(Status::permission_denied("namespace access denied"))
    }
}
pub(super) fn check_dataset_access(
    db: &RuntimeDb,
    security: &SecurityChecker,
    principals: &[String],
    dataset: &dataset::Dataset,
    write: bool,
) -> Result<(), Status> {
    if dataset.object_id.is_empty() {
        if is_managed_team_principal(db, principals)? {
            return Err(Status::permission_denied(
                "team principals cannot access unbound global datasets",
            ));
        }
        return Ok(());
    }
    let object = match db
        .get_object(&dataset.object_id)
        .map_err(Status::internal)?
    {
        Some(object) => object,
        None if is_managed_team_principal(db, principals)? => {
            return Err(Status::permission_denied(
                "team dataset binding object is unavailable",
            ));
        }
        None => {
            return if write {
                check_write(security, &dataset.object_id, principals)
            } else {
                check_read(security, &dataset.object_id, principals)
            };
        }
    };
    check_team_namespace(db, principals, &object.namespace, write)?;
    if write {
        check_write(security, &object.id, principals)
    } else {
        check_read(security, &object.id, principals)
    }
}
pub(super) fn check_schema_admin(
    security: &SecurityChecker,
    kind: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("schema", &refs)
        || security.can_admin(&schema_object_id(kind), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("schema admin required"))
}
pub(super) fn check_action_admin(
    security: &SecurityChecker,
    name: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("action", &refs)
        || security.can_admin(&action_object_id(name), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("action admin required"))
}
pub(super) fn principal_matches(owner_principal: &str, principals: &[String]) -> bool {
    !owner_principal.is_empty()
        && principals
            .iter()
            .any(|principal| principal == owner_principal)
}
pub(super) fn check_scope_read(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    if principal_matches(&scope.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("scope access denied"))
    }
}
pub(super) fn check_scope_write(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    check_scope_read(scope, principals)
}
pub(super) fn check_work_unit_read(
    db: &RuntimeDb,
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_object_namespace_access(db, principals, &work_unit.target_object_id, false)?;
        check_read(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit access denied"))
    }
}
pub(super) fn check_work_unit_write(
    db: &RuntimeDb,
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_object_namespace_access(db, principals, &work_unit.target_object_id, true)?;
        check_write(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit write denied"))
    }
}
