//! Deterministic Evaluation manifest resolution lifecycle.
//!
//! The gRPC adapter authenticates callers and maps protocol messages. This
//! module owns authorization-filtered resource resolution, immutable replay,
//! fail-closed manifest construction, snapshot consistency, and persistence.

use super::*;

fn principal_authority(
    db: &RuntimeDb,
    actor: &str,
) -> Result<markings::PrincipalAuthority, String> {
    if let Some(authority) = markings::trusted_service_authority(actor) {
        return Ok(authority);
    }
    let profile = db.find_by_external_id(&markings::principal_profile_external_id(actor))?;
    markings::principal_authority_from_profile(actor, profile.as_ref())
}

fn object_visible_to_actor(db: &RuntimeDb, object: &Object, actor: &str) -> Result<bool, String> {
    if matches!(actor, "root" | "local") {
        return Ok(true);
    }
    let grants = db.list_grants(&object.id)?;
    if !grants.is_empty() && !grants.iter().any(|grant| grant.principal == actor) {
        return Ok(false);
    }
    if markings::object_marking_token(object).is_none() {
        return Ok(true);
    }
    let authority = principal_authority(db, actor)?;
    let lattice = db.get_classification_lattice(&object.namespace)?;
    Ok(
        crate::sekai::classification_lattice::evaluate_lattice_access(
            "evaluation-plan-read",
            markings::object_marking_token(object),
            &authority,
            lattice.as_ref(),
        )
        .decision
            != markings::MarkingDecision::Deny,
    )
}

fn invariant_reference_visible(
    db: &RuntimeDb,
    namespace: &str,
    invariant_id: &str,
    actor: &str,
    visibility_cache: &mut HashMap<String, bool>,
    visibility_work: &mut usize,
) -> Result<bool, String> {
    const MAX_VISIBILITY_OBJECTS: usize = 4_096;
    let mut pending = vec![invariant_id.to_string()];
    while let Some(object_id) = pending.pop() {
        if let Some(visible) = visibility_cache.get(&object_id) {
            if !visible {
                return Ok(false);
            }
            continue;
        }
        *visibility_work += 1;
        if *visibility_work > MAX_VISIBILITY_OBJECTS {
            return Ok(false);
        }
        let Some(object) = db.get_object(&object_id)? else {
            visibility_cache.insert(object_id, false);
            return Ok(false);
        };
        if object.namespace != namespace || !object_visible_to_actor(db, &object, actor)? {
            visibility_cache.insert(object_id, false);
            return Ok(false);
        }
        visibility_cache.insert(object_id, true);
        if object.kind == governed_fact_domain::FACT_KIND {
            let fact = governed_fact_domain::fact_from_object(&object)?;
            pending.extend(fact.input.requirement_version_ids);
            pending.extend(fact.input.evidence_refs);
            if !fact.input.supersedes_object_id.is_empty() {
                pending.push(fact.input.supersedes_object_id);
            }
        } else if object.kind == governed_fact_domain::WAIVER_KIND {
            let waiver = governed_fact_domain::waiver_from_object(&object)?;
            pending.extend(waiver.input.invariant_version_ids);
            pending.extend(waiver.input.evidence_refs);
            if !waiver.input.supersedes_object_id.is_empty() {
                pending.push(waiver.input.supersedes_object_id);
            }
        }
    }
    Ok(true)
}

pub(super) fn evaluation_plan_visible(
    db: &RuntimeDb,
    plan: &evaluation_plan_domain::EvaluationPlan,
    actor: &str,
) -> Result<bool, String> {
    let mut visibility_cache = HashMap::new();
    let mut visibility_work = 0;
    for invariant_id in plan
        .nodes
        .iter()
        .flat_map(|node| node.invariant_version_ids.iter())
    {
        if !invariant_reference_visible(
            db,
            &plan.namespace,
            invariant_id,
            actor,
            &mut visibility_cache,
            &mut visibility_work,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn fact_evidence_classifications(
    db: &RuntimeDb,
    namespace: &str,
    fact_id: &str,
    fact_cache: &mut HashMap<String, HashSet<String>>,
    evidence_cache: &mut HashMap<String, String>,
    visiting: &mut HashSet<String>,
    work: &mut usize,
) -> Result<HashSet<String>, Status> {
    const MAX_CLASSIFICATION_OBJECTS: usize = 4_096;
    if let Some(classifications) = fact_cache.get(fact_id) {
        return Ok(classifications.clone());
    }
    if !visiting.insert(fact_id.to_string()) {
        return Err(Status::failed_precondition(
            "governed fact evidence closure contains a cycle",
        ));
    }
    *work += 1;
    if *work > MAX_CLASSIFICATION_OBJECTS {
        return Err(Status::resource_exhausted(
            "governed fact evidence closure exceeds the validation bound",
        ));
    }
    let object = db
        .get_object(fact_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::failed_precondition("governed fact reference unavailable"))?;
    if object.namespace != namespace || object.kind != governed_fact_domain::FACT_KIND {
        return Err(Status::failed_precondition(
            "governed fact reference unavailable",
        ));
    }
    let fact = governed_fact_domain::fact_from_object(&object).map_err(Status::data_loss)?;
    let mut classifications = HashSet::new();
    for evidence_id in &fact.input.evidence_refs {
        let classification = if let Some(classification) = evidence_cache.get(evidence_id) {
            classification.clone()
        } else {
            *work += 1;
            if *work > MAX_CLASSIFICATION_OBJECTS {
                return Err(Status::resource_exhausted(
                    "governed fact evidence closure exceeds the validation bound",
                ));
            }
            let evidence = db
                .get_object(evidence_id)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("evidence reference unavailable"))?;
            if evidence.namespace != namespace
                || evidence.kind != crate::domain::KIND_EXTERNAL_EVIDENCE
            {
                return Err(Status::failed_precondition(
                    "evidence reference unavailable",
                ));
            }
            let classification = evidence
                .properties
                .get("classification")
                .ok_or_else(|| {
                    Status::failed_precondition("evidence reference lacks a valid classification")
                })
                .and_then(|value| {
                    markings::parse_classification(value).map_err(|_| {
                        Status::failed_precondition(
                            "evidence reference lacks a valid classification",
                        )
                    })
                })?
                .as_str()
                .to_string();
            evidence_cache.insert(evidence_id.clone(), classification.clone());
            classification
        };
        classifications.insert(classification);
    }
    for requirement_id in &fact.input.requirement_version_ids {
        classifications.extend(fact_evidence_classifications(
            db,
            namespace,
            requirement_id,
            fact_cache,
            evidence_cache,
            visiting,
            work,
        )?);
    }
    visiting.remove(fact_id);
    fact_cache.insert(fact_id.to_string(), classifications.clone());
    Ok(classifications)
}

pub(super) fn validate_evaluation_plan_references(
    db: &RuntimeDb,
    plan: &evaluation_plan_domain::EvaluationPlan,
    actor: &str,
) -> Result<(), Status> {
    let mut visibility_cache = HashMap::new();
    let mut visibility_work = 0;
    let mut fact_classification_cache = HashMap::new();
    let mut evidence_classification_cache = HashMap::new();
    let mut classification_work = 0;
    for node in &plan.nodes {
        let definition = db
            .get_evaluator_definition(&node.evaluator_definition_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::failed_precondition("unknown evaluator definition"))?;
        if definition.namespace != plan.namespace {
            return Err(Status::failed_precondition(
                "evaluator definition is in a different namespace",
            ));
        }
        let availability = db
            .get_evaluator_availability(&definition.definition_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("evaluator availability is missing"))?;
        if availability.state != evaluation_plan_domain::AVAILABILITY_ENABLED {
            return Err(Status::failed_precondition(
                "evaluator definition is unavailable for new plans",
            ));
        }
        evaluation_plan_domain::validate_parameters(
            &definition.parameter_schema_json,
            &node.parameters_json,
        )
        .map_err(Status::invalid_argument)?;
        for binding in &node.input_bindings {
            if !definition
                .supported_input_schemas
                .contains(&binding.schema_id)
            {
                return Err(Status::failed_precondition(format!(
                    "node {:?} binds unsupported input schema {:?}",
                    node.node_id, binding.schema_id
                )));
            }
        }
        for invariant_id in &node.invariant_version_ids {
            if !invariant_reference_visible(
                db,
                &plan.namespace,
                invariant_id,
                actor,
                &mut visibility_cache,
                &mut visibility_work,
            )
            .map_err(Status::internal)?
            {
                return Err(Status::failed_precondition(
                    "governed invariant reference unavailable",
                ));
            }
            let object = db
                .get_object(invariant_id)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("unknown invariant version"))?;
            if object.kind != governed_fact_domain::FACT_KIND {
                return Err(Status::failed_precondition(
                    "evaluation plans may cover only governed invariant versions",
                ));
            }
            let invariant =
                governed_fact_domain::fact_from_object(&object).map_err(Status::data_loss)?;
            if invariant.input.fact_type != GovernedFactType::Invariant
                || invariant.input.status != "active"
            {
                return Err(Status::failed_precondition(
                    "evaluation plans require active invariant versions",
                ));
            }
            if !invariant.input.applicability.subject_refs.is_empty() {
                return Err(Status::failed_precondition(
                    "profile-wide evaluation plans cannot cover subject-specific invariants",
                ));
            }
            if !plan.accepted_subject_profiles.iter().all(|profile| {
                invariant
                    .input
                    .applicability
                    .subject_profiles
                    .contains(profile)
            }) {
                return Err(Status::failed_precondition(
                    "invariant applicability does not cover every accepted subject profile",
                ));
            }
            let verification = &invariant.input.verification;
            if !definition
                .supported_predicate_kinds
                .contains(&verification.predicate_kind)
                || !definition
                    .supported_input_schemas
                    .contains(&verification.input_schema)
                || !definition
                    .supported_result_schemas
                    .contains(&verification.result_schema)
            {
                return Err(Status::failed_precondition(
                    "evaluator definition is incompatible with invariant verification contract",
                ));
            }
            if !node.input_bindings.iter().any(|binding| {
                binding.source_kind == evaluation_plan_domain::INPUT_INVARIANT
                    && binding.schema_id == verification.input_schema
            }) {
                return Err(Status::failed_precondition(
                    "node lacks a typed invariant binding for its covered input schema",
                ));
            }
            let evidence_classifications = fact_evidence_classifications(
                db,
                &plan.namespace,
                invariant_id,
                &mut fact_classification_cache,
                &mut evidence_classification_cache,
                &mut HashSet::new(),
                &mut classification_work,
            )?;
            if evidence_classifications
                .iter()
                .any(|classification| !definition.evidence_classifications.contains(classification))
            {
                return Err(Status::failed_precondition(
                    "evaluator definition does not admit the invariant evidence classification",
                ));
            }
        }
    }
    Ok(())
}

fn resolution_outcome(
    status: &str,
    code: &str,
) -> evaluation_manifest_domain::EvaluationResolutionOutcome {
    evaluation_manifest_domain::blocked_outcome(status, code)
}

fn resolve_invariant_set_for_manifest(
    db: &RuntimeDb,
    request: &evaluation_manifest_domain::PreparedResolutionRequest,
) -> Result<
    (
        governed_fact_domain::ResolvedInvariantSet,
        Vec<governed_fact_domain::GovernedFactVersion>,
        Vec<governed_fact_domain::GovernedWaiverVersion>,
        bool,
    ),
    Status,
> {
    let profile_object = db
        .get_object(&governed_fact_domain::profile_object_id(
            &request.request.namespace,
        ))
        .map_err(Status::internal)?
        .ok_or_else(|| Status::failed_precondition("governed fact resolution unavailable"))?;
    if !object_visible_to_actor(db, &profile_object, &request.actor).map_err(Status::internal)? {
        return Err(Status::failed_precondition(
            "governed fact resolution unavailable",
        ));
    }
    let profile =
        governed_fact_domain::profile_from_object(&profile_object).map_err(Status::data_loss)?;
    let all_facts = governed_fact_domain::list_facts(db, &request.request.namespace)
        .map_err(Status::internal)?;
    let all_waivers = governed_fact_domain::list_waivers(db, &request.request.namespace)
        .map_err(Status::internal)?;
    let all_set = governed_fact_domain::resolve_invariant_set(
        &profile,
        all_facts.clone(),
        all_waivers.clone(),
        &request.request.subject_profile,
        &request.request.subject_identity,
        request.request.evaluation_time_ms,
        governed_fact_domain::MAX_RESOLUTION_LIMIT,
    )
    .map_err(map_invariant_resolution_error)?;
    let mut visibility_cache = HashMap::new();
    let mut visibility_work = 0;
    let mut visible_facts = Vec::new();
    for fact in all_facts {
        if invariant_reference_visible(
            db,
            &request.request.namespace,
            &fact.object_id,
            &request.actor,
            &mut visibility_cache,
            &mut visibility_work,
        )
        .map_err(Status::internal)?
        {
            visible_facts.push(fact);
        }
    }
    let mut visible_waivers = Vec::new();
    for waiver in all_waivers {
        if invariant_reference_visible(
            db,
            &request.request.namespace,
            &waiver.object_id,
            &request.actor,
            &mut visibility_cache,
            &mut visibility_work,
        )
        .map_err(Status::internal)?
        {
            visible_waivers.push(waiver);
        }
    }
    let visible_set = governed_fact_domain::resolve_invariant_set(
        &profile,
        visible_facts.clone(),
        visible_waivers.clone(),
        &request.request.subject_profile,
        &request.request.subject_identity,
        request.request.evaluation_time_ms,
        governed_fact_domain::MAX_RESOLUTION_LIMIT,
    )
    .map_err(map_invariant_resolution_error)?;
    let resolution_incomplete = all_set.set_digest != visible_set.set_digest;
    Ok((
        visible_set,
        visible_facts,
        visible_waivers,
        resolution_incomplete,
    ))
}

fn map_invariant_resolution_error(error: String) -> Status {
    if error.contains("exceeds") {
        Status::resource_exhausted(error)
    } else if error.contains("invalid") || error.contains("must") {
        Status::invalid_argument(error)
    } else {
        Status::failed_precondition("governed fact resolution unavailable")
    }
}

fn resolve_manifest_evidence(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    evidence_object_id: &str,
    subject_identity: &str,
    require_subject_binding: bool,
    evaluation_time_ms: i64,
) -> Result<Result<evaluation_manifest_domain::ResolvedEvidenceBinding, &'static str>, Status> {
    let Some(object) = db
        .get_object(evidence_object_id)
        .map_err(Status::internal)?
    else {
        return Ok(Err("evidence_unavailable"));
    };
    if object.namespace != namespace
        || object.kind != crate::domain::KIND_EXTERNAL_EVIDENCE
        || !object_visible_to_actor(db, &object, actor).map_err(Status::internal)?
    {
        return Ok(Err("evidence_unavailable"));
    }
    let Some(submission_id) = object.properties.get("submission_id") else {
        return Ok(Err("evidence_unavailable"));
    };
    let Some(submission) = db
        .get_evidence_submission(submission_id)
        .map_err(Status::internal)?
    else {
        return Ok(Err("evidence_unavailable"));
    };
    if submission.namespace != namespace {
        return Ok(Err("evidence_unavailable"));
    }
    if submission.lifecycle_state != crate::sekai::evidence::EvidenceLifecycleState::Available
        || submission.observed_at_ms > evaluation_time_ms
        || submission
            .expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= evaluation_time_ms)
    {
        return Ok(Err("evidence_stale"));
    }
    if require_subject_binding && submission.target_external_id != subject_identity {
        return Ok(Err("evidence_subject_mismatch"));
    }
    let envelope = submission
        .envelope
        .as_ref()
        .ok_or_else(|| Status::data_loss("admitted evidence envelope is missing"))?;
    let computed_digest = crate::sekai::evidence_store::canonical_content_digest(&envelope.content)
        .map_err(Status::data_loss)?;
    if computed_digest != submission.content_digest
        || envelope.content_digest != submission.content_digest
        || object
            .properties
            .get("content_digest")
            .is_none_or(|digest| digest != &submission.content_digest)
        || object
            .properties
            .get("classification")
            .is_none_or(|classification| classification != submission.classification.as_str())
    {
        return Err(Status::data_loss(
            "admitted evidence content binding is invalid",
        ));
    }
    let source_identity_digest = evaluation_manifest_domain::digest_json(&(
        submission.producer_identity.as_str(),
        submission.source_type.as_str(),
        submission.source_instance.as_str(),
        submission.source_record_id.as_str(),
        submission.source_version.as_str(),
        submission.source_sequence,
        submission.target_external_id.as_str(),
        submission.target_kind.as_str(),
    ))
    .map_err(Status::internal)?;
    Ok(Ok(evaluation_manifest_domain::ResolvedEvidenceBinding {
        evidence_object_id: evidence_object_id.into(),
        submission_id: submission.id,
        // Evidence admission stores canonical SHA-256 as lowercase hex. The
        // manifest qualifies the algorithm for unambiguous later binding.
        content_digest: format!("sha256:{}", submission.content_digest),
        evidence_type: submission.evidence_type,
        schema_id: submission.schema_id,
        schema_version: submission.schema_version,
        classification: submission.classification.as_str().into(),
        observed_at_ms: submission.observed_at_ms,
        expires_at_ms: submission.expires_at_ms.unwrap_or(0),
        source_identity_digest,
    }))
}

fn resolve_evaluation_manifest_live(
    db: &RuntimeDb,
    request: &evaluation_manifest_domain::PreparedResolutionRequest,
    now_ms: i64,
) -> Result<evaluation_manifest_domain::EvaluationResolutionOutcome, Status> {
    let Some(plan) = db
        .get_evaluation_plan(&request.request.plan_version_id)
        .map_err(Status::internal)?
    else {
        return Err(Status::not_found("evaluation plan not found"));
    };
    if plan.namespace != request.request.namespace
        || !evaluation_plan_visible(db, &plan, &request.actor).map_err(Status::internal)?
    {
        return Err(Status::not_found("evaluation plan not found"));
    }
    let canonical_plan =
        evaluation_plan_domain::prepare_plan(plan.clone(), &plan.created_by, plan.created_at_ms)
            .map_err(Status::data_loss)?;
    if canonical_plan != plan {
        return Err(Status::data_loss(
            "persisted evaluation plan content binding is invalid",
        ));
    }
    if !plan
        .accepted_subject_profiles
        .contains(&request.request.subject_profile)
    {
        return Ok(resolution_outcome(
            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
            "subject_profile_unsupported",
        ));
    }
    let (invariant_set, _, _, hidden_applicable_invariant) =
        match resolve_invariant_set_for_manifest(db, request) {
            Ok(resolved) => resolved,
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::FailedPrecondition | tonic::Code::NotFound
                ) =>
            {
                return Ok(resolution_outcome(
                    evaluation_manifest_domain::RESOLUTION_UNKNOWN,
                    "invariant_resolution_unavailable",
                ));
            }
            Err(status) => return Err(status),
        };
    if hidden_applicable_invariant {
        return Ok(resolution_outcome(
            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
            "invariant_resolution_incomplete",
        ));
    }
    let invariants = invariant_set
        .invariants
        .iter()
        .map(|invariant| (invariant.object_id.clone(), invariant))
        .collect::<HashMap<_, _>>();
    let plan_coverage = plan
        .nodes
        .iter()
        .flat_map(|node| node.invariant_version_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    if plan_coverage
        .iter()
        .any(|invariant_id| !invariants.contains_key(invariant_id))
    {
        return Ok(resolution_outcome(
            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
            "plan_invariant_unavailable",
        ));
    }
    let required_coverage = plan
        .nodes
        .iter()
        .filter(|node| node.classification == evaluation_plan_domain::NODE_REQUIRED)
        .flat_map(|node| node.invariant_version_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut waivers_by_invariant: HashMap<String, Vec<String>> = HashMap::new();
    for waiver in &invariant_set.waivers {
        for invariant_id in &waiver.input.invariant_version_ids {
            if invariants.contains_key(invariant_id) {
                waivers_by_invariant
                    .entry(invariant_id.clone())
                    .or_default()
                    .push(waiver.object_id.clone());
            }
        }
    }
    let uncovered_invariants = invariants
        .keys()
        .filter(|invariant_id| {
            !required_coverage.contains(*invariant_id)
                && !waivers_by_invariant.contains_key(*invariant_id)
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if !uncovered_invariants.is_empty() {
        return Ok(evaluation_manifest_domain::EvaluationResolutionOutcome {
            status: evaluation_manifest_domain::RESOLUTION_UNKNOWN.into(),
            manifest: None,
            findings: uncovered_invariants
                .into_iter()
                .map(|invariant_version_id| {
                    evaluation_manifest_domain::EvaluationResolutionFinding {
                        code: "invariant_uncovered".into(),
                        severity: evaluation_manifest_domain::FINDING_BLOCKING.into(),
                        node_id: String::new(),
                        invariant_version_id,
                    }
                })
                .collect(),
        });
    }

    let requested_evidence = request
        .request
        .evidence_object_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut all_evidence_ids = requested_evidence.clone();
    for fact in invariant_set
        .requirements
        .iter()
        .chain(invariant_set.invariants.iter())
    {
        all_evidence_ids.extend(fact.input.evidence_refs.iter().cloned());
    }
    for waiver in &invariant_set.waivers {
        all_evidence_ids.extend(waiver.input.evidence_refs.iter().cloned());
    }
    if all_evidence_ids.len() > evaluation_manifest_domain::MAX_MANIFEST_EVIDENCE {
        return Err(Status::resource_exhausted(
            "resolved evidence exceeds the manifest bound",
        ));
    }
    let mut admitted_evidence = Vec::with_capacity(all_evidence_ids.len());
    for evidence_id in &all_evidence_ids {
        match resolve_manifest_evidence(
            db,
            &request.request.namespace,
            &request.actor,
            evidence_id,
            &request.request.subject_identity,
            requested_evidence.contains(evidence_id),
            request.request.evaluation_time_ms,
        )? {
            Ok(evidence) => admitted_evidence.push(evidence),
            Err(code) => {
                return Ok(resolution_outcome(
                    evaluation_manifest_domain::RESOLUTION_UNKNOWN,
                    code,
                ));
            }
        }
    }
    let evidence_by_id = admitted_evidence
        .iter()
        .map(|evidence| (evidence.evidence_object_id.clone(), evidence))
        .collect::<HashMap<_, _>>();
    let mut consumed_requested_evidence = BTreeSet::new();
    let mut resolved_nodes = Vec::with_capacity(plan.nodes.len());
    for node in &plan.nodes {
        let Some(definition) = db
            .get_evaluator_definition(&node.evaluator_definition_id)
            .map_err(Status::internal)?
        else {
            return Ok(resolution_outcome(
                evaluation_manifest_domain::RESOLUTION_UNAVAILABLE,
                "evaluator_unavailable",
            ));
        };
        if definition.namespace != request.request.namespace {
            return Ok(resolution_outcome(
                evaluation_manifest_domain::RESOLUTION_UNAVAILABLE,
                "evaluator_unavailable",
            ));
        }
        let canonical_definition = evaluation_plan_domain::prepare_definition(
            definition.clone(),
            &definition.created_by,
            definition.created_at_ms,
        )
        .map_err(Status::data_loss)?;
        if canonical_definition != definition {
            return Err(Status::data_loss(
                "persisted evaluator definition content binding is invalid",
            ));
        }
        let availability = db
            .get_evaluator_availability(&definition.definition_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("evaluator availability is missing"))?;
        if availability.state != evaluation_plan_domain::AVAILABILITY_ENABLED {
            return Ok(resolution_outcome(
                evaluation_manifest_domain::RESOLUTION_UNAVAILABLE,
                "evaluator_unavailable",
            ));
        }
        if node.classification == evaluation_plan_domain::NODE_REQUIRED
            && definition.execution_class == evaluation_plan_domain::STOCHASTIC_EXECUTION_CLASS
            && !definition
                .stochastic_policy
                .as_ref()
                .is_some_and(|policy| policy.gate_eligible)
        {
            return Err(Status::data_loss(
                "required stochastic plan node lacks explicit gate eligibility",
            ));
        }
        evaluation_plan_domain::validate_parameters(
            &definition.parameter_schema_json,
            &node.parameters_json,
        )
        .map_err(Status::data_loss)?;
        let evidence_binding_schemas = node
            .input_bindings
            .iter()
            .filter(|binding| binding.source_kind == evaluation_plan_domain::INPUT_EVIDENCE)
            .map(|binding| binding.schema_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut node_evidence_ids = BTreeSet::new();
        let mut resolved_invariants = Vec::with_capacity(node.invariant_version_ids.len());
        for invariant_id in &node.invariant_version_ids {
            let invariant = invariants
                .get(invariant_id)
                .ok_or_else(|| Status::data_loss("plan invariant binding disappeared"))?;
            for evidence_type in &invariant.input.verification.evidence_types {
                let matching = requested_evidence
                    .iter()
                    .filter_map(|evidence_id| evidence_by_id.get(evidence_id))
                    .filter(|evidence| {
                        evidence.evidence_type == *evidence_type
                            && evidence_binding_schemas.contains(evidence.schema_id.as_str())
                    })
                    .collect::<Vec<_>>();
                if matching.is_empty() {
                    return Ok(resolution_outcome(
                        evaluation_manifest_domain::RESOLUTION_UNKNOWN,
                        "evidence_missing",
                    ));
                }
                for evidence in matching {
                    if !definition
                        .evidence_classifications
                        .contains(&evidence.classification)
                    {
                        return Ok(resolution_outcome(
                            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
                            "evidence_classification_mismatch",
                        ));
                    }
                    node_evidence_ids.insert(evidence.evidence_object_id.clone());
                    consumed_requested_evidence.insert(evidence.evidence_object_id.clone());
                }
            }
            let mut waiver_ids = waivers_by_invariant
                .get(invariant_id)
                .cloned()
                .unwrap_or_default();
            waiver_ids.sort();
            resolved_invariants.push(evaluation_manifest_domain::ResolvedInvariantBinding {
                invariant_version_id: invariant.object_id.clone(),
                content_digest: invariant.content_digest.clone(),
                predicate_kind: invariant.input.verification.predicate_kind.clone(),
                input_schema: invariant.input.verification.input_schema.clone(),
                result_schema: invariant.input.verification.result_schema.clone(),
                evidence_types: invariant.input.verification.evidence_types.clone(),
                provenance_evidence_object_ids: invariant.input.evidence_refs.clone(),
                waiver_version_ids: waiver_ids,
            });
        }
        if node_evidence_ids.len() > definition.resource_limits.max_evidence_items as usize {
            return Err(Status::resource_exhausted(
                "resolved node evidence exceeds evaluator resource limits",
            ));
        }
        resolved_nodes.push(evaluation_manifest_domain::ResolvedEvaluationNode {
            node_id: node.node_id.clone(),
            evaluator: evaluation_manifest_domain::ResolvedEvaluatorBinding {
                definition_id: definition.definition_id,
                definition_digest: definition.content_digest,
                implementation_digest: definition.implementation_digest,
                stochastic_policy: definition.stochastic_policy,
            },
            depends_on_node_ids: node.depends_on_node_ids.clone(),
            input_bindings: node
                .input_bindings
                .iter()
                .map(|binding| evaluation_manifest_domain::ResolvedInputBinding {
                    name: binding.name.clone(),
                    source_kind: binding.source_kind.clone(),
                    schema_id: binding.schema_id.clone(),
                })
                .collect(),
            parameters_json: node.parameters_json.clone(),
            invariants: resolved_invariants,
            evidence_object_ids: node_evidence_ids.into_iter().collect(),
            classification: node.classification.clone(),
        });
    }
    if consumed_requested_evidence != requested_evidence {
        return Ok(resolution_outcome(
            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
            "evidence_unbound",
        ));
    }
    let waivers = invariant_set
        .waivers
        .iter()
        .map(|waiver| evaluation_manifest_domain::ResolvedWaiverBinding {
            waiver_version_id: waiver.object_id.clone(),
            content_digest: waiver.content_digest.clone(),
            evidence_object_ids: waiver.input.evidence_refs.clone(),
            invariant_version_ids: waiver.input.invariant_version_ids.clone(),
        })
        .collect();
    let requirements = invariant_set
        .requirements
        .iter()
        .map(
            |requirement| evaluation_manifest_domain::ResolvedRequirementBinding {
                requirement_version_id: requirement.object_id.clone(),
                content_digest: requirement.content_digest.clone(),
                provenance_evidence_object_ids: requirement.input.evidence_refs.clone(),
            },
        )
        .collect();
    let manifest = evaluation_manifest_domain::prepare_manifest(
        evaluation_manifest_domain::ResolvedEvaluationManifest {
            contract_version: evaluation_manifest_domain::MANIFEST_CONTRACT.into(),
            resolver_version: request.request.resolver_version.clone(),
            manifest_id: String::new(),
            manifest_digest: String::new(),
            namespace: request.request.namespace.clone(),
            plan_version_id: plan.plan_version_id,
            plan_digest: plan.content_digest,
            subject_profile: request.request.subject_profile.clone(),
            subject_identity: request.request.subject_identity.clone(),
            subject_content_digest: request.request.subject_content_digest.clone(),
            invariant_set_id: invariant_set.set_id,
            invariant_set_digest: invariant_set.set_digest,
            invariant_profile_digest: invariant_set.profile_digest,
            evaluation_time_ms: request.request.evaluation_time_ms,
            resolved_by: request.actor.clone(),
            requirements,
            nodes: resolved_nodes,
            evidence: admitted_evidence,
            waivers,
            created_at_ms: now_ms,
        },
    )
    .map_err(map_evaluation_resource_error)?;
    Ok(evaluation_manifest_domain::resolved_outcome(manifest))
}

pub(super) struct EvaluationManifestResolutionLifecycle {
    db: Arc<RuntimeDb>,
}

impl EvaluationManifestResolutionLifecycle {
    pub(super) fn new(db: Arc<RuntimeDb>) -> Self {
        Self { db }
    }

    pub(super) fn resolve(
        &self,
        prepared: &evaluation_manifest_domain::PreparedResolutionRequest,
    ) -> Result<evaluation_manifest_domain::EvaluationResolutionOutcome, Status> {
        let (mut outcome, stored) = self.db.with_evaluation_resolution_snapshot(
            || {
                require_namespace_write_access(
                    &self.db,
                    &prepared.actor,
                    &prepared.request.namespace,
                )?;
                if let Some(replay) = self
                    .db
                    .get_evaluation_manifest_for_request(
                        &prepared.request.namespace,
                        &prepared.actor,
                        &prepared.request.request_id,
                    )
                    .map_err(Status::internal)?
                {
                    if replay.request_digest != prepared.request_digest {
                        return Err(Status::already_exists(
                            "evaluation resolution request already exists with different content",
                        ));
                    }
                    return Ok((
                        evaluation_manifest_domain::resolved_outcome(replay.manifest),
                        None,
                    ));
                }
                let outcome = resolve_evaluation_manifest_live(
                    &self.db,
                    prepared,
                    chrono::Utc::now().timestamp_millis(),
                )?;
                let write = outcome.manifest.as_ref().map(|manifest| {
                    crate::db::runtime_db::EvaluationManifestWrite {
                        manifest: manifest.clone(),
                        request_id: prepared.request.request_id.clone(),
                        request_digest: prepared.request_digest.clone(),
                    }
                });
                Ok((outcome, write))
            },
            map_evaluation_manifest_storage_error,
        )?;
        if let Some(stored) = stored {
            outcome.manifest = Some(stored);
        }
        Ok(outcome)
    }
}
