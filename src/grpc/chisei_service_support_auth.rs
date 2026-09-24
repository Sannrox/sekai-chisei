use super::*;

pub(super) fn evaluation_gate_suite_digest(suite: &crate::chisei::eval::Suite) -> String {
    let snapshot = EvaluationGateSuiteSnapshot {
        id: suite.id.clone(),
        name: suite.name.clone(),
        description: suite.description.clone(),
        cases: suite
            .cases
            .iter()
            .map(|case| EvaluationGateCaseSnapshot {
                id: case.id.clone(),
                name: case.name.clone(),
                namespace: case.namespace.clone(),
                spec: case.spec.clone(),
                assertions: case
                    .assertions
                    .iter()
                    .map(|assertion| EvaluationGateAssertionSnapshot {
                        assert_type: assertion.assert_type.clone(),
                        value: assertion.value.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };
    format!("{:x}", sha2::Sha256::digest(snapshot.encode_to_vec()))
}
pub(super) fn evaluation_gate_config_ref(
    release_digest: &str,
    artifact_digest: &str,
    suite_digest: &str,
) -> String {
    let mut hasher = sha2::Sha256::new();
    for value in [
        b"tenkai-gate-v1".as_slice(),
        release_digest.as_bytes(),
        artifact_digest.as_bytes(),
        suite_digest.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    format!("tenkai:{:x}", hasher.finalize())
}
pub(super) fn authenticated_actor<T>(request: &Request<T>) -> String {
    if let Some(context) = request
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        return context.principal.subject.clone();
    }
    request
        .metadata()
        .get("x-principal")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local")
        .to_string()
}
pub(super) fn enterprise_authenticated_context<T>(
    request: &Request<T>,
) -> Result<Option<&crate::enterprise::AuthenticatedContext>, Status> {
    if request
        .metadata()
        .get(AUTH_SOURCE_HEADER)
        .and_then(|value| value.to_str().ok())
        != Some("enterprise")
    {
        return Ok(None);
    }
    request
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
        .map(Some)
        .ok_or_else(|| Status::unauthenticated("enterprise execution credential rejected"))
}
pub(super) fn enterprise_execution_authority(
    context: Option<&crate::enterprise::AuthenticatedContext>,
) -> Option<String> {
    context.map(|context| match context.tenant.as_ref() {
        Some(tenant) => format!("tenant:{}", tenant.tenant_id),
        None => format!("credential:{}", context.principal.credential_id),
    })
}
pub(super) fn required_authenticated_actor<T>(request: &Request<T>) -> Result<String, Status> {
    request
        .metadata()
        .get("x-principal")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Status::unauthenticated("authenticated principal required"))
}
pub(super) fn require_eval_admin<T>(request: &Request<T>) -> Result<(), Status> {
    if matches!(authenticated_actor(request).as_str(), "root" | "local") {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "evaluation mutation requires control-plane administration",
        ))
    }
}
pub(super) fn required_lookup_promotion_admin<T>(request: &Request<T>) -> Result<String, Status> {
    let source = auth_source(request)
        .ok_or_else(|| Status::unauthenticated("authenticated request source required"))?;
    let metadata_actor = required_authenticated_actor(request)?;
    let actor = if let Some(context) = request
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        if context.principal.subject != metadata_actor {
            return Err(Status::unauthenticated(
                "authenticated principal does not match request context",
            ));
        }
        context.principal.subject.clone()
    } else if source == "local" {
        metadata_actor
    } else {
        return Err(Status::unauthenticated(
            "authenticated request context required",
        ));
    };
    if matches!(actor.as_str(), "root" | "local") {
        Ok(actor)
    } else {
        Err(Status::permission_denied(
            "evaluation mutation requires control-plane administration",
        ))
    }
}
pub(super) fn require_eval_reader<T>(request: &Request<T>, config: &Config) -> Result<(), Status> {
    let actor = authenticated_actor(request);
    if matches!(actor.as_str(), "root" | "local" | "chisei-gateway")
        || config
            .gateway_receipt_principals
            .iter()
            .any(|principal| principal == &actor)
    {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "evaluation reads require an authorized service principal",
        ))
    }
}
pub(super) fn require_telemetry_reader<T>(
    request: &Request<T>,
    config: &Config,
) -> Result<String, Status> {
    let actor = authenticated_actor(request);
    let allowed = matches!(actor.as_str(), "root" | "local" | "chisei-gateway")
        || config
            .gateway_receipt_principals
            .iter()
            .any(|principal| principal == &actor);
    if allowed {
        Ok(actor)
    } else {
        Err(Status::permission_denied(
            "telemetry readback requires an authorized service principal",
        ))
    }
}
pub(super) fn require_control_plane_admin<T>(
    request: &Request<T>,
    mutation: &str,
) -> Result<(), Status> {
    if matches!(authenticated_actor(request).as_str(), "root" | "local") {
        Ok(())
    } else {
        Err(Status::permission_denied(format!(
            "{mutation} requires control-plane administration"
        )))
    }
}
pub(super) fn canonical_namespace(namespace: &str) -> Result<&str, Status> {
    let canonical = namespace.trim();
    if canonical.is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    if canonical != namespace {
        return Err(Status::invalid_argument(
            "namespace must not contain leading or trailing whitespace",
        ));
    }
    Ok(canonical)
}
pub(super) fn content_version(value: &impl serde::Serialize) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(value).unwrap_or_default());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub(super) fn sample_observation_readback_digest(
    request_id: &str,
    namespace: &str,
    state: &str,
    observed_at: i64,
) -> String {
    let projection = SampleObservationReadbackDigest {
        version: "chisei.sample_observation.readback.v1",
        request_id,
        namespace,
        state,
        observed_at,
    };
    format!("sha256:{}", content_version(&projection))
}
pub(super) fn external_request_from_proto(
    request: ExternalActionRequest,
) -> external::ExternalActionRequest {
    external::ExternalActionRequest {
        version: request.version,
        operation_id: request.operation_id,
        parent_operation_id: request.parent_operation_id,
        attempt_id: request.attempt_id,
        request_id: request.request_id,
        actor: request.actor,
        namespace: request.namespace,
        requesting_harness: request.requesting_harness,
        intended_executor: request.intended_executor,
        action_type: request.action_type,
        parameter_schema: request.parameter_schema,
        canonical_arguments_digest: request.canonical_arguments_digest,
        policy_summary: request.policy_summary.into_iter().collect(),
        target_selectors: request.target_selectors,
        immutable_preconditions: request.immutable_preconditions.into_iter().collect(),
        risk_class: request.risk_class,
        expected_effects: request.expected_effects,
        requested_invocation_count: request.requested_invocation_count,
        deadline_ms: request.deadline_ms,
        estimated_cost_micros: request.estimated_cost_micros,
        estimated_volume: request.estimated_volume,
        affected_resource_count: request.affected_resource_count,
        rollback_capability: request.rollback_capability,
        required_host_capabilities: request.required_host_capabilities,
        idempotency_key: request.idempotency_key,
        policy_project: request.policy_project,
    }
}
pub(super) fn external_decision_to_proto(
    decision: &external::ExternalActionDecision,
) -> ExternalActionDecision {
    ExternalActionDecision {
        version: decision.version.clone(),
        authorization_id: decision.authorization_id.clone(),
        request_digest: decision.request_digest.clone(),
        decision: decision.decision.clone(),
        reason: decision.reason.clone(),
        approval_id: decision.approval_id.clone(),
        policy_scope: decision.policy_scope.clone(),
        policy_version: decision.policy_version.clone(),
        created_at_ms: decision.created_at_ms,
        expires_at_ms: decision.expires_at_ms,
        cancelled_at_ms: decision.cancelled_at_ms,
        assurance: Some(ExternalActionAssuranceDeclaration {
            version: decision.assurance.version.clone(),
            authorization_only: decision.assurance.authorization_only,
            host_must_verify_permit: decision.assurance.host_must_verify_permit,
            host_must_enforce_constraints: decision.assurance.host_must_enforce_constraints,
            physical_effect_verified: decision.assurance.physical_effect_verified,
        }),
        permit: None,
    }
}
pub(super) fn permit_signing_key(config: &Config) -> Result<ed25519_dalek::SigningKey, Status> {
    permit::signing_key_from_hex(config.permit_signing_key.as_deref().ok_or_else(|| {
        Status::failed_precondition("external-action permit signing is not configured")
    })?)
    .map_err(Status::failed_precondition)
}
pub(super) fn external_permit_to_proto(value: &permit::Permit) -> ExternalActionPermit {
    ExternalActionPermit {
        version: value.version.clone(),
        permit_id: value.permit_id.clone(),
        authorization_id: value.authorization_id.clone(),
        request_digest: value.request_digest.clone(),
        signature: value.signature.clone(),
        expires_at_ms: value.expires_at_ms,
        constraints: value.constraints.clone(),
        issuer: value.issuer.clone(),
        subject_actor: value.subject_actor.clone(),
        namespace: value.namespace.clone(),
        operation_id: value.operation_id.clone(),
        requesting_harness: value.requesting_harness.clone(),
        executor: value.executor.clone(),
        action_type: value.action_type.clone(),
        parameter_schema: value.parameter_schema.clone(),
        canonical_arguments_digest: value.canonical_arguments_digest.clone(),
        target_selectors: value.target_selectors.clone(),
        immutable_preconditions: value.immutable_preconditions.clone().into_iter().collect(),
        allowed_effects: value.allowed_effects.clone(),
        risk_class: value.risk_class.clone(),
        budget_micros: value.budget_micros,
        volume_limit: value.volume_limit,
        blast_radius_limit: value.blast_radius_limit,
        max_invocations: value.max_invocations,
        not_before_ms: value.not_before_ms,
        redemption_mode: value.redemption_mode.clone(),
        approval_identities: value.approval_identities.clone(),
        policy_version: value.policy_version.clone(),
        schema_version: value.schema_version.clone(),
        capability_version: value.capability_version.clone(),
        pricing_version: value.pricing_version.clone(),
        nonce: value.nonce.clone(),
        delegation_depth: value.delegation_depth,
        parent_permit_id: value.parent_permit_id.clone(),
        revocation_handle: value.revocation_handle.clone(),
        signature_algorithm: value.signature_algorithm.clone(),
        key_id: value.key_id.clone(),
        signed_digest: value.signed_digest.clone(),
        public_key: value.public_key.clone(),
        issued_at_ms: value.issued_at_ms,
        revocation_latency_ms: value.revocation_latency_ms,
        required_host_capabilities: value.required_host_capabilities.clone(),
        parent_chain: value.parent_chain.clone(),
        initiating_actor: value.initiating_actor.clone(),
        offline_revocation_unavailable: value.offline_revocation_unavailable,
        policy_scope: value.policy_scope.clone(),
        site_id: value.site_id.clone(),
    }
}
pub(super) fn external_permit_from_proto(value: ExternalActionPermit) -> permit::Permit {
    permit::Permit {
        version: value.version,
        permit_id: value.permit_id,
        authorization_id: value.authorization_id,
        request_digest: value.request_digest,
        issuer: value.issuer,
        subject_actor: value.subject_actor,
        namespace: value.namespace,
        operation_id: value.operation_id,
        requesting_harness: value.requesting_harness,
        executor: value.executor,
        action_type: value.action_type,
        parameter_schema: value.parameter_schema,
        canonical_arguments_digest: value.canonical_arguments_digest,
        target_selectors: value.target_selectors,
        immutable_preconditions: value.immutable_preconditions.into_iter().collect(),
        allowed_effects: value.allowed_effects,
        required_host_capabilities: value.required_host_capabilities,
        parent_chain: value.parent_chain,
        initiating_actor: value.initiating_actor,
        offline_revocation_unavailable: value.offline_revocation_unavailable,
        policy_scope: value.policy_scope,
        constraints: value.constraints,
        risk_class: value.risk_class,
        budget_micros: value.budget_micros,
        volume_limit: value.volume_limit,
        blast_radius_limit: value.blast_radius_limit,
        max_invocations: value.max_invocations,
        not_before_ms: value.not_before_ms,
        expires_at_ms: value.expires_at_ms,
        redemption_mode: value.redemption_mode,
        approval_identities: value.approval_identities,
        policy_version: value.policy_version,
        schema_version: value.schema_version,
        capability_version: value.capability_version,
        pricing_version: value.pricing_version,
        nonce: value.nonce,
        delegation_depth: value.delegation_depth,
        parent_permit_id: value.parent_permit_id,
        revocation_handle: value.revocation_handle,
        signature_algorithm: value.signature_algorithm,
        key_id: value.key_id,
        public_key: value.public_key,
        issued_at_ms: value.issued_at_ms,
        revocation_latency_ms: value.revocation_latency_ms,
        site_id: if value.site_id.trim().is_empty() {
            crate::sekai::lease::DEFAULT_SITE_ID.into()
        } else {
            value.site_id
        },
        signed_digest: value.signed_digest,
        signature: value.signature,
    }
}
pub(super) fn external_permit_policy_to_proto(
    value: &permit::ExternalPermitPolicy,
) -> ExternalPermitPolicy {
    ExternalPermitPolicy {
        scope: value.scope.clone(),
        offline_action_types: value.offline_action_types.clone(),
        offline_max_duration_ms: value.offline_max_duration_ms,
        offline_max_invocations: value.offline_max_invocations,
        permitted_delegators: value.permitted_delegators.clone(),
        max_delegation_depth: value.max_delegation_depth,
    }
}
pub(super) fn external_host_context(
    executor: String,
    harness: String,
    digest: String,
    targets: Vec<String>,
    preconditions: HashMap<String, String>,
    capabilities: Vec<String>,
) -> permit::HostContext {
    permit::HostContext {
        executor,
        requesting_harness: harness,
        canonical_arguments_digest: digest,
        target_selectors: targets,
        observed_preconditions: preconditions.into_iter().collect(),
        host_capabilities: capabilities,
    }
}
pub(super) fn map_quality_trend_error(error: String) -> Status {
    if error == "namespace access denied" {
        Status::permission_denied(error)
    } else if error == "invalid namespace"
        || error == "until_ms must be greater than since_ms"
        || error == "quality trend window exceeds one year"
    {
        Status::invalid_argument(error)
    } else if error.contains("receipt limit exceeded") {
        Status::resource_exhausted(error)
    } else {
        Status::internal(error)
    }
}
pub(super) fn quality_trend_report_to_proto(
    report: &crate::quality_trend::QualityTrendReport,
) -> QualityTrendReport {
    QualityTrendReport {
        version: report.version.clone(),
        source_receipt_version: report.source_receipt_version.clone(),
        authority: report.authority.clone(),
        namespace: report.namespace.clone(),
        since_ms: report.since_ms,
        until_ms: report.until_ms,
        totals: Some(QualityTrendTotals {
            receipts_scanned: report.totals.receipts_scanned,
            ignored_non_evaluation_receipts: report.totals.ignored_non_evaluation_receipts,
            evaluation_receipts: report.totals.evaluation_receipts,
            baseline_history_receipts: report.totals.baseline_history_receipts,
            baseline_history_valid_executions: report.totals.baseline_history_valid_executions,
            baseline_history_missing_dependencies: report
                .totals
                .baseline_history_missing_dependencies,
            baseline_history_invalid_executions: report.totals.baseline_history_invalid_executions,
            valid_executions: report.totals.valid_executions,
            missing_dependencies: report.totals.missing_dependencies,
            invalid_executions: report.totals.invalid_executions,
            allow: report.totals.allow,
            deny: report.totals.deny,
            unknown: report.totals.unknown,
            unavailable: report.totals.unavailable,
            cancelled: report.totals.cancelled,
            running: report.totals.running,
            partial_executions: report.totals.partial_executions,
            trend_points: report.totals.trend_points,
            step_pass: report.totals.step_pass,
            step_fail: report.totals.step_fail,
            step_unknown: report.totals.step_unknown,
            step_unavailable: report.totals.step_unavailable,
            step_error: report.totals.step_error,
            step_skipped: report.totals.step_skipped,
            stochastic_complete_populations: report.totals.stochastic_complete_populations,
            stochastic_low_sample_populations: report.totals.stochastic_low_sample_populations,
            baseline_compared: report.totals.baseline_compared,
            baseline_missing: report.totals.baseline_missing,
            baseline_incomparable: report.totals.baseline_incomparable,
            baseline_unavailable: report.totals.baseline_unavailable,
            regressed: report.totals.regressed,
            improved: report.totals.improved,
            unchanged: report.totals.unchanged,
            regression_unavailable: report.totals.regression_unavailable,
            hidden_dimensions: report.totals.hidden_dimensions,
            missing_dimensions: report.totals.missing_dimensions,
        }),
        series: report
            .series
            .iter()
            .map(|series| QualityTrendSeries {
                key: Some(QualityTrendSeriesKey {
                    plan_digest: series.key.plan_digest.clone(),
                    node_id: series.key.node_id.clone(),
                    evaluator_definition_digest: series.key.evaluator_definition_digest.clone(),
                    implementation_digest: series.key.implementation_digest.clone(),
                    provider: series.key.provider.clone(),
                    model: series.key.model.clone(),
                    agent: series.key.agent.clone(),
                }),
                points: series
                    .points
                    .iter()
                    .map(|point| QualityTrendPoint {
                        operation_id: point.operation_id.clone(),
                        manifest_digest: point.manifest_digest.clone(),
                        started_at_ms: point.started_at_ms,
                        completed_at_ms: point.completed_at_ms,
                        evaluation_time_ms: point.evaluation_time_ms,
                        evaluator_input_digest: point.evaluator_input_digest.clone(),
                        subject_content_digest: point.subject_content_digest.clone(),
                        subject_identity_state: point.subject_identity_state.clone(),
                        evidence_set_digest: point.evidence_set_digest.clone(),
                        evidence_digest_count: point.evidence_digest_count,
                        evidence_identity_state: point.evidence_identity_state.clone(),
                        dependency_result_set_digest: point.dependency_result_set_digest.clone(),
                        dependency_result_digest_count: point.dependency_result_digest_count,
                        dependency_result_identity_state: point
                            .dependency_result_identity_state
                            .clone(),
                        execution_status: point.execution_status.clone(),
                        gate_verdict: point.gate_verdict.clone(),
                        gate_reason_code: point.gate_reason_code.clone(),
                        step_status: point.step_status.clone(),
                        step_reason_code: point.step_reason_code.clone(),
                        classification: point.classification.clone(),
                        population_state: point.population_state.clone(),
                        trial_count: point.trial_count,
                        completed_trial_count: point.completed_trial_count,
                        mean_score_micros: point.mean_score_micros,
                        pass_rate_basis_points: point.pass_rate_basis_points,
                        score_variance_micros_squared: point.score_variance_micros_squared,
                        aggregation_rule: point.aggregation_rule.clone(),
                        baseline_state: point.baseline_state.clone(),
                        baseline_operation_id: point.baseline_operation_id.clone(),
                        mean_score_delta_micros: point.mean_score_delta_micros,
                        pass_rate_delta_basis_points: point.pass_rate_delta_basis_points,
                        variance_delta_micros_squared: point
                            .variance_delta_micros_squared
                            .map(|value| value.to_string()),
                        regression: point.regression.clone(),
                    })
                    .collect(),
            })
            .collect(),
        semantic_digest: report.semantic_digest.clone(),
    }
}
pub(super) fn require_namespace_access(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
) -> Result<(), Status> {
    let namespace = canonical_namespace(namespace)?;
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    let boundary = db
        .find_namespace_boundary(namespace)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::permission_denied("namespace access denied"))?;
    let granted = db
        .list_grants(&boundary.id)
        .map_err(Status::internal)?
        .into_iter()
        .any(|grant| grant.principal == actor);
    if granted {
        Ok(())
    } else {
        Err(Status::permission_denied("namespace access denied"))
    }
}
pub(super) fn require_namespace_write_access(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
) -> Result<(), Status> {
    let namespace = canonical_namespace(namespace)?;
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    let boundary = db
        .find_namespace_boundary(namespace)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::permission_denied("namespace write access denied"))?;
    let granted = db
        .list_grants(&boundary.id)
        .map_err(Status::internal)?
        .into_iter()
        .any(|grant| {
            grant.principal == actor
                && matches!(
                    grant.role,
                    crate::sekai::security::Role::Editor | crate::sekai::security::Role::Admin
                )
        });
    if granted {
        Ok(())
    } else {
        Err(Status::permission_denied("namespace write access denied"))
    }
}
/// Namespace administration: the `Admin` role on the namespace boundary.
/// Enterprise contexts carry no namespace-admin action yet, so they fail
/// closed here.
pub(super) fn require_namespace_admin_access(
    db: &RuntimeDb,
    actor: &str,
    context: Option<&crate::enterprise::AuthenticatedContext>,
    namespace: &str,
) -> Result<(), Status> {
    let namespace = canonical_namespace(namespace)?;
    if context.is_some() {
        return Err(Status::permission_denied(
            "namespace administration is unavailable for enterprise credentials",
        ));
    }
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    let boundary = db
        .find_namespace_boundary(namespace)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::permission_denied("namespace administration denied"))?;
    let granted = db
        .list_grants(&boundary.id)
        .map_err(Status::internal)?
        .into_iter()
        .any(|grant| {
            grant.principal == actor && matches!(grant.role, crate::sekai::security::Role::Admin)
        });
    if granted {
        Ok(())
    } else {
        Err(Status::permission_denied("namespace administration denied"))
    }
}
pub(super) fn require_external_project_access(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    project: &str,
) -> Result<(), Status> {
    if project == namespace {
        return Ok(());
    }
    let project_object = db
        .find_by_external_id(&format!("project:{project}"))
        .map_err(Status::internal)?
        .filter(|object| object.namespace == namespace)
        .ok_or_else(|| Status::permission_denied("external-action project access denied"))?;
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    let granted = db
        .list_grants(&project_object.id)
        .map_err(Status::internal)?
        .into_iter()
        .any(|grant| {
            grant.principal == actor
                && matches!(
                    grant.role,
                    crate::sekai::security::Role::Editor | crate::sekai::security::Role::Admin
                )
        });
    if granted {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "external-action project access denied",
        ))
    }
}
pub(super) fn require_team_namespace_access<T>(
    db: &RuntimeDb,
    _config: &Config,
    request: &Request<T>,
    namespace: &str,
) -> Result<(), Status> {
    let actor = authenticated_actor(request);
    require_team_namespace_actor_access(db, &actor, namespace)
}
pub(super) fn require_team_namespace_actor_access(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
) -> Result<(), Status> {
    let trusted_service = matches!(actor, "root" | "local" | "chisei-gateway");
    if trusted_service {
        return Ok(());
    }
    let boundary = db
        .find_namespace_boundary(namespace)
        .map_err(Status::internal)?;
    let team_managed_namespace = boundary.as_ref().is_some_and(|object| {
        object
            .properties
            .get("team_managed")
            .is_some_and(|value| value == "true")
    });
    if team_managed_namespace || db.is_team_principal(actor).map_err(Status::internal)? {
        require_namespace_access(db, actor, namespace)?;
    }
    Ok(())
}
pub(super) fn require_execution_namespace_access(
    db: &RuntimeDb,
    _config: &Config,
    actor: &str,
    namespace: &str,
) -> Result<(), Status> {
    if actor == "chisei-gateway" {
        canonical_namespace(namespace).map(|_| ())
    } else {
        require_namespace_access(db, actor, namespace)
    }
}
pub(super) fn require_execution_namespace_access_with_context(
    db: &RuntimeDb,
    config: &Config,
    actor: &str,
    context: Option<&crate::enterprise::AuthenticatedContext>,
    namespace: &str,
) -> Result<(), Status> {
    if let Some(context) = context {
        let scope_permitted = match context.credential_kind {
            crate::enterprise::CredentialKind::Machine => context
                .scopes
                .iter()
                .any(|scope| scope == CHISEI_EXECUTE_SCOPE),
            crate::enterprise::CredentialKind::HumanSession => {
                context.scopes.iter().any(|scope| scope == "sekai.write")
            }
        };
        if !scope_permitted {
            return Err(Status::permission_denied(
                "enterprise execution authorization denied",
            ));
        }
        let extension = db
            .enterprise_extension()
            .ok_or_else(|| Status::unauthenticated("enterprise execution credential rejected"))?;
        canonical_namespace(namespace)?;
        return extension
            .authorize_authenticated_context(
                context,
                namespace,
                crate::enterprise::NamespaceAction::Write,
            )
            .map_err(enterprise_execution_status);
    }
    require_execution_namespace_access(db, config, actor, namespace)
}
pub(super) fn enterprise_execution_status(error: crate::enterprise::ExtensionError) -> Status {
    match error {
        crate::enterprise::ExtensionError::CredentialNotFound
        | crate::enterprise::ExtensionError::Unauthenticated
        | crate::enterprise::ExtensionError::Expired
        | crate::enterprise::ExtensionError::Revoked
        | crate::enterprise::ExtensionError::Replayed
        | crate::enterprise::ExtensionError::IssuerMismatch
        | crate::enterprise::ExtensionError::ResourceMismatch => {
            Status::unauthenticated("enterprise execution credential rejected")
        }
        crate::enterprise::ExtensionError::PermissionDenied
        | crate::enterprise::ExtensionError::MembershipRevoked
        | crate::enterprise::ExtensionError::TenantSuspended
        | crate::enterprise::ExtensionError::InvalidState
        | crate::enterprise::ExtensionError::InvalidNonce
        | crate::enterprise::ExtensionError::InvalidRedirectUri
        | crate::enterprise::ExtensionError::InvalidPkce => {
            Status::permission_denied("enterprise execution authorization denied")
        }
        crate::enterprise::ExtensionError::UnsupportedVersion => {
            Status::failed_precondition("unsupported enterprise identity contract version")
        }
        crate::enterprise::ExtensionError::Unavailable(_) => {
            Status::unavailable("enterprise execution authorization unavailable")
        }
    }
}
pub(super) fn execution_budget_scope(
    namespace: &str,
    actor: &str,
    requested_user_id: &str,
) -> String {
    if matches!(actor, "root" | "local") {
        return if requested_user_id.trim().is_empty() {
            "default"
        } else {
            requested_user_id.trim()
        }
        .to_string();
    }
    format!("project:{}/agent:{}", namespace.trim(), actor.trim())
}
pub(super) fn strongest_pressure(
    left: crate::chisei::budget::PressureLevel,
    right: crate::chisei::budget::PressureLevel,
) -> crate::chisei::budget::PressureLevel {
    use crate::chisei::budget::PressureLevel;
    match (left, right) {
        (PressureLevel::Critical, _) | (_, PressureLevel::Critical) => PressureLevel::Critical,
        (PressureLevel::Moderate, _) | (_, PressureLevel::Moderate) => PressureLevel::Moderate,
        _ => PressureLevel::None,
    }
}
pub(super) fn execution_context_actor(
    db: &RuntimeDb,
    _config: &Config,
    actor: &str,
    delegated: Option<&str>,
    namespace: &str,
) -> Result<String, Status> {
    let Some(delegated) = delegated.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(actor.to_string());
    };
    if !matches!(actor, "root" | "local" | "chisei-gateway") {
        return Err(Status::permission_denied(
            "delegated execution identity requires a gateway service principal",
        ));
    }
    if db.is_team_principal(delegated).map_err(Status::internal)? {
        require_namespace_access(db, delegated, namespace)?;
        Ok(delegated.to_string())
    } else {
        Ok(actor.to_string())
    }
}
pub(super) fn auth_source<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get(AUTH_SOURCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}
pub(super) fn context_evidence_reference(
    reference: &pipe::EvidenceContextReference,
) -> ContextEvidenceReference {
    ContextEvidenceReference {
        submission_id: reference.submission_id.clone(),
        source_type: reference.source_type.clone(),
        source_instance: reference.source_instance.clone(),
        source_version: reference.source_version.clone(),
        source_sequence: reference.source_sequence,
        evidence_type: reference.evidence_type.clone(),
        schema_id: reference.schema_id.clone(),
        schema_version: reference.schema_version.clone(),
        content_digest: reference.content_digest.clone(),
        observed_at_ms: reference.observed_at_ms,
        classification: reference.classification.clone(),
        projection_version: reference.projection_version.clone(),
        disclosed_fields: reference.disclosed_fields.clone(),
        descriptor: Some(epistemic_descriptor_to_pb(&reference.descriptor)),
    }
}
pub(super) fn epistemic_descriptor_to_pb(
    descriptor: &crate::chisei::epistemic_descriptor::EpistemicDescriptor,
) -> crate::grpc::pb::chisei::EpistemicDescriptor {
    debug_assert!(descriptor.validate().is_ok());
    crate::grpc::pb::chisei::EpistemicDescriptor {
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
pub(super) fn memory_context_reference(
    reference: &pipe::MemoryContextReference,
) -> MemoryContextReference {
    MemoryContextReference {
        memory_id: reference.memory_id.clone(),
        memory_version: reference.memory_version,
        classification: reference.classification.clone(),
        confidence_bps: u32::from(reference.confidence_bps),
        applicability: reference.applicability.clone(),
        evidence_operation_ids: reference.evidence_operation_ids.clone(),
        content_digest: reference.content_digest.clone(),
        descriptor: Some(epistemic_descriptor_to_pb(&reference.descriptor)),
    }
}
pub(super) fn context_bytes(system: &str, messages: &[ChatMessage]) -> u64 {
    let message_bytes = messages
        .iter()
        .map(|message| {
            let tool_call_bytes = message
                .tool_calls
                .iter()
                .map(|tool_call| {
                    (tool_call.id.len() + tool_call.name.len() + tool_call.args_json.len()) as u64
                })
                .fold(0_u64, u64::saturating_add);
            ((message.role.len() + message.content.len() + message.tool_call_id.len()) as u64)
                .saturating_add(tool_call_bytes)
        })
        .fold(0_u64, u64::saturating_add);
    (system.len() as u64).saturating_add(message_bytes)
}
pub(super) fn estimate_context_tokens(system: &str, messages: &[ChatMessage]) -> u64 {
    context_bytes(system, messages).div_ceil(4)
}
pub(super) fn memory_lifecycle_allows_execution(
    state: crate::chisei::kioku::MemoryLifecycleState,
    expires_at_ms: Option<i64>,
    retention_until_ms: Option<i64>,
    now_ms: i64,
) -> bool {
    state == crate::chisei::kioku::MemoryLifecycleState::Active
        && expires_at_ms.is_none_or(|expires_at_ms| expires_at_ms > now_ms)
        && retention_until_ms.is_none_or(|retention_until_ms| retention_until_ms > now_ms)
}
pub(super) fn epistemic_descriptor_receipt_attributes(
    plan: &ExecutionPlan,
) -> BTreeMap<String, String> {
    let descriptors = plan
        .evidence_references
        .iter()
        .filter_map(|reference| reference.descriptor.as_ref())
        .chain(
            plan.memory_references
                .iter()
                .filter_map(|reference| reference.descriptor.as_ref()),
        )
        .collect::<Vec<_>>();
    let source_rows = descriptors
        .iter()
        .filter_map(|descriptor| descriptor.source_row_count)
        .map(u64::from)
        .sum::<u64>();
    let source_refs = descriptors
        .iter()
        .map(|descriptor| descriptor.source_refs.len() as u64)
        .sum::<u64>();
    let source_digests = descriptors
        .iter()
        .map(|descriptor| descriptor.source_digests.len() as u64)
        .sum::<u64>();
    let truncated = descriptors
        .iter()
        .any(|descriptor| descriptor.source_rows_truncated);
    let mut evidence_status_counts = BTreeMap::<String, u64>::new();
    let mut lifecycle_status_counts = BTreeMap::<String, u64>::new();
    for descriptor in &descriptors {
        *evidence_status_counts
            .entry(descriptor.evidence_status.clone())
            .or_default() += 1;
        *lifecycle_status_counts
            .entry(descriptor.lifecycle_status.clone())
            .or_default() += 1;
    }
    let encode_counts = |counts: &BTreeMap<String, u64>| {
        counts
            .iter()
            .map(|(status, count)| format!("{status}={count}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut attributes = BTreeMap::from([
        (
            "epistemic_accounting_version".into(),
            "chisei.epistemic-context-operations/v1".into(),
        ),
        (
            "epistemic_descriptor_version".into(),
            EPISTEMIC_DESCRIPTOR_VERSION.into(),
        ),
        (
            "epistemic_descriptor_count".into(),
            descriptors.len().min(128).to_string(),
        ),
        (
            "epistemic_descriptor_source_rows".into(),
            source_rows.min(128 * 128).to_string(),
        ),
        (
            "epistemic_descriptor_source_refs".into(),
            source_refs.min(128 * 8).to_string(),
        ),
        (
            "epistemic_descriptor_source_digests".into(),
            source_digests.min(128 * 8).to_string(),
        ),
        (
            "epistemic_descriptor_source_rows_truncated".into(),
            truncated.to_string(),
        ),
        (
            "epistemic_evidence_status_counts".into(),
            encode_counts(&evidence_status_counts),
        ),
        (
            "epistemic_lifecycle_status_counts".into(),
            encode_counts(&lifecycle_status_counts),
        ),
        (
            "epistemic_context_bytes".into(),
            plan.context_bytes.to_string(),
        ),
        (
            "epistemic_context_tokens".into(),
            plan.context_tokens.to_string(),
        ),
        (
            "epistemic_projection_latency_ms".into(),
            plan.context_projection_latency_ms.to_string(),
        ),
        (
            "epistemic_context_truncated".into(),
            plan.context_truncated.to_string(),
        ),
    ]);
    if !plan.context_admission_policy_version.is_empty() {
        attributes.insert(
            "context_admission_policy_version".into(),
            plan.context_admission_policy_version.clone(),
        );
        attributes.insert(
            "context_admission_descriptor_version".into(),
            plan.context_admission_descriptor_version.clone(),
        );
    }
    if !plan.context_admission_decision.is_empty() {
        attributes.insert(
            "context_admission_decision".into(),
            plan.context_admission_decision.clone(),
        );
        attributes.insert(
            "context_admission_reasons".into(),
            plan.context_admission_reasons.join(","),
        );
        attributes.insert(
            "context_admission_source_digests".into(),
            plan.context_admission_source_digests.join(","),
        );
    }
    attributes
}
pub(super) fn receipt_mutation_transport_allowed<T>(request: &Request<T>, config: &Config) -> bool {
    match auth_source(request).as_deref() {
        Some("token") => true,
        Some("local") => config.insecure,
        _ => false,
    }
}
pub(super) fn reportable_receipt_kind(kind: ReceiptEventKind) -> bool {
    matches!(
        kind,
        ReceiptEventKind::AttemptStarted
            | ReceiptEventKind::ModelCalled
            | ReceiptEventKind::ActionPerformed
            | ReceiptEventKind::ApprovalDecided
            | ReceiptEventKind::ArtifactProduced
            | ReceiptEventKind::VerificationRecorded
            | ReceiptEventKind::HumanIntervened
            | ReceiptEventKind::OutcomeRecorded
    )
}
pub(super) fn content_hash(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        let bytes = part.as_ref();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    format!("{:x}", hasher.finalize())
}
pub(super) fn planned_response_hash(response: &PlannedChatResponse) -> String {
    let tool_calls = response
        .tool_calls
        .iter()
        .map(|call| (&call.id, &call.name, &call.args_json))
        .collect::<Vec<_>>();
    let canonical_tool_calls = serde_json::to_vec(&tool_calls).unwrap_or_default();
    content_hash([response.content.as_bytes(), canonical_tool_calls.as_slice()])
}
pub(super) fn receipt_event(
    operation_id: &str,
    suffix: &str,
    parent_suffix: Option<&str>,
    timestamp_ms: i64,
    kind: ReceiptEventKind,
    actor: &str,
    attributes: BTreeMap<String, String>,
) -> OperationReceiptEvent {
    OperationReceiptEvent {
        event_id: format!("{operation_id}:{suffix}"),
        operation_id: operation_id.to_string(),
        parent_event_id: parent_suffix.map(|parent| format!("{operation_id}:{parent}")),
        timestamp_ms,
        surface: kind.surface(),
        kind,
        actor: actor.to_string(),
        references: Vec::new(),
        attributes,
    }
}
pub(super) fn persist_namespace_policy(
    db: &RuntimeDb,
    namespace: &str,
    policy: &Policy,
    context_admission_policy: Option<&crate::chisei::policy::ContextAdmissionPolicy>,
) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    let external_id = format!("policy:{namespace}");
    let mut properties = policy_properties(policy, context_admission_policy);
    properties.insert("namespace".to_string(), namespace.to_string());

    if let Some(mut existing) = db.find_by_external_id(&external_id)? {
        existing.name = namespace.to_string();
        existing.namespace = namespace.to_string();
        existing.properties = properties;
        existing.updated = now;
        db.update_object(&existing)
    } else {
        db.create_object(&Object {
            id: format!("policy-{namespace}"),
            kind: POLICY_KIND.to_string(),
            name: namespace.to_string(),
            namespace: namespace.to_string(),
            external_id,
            properties,
            created: now,
            updated: now,
        })
    }
}
pub(super) fn from_proto_evaluator_definition(
    value: EvaluatorDefinition,
) -> Result<evaluation_plan_domain::EvaluatorDefinition, Status> {
    let limits = value
        .resource_limits
        .ok_or_else(|| Status::invalid_argument("evaluator resource_limits required"))?;
    Ok(evaluation_plan_domain::EvaluatorDefinition {
        contract_version: value.contract_version,
        definition_id: value.definition_id,
        namespace: value.namespace,
        evaluator_id: value.evaluator_id,
        version: value.version,
        implementation_digest: value.implementation_digest,
        execution_class: value.execution_class,
        supported_predicate_kinds: value.supported_predicate_kinds,
        supported_input_schemas: value.supported_input_schemas,
        supported_result_schemas: value.supported_result_schemas,
        parameter_schema_json: value.parameter_schema_json,
        evidence_classifications: value.evidence_classifications,
        resource_limits: evaluation_plan_domain::EvaluatorResourceLimits {
            timeout_ms: limits.timeout_ms,
            max_input_bytes: limits.max_input_bytes,
            max_output_bytes: limits.max_output_bytes,
            max_evidence_items: limits.max_evidence_items,
        },
        adapter_endpoint: value.adapter_endpoint,
        stochastic_policy: value
            .stochastic_policy
            .map(from_proto_stochastic_evaluator_policy),
        source_ref: value.source_ref,
        content_digest: value.content_digest,
        created_by: value.created_by,
        created_at_ms: value.created_at_ms,
    })
}
pub(super) fn to_proto_evaluator_definition(
    value: &evaluation_plan_domain::EvaluatorDefinition,
) -> EvaluatorDefinition {
    EvaluatorDefinition {
        contract_version: value.contract_version.clone(),
        definition_id: value.definition_id.clone(),
        namespace: value.namespace.clone(),
        evaluator_id: value.evaluator_id.clone(),
        version: value.version.clone(),
        implementation_digest: value.implementation_digest.clone(),
        execution_class: value.execution_class.clone(),
        supported_predicate_kinds: value.supported_predicate_kinds.clone(),
        supported_input_schemas: value.supported_input_schemas.clone(),
        supported_result_schemas: value.supported_result_schemas.clone(),
        parameter_schema_json: value.parameter_schema_json.clone(),
        evidence_classifications: value.evidence_classifications.clone(),
        resource_limits: Some(EvaluatorResourceLimits {
            timeout_ms: value.resource_limits.timeout_ms,
            max_input_bytes: value.resource_limits.max_input_bytes,
            max_output_bytes: value.resource_limits.max_output_bytes,
            max_evidence_items: value.resource_limits.max_evidence_items,
        }),
        adapter_endpoint: value.adapter_endpoint.clone(),
        stochastic_policy: value
            .stochastic_policy
            .as_ref()
            .map(to_proto_stochastic_evaluator_policy),
        source_ref: value.source_ref.clone(),
        content_digest: value.content_digest.clone(),
        created_by: value.created_by.clone(),
        created_at_ms: value.created_at_ms,
    }
}
pub(super) fn from_proto_stochastic_evaluator_policy(
    value: StochasticEvaluatorPolicy,
) -> evaluation_plan_domain::StochasticEvaluatorPolicy {
    evaluation_plan_domain::StochasticEvaluatorPolicy {
        provider: value.provider,
        model: value.model,
        prompt_profile: value.prompt_profile,
        prompt_profile_digest: value.prompt_profile_digest,
        result_schema: value.result_schema,
        trial_count: value.trial_count,
        temperature_millis: value.temperature_millis,
        top_p_millionths: value.top_p_millionths,
        seed_supported: value.seed_supported,
        base_seed: value.base_seed,
        aggregation_rule: value.aggregation_rule,
        minimum_mean_score_micros: value.minimum_mean_score_micros,
        minimum_pass_rate_basis_points: value.minimum_pass_rate_basis_points,
        maximum_score_variance_micros_squared: value.maximum_score_variance_micros_squared,
        gate_eligible: value.gate_eligible,
        max_retries_per_trial: value.max_retries_per_trial,
        max_tokens_per_trial: value.max_tokens_per_trial,
        max_total_tokens: value.max_total_tokens,
        egress_policy: value.egress_policy,
        raw_response_retention: value.raw_response_retention,
    }
}
pub(super) fn to_proto_stochastic_evaluator_policy(
    value: &evaluation_plan_domain::StochasticEvaluatorPolicy,
) -> StochasticEvaluatorPolicy {
    StochasticEvaluatorPolicy {
        provider: value.provider.clone(),
        model: value.model.clone(),
        prompt_profile: value.prompt_profile.clone(),
        prompt_profile_digest: value.prompt_profile_digest.clone(),
        result_schema: value.result_schema.clone(),
        trial_count: value.trial_count,
        temperature_millis: value.temperature_millis,
        top_p_millionths: value.top_p_millionths,
        seed_supported: value.seed_supported,
        base_seed: value.base_seed,
        aggregation_rule: value.aggregation_rule.clone(),
        minimum_mean_score_micros: value.minimum_mean_score_micros,
        minimum_pass_rate_basis_points: value.minimum_pass_rate_basis_points,
        maximum_score_variance_micros_squared: value.maximum_score_variance_micros_squared,
        gate_eligible: value.gate_eligible,
        max_retries_per_trial: value.max_retries_per_trial,
        max_tokens_per_trial: value.max_tokens_per_trial,
        max_total_tokens: value.max_total_tokens,
        egress_policy: value.egress_policy.clone(),
        raw_response_retention: value.raw_response_retention.clone(),
    }
}
pub(super) fn to_proto_evaluator_availability(
    value: &evaluation_plan_domain::EvaluatorAvailability,
) -> EvaluatorAvailability {
    EvaluatorAvailability {
        definition_id: value.definition_id.clone(),
        state: value.state.clone(),
        superseded_by_definition_id: value.superseded_by_definition_id.clone(),
        reason: value.reason.clone(),
        request_id: value.request_id.clone(),
        request_digest: value.request_digest.clone(),
        changed_by: value.changed_by.clone(),
        changed_at_ms: value.changed_at_ms,
    }
}
pub(super) fn evaluator_record(
    db: &RuntimeDb,
    definition: &evaluation_plan_domain::EvaluatorDefinition,
    implementation_executable: bool,
    implementation_status: &str,
) -> Result<EvaluatorDefinitionRecord, Status> {
    let availability = db
        .get_evaluator_availability(&definition.definition_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::data_loss("evaluator availability is missing"))?;
    Ok(evaluator_record_with_availability(
        definition,
        &availability,
        implementation_executable,
        implementation_status,
    ))
}
pub(super) fn evaluator_record_with_availability(
    definition: &evaluation_plan_domain::EvaluatorDefinition,
    availability: &evaluation_plan_domain::EvaluatorAvailability,
    implementation_executable: bool,
    implementation_status: &str,
) -> EvaluatorDefinitionRecord {
    EvaluatorDefinitionRecord {
        definition: Some(to_proto_evaluator_definition(definition)),
        availability: Some(to_proto_evaluator_availability(availability)),
        implementation_executable,
        implementation_status: implementation_status.into(),
    }
}
pub(super) fn from_proto_evaluation_plan(
    value: EvaluationPlan,
) -> evaluation_plan_domain::EvaluationPlan {
    evaluation_plan_domain::EvaluationPlan {
        contract_version: value.contract_version,
        plan_version_id: value.plan_version_id,
        namespace: value.namespace,
        plan_id: value.plan_id,
        version: value.version,
        accepted_subject_profiles: value.accepted_subject_profiles,
        nodes: value
            .nodes
            .into_iter()
            .map(|node| evaluation_plan_domain::EvaluationPlanNode {
                node_id: node.node_id,
                evaluator_definition_id: node.evaluator_definition_id,
                depends_on_node_ids: node.depends_on_node_ids,
                input_bindings: node
                    .input_bindings
                    .into_iter()
                    .map(|binding| evaluation_plan_domain::EvaluationInputBinding {
                        name: binding.name,
                        source_kind: binding.source_kind,
                        schema_id: binding.schema_id,
                    })
                    .collect(),
                parameters_json: node.parameters_json,
                invariant_version_ids: node.invariant_version_ids,
                classification: node.classification,
            })
            .collect(),
        reducer: value.reducer,
        source_ref: value.source_ref,
        content_digest: value.content_digest,
        created_by: value.created_by,
        created_at_ms: value.created_at_ms,
    }
}
pub(super) fn to_proto_evaluation_plan(
    value: &evaluation_plan_domain::EvaluationPlan,
) -> EvaluationPlan {
    EvaluationPlan {
        contract_version: value.contract_version.clone(),
        plan_version_id: value.plan_version_id.clone(),
        namespace: value.namespace.clone(),
        plan_id: value.plan_id.clone(),
        version: value.version.clone(),
        accepted_subject_profiles: value.accepted_subject_profiles.clone(),
        nodes: value
            .nodes
            .iter()
            .map(|node| EvaluationPlanNode {
                node_id: node.node_id.clone(),
                evaluator_definition_id: node.evaluator_definition_id.clone(),
                depends_on_node_ids: node.depends_on_node_ids.clone(),
                input_bindings: node
                    .input_bindings
                    .iter()
                    .map(|binding| EvaluationInputBinding {
                        name: binding.name.clone(),
                        source_kind: binding.source_kind.clone(),
                        schema_id: binding.schema_id.clone(),
                    })
                    .collect(),
                parameters_json: node.parameters_json.clone(),
                invariant_version_ids: node.invariant_version_ids.clone(),
                classification: node.classification.clone(),
            })
            .collect(),
        reducer: value.reducer.clone(),
        source_ref: value.source_ref.clone(),
        content_digest: value.content_digest.clone(),
        created_by: value.created_by.clone(),
        created_at_ms: value.created_at_ms,
    }
}
pub(super) fn from_proto_evaluation_resolution(
    value: EvaluationResolutionRequest,
) -> evaluation_manifest_domain::EvaluationResolutionRequest {
    evaluation_manifest_domain::EvaluationResolutionRequest {
        contract_version: value.contract_version,
        resolver_version: value.resolver_version,
        namespace: value.namespace,
        request_id: value.request_id,
        plan_version_id: value.plan_version_id,
        subject_profile: value.subject_profile,
        subject_identity: value.subject_identity,
        subject_content_digest: value.subject_content_digest,
        evidence_object_ids: value.evidence_object_ids,
        evaluation_time_ms: value.evaluation_time_ms,
    }
}
pub(super) fn to_proto_evaluation_manifest(
    value: &evaluation_manifest_domain::ResolvedEvaluationManifest,
) -> ResolvedEvaluationManifest {
    ResolvedEvaluationManifest {
        contract_version: value.contract_version.clone(),
        resolver_version: value.resolver_version.clone(),
        manifest_id: value.manifest_id.clone(),
        manifest_digest: value.manifest_digest.clone(),
        namespace: value.namespace.clone(),
        plan_version_id: value.plan_version_id.clone(),
        plan_digest: value.plan_digest.clone(),
        subject_profile: value.subject_profile.clone(),
        subject_identity: value.subject_identity.clone(),
        subject_content_digest: value.subject_content_digest.clone(),
        invariant_set_id: value.invariant_set_id.clone(),
        invariant_set_digest: value.invariant_set_digest.clone(),
        invariant_profile_digest: value.invariant_profile_digest.clone(),
        evaluation_time_ms: value.evaluation_time_ms,
        resolved_by: value.resolved_by.clone(),
        requirements: value
            .requirements
            .iter()
            .map(|requirement| ResolvedRequirementBinding {
                requirement_version_id: requirement.requirement_version_id.clone(),
                content_digest: requirement.content_digest.clone(),
                provenance_evidence_object_ids: requirement.provenance_evidence_object_ids.clone(),
            })
            .collect(),
        nodes: value
            .nodes
            .iter()
            .map(|node| ResolvedEvaluationNode {
                node_id: node.node_id.clone(),
                evaluator: Some(ResolvedEvaluatorBinding {
                    definition_id: node.evaluator.definition_id.clone(),
                    definition_digest: node.evaluator.definition_digest.clone(),
                    implementation_digest: node.evaluator.implementation_digest.clone(),
                    stochastic_policy: node
                        .evaluator
                        .stochastic_policy
                        .as_ref()
                        .map(to_proto_stochastic_evaluator_policy),
                }),
                depends_on_node_ids: node.depends_on_node_ids.clone(),
                input_bindings: node
                    .input_bindings
                    .iter()
                    .map(|binding| ResolvedInputBinding {
                        name: binding.name.clone(),
                        source_kind: binding.source_kind.clone(),
                        schema_id: binding.schema_id.clone(),
                    })
                    .collect(),
                parameters_json: node.parameters_json.clone(),
                invariants: node
                    .invariants
                    .iter()
                    .map(|invariant| ResolvedInvariantBinding {
                        invariant_version_id: invariant.invariant_version_id.clone(),
                        content_digest: invariant.content_digest.clone(),
                        predicate_kind: invariant.predicate_kind.clone(),
                        input_schema: invariant.input_schema.clone(),
                        result_schema: invariant.result_schema.clone(),
                        evidence_types: invariant.evidence_types.clone(),
                        provenance_evidence_object_ids: invariant
                            .provenance_evidence_object_ids
                            .clone(),
                        waiver_version_ids: invariant.waiver_version_ids.clone(),
                    })
                    .collect(),
                evidence_object_ids: node.evidence_object_ids.clone(),
                classification: node.classification.clone(),
            })
            .collect(),
        evidence: value
            .evidence
            .iter()
            .map(|evidence| ResolvedEvidenceBinding {
                evidence_object_id: evidence.evidence_object_id.clone(),
                submission_id: evidence.submission_id.clone(),
                content_digest: evidence.content_digest.clone(),
                evidence_type: evidence.evidence_type.clone(),
                schema_id: evidence.schema_id.clone(),
                schema_version: evidence.schema_version.clone(),
                classification: evidence.classification.clone(),
                observed_at_ms: evidence.observed_at_ms,
                expires_at_ms: evidence.expires_at_ms,
                source_identity_digest: evidence.source_identity_digest.clone(),
            })
            .collect(),
        waivers: value
            .waivers
            .iter()
            .map(|waiver| ResolvedWaiverBinding {
                waiver_version_id: waiver.waiver_version_id.clone(),
                content_digest: waiver.content_digest.clone(),
                evidence_object_ids: waiver.evidence_object_ids.clone(),
                invariant_version_ids: waiver.invariant_version_ids.clone(),
            })
            .collect(),
        created_at_ms: value.created_at_ms,
    }
}
pub(super) fn to_proto_evaluation_resolution(
    outcome: &evaluation_manifest_domain::EvaluationResolutionOutcome,
) -> ResolveEvaluationPlanResponse {
    ResolveEvaluationPlanResponse {
        status: outcome.status.clone(),
        manifest: outcome.manifest.as_ref().map(to_proto_evaluation_manifest),
        findings: outcome
            .findings
            .iter()
            .map(|finding| EvaluationResolutionFinding {
                code: finding.code.clone(),
                severity: finding.severity.clone(),
                node_id: finding.node_id.clone(),
                invariant_version_id: finding.invariant_version_id.clone(),
            })
            .collect(),
    }
}
pub(super) fn from_proto_evaluation_execution(
    value: EvaluationExecutionRequest,
) -> evaluation_execution_domain::EvaluationExecutionRequest {
    evaluation_execution_domain::EvaluationExecutionRequest {
        contract_version: value.contract_version,
        executor_version: value.executor_version,
        namespace: value.namespace,
        manifest_digest: value.manifest_digest,
        max_total_duration_ms: value.max_total_duration_ms,
    }
}
pub(super) fn to_proto_evaluation_step(
    value: &evaluation_execution_domain::EvaluationStepReceipt,
) -> EvaluationStepReceipt {
    EvaluationStepReceipt {
        contract_version: value.contract_version.clone(),
        manifest_digest: value.manifest_digest.clone(),
        node_id: value.node_id.clone(),
        classification: value.classification.clone(),
        status: value.status.clone(),
        reason_code: value.reason_code.clone(),
        input_digest: value.input_digest.clone(),
        parameters_digest: value.parameters_digest.clone(),
        evaluator_definition_digest: value.evaluator_definition_digest.clone(),
        implementation_digest: value.implementation_digest.clone(),
        evidence_digests: value.evidence_digests.clone(),
        dependency_result_digests: value.dependency_result_digests.clone(),
        result_digest: value.result_digest.clone(),
        step_receipt_digest: value.step_receipt_digest.clone(),
        stochastic_evidence: value.stochastic_evidence.as_ref().map(|evidence| {
            StochasticStepEvidence {
                contract_version: evidence.contract_version.clone(),
                provider: evidence.provider.clone(),
                model: evidence.model.clone(),
                prompt_profile: evidence.prompt_profile.clone(),
                prompt_profile_digest: evidence.prompt_profile_digest.clone(),
                result_schema: evidence.result_schema.clone(),
                trial_count: evidence.trial_count,
                aggregation_rule: evidence.aggregation_rule.clone(),
                minimum_mean_score_micros: evidence.minimum_mean_score_micros,
                minimum_pass_rate_basis_points: evidence.minimum_pass_rate_basis_points,
                maximum_score_variance_micros_squared: evidence
                    .maximum_score_variance_micros_squared,
                gate_eligible: evidence.gate_eligible,
                completed_trial_count: evidence.completed_trial_count,
                mean_score_micros: evidence.mean_score_micros,
                pass_rate_basis_points: evidence.pass_rate_basis_points,
                score_variance_micros_squared: evidence.score_variance_micros_squared,
                total_input_tokens: evidence.total_input_tokens,
                total_output_tokens: evidence.total_output_tokens,
                total_retry_accounted_tokens: evidence.total_retry_accounted_tokens,
                trials: evidence
                    .trials
                    .iter()
                    .map(|trial| StochasticTrialEvidence {
                        trial_index: trial.trial_index,
                        seed: trial.seed,
                        attempt_count: trial.attempt_count,
                        status: trial.status.clone(),
                        reason_code: trial.reason_code.clone(),
                        score_micros: trial.score_micros,
                        input_tokens: trial.input_tokens,
                        output_tokens: trial.output_tokens,
                        retry_accounted_tokens: trial.retry_accounted_tokens,
                        result_digest: trial.result_digest.clone(),
                    })
                    .collect(),
                aggregate_digest: evidence.aggregate_digest.clone(),
            }
        }),
    }
}
pub(super) fn to_proto_evaluation_gate(
    value: &evaluation_execution_domain::EvaluationGateDecision,
) -> EvaluationGateDecision {
    EvaluationGateDecision {
        contract_version: value.contract_version.clone(),
        manifest_digest: value.manifest_digest.clone(),
        reducer: value.reducer.clone(),
        verdict: value.verdict.clone(),
        reason_code: value.reason_code.clone(),
        step_receipt_digests: value.step_receipt_digests.clone(),
        invariant_coverage: value
            .invariant_coverage
            .iter()
            .map(|coverage| InvariantCoverageDecision {
                invariant_version_id: coverage.invariant_version_id.clone(),
                covered_by_node_ids: coverage.covered_by_node_ids.clone(),
                waiver_version_ids: coverage.waiver_version_ids.clone(),
                satisfied: coverage.satisfied,
            })
            .collect(),
        decision_digest: value.decision_digest.clone(),
    }
}
pub(super) fn to_proto_evaluation_execution_projection(
    value: &evaluation_execution_domain::EvaluationExecutionProjection,
) -> EvaluationExecutionProjection {
    EvaluationExecutionProjection {
        manifest_digest: value.manifest_digest.clone(),
        operation_id: value.operation_id.clone(),
        namespace: value.namespace.clone(),
        status: value.status.clone(),
        steps: value.steps.iter().map(to_proto_evaluation_step).collect(),
        decision: value.decision.as_ref().map(to_proto_evaluation_gate),
    }
}
pub(super) fn evaluation_operation_id(manifest_digest: &str) -> String {
    evaluation_execution_domain::execution_operation_id(manifest_digest)
}
pub(super) fn evaluation_manifest_reference(manifest_digest: &str) -> GovernedReference {
    GovernedReference {
        kind: "evaluation_manifest".into(),
        reference: manifest_digest.into(),
        content_hash: Some(manifest_digest.into()),
        disclosed_fields: vec!["manifest_digest".into()],
        omitted: false,
        omission_reason: None,
    }
}
pub(super) fn initial_evaluation_receipt(
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    actor: &str,
    now_ms: i64,
    max_total_duration_ms: u64,
    topological_order: &[String],
) -> Result<OperationReceipt, Status> {
    let operation_id = evaluation_operation_id(&manifest.manifest_digest);
    let manifest_reference = evaluation_manifest_reference(&manifest.manifest_digest);
    let intent_id = format!("{operation_id}:intent");
    let policy_id = format!("{operation_id}:policy");
    let routing_id = format!("{operation_id}:routing");
    let budget_id = format!("{operation_id}:budget");
    let events = vec![
        OperationReceiptEvent {
            event_id: intent_id.clone(),
            operation_id: operation_id.clone(),
            parent_event_id: None,
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::IntentRecorded,
            surface: ReceiptSurface::Intent,
            actor: actor.into(),
            references: vec![manifest_reference.clone()],
            attributes: BTreeMap::from([
                ("manifest_digest".into(), manifest.manifest_digest.clone()),
                (
                    "executor_version".into(),
                    evaluation_execution_domain::EXECUTOR_VERSION.into(),
                ),
            ]),
        },
        OperationReceiptEvent {
            event_id: policy_id.clone(),
            operation_id: operation_id.clone(),
            parent_event_id: Some(intent_id),
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::PolicyDecided,
            surface: ReceiptSurface::Policy,
            actor: "chisei.evaluation-executor".into(),
            references: vec![manifest_reference.clone()],
            attributes: BTreeMap::from([(
                "reducer".into(),
                evaluation_plan_domain::FIXED_REDUCER.into(),
            )]),
        },
        OperationReceiptEvent {
            event_id: routing_id.clone(),
            operation_id: operation_id.clone(),
            parent_event_id: Some(policy_id),
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::RouteSelected,
            surface: ReceiptSurface::Routing,
            actor: "chisei.evaluation-executor".into(),
            references: vec![manifest_reference.clone()],
            attributes: BTreeMap::from([(
                "topological_order_json".into(),
                serde_json::to_string(topological_order)
                    .map_err(|error| Status::internal(error.to_string()))?,
            )]),
        },
        OperationReceiptEvent {
            event_id: budget_id,
            operation_id: operation_id.clone(),
            parent_event_id: Some(routing_id),
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::BudgetDecided,
            surface: ReceiptSurface::Budget,
            actor: "chisei.evaluation-executor".into(),
            references: vec![manifest_reference],
            attributes: BTreeMap::from([
                (
                    "max_total_duration_ms".into(),
                    max_total_duration_ms.to_string(),
                ),
                ("node_count".into(), manifest.nodes.len().to_string()),
            ]),
        },
    ];
    Ok(OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id,
        parent_operation_id: None,
        namespace: manifest.namespace.clone(),
        operation_class: evaluation_execution_domain::EXECUTION_OPERATION_CLASS.into(),
        initiating_actor: actor.into(),
        schema_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
        policy_version: evaluation_plan_domain::FIXED_REDUCER.into(),
        started_at_ms: now_ms,
        completed_at_ms: None,
        events,
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    })
}
pub(super) fn evaluation_total_budget_ms(receipt: &OperationReceipt) -> Result<u64, Status> {
    let mut budgets = receipt.events.iter().filter(|event| {
        event.kind == ReceiptEventKind::BudgetDecided
            && event.surface == ReceiptSurface::Budget
            && event.actor == "chisei.evaluation-executor"
    });
    let budget = budgets
        .next()
        .and_then(|event| event.attributes.get("max_total_duration_ms"))
        .ok_or_else(|| Status::data_loss("evaluation execution budget is missing"))?
        .parse::<u64>()
        .map_err(|_| Status::data_loss("evaluation execution budget is invalid"))?;
    if budgets.next().is_some()
        || budget == 0
        || budget > evaluation_execution_domain::MAX_TOTAL_DURATION_MS
    {
        return Err(Status::data_loss(
            "evaluation execution budget is not canonical",
        ));
    }
    Ok(budget)
}
pub(super) fn evaluation_step_event(
    operation_id: &str,
    node: &evaluation_manifest_domain::ResolvedEvaluationNode,
    step: &evaluation_execution_domain::EvaluationStepReceipt,
    now_ms: i64,
) -> Result<OperationReceiptEvent, Status> {
    let parent_event_id = node
        .depends_on_node_ids
        .iter()
        .max()
        .map(|dependency| format!("{operation_id}:step:{dependency}"))
        .unwrap_or_else(|| format!("{operation_id}:budget"));
    Ok(OperationReceiptEvent {
        event_id: format!("{operation_id}:step:{}", node.node_id),
        operation_id: operation_id.into(),
        parent_event_id: Some(parent_event_id),
        timestamp_ms: now_ms,
        kind: ReceiptEventKind::VerificationRecorded,
        surface: ReceiptSurface::Verification,
        actor: "chisei.evaluation-executor".into(),
        references: vec![
            evaluation_manifest_reference(&step.manifest_digest),
            GovernedReference {
                kind: "evaluator_definition".into(),
                reference: node.evaluator.definition_id.clone(),
                content_hash: Some(node.evaluator.definition_digest.clone()),
                disclosed_fields: vec![
                    "definition_id".into(),
                    "definition_digest".into(),
                    "implementation_digest".into(),
                ],
                omitted: false,
                omission_reason: None,
            },
        ],
        attributes: BTreeMap::from([
            (
                "evaluation_step_receipt".into(),
                serde_json::to_string(step).map_err(|error| Status::internal(error.to_string()))?,
            ),
            ("node_id".into(), step.node_id.clone()),
            ("status".into(), step.status.clone()),
            ("reason_code".into(), step.reason_code.clone()),
            ("result_digest".into(), step.result_digest.clone()),
            (
                "step_receipt_digest".into(),
                step.step_receipt_digest.clone(),
            ),
        ]),
    })
}
pub(super) fn evaluation_gate_event(
    operation_id: &str,
    parent_event_id: String,
    decision: &evaluation_execution_domain::EvaluationGateDecision,
    now_ms: i64,
) -> Result<OperationReceiptEvent, Status> {
    Ok(OperationReceiptEvent {
        event_id: format!("{operation_id}:gate"),
        operation_id: operation_id.into(),
        parent_event_id: Some(parent_event_id),
        timestamp_ms: now_ms,
        kind: ReceiptEventKind::OutcomeRecorded,
        surface: ReceiptSurface::Outcome,
        actor: "chisei.evaluation-executor".into(),
        references: vec![evaluation_manifest_reference(&decision.manifest_digest)],
        attributes: BTreeMap::from([
            (
                "evaluation_gate_decision".into(),
                serde_json::to_string(decision)
                    .map_err(|error| Status::internal(error.to_string()))?,
            ),
            ("verdict".into(), decision.verdict.clone()),
            ("reason_code".into(), decision.reason_code.clone()),
            ("decision_digest".into(), decision.decision_digest.clone()),
        ]),
    })
}
pub(super) fn evaluation_cancellation_event(
    receipt: &OperationReceipt,
    actor: &str,
    now_ms: i64,
) -> OperationReceiptEvent {
    let parent_event_id = receipt
        .events
        .iter()
        .rev()
        .find(|event| event.kind == ReceiptEventKind::VerificationRecorded)
        .map(|event| event.event_id.clone())
        .unwrap_or_else(|| format!("{}:budget", receipt.operation_id));
    OperationReceiptEvent {
        event_id: format!("{}:cancel", receipt.operation_id),
        operation_id: receipt.operation_id.clone(),
        parent_event_id: Some(parent_event_id),
        timestamp_ms: now_ms,
        kind: ReceiptEventKind::HumanIntervened,
        surface: ReceiptSurface::Intervention,
        actor: actor.into(),
        references: Vec::new(),
        attributes: BTreeMap::from([("evaluation_cancel_requested".into(), "true".into())]),
    }
}
pub(super) fn evaluation_cancellation_requested(receipt: &OperationReceipt) -> bool {
    evaluation_execution_domain::cancellation_requested(receipt)
}
pub(super) fn order_parent_event_id(
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    operation_id: &str,
) -> String {
    evaluation_execution_domain::deterministic_topological_order(manifest)
        .ok()
        .and_then(|order| order.last().cloned())
        .map(|node_id| format!("{operation_id}:step:{node_id}"))
        .unwrap_or_else(|| format!("{operation_id}:budget"))
}
pub(super) fn evaluation_projection_from_receipt(
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    index: &evaluation_execution_domain::EvaluationExecutionIndex,
    receipt: &OperationReceipt,
) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, String> {
    evaluation_execution_domain::projection_from_receipt(manifest, index, receipt)
}
pub(super) fn map_evaluation_resource_error(error: String) -> Status {
    if error.contains("already exists") {
        Status::already_exists(error)
    } else if error.contains("not found")
        || error.contains("disabled")
        || error.contains("superseded")
        || error.contains("incompatible")
        || error.contains("unavailable")
    {
        Status::failed_precondition(error)
    } else if error.contains("exceeds") {
        Status::resource_exhausted(error)
    } else {
        Status::invalid_argument(error)
    }
}
pub(super) fn map_evaluation_manifest_storage_error(error: String) -> Status {
    if error.contains("already exists") {
        Status::already_exists(error)
    } else if error.contains("persisted evaluation manifest")
        || error.contains("manifest digest conflicts")
    {
        Status::data_loss(error)
    } else {
        Status::internal(error)
    }
}
