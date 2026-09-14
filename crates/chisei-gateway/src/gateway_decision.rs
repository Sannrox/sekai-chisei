use super::*;

pub(super) fn validate_harness_request_headers(
    responses_route: bool,
    headers: &HeaderMap,
) -> Result<(), String> {
    if responses_route && headers.contains_key(&IDEMPOTENCY_KEY) {
        return Err("Idempotency-Key is not supported by this gateway profile version".into());
    }
    Ok(())
}
pub(super) fn is_responses_create(method: &Method, normalized_path: &str) -> bool {
    method == Method::POST && matches!(normalized_path, "/responses" | "/responses/")
}
pub(super) async fn rate_limit_rejection(
    runtime: &GatewayRuntime,
    identity: &GatewayIdentity,
) -> Option<String> {
    let mut subjects = vec![
        (
            "gateway:global".to_string(),
            runtime.global_rate_limit_requests,
        ),
        (
            format!("agent:{}", identity.agent),
            runtime.rate_limit_requests,
        ),
    ];
    if !identity.key_id.is_empty() {
        subjects.push((
            format!("key:{}", identity.key_id),
            runtime.rate_limit_requests,
        ));
    }
    let now = Instant::now();
    let mut limits = runtime.rate_limits.write().await;
    limits.retain(|_, window| now.duration_since(window.started_at) < runtime.rate_limit_window);
    for (subject, limit) in &subjects {
        if !limits.contains_key(subject) && limits.len() >= MAX_RATE_LIMIT_SUBJECTS {
            return Some("gateway:subject_capacity".to_string());
        }
        let window = limits.entry(subject.clone()).or_insert(RateLimitWindow {
            started_at: now,
            requests: 0,
        });
        if now.duration_since(window.started_at) >= runtime.rate_limit_window {
            window.started_at = now;
            window.requests = 0;
        }
        if window.requests >= *limit {
            return Some(subject.clone());
        }
    }
    for (subject, _) in subjects {
        limits
            .get_mut(&subject)
            .expect("rate window exists")
            .requests += 1;
    }
    None
}
#[allow(clippy::too_many_arguments)]
pub(super) fn early_refusal_context(
    correlation: &GatewayCorrelation,
    responses_profile: bool,
    provider: ProviderKind,
    requested_model: Option<String>,
    work_unit_id: Option<String>,
    request_bytes: usize,
    started_ms: i64,
    task_class: String,
    request_hash: String,
    capability_snapshot_version: String,
) -> UsageContext {
    UsageContext {
        request_id: correlation.request_id.clone(),
        lookup_request_id: correlation.lookup_request_id.clone(),
        caller_scope: correlation.caller_scope.clone(),
        operation_id: correlation.operation_id.clone(),
        parent_operation_id: correlation.parent_operation_id.clone(),
        turn_id: correlation.turn_id.clone(),
        attempt: correlation.attempt,
        provider_ordinal: 1,
        cycle_id: correlation.cycle_id.clone(),
        traceparent: correlation.traceparent.clone(),
        responses_profile,
        responses_terminal_required: false,
        provider,
        requested_model,
        resolved_model: None,
        route_override: None,
        requested_alias: None,
        profile_version: None,
        capability_snapshot_version: Some(capability_snapshot_version),
        pricing_snapshot_version: None,
        governance_metadata_status: None,
        work_unit_id,
        pipeline_observation: None,
        request_bytes,
        started_ms,
        route_bias: None,
        policy_scope: None,
        policy_version: None,
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
        task_class,
        data_class: "unclassified".into(),
        request_hash,
        budget_subject: None,
        budget_status: "not_evaluated".into(),
        egress_applied: false,
        cache_requested: false,
    }
}
pub(super) fn is_transient_governance_status(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable
            | tonic::Code::DeadlineExceeded
            | tonic::Code::Cancelled
            | tonic::Code::Unknown
            | tonic::Code::Internal
    )
}
pub(super) fn governance_status_rejection(status: &tonic::Status) -> GatewayRejection {
    if status.code() == tonic::Code::FailedPrecondition
        && status.message().starts_with("capability_unsupported:")
    {
        return GatewayRejection::json(
            StatusCode::BAD_REQUEST,
            "capability_unsupported",
            status
                .message()
                .trim_start_matches("capability_unsupported:")
                .trim(),
        );
    }
    let (http_status, error_type) = match status.code() {
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
            (StatusCode::FORBIDDEN, "governance_denied")
        }
        tonic::Code::NotFound => (StatusCode::NOT_FOUND, "governance_not_found"),
        tonic::Code::FailedPrecondition => (StatusCode::CONFLICT, "governance_precondition"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "governance_unavailable"),
    };
    GatewayRejection::json(http_status, error_type, status.to_string())
}
/// Build policy, budget, and egress preflight from a gateway decision.
#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_gateway_decision(
    config: &GatewayConfig,
    runtime: &GatewayRuntime,
    identity: &GatewayIdentity,
    preflight_context: &mut UsageContext,
    registry_snapshot: &ProviderRegistry,
    admit: GatewayDecisionAdmit,
    body: Vec<u8>,
    requested_provider: ProviderKind,
    client_provider: ProviderKind,
    capability_surface: Option<CapabilityRequestSurface>,
    context_request: Option<&GatewayContextRequest>,
    requested_model: Option<&str>,
    request_id: &str,
    work_unit_id: Option<&str>,
) -> Result<
    (
        PolicyPreflight,
        ContextEgressPreflight,
        Option<BudgetPreflight>,
    ),
    GatewayRejection,
> {
    preflight_context.pipeline_observation = admit.pipeline_observation.clone();
    let decision_model = admit.resolved_model.clone();
    let eval_regressed = admit.eval_regressed;
    let eval_regression_reason = admit.eval_regression_reason.clone();
    let budget = BudgetPreflight {
        provisional_local_free: admit.provisional_local_free,
        budget_subject: Some(admit.budget_scope.clone()),
    };
    preflight_context.budget_subject = budget.budget_subject.clone();
    preflight_context.budget_status = if budget.provisional_local_free {
        "local_free"
    } else {
        "allowed"
    }
    .into();
    let resolved_provider = if admit.metadata_operation {
        requested_provider
    } else {
        ProviderKind::from_runtime(&admit.resolved_runtime).ok_or_else(|| {
            GatewayRejection::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "governance_incompatible",
                format!(
                    "gateway decision returned an unsupported runtime: {}",
                    admit.resolved_runtime
                ),
            )
        })?
    };
    if !client_provider.same_family(resolved_provider) && !config.allow_cross_provider {
        return Err(GatewayRejection::json(
            StatusCode::FORBIDDEN,
            "policy_denied",
            format!(
                "cross-provider routing from {} to {} is disabled",
                client_provider.runtime_name(),
                resolved_provider.runtime_name()
            ),
        ));
    }
    let canonical_model = if admit.metadata_operation {
        None
    } else {
        Some(
            registry_snapshot
                .resolve_model_for_provider(
                    &admit.resolved_model,
                    capability_provider_id(resolved_provider),
                )
                .map_err(|error| {
                    GatewayRejection::json(
                        StatusCode::BAD_REQUEST,
                        "capability_unsupported",
                        format!("gateway decision returned an invalid model: {error}"),
                    )
                })?
                .canonical_model,
        )
    };
    let resolved = PolicyPreflight {
        body,
        resolved_model: canonical_model,
        resolved_provider,
        route_bias: admit.route_bias.clone(),
        policy_scope: admit
            .policy_scope
            .clone()
            .or_else(|| Some(admit.budget_scope.clone())),
        policy_version: Some(admit.policy_version.clone()).filter(|v| !v.is_empty()),
        fallback_models: admit.fallback_models,
        data_class: admit.data_class,
        context_admission_policy_version: admit.context_admission_policy_version.clone(),
        context_admission_descriptor_version: admit.context_admission_descriptor_version.clone(),
        context_admission_decision: admit.context_admission_decision.clone(),
        context_admission_reasons: admit.context_admission_reasons.clone(),
    };
    if admit.provisional_local_free
        && resolved.resolved_provider != ProviderKind::OpenAi(OpenAiRuntime::Ollama)
    {
        return Err(GatewayRejection::json(
            StatusCode::TOO_MANY_REQUESTS,
            "budget_exceeded",
            "budget exceeded and local-free routing could not be verified",
        ));
    }
    let originally_resolved_model = resolved.resolved_model.clone();
    let resolved = select_healthy_policy_fallback(
        runtime,
        registry_snapshot,
        resolved,
        capability_surface,
        client_provider,
        config.allow_cross_provider,
        budget.provisional_local_free,
    )
    .await?;
    if resolved.resolved_model != originally_resolved_model {
        crate::obs::signals::record_fallback(
            crate::obs::labels::Subsystem::Gateway,
            crate::obs::labels::FallbackTrigger::ProviderUnhealthy,
        );
    }
    if !admit.metadata_operation
        && requested_model.is_some_and(|requested| requested != decision_model)
    {
        record_gateway_decision(
            config,
            identity,
            "gateway.model_rewrite",
            "model rewritten by Chisei policy",
            "rewritten",
            HashMap::from([
                (
                    "requested_model".to_string(),
                    requested_model.unwrap_or_default().to_string(),
                ),
                ("resolved_model".to_string(), decision_model.clone()),
                ("project".to_string(), identity.project.clone()),
            ]),
        )
        .await;
    }
    if eval_regressed {
        record_gateway_decision(
            config,
            identity,
            "gateway.eval_regression",
            if eval_regression_reason.is_empty() {
                "eval regression signal influenced gateway routing"
            } else {
                &eval_regression_reason
            },
            "routed",
            HashMap::from([
                (
                    "requested_model".to_string(),
                    requested_model.unwrap_or_default().to_string(),
                ),
                ("resolved_model".to_string(), decision_model),
                ("project".to_string(), identity.project.clone()),
            ]),
        )
        .await;
    }
    preflight_context.provider = resolved.resolved_provider;
    preflight_context.resolved_model = resolved.resolved_model.clone();
    preflight_context.route_bias = resolved.route_bias.clone();
    preflight_context.policy_scope = resolved.policy_scope.clone();
    preflight_context.policy_version = resolved.policy_version.clone();
    preflight_context.egress_applied = true;
    let egress = apply_context_egress(
        config,
        runtime,
        identity,
        client_provider,
        resolved.resolved_provider,
        &resolved.body,
        context_request,
        requested_model,
        resolved.resolved_model.as_deref(),
        request_id,
        work_unit_id,
    )
    .await?;
    Ok((resolved, egress, Some(budget)))
}
/// Request the canonical gateway governance decision.
///
/// Any denial, invalid response, or control-plane failure is returned as a
/// rejection so provider contact remains fail-closed.
#[allow(clippy::too_many_arguments)]
pub(super) async fn gateway_decision_preflight(
    config: &GatewayConfig,
    runtime: &GatewayRuntime,
    identity: &GatewayIdentity,
    preferred_runtime: &str,
    requested_model: &str,
    request_bytes: usize,
    work_unit: &str,
    task_class: &str,
    request_id: &str,
    route_override: Option<&str>,
    capability_requirements_json: Vec<u8>,
    model_metadata_request: bool,
    pipeline_spec: &str,
) -> Result<GatewayDecisionAdmit, GatewayRejection> {
    let Some(target) = &config.chisei_grpc_target else {
        return Err(GatewayRejection::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "governance_unavailable",
            "control-plane governance is not configured",
        ));
    };
    let namespace = if identity.project.trim().is_empty() {
        config.default_project.clone()
    } else {
        identity.project.clone()
    };
    let request = DecideGatewayExecutionRequest {
        contract_version: "gateway.decide/v2".into(),
        namespace: namespace.clone(),
        requested_model: requested_model.to_string(),
        operation_class: if model_metadata_request {
            "gateway.http.metadata"
        } else {
            "gateway.http"
        }
        .into(),
        estimated_cost_usd_micros: 0,
        correlation_operation_id: if request_id.trim().is_empty() {
            format!("gateway-{}", Utc::now().timestamp_millis())
        } else {
            request_id.to_string()
        },
        correlation_attempt: 1,
        estimated_tokens: estimate_tokens_from_bytes(request_bytes),
        task_class: task_class.to_string(),
        preferred_runtime: preferred_runtime.to_string(),
        project: namespace,
        agent: identity.agent.clone(),
        key_id: identity.key_id.clone(),
        work_unit: work_unit.to_string(),
        local_free_available: !config.ollama_base_url.trim().is_empty(),
        user_id: identity.user_id.clone(),
        route_override: route_override.unwrap_or_default().to_string(),
        capability_requirements_json,
        expected_calls: 1,
        pipeline_spec: pipeline_spec.to_string(),
    };
    match connect_governance(runtime, target).await {
        Ok(channel) => {
            let mut client = ChiseiServiceClient::new(channel);
            if runtime.usage_recovery.read().await.usage_recovery_saturated {
                return Err(GatewayRejection::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "governance_unavailable",
                    "budget usage reconciliation is saturated",
                ));
            }
            reconcile_pending_usage_records(runtime, &mut client)
                .await
                .map_err(|error| {
                    GatewayRejection::json(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "governance_unavailable",
                        format!("pending budget usage reconciliation failed: {error}"),
                    )
                })?;
            let mut request = gateway_request(request);
            if identity.can_delegate_principal()
                && let Ok(principal) =
                    tonic::metadata::MetadataValue::try_from(identity.delegated_principal())
            {
                request
                    .metadata_mut()
                    .insert(DELEGATED_PRINCIPAL_HEADER, principal);
            }
            match client.decide_gateway_execution(request).await {
                Ok(response) => {
                    record_control_plane_success(runtime).await;
                    let decision = response.into_inner();
                    if decision.contract_version != "gateway.decide/v2" {
                        return Err(GatewayRejection::json(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "governance_unavailable",
                            "control plane returned an incompatible gateway decision contract",
                        ));
                    }
                    if decision.admitted {
                        let route_bias = decision.route_bias.trim();
                        Ok(GatewayDecisionAdmit {
                            resolved_model: decision.resolved_model,
                            resolved_runtime: decision.resolved_runtime,
                            policy_version: decision.policy_version,
                            budget_scope: decision.budget_scope,
                            budget_grant_id: decision.budget_grant_id,
                            route_bias: (!route_bias.is_empty()).then(|| route_bias.to_string()),
                            provisional_local_free: decision.degradation_level == "local_free"
                                || route_bias == "local_free",
                            policy_scope: Some(decision.policy_scope)
                                .filter(|scope| !scope.is_empty()),
                            data_class: Some(decision.data_class).filter(|class| !class.is_empty()),
                            fallback_models: decision.fallback_models,
                            eval_regressed: decision.eval_regressed,
                            eval_regression_reason: decision.eval_regression_reason,
                            context_admission_policy_version: Some(
                                decision.context_admission_policy_version,
                            )
                            .filter(|value| !value.is_empty()),
                            context_admission_descriptor_version: Some(
                                decision.context_admission_descriptor_version,
                            )
                            .filter(|value| !value.is_empty()),
                            context_admission_decision: Some(decision.context_admission_decision)
                                .filter(|value| !value.is_empty()),
                            context_admission_reasons: decision.context_admission_reasons,
                            pipeline_observation: decision.sampling_evaluated.then_some({
                                GatewayPipelineObservation {
                                    sampled: decision.sampled,
                                    reason: decision.sample_reason,
                                    rate: decision.sample_rate,
                                    prepared_spec: decision.prepared_spec,
                                }
                            }),
                            metadata_operation: model_metadata_request,
                        })
                    } else {
                        let error_type = if decision.deny_reason.is_empty() {
                            "governance_denied"
                        } else {
                            decision.deny_reason.as_str()
                        };
                        let status = match error_type {
                            "budget_denied" => StatusCode::TOO_MANY_REQUESTS,
                            "invalid_request" | "capability_unsupported" => StatusCode::BAD_REQUEST,
                            _ => StatusCode::FORBIDDEN,
                        };
                        let public_error_type = if error_type == "budget_denied" {
                            "budget_exceeded"
                        } else {
                            error_type
                        };
                        if error_type == "budget_denied" {
                            record_gateway_decision(
                                config,
                                identity,
                                "gateway.budget_denied",
                                if decision.deny_message.is_empty() {
                                    "gateway budget denied"
                                } else {
                                    &decision.deny_message
                                },
                                "denied",
                                HashMap::from([(
                                    "budget_subject".to_string(),
                                    decision.budget_scope.clone(),
                                )]),
                            )
                            .await;
                        }
                        Err(GatewayRejection::json(
                            status,
                            public_error_type,
                            if decision.deny_message.is_empty() {
                                "gateway fat-decide denied".into()
                            } else {
                                decision.deny_message
                            },
                        ))
                    }
                }
                Err(err) => {
                    record_control_plane_failure(runtime, &err).await;
                    Err(governance_status_rejection(&err))
                }
            }
        }
        Err(err) => Err(GatewayRejection::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "governance_unavailable",
            format!("gateway decision control plane unavailable: {err}"),
        )),
    }
}
pub(super) async fn select_healthy_policy_fallback(
    runtime: &GatewayRuntime,
    registry: &ProviderRegistry,
    decision: PolicyPreflight,
    surface: Option<CapabilityRequestSurface>,
    client_provider: ProviderKind,
    allow_cross_provider: bool,
    local_free_only: bool,
) -> Result<PolicyPreflight, GatewayRejection> {
    let selected_key = capability_provider_id(decision.resolved_provider);
    let circuits = runtime.upstream_circuits.read().await;
    let selected_unhealthy = circuits
        .get(selected_key)
        .is_some_and(CircuitBreakerState::is_open);
    if !selected_unhealthy {
        return Ok(decision);
    }
    drop(circuits);
    match select_next_failover_candidate(
        runtime,
        registry,
        &decision,
        surface,
        client_provider,
        allow_cross_provider,
        local_free_only,
        &[],
    )
    .await
    {
        Ok(Some(next)) => Ok(next),
        Ok(None) => Err(GatewayRejection::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream_unavailable",
            format!(
                "provider {selected_key:?} is unhealthy and no policy-authorized capability and governance equivalent fallback is eligible"
            ),
        )
        .with_retry_safety("safe")),
        Err(rejection) => Err(rejection),
    }
}
/// Whether the client protocol can be prepared for the candidate provider.
///
/// Same-family is always adaptable. The only implemented cross-family adapter is
/// Anthropic Messages → OpenAI-compatible chat.
pub(super) fn client_can_dispatch_to_provider(client: ProviderKind, target: ProviderKind) -> bool {
    client == target
        || client.same_family(target)
        || (client == ProviderKind::Anthropic && target.is_openai())
}
/// Pick the next policy-authorized fallback, skipping open circuits and already-tried providers.
///
/// Used both for preflight health fallback and same-request mid-request failover after a live
/// upstream failure. Never crosses governance, capability, family (unless allowed), or local-free
/// boundaries. Also skips candidates the client protocol cannot adapt to, so preparation
/// failures do not terminate failover early.
#[allow(clippy::too_many_arguments)]
pub(super) async fn select_next_failover_candidate(
    runtime: &GatewayRuntime,
    registry: &ProviderRegistry,
    decision: &PolicyPreflight,
    surface: Option<CapabilityRequestSurface>,
    client_provider: ProviderKind,
    allow_cross_provider: bool,
    local_free_only: bool,
    excluded_provider_ids: &[&str],
) -> Result<Option<PolicyPreflight>, GatewayRejection> {
    let selected_key = capability_provider_id(decision.resolved_provider);
    let selected_profile = registry.effective_profile(selected_key).ok_or_else(|| {
        GatewayRejection::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream_unavailable",
            format!("selected provider {selected_key:?} has no effective profile"),
        )
        .with_retry_safety("safe")
    })?;
    let requirements = surface
        .map(|surface| match surface {
            CapabilityRequestSurface::Responses => {
                CapabilityRequirements::from_responses_body(&decision.body)
            }
            CapabilityRequestSurface::OpenAiChat => {
                CapabilityRequirements::from_openai_chat_body(&decision.body)
            }
            CapabilityRequestSurface::AnthropicMessages => {
                CapabilityRequirements::from_anthropic_messages_body(&decision.body)
            }
        })
        .transpose()
        .map_err(|reason| {
            GatewayRejection::json(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("cannot derive fallback requirements: {reason}"),
            )
        })?;
    let circuits = runtime.upstream_circuits.read().await;
    for candidate in &decision.fallback_models {
        let Ok(resolved) = registry.resolve_model(candidate) else {
            continue;
        };
        let Some(provider) = ProviderKind::from_runtime(&resolved.provider) else {
            continue;
        };
        let provider_id = capability_provider_id(provider);
        if excluded_provider_ids.contains(&provider_id) {
            continue;
        }
        if local_free_only && provider != ProviderKind::OpenAi(OpenAiRuntime::Ollama) {
            continue;
        }
        if !decision.resolved_provider.same_family(provider) && !allow_cross_provider {
            continue;
        }
        if !client_can_dispatch_to_provider(client_provider, provider) {
            continue;
        }
        if let Some(surface) = surface
            && enforce_adapter_capabilities(client_provider, provider, surface, &decision.body)
                .is_err()
        {
            continue;
        }
        if circuits
            .get(provider_id)
            .is_some_and(CircuitBreakerState::is_open)
        {
            continue;
        }
        let Some(profile) = registry.effective_profile(&resolved.provider) else {
            continue;
        };
        if profile.governance != selected_profile.governance
            || requirements
                .as_ref()
                .is_some_and(|required| !required.unsupported_by(&profile.capabilities).is_empty())
        {
            continue;
        }
        let mut next = decision.clone();
        next.body =
            rewrite_request_model(&decision.body, &resolved.canonical_model).map_err(|error| {
                GatewayRejection::json(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    format!("could not rewrite fallback model: {error}"),
                )
            })?;
        next.resolved_model = Some(resolved.canonical_model);
        next.resolved_provider = provider;
        next.route_bias = Some("health_fallback".into());
        return Ok(Some(next));
    }
    Ok(None)
}
pub(super) fn stable_recovery_key(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}
pub(super) async fn queue_pending_usage_records(
    runtime: &GatewayRuntime,
    requests: impl IntoIterator<Item = RecordUsageRequest>,
) -> bool {
    let _journal_guard = runtime.usage_recovery_lock.lock().await;
    let mut cache = runtime.usage_recovery.write().await;
    let mut accepted = true;
    for request in requests {
        let key = usage_recovery_key(&request);
        if cache.pending_usage_records.contains_key(&key) {
            continue;
        } else if cache.pending_usage_records.len() < MAX_PENDING_USAGE_RECOVERIES {
            cache.pending_usage_records.insert(key, request);
        } else {
            cache.usage_recovery_saturated = true;
            accepted = false;
        }
    }
    let snapshot = cache
        .pending_usage_records
        .values()
        .cloned()
        .map(PendingUsageRecovery::from)
        .collect::<Vec<_>>();
    drop(cache);
    if persist_pending_usage_records(runtime.usage_recovery_path.clone(), snapshot).await {
        accepted
    } else {
        runtime
            .usage_recovery
            .write()
            .await
            .usage_recovery_saturated = true;
        false
    }
}
pub(super) async fn persist_pending_usage_records(
    path: Option<PathBuf>,
    pending: Vec<PendingUsageRecovery>,
) -> bool {
    let Some(path) = path else {
        return true;
    };
    let Ok(bytes) = serde_json::to_vec(&pending) else {
        return false;
    };
    matches!(
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            use std::io::Write;
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let temporary = path.with_extension("tmp");
            let mut options = std::fs::OpenOptions::new();
            options.create(true).truncate(true).write(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(temporary, path)
        })
        .await,
        Ok(Ok(()))
    )
}
pub(super) fn usage_recovery_key(request: &RecordUsageRequest) -> String {
    if !request.idempotency_key.is_empty() {
        return request.idempotency_key.clone();
    }
    stable_recovery_key(&[
        "usage-recovery-v1",
        &request.subject,
        &request.project,
        &request.agent,
        &request.key_id,
        &request.work_unit,
        &request.user_id,
        &request.metric,
    ])
}
pub(super) async fn reconcile_pending_usage_records(
    runtime: &GatewayRuntime,
    client: &mut ChiseiServiceClient<GatewayClient>,
) -> Result<usize, tonic::Status> {
    let _journal_guard = runtime.usage_recovery_lock.lock().await;
    let pending = {
        let mut cache = runtime.usage_recovery.write().await;
        std::mem::take(&mut cache.pending_usage_records)
            .into_values()
            .collect::<Vec<_>>()
    };
    let mut reconciled = 0usize;
    for (index, request) in pending.iter().cloned().enumerate() {
        if let Err(status) = client.record_usage(gateway_request(request)).await {
            let mut cache = runtime.usage_recovery.write().await;
            for request in pending[index..].iter().cloned() {
                let key = usage_recovery_key(&request);
                cache.pending_usage_records.insert(key, request);
            }
            let snapshot = cache
                .pending_usage_records
                .values()
                .cloned()
                .map(PendingUsageRecovery::from)
                .collect();
            drop(cache);
            if !persist_pending_usage_records(runtime.usage_recovery_path.clone(), snapshot).await {
                runtime
                    .usage_recovery
                    .write()
                    .await
                    .usage_recovery_saturated = true;
            }
            return Err(status);
        }
        reconciled += 1;
    }
    if !persist_pending_usage_records(runtime.usage_recovery_path.clone(), Vec::new()).await {
        runtime
            .usage_recovery
            .write()
            .await
            .usage_recovery_saturated = true;
    }
    // Saturation means at least one usage event was not retained. It is
    // intentionally sticky: only operator reconciliation plus restart can
    // safely restore admissions without silently accepting an undercount.
    Ok(reconciled)
}
