use super::*;

pub(super) async fn proxy_gateway(
    State(state): State<GatewayState>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response<Body> {
    let span = tracing::info_span!("gateway.http", stage = "operation", otel.kind = "server",);
    crate::obs::otel::set_parent_from_headers(&span, &headers);

    // Keep the large operation future off the runtime stack before adding the
    // tracing wrapper; otherwise the default Tokio stack can overflow.
    Box::pin(
        async move {
            let identity_context = match resolve_identity(&headers, &state).await {
                Ok(identity) => identity,
                Err(err) => {
                    record_gateway_event(
                        &state.config,
                        "chisei-gateway",
                        "gateway.auth_failed",
                        err.reason(),
                        "denied",
                        err.evidence(&state.config),
                    )
                    .await;
                    let correlation = GatewayCorrelation::generated("unauthenticated");
                    let mut response = err.response();
                    correlation.apply_response_headers(&mut response);
                    return response;
                }
            };
            let correlation_scope = gateway_correlation_scope(&identity_context.identity);
            let correlation = match GatewayCorrelation::from_headers(&headers, &correlation_scope) {
                Ok(correlation) => correlation,
                Err(reason) => {
                    let correlation = GatewayCorrelation::generated(&correlation_scope);
                    let mut response =
                        json_error(StatusCode::BAD_REQUEST, "invalid_correlation", &reason);
                    correlation.apply_response_headers(&mut response);
                    return response;
                }
            };
            let mut response = proxy_gateway_inner(
                state,
                uri,
                method,
                headers,
                request,
                correlation.clone(),
                identity_context,
            )
            .await;
            correlation.apply_response_headers(&mut response);
            response
        }
        .instrument(span),
    )
    .await
}
pub(super) async fn proxy_gateway_inner(
    state: GatewayState,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    request: Request<Body>,
    correlation: GatewayCorrelation,
    identity_context: IdentityContext,
) -> Response<Body> {
    if identity_context.authenticated.principal.subject
        != identity_context.identity.context_principal()
    {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "validated identity context mismatch",
        );
    }
    let registry = match state.runtime.refresh_registry_snapshot(false).await {
        Ok(registry) => registry,
        Err(reason) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "provider_registry_unavailable",
                &reason,
            );
        }
    };
    let canary_requested = header_str(&headers, &X_CHISEI_ADMISSION) == Some("canary");
    if canary_requested && !canary_admission_allowed(&identity_context, &headers) {
        return json_error(
            StatusCode::FORBIDDEN,
            "policy_denied",
            "canary admission requires an operator-managed low-risk identity and an explicit bounded task class",
        );
    }
    let scoped = proxy_gateway_inner_scoped(
        state,
        uri,
        method,
        headers,
        request,
        correlation,
        identity_context,
    );
    crate::provider_profile::with_provider_registry_snapshot(registry, async move {
        if canary_requested {
            crate::provider_profile::with_canary_admission(scoped).await
        } else {
            scoped.await
        }
    })
    .await
}
pub(super) fn canary_admission_allowed(identity: &IdentityContext, headers: &HeaderMap) -> bool {
    identity.upstream_auth == UpstreamAuthMode::GatewayKey
        && identity.identity.tier == "low-risk"
        && header_str(headers, &X_CHISEI_TASK_CLASS)
            .is_some_and(crate::gateway_support::is_cheap_eligible_task_class)
}
pub(super) async fn proxy_gateway_inner_scoped(
    state: GatewayState,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    request: Request<Body>,
    correlation: GatewayCorrelation,
    identity_context: IdentityContext,
) -> Response<Body> {
    if uri.path() == "/v1/chisei/capabilities" {
        if method != Method::GET {
            return json_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "invalid_request_error",
                "provider capability matrix requires GET",
            );
        }
        let discovery = sekai_provider::model_availability::ModelDiscoveryConfig {
            openai_base_url: state.config.openai_base_url.clone(),
            openai_api_key: state.config.openai_api_key.clone(),
            anthropic_base_url: state.config.anthropic_base_url.clone(),
            anthropic_api_key: state.config.anthropic_api_key.clone(),
            ollama_url: state
                .config
                .ollama_base_url
                .trim_end_matches("/v1")
                .to_string(),
            native_configured: state.config.native_base_url.is_some(),
        };
        let availability =
            sekai_provider::model_availability::refresh_model_availability(&discovery, false).await;
        let mut response = json_response(
            StatusCode::OK,
            serde_json::to_value(CapabilityMatrix::public_discovery(availability))
                .expect("provider capability matrix is serializable"),
        );
        insert_header(
            response.headers_mut(),
            &X_CHISEI_CALLER_SCOPE,
            &correlation.caller_scope,
        );
        insert_header(
            response.headers_mut(),
            &X_CHISEI_CAPABILITY_CATALOG,
            CAPABILITY_MATRIX_VERSION,
        );
        return response;
    }
    if uri.path() == "/v1/chisei/models" {
        if method != Method::GET {
            return json_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "invalid_request_error",
                "available model discovery requires GET",
            );
        }
        let provider = uri.query().and_then(|query| {
            query
                .split('&')
                .find_map(|pair| pair.strip_prefix("provider="))
                .map(str::to_string)
        });
        let discovery = sekai_provider::model_availability::ModelDiscoveryConfig {
            openai_base_url: state.config.openai_base_url.clone(),
            openai_api_key: state.config.openai_api_key.clone(),
            anthropic_base_url: state.config.anthropic_base_url.clone(),
            anthropic_api_key: state.config.anthropic_api_key.clone(),
            ollama_url: state
                .config
                .ollama_base_url
                .trim_end_matches("/v1")
                .to_string(),
            native_configured: state.config.native_base_url.is_some(),
        };
        let availability =
            sekai_provider::model_availability::refresh_model_availability(&discovery, false).await;
        let mut response = json_response(
            StatusCode::OK,
            serde_json::to_value(availability.public_models(provider.as_deref()))
                .expect("available models view is serializable"),
        );
        insert_header(
            response.headers_mut(),
            &X_CHISEI_CALLER_SCOPE,
            &correlation.caller_scope,
        );
        return response;
    }
    let Some((mut client_provider, normalized_path)) = upstream_path(&uri) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "chisei-gateway currently supports /v1/responses, /v1/chat/completions, /v1/models, /v1/messages, and /v1/messages/count_tokens",
        );
    };
    if normalized_path.starts_with("/models") && headers.contains_key("anthropic-version") {
        client_provider = ProviderKind::Anthropic;
    }
    let responses_profile = normalized_path.starts_with("/responses");
    let responses_create = is_responses_create(&method, &normalized_path);
    if responses_profile && !responses_create {
        return json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Responses retrieval, cancellation, and deletion require caller-bound provider ownership and are not exposed by this gateway",
        );
    }
    let capability_surface = capability_request_surface(&method, &normalized_path);
    if let Err(reason) = validate_harness_request_headers(responses_profile, &headers) {
        return json_error(StatusCode::BAD_REQUEST, "capability_unsupported", &reason);
    }
    let identity = identity_context.identity;

    if let Some(subject) = rate_limit_rejection(&state.runtime, &identity).await {
        record_gateway_decision(
            &state.config,
            &identity,
            "gateway.rate_limited",
            "gateway request rate exceeded",
            "denied",
            HashMap::from([("rate_limit_subject".to_string(), subject)]),
        )
        .await;
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
            "gateway request rate exceeded",
        );
    }

    let body = match to_bytes(request.into_body(), state.runtime.max_request_bytes).await {
        Ok(body) => body,
        Err(err) => {
            let length_limited = err
                .source()
                .is_some_and(|source| source.is::<LengthLimitError>());
            let message = if length_limited {
                format!(
                    "request body exceeds the gateway limit of {} bytes",
                    state.runtime.max_request_bytes
                )
            } else {
                "failed to read request body".to_string()
            };
            return json_error(
                if length_limited {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                },
                "invalid_request_error",
                &message,
            );
        }
    };
    let (body, context_request) = match extract_gateway_context_request(&body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("invalid chisei_context: {err}"),
            );
        }
    };
    let request_bytes = body.len();
    let request_hash = format!("{:x}", Sha256::digest(&body));
    let requested_model = extract_request_model(&body);
    let route_override = match route_override_header(&headers) {
        Ok(value) => value,
        Err(reason) => {
            return json_error(StatusCode::BAD_REQUEST, "invalid_request_error", &reason);
        }
    };
    if route_override.is_some() && requested_model.is_none() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "x-chisei-route-override requires a request body model",
        );
    }
    let request_id = correlation.request_id.clone();
    let work_unit_id = gateway_work_unit_id(&headers).map(ToOwned::to_owned);
    let pipeline_spec = extract_gateway_pipeline_spec(&body);
    let cache_requested = prompt_cache_requested(&body);
    let started_ms = Utc::now().timestamp_millis();
    let task_class = resolve_task_class(&headers, requested_model.as_deref());
    let registry_snapshot = provider_registry_snapshot();
    let registry_snapshot_version = capability_snapshot_identifier(&registry_snapshot);
    let policy_model_sentinel = requested_model.as_deref() == Some("auto");
    let wire_provider_id = capability_provider_id(client_provider);
    let requested_provider_without_lifecycle = requested_model
        .as_deref()
        .filter(|_| !policy_model_sentinel)
        .and_then(|model| ProviderKind::from_model(model).ok())
        .unwrap_or(client_provider);
    let alias_context = early_refusal_context(
        &correlation,
        responses_profile,
        requested_provider_without_lifecycle,
        requested_model.clone(),
        work_unit_id.clone(),
        request_bytes,
        started_ms,
        task_class.clone(),
        request_hash.clone(),
        registry_snapshot_version.clone(),
    );
    let requested_registry_model = match requested_model
        .as_deref()
        .filter(|_| !policy_model_sentinel)
        .map(|model| registry_snapshot.resolve_model_for_provider(model, wire_provider_id))
        .transpose()
    {
        Ok(resolved) => resolved,
        Err(reason) => {
            let lifecycle_denial = requested_model.as_deref().is_some_and(|model| {
                registry_snapshot
                    .model_or_provider_is_unavailable_for_provider(model, wire_provider_id)
            });
            let rejection = GatewayRejection::json(
                if lifecycle_denial {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::BAD_REQUEST
                },
                if lifecycle_denial {
                    "policy_denied"
                } else {
                    "invalid_request_error"
                },
                format!("model resolution failed: {reason}"),
            );
            if lifecycle_denial {
                record_gateway_decision(
                    &state.config,
                    &identity,
                    "gateway.lifecycle_denied",
                    &rejection.reason,
                    "denied",
                    HashMap::from([("request_id".into(), request_id.clone())]),
                )
                .await;
            }
            return rejection.response();
        }
    };
    let requested_provider = requested_registry_model
        .as_ref()
        .and_then(|resolved| ProviderKind::from_model(&resolved.canonical_model).ok())
        .unwrap_or(client_provider);
    let requested_profile = requested_registry_model
        .as_ref()
        .and_then(|resolved| registry_snapshot.profile(&resolved.provider));
    let caller_data_class = header_str(&headers, &X_CHISEI_DATA_CLASS)
        .map(normalize_governance_label)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let mut preflight_context = UsageContext {
        request_id: request_id.clone(),
        // The client alias is not owned until durable reservation succeeds.
        // Pre-dispatch refusal receipts remain addressable by canonical request
        // and operation ids without consuming a retryable alias.
        lookup_request_id: None,
        caller_scope: correlation.caller_scope.clone(),
        operation_id: correlation.operation_id.clone(),
        parent_operation_id: correlation.parent_operation_id.clone(),
        turn_id: correlation.turn_id.clone(),
        attempt: correlation.attempt,
        provider_ordinal: 1,
        cycle_id: correlation.cycle_id.clone(),
        traceparent: correlation.traceparent.clone(),
        responses_profile,
        responses_terminal_required: responses_create,
        provider: requested_provider,
        requested_model: requested_model.clone(),
        resolved_model: None,
        route_override: route_override.clone(),
        requested_alias: requested_registry_model
            .as_ref()
            .and_then(|resolved| resolved.requested_alias.clone()),
        profile_version: requested_profile.map(|profile| profile.profile_version.clone()),
        capability_snapshot_version: Some(registry_snapshot_version.clone()),
        pricing_snapshot_version: effective_pricing_snapshot_version(
            &state.config,
            requested_profile,
            requested_registry_model
                .as_ref()
                .map(|model| model.canonical_model.as_str()),
            requested_model.as_deref(),
        ),
        governance_metadata_status: requested_profile
            .map(|profile| profile.governance.metadata_status.clone()),
        work_unit_id: work_unit_id.clone(),
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
        task_class: task_class.clone(),
        data_class: caller_data_class.clone(),
        request_hash: request_hash.clone(),
        budget_subject: None,
        budget_status: "not_evaluated".into(),
        egress_applied: false,
        cache_requested: false,
    };
    if !client_provider.same_family(requested_provider) && !state.config.allow_cross_provider {
        let rejection = GatewayRejection::json(
            StatusCode::FORBIDDEN,
            "policy_denied",
            format!(
                "cross-provider routing from {} to {} is disabled",
                client_provider.runtime_name(),
                requested_provider.runtime_name()
            ),
        );
        record_refusal_and_append(
            &state.config,
            &state.runtime,
            &identity,
            &preflight_context,
            &rejection,
        )
        .await;
        return rejection.response();
    }
    // A configured gateway has one canonical governance boundary:
    // DecideGatewayExecution. Any denial or unavailable decision returns
    // before provider contact.
    let model_metadata_path = matches!(uri.path(), "/v1/models" | "/models")
        || uri.path().starts_with("/v1/models/")
        || uri.path().starts_with("/models/");
    let model_metadata_request =
        matches!(method, Method::GET | Method::HEAD) && model_metadata_path && body.is_empty();
    let capability_requirements_json = capability_surface
        .map(|surface| match surface {
            CapabilityRequestSurface::Responses => {
                CapabilityRequirements::from_responses_body(&body)
            }
            CapabilityRequestSurface::OpenAiChat => {
                CapabilityRequirements::from_openai_chat_body(&body)
            }
            CapabilityRequestSurface::AnthropicMessages => {
                CapabilityRequirements::from_anthropic_messages_body(&body)
            }
        })
        .transpose()
        .map_err(|reason| {
            GatewayRejection::json(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("cannot derive request capabilities: {reason}"),
            )
        });
    let capability_requirements_json = match capability_requirements_json {
        Ok(requirements) => requirements
            .as_ref()
            .map(|requirements| {
                serde_json::to_vec(requirements).expect("capability requirements are serializable")
            })
            .unwrap_or_default(),
        Err(rejection) => {
            record_refusal_and_append(
                &state.config,
                &state.runtime,
                &identity,
                &preflight_context,
                &rejection,
            )
            .await;
            return rejection.response();
        }
    };
    let preferred_runtime = requested_registry_model
        .as_ref()
        .map(|model| model.provider.as_str())
        .unwrap_or_else(|| capability_provider_id(requested_provider));
    let preferred_model = requested_registry_model
        .as_ref()
        .map(|model| model.canonical_model.as_str())
        .or(requested_model.as_deref())
        .unwrap_or("");
    let gateway_admit = match gateway_decision_preflight(
        &state.config,
        &state.runtime,
        &identity,
        preferred_runtime,
        preferred_model,
        request_bytes,
        work_unit_id.as_deref().unwrap_or(""),
        &task_class,
        &request_id,
        route_override.as_deref(),
        capability_requirements_json,
        model_metadata_request,
        &pipeline_spec,
    )
    .await
    {
        Ok(admit) => admit,
        Err(rejection) => {
            record_refusal_and_append(
                &state.config,
                &state.runtime,
                &identity,
                &preflight_context,
                &rejection,
            )
            .await;
            return rejection.response();
        }
    };
    let (mut resolved, mut egress, budget) = match apply_gateway_decision(
        &state.config,
        &state.runtime,
        &identity,
        &mut preflight_context,
        &registry_snapshot,
        gateway_admit,
        body.to_vec(),
        requested_provider,
        client_provider,
        capability_surface,
        context_request.as_ref(),
        requested_model.as_deref(),
        &request_id,
        work_unit_id.as_deref(),
    )
    .await
    {
        Ok(triple) => triple,
        Err(rejection) => {
            record_refusal_and_append(
                &state.config,
                &state.runtime,
                &identity,
                &preflight_context,
                &rejection,
            )
            .await;
            return rejection.response();
        }
    };
    let classification_exempt_metadata_request = model_metadata_request && uri.query().is_none();
    if caller_data_class == "sensitive"
        && !classification_exempt_metadata_request
        && resolved.data_class.as_deref() != Some("sensitive")
    {
        let rejection = GatewayRejection::json(
            StatusCode::FORBIDDEN,
            "data_class_conflict",
            "request data classification is stricter than the resolved namespace policy",
        );
        record_refusal_and_append(
            &state.config,
            &state.runtime,
            &identity,
            &preflight_context,
            &rejection,
        )
        .await;
        return rejection.response();
    }
    if responses_create {
        egress.body = match normalize_responses_request(&egress.body) {
            Ok(body) => body,
            Err(reason) => {
                let rejection = GatewayRejection::json(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    reason,
                );
                record_refusal_and_append(
                    &state.config,
                    &state.runtime,
                    &identity,
                    &preflight_context,
                    &rejection,
                )
                .await;
                return rejection.response();
            }
        };
    }
    let resolved_registry_model = resolved.resolved_model.as_deref().or_else(|| {
        requested_registry_model
            .as_ref()
            .map(|model| model.canonical_model.as_str())
    });
    let mut contact_requirements = None;
    if let Some(surface) = capability_surface {
        let enforcement = enforce_provider_capabilities(
            resolved.resolved_provider,
            resolved_registry_model,
            surface,
            &egress.body,
        )
        .and_then(|requirements| {
            enforce_adapter_capabilities(
                client_provider,
                resolved.resolved_provider,
                surface,
                &egress.body,
            )?;
            Ok(requirements)
        });
        match enforcement {
            Ok(requirements) => contact_requirements = Some(requirements),
            Err(rejection) => {
                record_gateway_decision(
                    &state.config,
                    &identity,
                    "gateway.capability_denied",
                    &rejection.reason,
                    "denied",
                    HashMap::from([
                        (
                            "provider".into(),
                            capability_provider_id(resolved.resolved_provider).into(),
                        ),
                        ("request_id".into(), request_id.clone()),
                    ]),
                )
                .await;
                record_refusal_and_append(
                    &state.config,
                    &state.runtime,
                    &identity,
                    &preflight_context,
                    &rejection,
                )
                .await;
                return rejection.response();
            }
        }
    }
    let local_free_only = budget
        .as_ref()
        .is_some_and(|budget| budget.provisional_local_free);
    // Governed egress + Responses normalization applied once; mid-request
    // failover only rewrites the model field onto this baseline.
    let egress_baseline = egress.body;

    // First-attempt preparation is fallible and must complete before the alias
    // is reserved/claimed so preparation failures do not strand dispatch.
    let mut prepared = {
        let resolved_registry_metadata = resolved
            .resolved_model
            .as_deref()
            .and_then(|model| registry_snapshot.resolve_model(model).ok());
        match prepare_upstream_request(
            &state.config,
            &identity,
            &uri,
            client_provider,
            resolved.resolved_provider,
            egress_baseline.clone(),
            resolved_registry_metadata.as_ref(),
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(response) => return response,
        }
    };
    let mut contact_guard = {
        let resolved_registry_model = resolved.resolved_model.as_deref().or_else(|| {
            requested_registry_model
                .as_ref()
                .map(|model| model.canonical_model.as_str())
        });
        ProviderContactGuard {
            provider: resolved.resolved_provider,
            resolved_model: resolved_registry_model.map(str::to_string),
            requirements: contact_requirements.clone(),
        }
    };

    // First-attempt auth and header assembly are fallible (e.g. missing provider
    // credentials) and must finish before the alias is claimed, or a retry of the
    // same request id would be rejected as already dispatched.
    let build_upstream = |prepared: &PreparedUpstreamRequest| -> Result<
        reqwest::RequestBuilder,
        Box<Response<Body>>,
    > {
            let upstream_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
                Ok(method) => method,
                Err(err) => {
                    return Err(Box::new(json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request_error",
                        &format!("unsupported method: {err}"),
                    )));
                }
            };
            let mut upstream = state
                .client
                .request(upstream_method, prepared.url.clone())
                .body(prepared.body.clone());
            let upstream_auth_mode = upstream_auth_mode(
                &state.config,
                identity_context.upstream_auth,
                prepared.provider,
            );
            let resolved_to_isolated_openai_backend = matches!(
                prepared.provider,
                ProviderKind::OpenAi(
                    OpenAiRuntime::Ollama
                        | OpenAiRuntime::Native
                        | OpenAiRuntime::Xai
                        | OpenAiRuntime::Meta
                )
            );
            if prepared.cross_provider
                || resolved_to_isolated_openai_backend
                || upstream_auth_mode == UpstreamAuthMode::GatewayKey
            {
                upstream = match apply_provider_auth(upstream, &state.config, prepared.provider) {
                    Ok(upstream) => upstream,
                    Err(response) => return Err(response),
                };
            }
            for (name, value) in headers.iter() {
                let strip_client_auth = should_strip_isolated_client_credential(
                    name,
                    prepared.cross_provider || resolved_to_isolated_openai_backend,
                );
                if should_forward_request_header(name, upstream_auth_mode) && !strip_client_auth {
                    upstream = upstream.header(name, value);
                }
            }
            Ok(upstream)
        };

    let mut upstream = match build_upstream(&prepared) {
        Ok(upstream) => upstream,
        Err(response) => return *response,
    };

    // Atomically bind the opaque alias and claim its one provider dispatch only
    // after every fallible pre-dispatch step has completed.
    let dispatch_token = uuid::Uuid::new_v4().to_string();
    if let Err(error) = claim_gateway_dispatch(&state.config, &alias_context, &dispatch_token).await
    {
        return alias_reservation_error_response(error);
    }

    let mut tried_provider_ids: Vec<String> =
        vec![capability_provider_id(resolved.resolved_provider).into()];
    let mut provider_attempt: u32 = 1;
    let mut usage_context = {
        let resolved_registry_metadata = resolved
            .resolved_model
            .as_deref()
            .and_then(|model| registry_snapshot.resolve_model(model).ok());
        let resolved_profile = resolved_registry_metadata
            .as_ref()
            .and_then(|resolved| registry_snapshot.profile(&resolved.provider));
        let automatic_cache_requested = automatic_cache_attempted(resolved_profile, &prepared.body);
        UsageContext {
            request_id,
            lookup_request_id: correlation.lookup_request_id,
            caller_scope: correlation.caller_scope,
            operation_id: correlation.operation_id,
            parent_operation_id: correlation.parent_operation_id,
            turn_id: correlation.turn_id,
            attempt: correlation.attempt,
            provider_ordinal: 1,
            cycle_id: correlation.cycle_id,
            traceparent: correlation.traceparent,
            responses_profile,
            responses_terminal_required: responses_create,
            provider: prepared.provider,
            requested_model: requested_model.clone(),
            resolved_model: resolved.resolved_model.clone(),
            route_override: route_override.clone(),
            requested_alias: requested_registry_model
                .as_ref()
                .and_then(|resolved| resolved.requested_alias.clone()),
            profile_version: resolved_profile.map(|profile| profile.profile_version.clone()),
            capability_snapshot_version: Some(registry_snapshot_version.clone()),
            pricing_snapshot_version: effective_pricing_snapshot_version(
                &state.config,
                resolved_profile,
                resolved.resolved_model.as_deref(),
                requested_model.as_deref(),
            ),
            governance_metadata_status: resolved_profile
                .map(|profile| profile.governance.metadata_status.clone()),
            work_unit_id,
            pipeline_observation: preflight_context.pipeline_observation,
            request_bytes,
            started_ms,
            route_bias: resolved.route_bias.clone(),
            policy_scope: resolved.policy_scope.clone(),
            policy_version: resolved.policy_version.clone(),
            context_admission_policy_version: resolved.context_admission_policy_version.clone(),
            context_admission_descriptor_version: resolved
                .context_admission_descriptor_version
                .clone(),
            context_admission_decision: resolved.context_admission_decision.clone(),
            context_admission_reasons: resolved.context_admission_reasons.clone(),
            task_class,
            data_class: effective_data_class(&caller_data_class, resolved.data_class.as_deref()),
            request_hash,
            budget_subject: budget
                .as_ref()
                .and_then(|budget| budget.budget_subject.clone()),
            budget_status: budget
                .as_ref()
                .map(|budget| {
                    if budget.provisional_local_free {
                        "local_free"
                    } else {
                        "allowed"
                    }
                })
                .unwrap_or("not_evaluated")
                .into(),
            egress_applied: true,
            cache_requested: cache_requested || automatic_cache_requested,
        }
    };

    loop {
        let send_result = send_upstream_with_resilience(
            &state.runtime,
            prepared.provider,
            upstream,
            &contact_guard,
        )
        .await;

        // Mid-request failover only when the first provider never received work:
        // open circuit (pre-send) or connect failure. HTTP error statuses and
        // ambiguous transport losses are not replayed to another provider.
        let failover_rejection = match &send_result {
            Err(UpstreamSendError::CircuitOpen { health }) => {
                let error_type = match health {
                    ProviderHealth::RateLimited => "upstream_rate_limited",
                    ProviderHealth::QuotaExhausted => "upstream_quota_exhausted",
                    _ => "upstream_unavailable",
                };
                let rejection = GatewayRejection::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    error_type,
                    format!(
                        "{} upstream is temporarily in {:?} health state",
                        prepared.provider.runtime_name(),
                        health
                    ),
                )
                .with_retry_safety("safe");
                Some(rejection)
            }
            Err(UpstreamSendError::Request { error: err, .. }) if err.is_connect() => {
                let rejection = GatewayRejection::json(
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    safe_upstream_error_reason(prepared.provider, "request", err),
                )
                .with_retry_safety("safe");
                Some(rejection)
            }
            _ => None,
        };

        if let Some(rejection) = failover_rejection {
            let excluded: Vec<&str> = tried_provider_ids.iter().map(String::as_str).collect();
            let next_ordinal = usage_context.provider_ordinal.checked_add(1);
            let next = if provider_attempt < MAX_MID_REQUEST_PROVIDER_ATTEMPTS
                && next_ordinal.is_some()
                && !resolved.fallback_models.is_empty()
            {
                select_next_failover_candidate(
                    &state.runtime,
                    &registry_snapshot,
                    &resolved,
                    capability_surface,
                    client_provider,
                    state.config.allow_cross_provider,
                    local_free_only,
                    &excluded,
                )
                .await
                .unwrap_or(None)
            } else {
                None
            };
            if let (Some(next_decision), Some(next_ordinal)) = (next, next_ordinal) {
                if let Err(UpstreamSendError::Request {
                    snapshot_version, ..
                }) = &send_result
                {
                    usage_context.capability_snapshot_version = Some(snapshot_version.clone());
                }
                let failed_route = resolved.resolved_model.clone().unwrap_or_default();
                let model_attempted =
                    !matches!(&send_result, Err(UpstreamSendError::CircuitOpen { .. }));
                // Prepare a usable failover candidate first. Only then persist the
                // failed-attempt receipt and failover decision — otherwise a chain
                // of unusable candidates would double-record the original failure.
                resolved = next_decision;
                tried_provider_ids.push(capability_provider_id(resolved.resolved_provider).into());

                // Re-prepare after claim. Skip operationally unusable candidates
                // (missing endpoint, rewrite failure) and keep searching so a
                // later configured fallback still runs.
                let mut prepared_failover = false;
                while !prepared_failover {
                    let resolved_registry_metadata = resolved
                        .resolved_model
                        .as_deref()
                        .and_then(|model| registry_snapshot.resolve_model(model).ok());
                    let attempt_body = match resolved.resolved_model.as_deref() {
                        Some(model) => match rewrite_request_model(&egress_baseline, model) {
                            Ok(body) => body,
                            Err(_) => {
                                let excluded: Vec<&str> =
                                    tried_provider_ids.iter().map(String::as_str).collect();
                                match select_next_failover_candidate(
                                    &state.runtime,
                                    &registry_snapshot,
                                    &resolved,
                                    capability_surface,
                                    client_provider,
                                    state.config.allow_cross_provider,
                                    local_free_only,
                                    &excluded,
                                )
                                .await
                                .unwrap_or(None)
                                {
                                    Some(more) => {
                                        resolved = more;
                                        tried_provider_ids.push(
                                            capability_provider_id(resolved.resolved_provider)
                                                .into(),
                                        );
                                        continue;
                                    }
                                    None => break,
                                }
                            }
                        },
                        None => egress_baseline.clone(),
                    };
                    match prepare_upstream_request(
                        &state.config,
                        &identity,
                        &uri,
                        client_provider,
                        resolved.resolved_provider,
                        attempt_body,
                        resolved_registry_metadata.as_ref(),
                    )
                    .await
                    {
                        Ok(next_prepared) => {
                            prepared = next_prepared;
                            prepared_failover = true;
                        }
                        Err(_) => {
                            let excluded: Vec<&str> =
                                tried_provider_ids.iter().map(String::as_str).collect();
                            match select_next_failover_candidate(
                                &state.runtime,
                                &registry_snapshot,
                                &resolved,
                                capability_surface,
                                client_provider,
                                state.config.allow_cross_provider,
                                local_free_only,
                                &excluded,
                            )
                            .await
                            .unwrap_or(None)
                            {
                                Some(more) => {
                                    resolved = more;
                                    tried_provider_ids.push(
                                        capability_provider_id(resolved.resolved_provider).into(),
                                    );
                                }
                                None => break,
                            }
                        }
                    }
                }
                if !prepared_failover {
                    // Fall through to surface the original send_result failure once.
                } else {
                    record_refusal_with_usage_and_append(
                        &state.config,
                        &state.runtime,
                        &identity,
                        &usage_context,
                        &rejection,
                        None,
                        model_attempted,
                    )
                    .await;
                    crate::obs::signals::record_fallback(
                        crate::obs::labels::Subsystem::Gateway,
                        crate::obs::labels::FallbackTrigger::ProviderUnhealthy,
                    );
                    record_gateway_decision(
                        &state.config,
                        &identity,
                        "gateway.mid_request_failover",
                        "policy-authorized equivalent fallback selected after live upstream failure",
                        "routed",
                        HashMap::from([
                            ("failed_route".into(), failed_route),
                            (
                                "fallback_route".into(),
                                resolved.resolved_model.clone().unwrap_or_default(),
                            ),
                            ("attempt".into(), usage_context.attempt.to_string()),
                            (
                                "provider_ordinal".into(),
                                usage_context.provider_ordinal.to_string(),
                            ),
                        ]),
                    )
                    .await;
                    usage_context.provider_ordinal = next_ordinal;
                    provider_attempt = provider_attempt.saturating_add(1);
                    let resolved_registry_model =
                        resolved.resolved_model.as_deref().or_else(|| {
                            requested_registry_model
                                .as_ref()
                                .map(|model| model.canonical_model.as_str())
                        });
                    contact_guard = ProviderContactGuard {
                        provider: resolved.resolved_provider,
                        resolved_model: resolved_registry_model.map(str::to_string),
                        requirements: contact_requirements.clone(),
                    };
                    let resolved_registry_metadata = resolved
                        .resolved_model
                        .as_deref()
                        .and_then(|model| registry_snapshot.resolve_model(model).ok());
                    let resolved_profile = resolved_registry_metadata
                        .as_ref()
                        .and_then(|resolved| registry_snapshot.profile(&resolved.provider));
                    usage_context.provider = prepared.provider;
                    usage_context.resolved_model = resolved.resolved_model.clone();
                    usage_context.route_bias = resolved.route_bias.clone();
                    usage_context.policy_scope = resolved.policy_scope.clone();
                    usage_context.policy_version = resolved.policy_version.clone();
                    usage_context.profile_version =
                        resolved_profile.map(|profile| profile.profile_version.clone());
                    usage_context.pricing_snapshot_version = effective_pricing_snapshot_version(
                        &state.config,
                        resolved_profile,
                        resolved.resolved_model.as_deref(),
                        requested_model.as_deref(),
                    );
                    usage_context.governance_metadata_status =
                        resolved_profile.map(|profile| profile.governance.metadata_status.clone());
                    usage_context.cache_requested = cache_requested
                        || automatic_cache_attempted(resolved_profile, &prepared.body);
                    // Rebuild authenticated request for the failover candidate.
                    // Auth failure after claim is rare (credentials are gateway-side);
                    // surface the original failure if the rebuild cannot proceed.
                    match build_upstream(&prepared) {
                        Ok(next_upstream) => {
                            upstream = next_upstream;
                            continue;
                        }
                        Err(_) => {
                            // Fall through to original send_result.
                        }
                    }
                }
            }
            // No further candidate: surface the original outcome.
        }

        return match send_result {
            Ok((resp, contact_snapshot_version)) => {
                usage_context.capability_snapshot_version = Some(contact_snapshot_version);
                response_from_upstream(
                    resp,
                    &state.config,
                    &state.runtime,
                    &identity,
                    usage_context,
                    prepared.response_adapter,
                    prepared.client_response_model,
                )
                .await
            }
            Err(UpstreamSendError::Governance {
                rejection,
                snapshot_version,
                model_attempted,
            }) => {
                usage_context.capability_snapshot_version = Some(snapshot_version);
                let action = match rejection.error_type.as_str() {
                    "capability_unsupported" => "gateway.capability_denied",
                    "provider_registry_unavailable" => "gateway.provider_registry_unavailable",
                    _ => "gateway.lifecycle_denied",
                };
                record_gateway_decision(
                    &state.config,
                    &identity,
                    action,
                    &rejection.reason,
                    "denied",
                    HashMap::from([("request_id".into(), usage_context.request_id.clone())]),
                )
                .await;
                record_refusal_with_usage_and_append(
                    &state.config,
                    &state.runtime,
                    &identity,
                    &usage_context,
                    &rejection,
                    None,
                    model_attempted,
                )
                .await;
                rejection.response()
            }
            Err(UpstreamSendError::CircuitOpen { health }) => {
                let error_type = match health {
                    ProviderHealth::RateLimited => "upstream_rate_limited",
                    ProviderHealth::QuotaExhausted => "upstream_quota_exhausted",
                    _ => "upstream_unavailable",
                };
                let rejection = GatewayRejection {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    error_type: error_type.into(),
                    reason: format!(
                        "{} upstream is temporarily in {:?} health state",
                        prepared.provider.runtime_name(),
                        health
                    ),
                    retry_safety: Some("safe"),
                };
                record_refusal_with_usage_and_append(
                    &state.config,
                    &state.runtime,
                    &identity,
                    &usage_context,
                    &rejection,
                    None,
                    false,
                )
                .await;
                json_error_with_retry_safety(
                    rejection.status,
                    &rejection.error_type,
                    &rejection.reason,
                    "safe",
                )
            }
            Err(UpstreamSendError::Request {
                error: err,
                snapshot_version,
            }) => {
                usage_context.capability_snapshot_version = Some(snapshot_version);
                let retry_safety = if err.is_connect() {
                    "safe"
                } else {
                    "ambiguous"
                };
                let rejection = GatewayRejection {
                    status: StatusCode::BAD_GATEWAY,
                    error_type: "upstream_error".into(),
                    reason: safe_upstream_error_reason(prepared.provider, "request", &err),
                    retry_safety: Some(retry_safety),
                };
                record_refusal_with_usage_and_append(
                    &state.config,
                    &state.runtime,
                    &identity,
                    &usage_context,
                    &rejection,
                    None,
                    true,
                )
                .await;
                json_error_with_retry_safety(
                    rejection.status,
                    &rejection.error_type,
                    &rejection.reason,
                    retry_safety,
                )
            }
        };
    }
}
