use super::*;

pub(super) fn validate_gateway_security(
    bind_addr: SocketAddr,
    gateway_keys: &HashMap<String, GatewayIdentity>,
    allow_auth_passthrough: bool,
    admin_token: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !gateway_keys.is_empty() {
        return Err(format!(
            "GATEWAY_KEYS cannot be combined with {POLICY_PATH_ENV}; name principals and keys in the policy"
        )
        .into());
    }
    if let Some(token) = admin_token.map(str::trim).filter(|token| !token.is_empty())
        && (token == "change-me" || token.len() < MIN_ADMIN_TOKEN_BYTES)
    {
        return Err(format!(
            "CHISEI_GATEWAY_ADMIN_TOKEN must contain at least {MIN_ADMIN_TOKEN_BYTES} bytes and must not use a documented placeholder"
        )
        .into());
    }

    if !bind_addr.ip().is_loopback() && allow_auth_passthrough {
        return Err(
            "CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH cannot be used on an exposed gateway".into(),
        );
    }
    Ok(())
}
pub(super) fn normalize_governance_label(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '_'], "-")
}
pub(super) fn effective_data_class(caller: &str, resolved: Option<&str>) -> String {
    if caller.eq_ignore_ascii_case("sensitive")
        || resolved.is_some_and(|value| value.eq_ignore_ascii_case("sensitive"))
    {
        "sensitive".to_string()
    } else {
        resolved
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(caller)
            .to_string()
    }
}
pub(super) fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
pub(super) fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
pub(super) fn positive_env(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
}
pub fn app(config: GatewayConfig) -> Router {
    app_with_runtime(config, GatewayRuntime::from_env())
}
pub(super) fn app_with_runtime(config: GatewayConfig, runtime: GatewayRuntime) -> Router {
    let state = GatewayState {
        client: runtime.http_timeouts.gateway_client(),
        config: Arc::new(config),
        runtime,
    };

    let routes = [
        (
            COMMUNITY_GATEWAY_ROUTES[0],
            axum::routing::get(gateway_health),
        ),
        (
            COMMUNITY_GATEWAY_ROUTES[1],
            axum::routing::get(gateway_readiness),
        ),
        (
            COMMUNITY_GATEWAY_ROUTES[2],
            axum::routing::get(gateway_status),
        ),
        (COMMUNITY_GATEWAY_ROUTES[3], post(refresh_gateway_admin)),
        (
            COMMUNITY_GATEWAY_ROUTES[4],
            axum::routing::get(published_policy),
        ),
        (
            COMMUNITY_GATEWAY_ROUTES[5],
            axum::routing::get(read_egress_log),
        ),
        (COMMUNITY_GATEWAY_ROUTES[6], post(acknowledge_egress_log)),
        (COMMUNITY_GATEWAY_ROUTES[7], any(proxy_gateway)),
    ];
    routes
        .into_iter()
        .fold(Router::new(), |router, (path, method)| {
            router.route(path, method)
        })
        .with_state(state)
}
pub(super) async fn gateway_health() -> Response<Body> {
    json_response(StatusCode::OK, serde_json::json!({"status": "healthy"}))
}
pub(super) async fn gateway_status(State(state): State<GatewayState>) -> Response<Body> {
    let provider_health = {
        let mut circuits = state.runtime.upstream_circuits.write().await;
        circuits
            .iter_mut()
            .map(|(provider, circuit)| {
                let open = circuit.observe(provider);
                serde_json::json!({
                    "provider": provider,
                    "health": circuit.health,
                    "circuit_open": open,
                    "consecutive_failures": circuit.consecutive_failures,
                })
            })
            .collect::<Vec<_>>()
    };
    let provider_circuit_open = provider_health
        .iter()
        .any(|provider| provider["circuit_open"] == true);
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "status": if provider_circuit_open { "degraded" } else { "live" },
            "provider_health": provider_health
        }),
    )
}
pub(super) async fn gateway_readiness(State(state): State<GatewayState>) -> Response<Body> {
    if let Err(reason) = state.runtime.refresh_registry_snapshot(true).await {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "status": "not_ready",
                "reason": "provider_registry_unavailable",
                "detail": reason
            }),
        );
    }
    if let Some(policy) = &state.runtime.policy {
        let (status, body) = policy.readiness();
        // A failing log denies every request, so the gateway cannot do work.
        if let Some(error) = state
            .runtime
            .egress_log
            .as_ref()
            .and_then(EgressLog::last_error)
        {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({
                    "status": "not_ready",
                    "reason": "log_unavailable",
                    "detail": error,
                }),
            );
        }
        return json_response(status, body);
    }
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        serde_json::json!({
            "status": "not_ready",
            "reason": "no_valid_policy"
        }),
    )
}
pub async fn serve(config: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut runtime = GatewayRuntime::from_env();
    // Policy mode records every admission before provider contact, so it does
    // not start without its log.
    if let Some(policy_path) = policy_path_from_env() {
        runtime.egress_log =
            Some(EgressLog::open(&log_dir_from_env(&policy_path)).map_err(std::io::Error::other)?);
    }
    if let Some(state_path) = runtime.provider_registry_state_path.as_deref() {
        validate_provider_registry_storage(state_path).map_err(std::io::Error::other)?;
        refresh_provider_registry(state_path).map_err(std::io::Error::other)?;
    }
    validate_gateway_security(
        config.bind_addr,
        &config.gateway_keys,
        config.allow_auth_passthrough,
        runtime.admin_token.as_deref(),
    )?;
    if let Some(policy) = &runtime.policy {
        policy.spawn_watcher();
    }
    let bind_addr = config.bind_addr;
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!(addr = %bind_addr, "chisei-gateway listening");
    axum::serve(listener, app_with_runtime(config, runtime)).await?;
    Ok(())
}
pub(super) async fn refresh_gateway_admin(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response<Body> {
    if state.runtime.admin_token.is_none() {
        return json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "chisei gateway admin endpoint is disabled",
        );
    }
    if !admin_authorized(&headers, &state.runtime) {
        record_gateway_event(
            &state.config,
            "chisei-gateway-admin",
            "gateway.admin_refresh",
            "invalid admin credential",
            "denied",
            HashMap::new(),
        )
        .await;
        return json_error(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "invalid chisei gateway admin token",
        );
    }
    let mut key_cache = state.runtime.key_cache.write().await;
    let cleared_entries = key_cache.len();
    key_cache.clear();
    drop(key_cache);
    record_gateway_event(
        &state.config,
        "chisei-gateway-admin",
        "gateway.admin_refresh",
        "gateway key cache refreshed",
        "allowed",
        HashMap::from([(
            "cleared_key_cache_entries".to_string(),
            cleared_entries.to_string(),
        )]),
    )
    .await;
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "refreshed": true,
            "cleared_key_cache_entries": cleared_entries,
        }),
    )
}
pub(super) fn admin_authorized(headers: &HeaderMap, runtime: &GatewayRuntime) -> bool {
    let Some(expected) = runtime.admin_token.as_deref() else {
        return false;
    };
    let Some(token) = client_key(headers) else {
        return false;
    };
    expected.as_bytes().ct_eq(token.as_bytes()).into()
}
/// Receipt identity for a client attempt, optionally qualified by an internal
/// mid-request provider ordinal so failover dispatches do not collide with the
/// client-controlled `x-chisei-attempt` namespace.
pub(super) fn gateway_provider_receipt_id(
    operation_id: &str,
    request_id: &str,
    attempt: u32,
    provider_ordinal: u32,
) -> String {
    let mut digest = Sha256::new();
    digest.update((operation_id.len() as u64).to_be_bytes());
    digest.update(operation_id.as_bytes());
    digest.update((request_id.len() as u64).to_be_bytes());
    digest.update(request_id.as_bytes());
    if provider_ordinal <= 1 {
        format!(
            "{operation_id}:__attempt__:{:x}:{attempt}",
            digest.finalize()
        )
    } else {
        format!(
            "{operation_id}:__attempt__:{:x}:{attempt}:p{provider_ordinal}",
            digest.finalize()
        )
    }
}
pub(super) fn gateway_correlation_scope(identity: &GatewayIdentity) -> String {
    let digest = Sha256::digest(
        [
            identity.agent.as_str(),
            identity.project.as_str(),
            identity.user_id.as_str(),
            identity.key_id.as_str(),
        ]
        .join("\0")
        .as_bytes(),
    );
    format!("{digest:x}")[..16].to_string()
}
pub(super) fn scoped_request_id(value: &str, caller_scope: &str) -> String {
    let mut digest = Sha256::new();
    digest.update((caller_scope.len() as u64).to_be_bytes());
    digest.update(caller_scope.as_bytes());
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
    format!("chisei:{caller_scope}:request:{:x}", digest.finalize())
}
pub(super) fn scoped_operation_id(value: &str, caller_scope: &str) -> Result<String, String> {
    const RESERVED_ATTEMPT_SEGMENT: &str = "__attempt__:";
    let prefix = format!("chisei:{caller_scope}:");
    if value.starts_with("chisei:") {
        let suffix = value
            .strip_prefix(&prefix)
            .ok_or_else(|| "operation id belongs to a different caller scope".to_string())?;
        if suffix.is_empty() {
            return Err("operation id requires a non-empty scoped identifier".into());
        }
        if suffix.contains(RESERVED_ATTEMPT_SEGMENT) {
            return Err("operation id contains a reserved attempt segment".into());
        }
        return Ok(value.to_string());
    }
    if value.contains(RESERVED_ATTEMPT_SEGMENT) {
        return Err("operation id contains a reserved attempt segment".into());
    }
    if value.len().saturating_add(prefix.len()) > 128 {
        return Err("operation id is too long after caller scoping".into());
    }
    Ok(format!("{prefix}{value}"))
}
pub(super) fn correlation_header(
    headers: &HeaderMap,
    name: &HeaderName,
) -> Result<Option<String>, String> {
    let Some(value) = header_str(headers, name) else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return Err(format!("{name} must contain 1 to 128 characters"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!("{name} contains unsupported characters"));
    }
    Ok(Some(value.to_string()))
}
pub(super) fn route_override_header(headers: &HeaderMap) -> Result<Option<String>, String> {
    let Some(value) = header_str(headers, &X_CHISEI_ROUTE_OVERRIDE) else {
        return Ok(None);
    };
    let value = value.trim();
    let canonical = value.split_once('/').is_some_and(|(provider, model)| {
        !provider.is_empty()
            && !model.is_empty()
            && !model.contains('/')
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
            })
    });
    if value.len() > 128 || !canonical {
        return Err(
            "x-chisei-route-override must be a canonical provider/model of at most 128 characters"
                .into(),
        );
    }
    Ok(Some(value.to_string()))
}
pub(super) fn validate_traceparent(value: &str) -> Result<String, String> {
    let parts = value.split('-').collect::<Vec<_>>();
    let valid_hex = |part: &str, len: usize| {
        part.len() == len
            && part.bytes().all(|byte| byte.is_ascii_hexdigit())
            && part.bytes().any(|byte| byte != b'0')
    };
    if parts.len() != 4
        || parts[0].len() != 2
        || !parts[0].bytes().all(|byte| byte.is_ascii_hexdigit())
        || parts[0].eq_ignore_ascii_case("ff")
        || !valid_hex(parts[1], 32)
        || !valid_hex(parts[2], 16)
        || parts[3].len() != 2
        || !parts[3].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("traceparent must use the W3C version-trace-parent-flags format".into());
    }
    Ok(value.to_ascii_lowercase())
}
pub(super) fn insert_header(headers: &mut HeaderMap, name: &HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}
