use super::*;

pub(super) fn required_control_plane_target(
    chisei_grpc_url: Option<String>,
    sekai_socket: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    chisei_grpc_url
        .filter(|value| !value.trim().is_empty())
        .or_else(|| sekai_socket.filter(|value| !value.trim().is_empty()))
        .ok_or_else(|| "CHISEI_GRPC_URL or SEKAI_SOCKET is required for chisei-gateway".into())
}
pub(super) fn validate_gateway_security(
    bind_addr: SocketAddr,
    gateway_keys: &HashMap<String, GatewayIdentity>,
    allow_auth_passthrough: bool,
    admin_token: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(token) = admin_token.map(str::trim).filter(|token| !token.is_empty())
        && (token == "change-me" || token.len() < MIN_ADMIN_TOKEN_BYTES)
    {
        return Err(format!(
            "CHISEI_GATEWAY_ADMIN_TOKEN must contain at least {MIN_ADMIN_TOKEN_BYTES} bytes and must not use a documented placeholder"
        )
        .into());
    }

    if !bind_addr.ip().is_loopback() {
        if gateway_keys.is_empty() {
            return Err(
                "an exposed gateway requires at least one authenticated GATEWAY_KEYS entry".into(),
            );
        }
        if allow_auth_passthrough {
            return Err(
                "CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH cannot be used on an exposed gateway".into(),
            );
        }
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
pub(super) fn resolve_usage_recovery_path(configured: Option<String>) -> PathBuf {
    configured
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_USAGE_RECOVERY_PATH))
}
pub(super) fn resolve_recovery_spool_path(configured: Option<String>) -> PathBuf {
    configured
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RECOVERY_SPOOL_PATH))
}
pub(super) fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
pub(super) fn configured_control_plane_timeout() -> Duration {
    Duration::from_millis(
        env_u64(
            "CHISEI_GATEWAY_CONTROL_PLANE_TIMEOUT_MS",
            DEFAULT_CONTROL_PLANE_TIMEOUT_MS,
        )
        .max(1),
    )
}
pub(super) async fn connect_governance(
    runtime: &GatewayRuntime,
    target: &str,
) -> Result<GatewayClient, Box<dyn std::error::Error + Send + Sync>> {
    if runtime.control_plane_circuit.read().await.is_open() {
        return Err(std::io::Error::other("control-plane circuit is open").into());
    }

    let mut last_error = None;
    for attempt in 0..=runtime.resilience.control_plane_retries {
        match connect_sekai_with_timeout(target, Some(runtime.resilience.control_plane_timeout))
            .await
        {
            Ok(channel) => return Ok(channel),
            Err(error) => {
                last_error = Some(error);
                if attempt < runtime.resilience.control_plane_retries {
                    let multiplier = 1u32.checked_shl(attempt.min(10)).unwrap_or(u32::MAX);
                    tokio::time::sleep(runtime.resilience.control_plane_retry_backoff * multiplier)
                        .await;
                }
            }
        }
    }
    let error = last_error.unwrap_or_else(|| std::io::Error::other("connection failed").into());
    runtime
        .control_plane_circuit
        .write()
        .await
        .record_failure(error.to_string(), &runtime.resilience);
    Err(error)
}
pub(super) async fn record_control_plane_success(runtime: &GatewayRuntime) {
    runtime.control_plane_circuit.write().await.record_success();
}
pub(super) async fn record_control_plane_failure(runtime: &GatewayRuntime, error: &impl ToString) {
    runtime
        .control_plane_circuit
        .write()
        .await
        .record_failure(error.to_string(), &runtime.resilience);
}
pub(super) fn initialize_usage_recovery_journal(
    path: &Path,
) -> std::io::Result<Vec<PendingUsageRecovery>> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            for _ in 0..10 {
                let bytes = std::fs::read(path)?;
                if let Ok(entries) = serde_json::from_slice(&bytes) {
                    return Ok(entries);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "concurrently created usage recovery journal is invalid",
            ));
        }
        Err(error) => return Err(error),
    };
    file.write_all(b"[]")?;
    file.sync_all()?;
    Ok(Vec::new())
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
        (COMMUNITY_GATEWAY_ROUTES[4], any(proxy_gateway)),
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
    let circuit_open = state.runtime.control_plane_circuit.read().await.is_open();
    let cache = state.runtime.usage_recovery.read().await;
    let pending_usage_recoveries = cache.pending_usage_records.len();
    let usage_recovery_saturated = cache.usage_recovery_saturated;
    drop(cache);
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
            "status": if circuit_open
                || provider_circuit_open
                || pending_usage_recoveries > 0
                || usage_recovery_saturated
            {
                "degraded"
            } else {
                "live"
            },
            "control_plane_circuit_open": circuit_open,
            "pending_usage_recoveries": pending_usage_recoveries,
            "usage_recovery_saturated": usage_recovery_saturated,
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
    let Some(target) = state.config.chisei_grpc_target.as_deref() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "status": "not_ready",
                "reason": "control_plane_unconfigured"
            }),
        );
    };
    let circuit = state.runtime.control_plane_circuit.read().await;
    if circuit.is_open() {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "status": "not_ready",
                "governance": "circuit_open",
                "reason": "control-plane circuit is open"
            }),
        );
    }
    drop(circuit);

    // This endpoint is intentionally unauthenticated for orchestrator probes.
    // Serialize and cache the bounded dependency check so callers cannot turn
    // it into an unbounded authenticated control-plane RPC source.
    let mut cached_probe = state.runtime.readiness_probe.lock().await;
    let ready = if let Some((checked_at, ready)) = *cached_probe
        && checked_at.elapsed() < Duration::from_secs(READINESS_PROBE_CACHE_SECS)
    {
        ready
    } else {
        let ready = match connect_sekai_with_timeout(
            target,
            Some(state.runtime.resilience.control_plane_timeout),
        )
        .await
        {
            Ok(channel) => {
                let mut client = SekaiServiceClient::new(channel);
                client
                    .list_schema_types(gateway_request(ListSchemaTypesRequest {}))
                    .await
                    .is_ok()
            }
            Err(_) => false,
        };
        *cached_probe = Some((Instant::now(), ready));
        ready
    };
    if ready {
        json_response(
            StatusCode::OK,
            serde_json::json!({"status": "ready", "governance": "available"}),
        )
    } else {
        json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"status": "not_ready", "governance": "unavailable"}),
        )
    }
}
pub async fn serve(config: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = GatewayRuntime::from_env();
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
    let usage_recovery = state.runtime.usage_recovery.read().await;
    let pending_usage_recoveries = usage_recovery.pending_usage_records.len();
    drop(usage_recovery);
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
            "pending_usage_recoveries": pending_usage_recoveries
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
