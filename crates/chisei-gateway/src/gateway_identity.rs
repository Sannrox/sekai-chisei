use super::*;

pub(super) async fn resolve_identity(
    headers: &HeaderMap,
    state: &GatewayState,
) -> Result<IdentityContext, IdentityError> {
    let config = &state.config;
    let Some(key) = client_key(headers) else {
        return Err(IdentityError::MissingKey);
    };
    if config.allow_auth_passthrough
        && let Some(identity) = passthrough_identity(headers, &config.default_project)
    {
        return Ok(IdentityContext::machine(
            identity,
            UpstreamAuthMode::Passthrough,
        ));
    }

    if let Some(identity) = config.gateway_keys.get(key) {
        return Ok(IdentityContext::machine(
            identity.clone(),
            UpstreamAuthMode::GatewayKey,
        ));
    }
    if !config.gateway_keys.is_empty() {
        return Err(IdentityError::UnknownKey);
    }

    if let Some(identity) = resolve_identity_from_key_store(state, key).await? {
        return Ok(IdentityContext::machine(
            identity,
            UpstreamAuthMode::GatewayKey,
        ));
    }

    Ok(IdentityContext::machine(
        derive_identity_from_key(key, &config.default_project),
        UpstreamAuthMode::GatewayKey,
    ))
}
pub(super) async fn resolve_identity_from_key_store(
    state: &GatewayState,
    key: &str,
) -> Result<Option<GatewayIdentity>, IdentityError> {
    let config = &state.config;
    let Some(target) = &config.chisei_grpc_target else {
        return Ok(None);
    };
    let key_hash = hash_gateway_key(key);
    if let Some(entry) = cached_gateway_key_identity(state, &key_hash).await {
        return entry.identity.ok_or(IdentityError::UnknownKey).map(Some);
    }
    let channel = connect_governance(&state.runtime, target)
        .await
        .map_err(|_| IdentityError::KeyStoreUnavailable)?;
    let mut sekai = SekaiServiceClient::new(channel);
    let resp = match sekai
        .find_by_property(gateway_request(FindByPropertyRequest {
            kind: "gateway_key".to_string(),
            key: "key_hash".to_string(),
            value: key_hash.clone(),
        }))
        .await
    {
        Ok(resp) => {
            record_control_plane_success(&state.runtime).await;
            resp.into_inner()
        }
        Err(error) => {
            if is_transient_governance_status(&error) {
                record_control_plane_failure(&state.runtime, &error).await;
            } else {
                record_control_plane_success(&state.runtime).await;
            }
            return Err(IdentityError::KeyStoreUnavailable);
        }
    };
    let object = resp.objects.into_iter().find(|object| {
        object
            .properties
            .get("status")
            .map(|status| status == "active")
            .unwrap_or(true)
    });
    let Some(object) = object else {
        cache_gateway_key_identity(state, key_hash, None).await;
        return Err(IdentityError::UnknownKey);
    };
    let Some(agent) = object
        .properties
        .get("agent")
        .filter(|value| !value.is_empty())
    else {
        cache_gateway_key_identity(state, key_hash, None).await;
        return Err(IdentityError::UnknownKey);
    };
    let project = object
        .properties
        .get("project")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| config.default_project.clone());
    let identity = GatewayIdentity {
        agent: agent.clone(),
        project,
        user_id: format!("agent:{agent}"),
        key_id: object.name.clone(),
        tier: object
            .properties
            .get("tier")
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .unwrap_or_else(|| DEFAULT_GATEWAY_TIER.to_string()),
    };
    cache_gateway_key_identity(state, key_hash, Some(identity.clone())).await;
    Ok(Some(identity))
}
pub(super) async fn cached_gateway_key_identity(
    state: &GatewayState,
    key_hash: &str,
) -> Option<KeyCacheEntry> {
    use crate::obs::labels::{Cache, CacheOutcome};

    let cache = state.runtime.key_cache.read().await;
    let Some(entry) = cache.get(key_hash) else {
        crate::obs::signals::record_cache_event(Cache::GatewayKey, CacheOutcome::Miss);
        return None;
    };
    if entry.cached_at.elapsed() < state.runtime.key_cache_ttl {
        crate::obs::signals::record_cache_event(Cache::GatewayKey, CacheOutcome::Hit);
        return Some(entry.clone());
    }
    // Present but past its TTL. Counting this as a plain miss would hide
    // whether the cache is too small or the TTL is too short.
    crate::obs::signals::record_cache_event(Cache::GatewayKey, CacheOutcome::Evicted);
    None
}
pub(super) async fn cache_gateway_key_identity(
    state: &GatewayState,
    key_hash: String,
    identity: Option<GatewayIdentity>,
) {
    state.runtime.key_cache.write().await.insert(
        key_hash,
        KeyCacheEntry {
            identity,
            cached_at: Instant::now(),
        },
    );
}
pub(super) fn client_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .or_else(|| headers.get(X_API_KEY).and_then(|value| value.to_str().ok()))
        .filter(|value| !value.trim().is_empty())
}
pub(super) fn passthrough_identity(
    headers: &HeaderMap,
    default_project: &str,
) -> Option<GatewayIdentity> {
    let agent = header_str(headers, &X_CHISEI_AGENT)?;
    let project = header_str(headers, &X_CHISEI_PROJECT).unwrap_or(default_project);
    Some(GatewayIdentity {
        user_id: format!("agent:{agent}"),
        agent: agent.to_string(),
        project: project.to_string(),
        key_id: String::new(),
        // Passthrough is an explicit operator opt-in. Keep its availability
        // posture distinct from unrestricted derived keys, which remain
        // fail-closed unless registered with a trusted low-risk tier.
        tier: "low-risk".to_string(),
    })
}
pub(super) fn gateway_work_unit_id(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, &X_CHISEI_WORK_UNIT).or_else(|| header_str(headers, &X_CHISEI_TASK_ID))
}
/// Resolve the routing task class for a request. An explicit
/// `x-chisei-task-class` header wins; otherwise a coarse heuristic classifies
/// small/fast models (the background tier clients use for cheap side work) as
/// `background` and everything else as `primary`. The value is advisory input
/// to policy tiering — the control plane decides whether a class may route to a
/// cheaper model, defaulting unknown classes to the capable tier.
pub(super) fn resolve_task_class(headers: &HeaderMap, requested_model: Option<&str>) -> String {
    if let Some(explicit) = header_str(headers, &X_CHISEI_TASK_CLASS) {
        return explicit.to_ascii_lowercase();
    }
    match requested_model {
        Some(model) if is_small_fast_model(model) => "background".to_string(),
        _ => "primary".to_string(),
    }
}
/// Whether a model name looks like a small/fast/background-tier model. Used only
/// as a fallback classifier when the client sends no explicit task class.
pub(super) fn is_small_fast_model(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    ["haiku", "mini", "nano", "flash", "small", "fast"]
        .iter()
        .any(|marker| lower.contains(marker))
}
pub(super) fn header_str<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
pub(super) fn derive_identity_from_key(key: &str, default_project: &str) -> GatewayIdentity {
    let agent = key
        .strip_prefix("sk-chisei-")
        .unwrap_or("unknown")
        .to_string();
    GatewayIdentity {
        user_id: format!("agent:{agent}"),
        key_id: agent.clone(),
        agent,
        project: default_project.to_string(),
        // This compatibility path has no operator-managed registration from
        // which to derive a trusted failure posture.
        tier: "untrusted".to_string(),
    }
}
pub(super) fn parse_gateway_keys(
    spec: &str,
    default_project: &str,
) -> Result<HashMap<String, GatewayIdentity>, Box<dyn std::error::Error>> {
    let mut keys = HashMap::new();
    for entry in spec
        .split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            format!("invalid GATEWAY_KEYS entry {entry:?}; expected key=agent:project[:tier]")
        })?;
        let key = key.trim();
        if key.is_empty() {
            return Err("invalid GATEWAY_KEYS entry with empty key".into());
        }
        let mut parts = value.split(':');
        let agent = parts.next().map(str::trim).unwrap_or_default();
        let project = parts.next().map(str::trim);
        let tier = parts.next().map(str::trim);
        if parts.next().is_some() {
            return Err(format!(
                "invalid GATEWAY_KEYS entry {entry:?}; expected key=agent:project[:tier]"
            )
            .into());
        }
        if agent.is_empty() {
            return Err(format!("invalid GATEWAY_KEYS entry {entry:?}; empty agent").into());
        }
        let project = match project {
            None | Some("") => default_project,
            Some(value) => value,
        };
        if project.is_empty() {
            return Err(format!("invalid GATEWAY_KEYS entry {entry:?}; empty project").into());
        }
        let tier = match tier {
            None | Some("") => DEFAULT_GATEWAY_TIER,
            Some(value) => value,
        };
        let key_id = agent.to_string();
        keys.insert(
            key.to_string(),
            GatewayIdentity {
                agent: agent.to_string(),
                project: project.to_string(),
                user_id: format!("agent:{agent}"),
                key_id,
                tier: tier.to_string(),
            },
        );
    }
    Ok(keys)
}
pub(super) fn estimate_cost_usd_micros(
    config: &GatewayConfig,
    context: &UsageContext,
    usage: &ResponseUsage,
) -> Option<i64> {
    let (model, pricing) = lookup_model_pricing(config, context)?;
    cost_for_model(model, pricing, usage)
}
pub(super) fn insert_normalized_usage_values(
    values: &mut HashMap<String, String>,
    usage: &ResponseUsage,
) {
    values.insert("input_tokens".into(), usage.input_tokens.to_string());
    values.insert("output_tokens".into(), usage.output_tokens.to_string());
    values.insert("total_tokens".into(), usage.total_tokens.to_string());
    let uncached_input = if usage.cache_read_included_in_input {
        usage
            .input_tokens
            .saturating_sub(usage.cache_read_input_tokens)
    } else {
        usage.input_tokens
    };
    values.insert("uncached_input_tokens".into(), uncached_input.to_string());
    if let Some(provider_total) = usage.provider_total_tokens {
        values.insert("provider_total_tokens".into(), provider_total.to_string());
    }
    if usage.cache_read_reported {
        values.insert(
            "cache_read_input_tokens".into(),
            usage.cache_read_input_tokens.to_string(),
        );
    }
    if usage.cache_creation_reported {
        values.insert(
            "cache_creation_input_tokens".into(),
            usage.cache_creation_input_tokens.to_string(),
        );
    }
    if usage.cache_creation_5m_reported {
        values.insert(
            "cache_creation_5m_input_tokens".into(),
            usage.cache_creation_5m_input_tokens.to_string(),
        );
    }
    if usage.cache_creation_1h_reported {
        values.insert(
            "cache_creation_1h_input_tokens".into(),
            usage.cache_creation_1h_input_tokens.to_string(),
        );
    }
}
/// Dollar savings attributable to prompt caching on this call: the cache-read
/// tokens priced at the full input rate minus the discounted cached rate.
/// Provider-independent, since it only measures the rate delta on the
/// cache-read tokens. Returns `None` when no pricing is configured.
pub(super) fn estimate_cache_savings_usd_micros(
    config: &GatewayConfig,
    context: &UsageContext,
    usage: &ResponseUsage,
) -> Option<i64> {
    let (_model, pricing) = lookup_model_pricing(config, context)?;
    cache_savings_for_pricing(pricing, usage)
}
/// Resolve the pricing entry for a usage context, preferring the resolved model
/// and falling back to the requested model. Returns the model name alongside
/// its pricing so callers can apply provider-specific token semantics.
pub(super) fn lookup_model_pricing<'c>(
    config: &'c GatewayConfig,
    context: &'c UsageContext,
) -> Option<(&'c str, &'c ModelPricing)> {
    context
        .resolved_model
        .as_ref()
        .and_then(|model| lookup_pricing_entry(&config.pricing, model))
        .or_else(|| {
            context
                .requested_model
                .as_ref()
                .and_then(|model| lookup_pricing_entry(&config.pricing, model))
        })
}
pub(super) fn effective_pricing_snapshot_version(
    config: &GatewayConfig,
    profile: Option<&ProviderProfile>,
    resolved_model: Option<&str>,
    requested_model: Option<&str>,
) -> Option<String> {
    let configured_rate_applies = resolved_model
        .and_then(|model| lookup_pricing_entry(&config.pricing, model))
        .or_else(|| requested_model.and_then(|model| lookup_pricing_entry(&config.pricing, model)))
        .is_some();
    if !configured_rate_applies {
        return profile.map(|profile| profile.pricing.version.clone());
    }

    let mut entries = config.pricing.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(model, _)| *model);
    let mut hasher = Sha256::new();
    hasher.update(b"chisei.gateway-pricing/v2\0");
    for (model, pricing) in entries {
        hasher.update(model.as_bytes());
        hasher.update([0]);
        hasher.update(pricing.input_usd_micros_per_million.to_be_bytes());
        hasher.update(pricing.output_usd_micros_per_million.to_be_bytes());
        hasher.update(pricing.cached_input_usd_micros_per_million.to_be_bytes());
        hasher.update(
            pricing
                .cache_write_5m_usd_micros_per_million
                .unwrap_or(-1)
                .to_be_bytes(),
        );
        hasher.update(
            pricing
                .cache_write_1h_usd_micros_per_million
                .unwrap_or(-1)
                .to_be_bytes(),
        );
    }
    Some(format!("chisei.gateway-pricing/v2:{:x}", hasher.finalize()))
}
pub(super) fn cache_savings_for_pricing(
    pricing: &ModelPricing,
    usage: &ResponseUsage,
) -> Option<i64> {
    let cache_read = usage.cache_read_input_tokens.max(0) as i128;
    let rate_delta = (pricing.input_usd_micros_per_million
        - pricing.cached_input_usd_micros_per_million)
        .max(0) as i128;
    let savings = cache_read.checked_mul(rate_delta)?.checked_div(1_000_000)?;
    i64::try_from(savings).ok()
}
/// Pure cost math for a resolved model/pricing pair, split out so it can be
/// tested without constructing a full gateway config/context.
pub(super) fn cost_for_model(
    model: &str,
    pricing: &ModelPricing,
    usage: &ResponseUsage,
) -> Option<i64> {
    crate::cost_estimate::cost_usd_micros_with_cache_classes(
        model,
        pricing,
        i64::from(usage.input_tokens),
        i64::from(usage.output_tokens),
        i64::from(usage.cache_read_input_tokens),
        crate::cost_estimate::CacheCreationUsage {
            total_tokens: i64::from(usage.cache_creation_input_tokens),
            five_minute_tokens: usage
                .cache_creation_5m_reported
                .then_some(i64::from(usage.cache_creation_5m_input_tokens)),
            one_hour_tokens: usage
                .cache_creation_1h_reported
                .then_some(i64::from(usage.cache_creation_1h_input_tokens)),
        },
    )
}
pub(super) fn format_usd_micros(value: i64) -> String {
    format!("{}.{:06}", value / 1_000_000, (value % 1_000_000).abs())
}
