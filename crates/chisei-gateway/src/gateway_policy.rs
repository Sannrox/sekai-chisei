//! Gateway-owned egress policy (ADR 0152).
//!
//! With `CHISEI_GATEWAY_POLICY_PATH` set the gateway runs in policy mode: it
//! admits requests against an operator-written JSON file and never calls Sekai
//! or Chisei. The file names principals and the SHA-256 of their keys, the
//! provider and model routes each may reach, request limits per principal and
//! per model, and which data classes may leave toward each provider.
//!
//! The file is read at start and polled for changes. A file that fails to
//! parse or validate never replaces the active policy; the failure shows on
//! `/readyz`. A gateway with no valid policy denies every request.

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{PoisonError, RwLock as SyncRwLock};

/// Environment variable that turns policy mode on.
pub(super) const POLICY_PATH_ENV: &str = "CHISEI_GATEWAY_POLICY_PATH";
/// The only policy file format this gateway reads.
pub(super) const POLICY_FORMAT: &str = "chisei.gateway-policy/v1";
/// The policy file named by `CHISEI_GATEWAY_POLICY_PATH`, when policy mode is on.
pub(super) fn policy_path_from_env() -> Option<PathBuf> {
    std::env::var(POLICY_PATH_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}
/// How often the watcher rereads the policy file.
const POLICY_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Provider ids a route or egress rule may name (see `capability_provider_id`).
const POLICY_PROVIDERS: [&str; 6] = ["openai", "anthropic", "ollama", "native", "xai", "meta"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    format: String,
    /// Operator-assigned generation. A changed file must carry a higher one.
    generation: u64,
    /// Gateway instances sharing this file. Each enforces
    /// `ceil(requests / instances)` of every limit.
    #[serde(default = "one_instance")]
    instances: u32,
    principals: Vec<PrincipalPolicy>,
    #[serde(default)]
    models: Vec<ModelPolicy>,
    egress: Vec<EgressRule>,
}

fn one_instance() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrincipalPolicy {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project: Option<String>,
    /// Sekai principal this gateway principal maps to; defaults to `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sekai_principal: Option<String>,
    /// Lowercase hex SHA-256 of each key. Never published.
    #[serde(skip_serializing)]
    key_sha256: Vec<String>,
    routes: Vec<RoutePolicy>,
    #[serde(default)]
    limits: Vec<RequestLimit>,
    /// May read and acknowledge the gateway's egress log (Chisei).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    log_reader: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RoutePolicy {
    provider: String,
    /// Model names (canonical or within the provider), or `*` for all.
    models: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelPolicy {
    model: String,
    limits: Vec<RequestLimit>,
}

/// At most `requests` admissions per fixed window of `window_secs`. A short
/// window is a rate limit, a long one a quota.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestLimit {
    requests: u64,
    window_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EgressRule {
    provider: String,
    data_classes: Vec<String>,
}

/// A validated policy generation.
#[derive(Debug)]
pub(super) struct EgressPolicy {
    file: PolicyFile,
    digest: String,
    principal_by_key: HashMap<String, usize>,
    egress: HashMap<String, HashSet<String>>,
}

impl EgressPolicy {
    /// Parses and validates a policy file. Any error rejects the whole file.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut file: PolicyFile =
            serde_json::from_slice(bytes).map_err(|error| format!("invalid policy: {error}"))?;
        if file.format != POLICY_FORMAT {
            return Err(format!("policy format must be {POLICY_FORMAT}"));
        }
        if file.generation == 0 {
            return Err("policy generation must be at least 1".into());
        }
        if file.instances == 0 {
            return Err("policy instances must be at least 1".into());
        }
        let mut egress = HashMap::new();
        for rule in &mut file.egress {
            known_provider(&rule.provider)?;
            rule.data_classes = rule
                .data_classes
                .iter()
                .map(|class| normalize_governance_label(class))
                .collect();
            if rule.data_classes.iter().any(String::is_empty) {
                return Err(format!(
                    "egress for {} has an empty data class",
                    rule.provider
                ));
            }
            if egress
                .insert(
                    rule.provider.clone(),
                    rule.data_classes.iter().cloned().collect::<HashSet<_>>(),
                )
                .is_some()
            {
                return Err(format!("egress for {} is listed twice", rule.provider));
            }
        }
        let mut names = HashSet::new();
        let mut principal_by_key = HashMap::new();
        for (index, principal) in file.principals.iter_mut().enumerate() {
            let name = &principal.name;
            if name.trim().is_empty() || name.trim() != name {
                return Err("principal name must be non-empty without surrounding spaces".into());
            }
            if !names.insert(name.clone()) {
                return Err(format!("principal {name} is listed twice"));
            }
            if principal.key_sha256.is_empty() {
                return Err(format!("principal {name} has no key"));
            }
            for key in &mut principal.key_sha256 {
                *key = key.to_ascii_lowercase();
                if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(format!(
                        "principal {name} has a key_sha256 that is not 64 hex digits"
                    ));
                }
                if principal_by_key.insert(key.clone(), index).is_some() {
                    return Err(format!("principal {name} reuses another principal's key"));
                }
            }
            if principal.routes.is_empty() {
                return Err(format!("principal {name} has no route"));
            }
            for route in &principal.routes {
                known_provider(&route.provider)?;
                if route.models.is_empty() || route.models.iter().any(|m| m.trim().is_empty()) {
                    return Err(format!(
                        "principal {name} route {} needs model names or *",
                        route.provider
                    ));
                }
                if !egress.contains_key(&route.provider) {
                    return Err(format!(
                        "principal {name} routes to {} which has no egress rule",
                        route.provider
                    ));
                }
            }
            validate_limits(&principal.limits, name)?;
        }
        let mut models = HashSet::new();
        for model in &file.models {
            if model.model.trim().is_empty() || !models.insert(model.model.as_str()) {
                return Err(format!("model {:?} is empty or listed twice", model.model));
            }
            validate_limits(&model.limits, &model.model)?;
        }
        Ok(Self {
            file,
            digest: format!("sha256:{:x}", Sha256::digest(bytes)),
            principal_by_key,
            egress,
        })
    }

    pub(super) fn generation(&self) -> u64 {
        self.file.generation
    }

    fn principal(&self, name: &str) -> Option<&PrincipalPolicy> {
        self.file.principals.iter().find(|p| p.name == name)
    }

    /// The read-only view the gateway publishes: everything but keys.
    fn published_view(&self) -> serde_json::Value {
        serde_json::json!({
            "format": self.file.format,
            "generation": self.file.generation,
            "digest": self.digest,
            "instances": self.file.instances,
            "principals": self.file.principals,
            "models": self.file.models,
            "egress": self.file.egress,
        })
    }

    /// Fixed-window subjects one admission charges, with this instance's share.
    fn limit_subjects(
        &self,
        principal: &PrincipalPolicy,
        provider: &str,
        model: Option<&str>,
    ) -> Vec<LimitSubject> {
        let share = |limit: &RequestLimit| limit.requests.div_ceil(u64::from(self.file.instances));
        let principal_limits = principal.limits.iter().map(|limit| LimitSubject {
            key: format!("principal:{}:{}s", principal.name, limit.window_secs),
            requests: share(limit),
            window: Duration::from_secs(limit.window_secs),
        });
        let model_limits = self
            .file
            .models
            .iter()
            .filter(|policy| model.is_some_and(|model| names_model(&policy.model, provider, model)))
            .flat_map(|policy| policy.limits.iter().map(move |limit| (policy, limit)))
            .map(|(policy, limit)| LimitSubject {
                // Keyed by the policy entry, as reload pruning expects.
                key: format!("model:{}:{}s", policy.model, limit.window_secs),
                requests: share(limit),
                window: Duration::from_secs(limit.window_secs),
            });
        principal_limits.chain(model_limits).collect()
    }
}

/// Whether a model name in the policy names the canonical `model`. Policies may
/// use the canonical id (`openai/gpt-5.5`) or the name within its provider
/// (`gpt-5.5`).
fn names_model(name: &str, provider: &str, model: &str) -> bool {
    name == model
        || model
            .strip_prefix(provider)
            .and_then(|rest| rest.strip_prefix('/'))
            == Some(name)
}

fn known_provider(provider: &str) -> Result<(), String> {
    if POLICY_PROVIDERS.contains(&provider) {
        Ok(())
    } else {
        Err(format!(
            "unknown provider {provider:?}; expected one of {}",
            POLICY_PROVIDERS.join(", ")
        ))
    }
}

fn validate_limits(limits: &[RequestLimit], owner: &str) -> Result<(), String> {
    if limits
        .iter()
        .any(|limit| limit.requests == 0 || limit.window_secs == 0)
    {
        return Err(format!("{owner} has a limit with zero requests or window"));
    }
    Ok(())
}

struct LimitSubject {
    key: String,
    requests: u64,
    window: Duration,
}

/// What a policy-mode request asks for.
pub(super) struct PolicyRequest<'a> {
    pub(super) principal: &'a str,
    pub(super) provider: &'static str,
    /// Canonical model, or `None` for a model-metadata request.
    pub(super) model: Option<&'a str>,
    pub(super) data_class: &'a str,
}

/// Why policy mode refused a request. Every variant refuses before provider
/// contact.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum PolicyDenial {
    NoValidPolicy,
    UnknownPrincipal,
    RouteDenied(String),
    DataClassDenied(String),
    LimitExceeded(String),
}

impl PolicyDenial {
    pub(super) fn rejection(self) -> GatewayRejection {
        match self {
            Self::NoValidPolicy => GatewayRejection::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_unavailable",
                "the gateway has no valid egress policy",
            ),
            Self::UnknownPrincipal => GatewayRejection::json(
                StatusCode::FORBIDDEN,
                "policy_denied",
                "principal is not in the active egress policy",
            ),
            Self::RouteDenied(reason) => {
                GatewayRejection::json(StatusCode::FORBIDDEN, "policy_denied", reason)
            }
            Self::DataClassDenied(reason) => {
                GatewayRejection::json(StatusCode::FORBIDDEN, "data_class_denied", reason)
            }
            Self::LimitExceeded(subject) => GatewayRejection::json(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                format!("egress policy limit exceeded for {subject}"),
            ),
        }
    }
}

#[derive(Default)]
struct PolicyState {
    active: Option<Arc<EgressPolicy>>,
    /// Digest of the last file that failed, so an unchanged bad file is not
    /// reparsed and relogged on every poll.
    failed_digest: Option<String>,
    last_error: Option<String>,
    windows: HashMap<String, RateLimitWindow>,
}

/// The active egress policy, its reload status, and this instance's limit
/// counters. Cloning shares the same state.
#[derive(Clone)]
pub(super) struct PolicyStore {
    path: PathBuf,
    state: Arc<SyncRwLock<PolicyState>>,
}

impl PolicyStore {
    /// Opens the store and loads the file once. A failed first load leaves the
    /// store without a policy, so every request is denied until a valid file
    /// appears.
    pub(super) fn open(path: PathBuf) -> Self {
        let store = Self {
            path,
            state: Arc::default(),
        };
        store.reload();
        store
    }

    /// Rereads the file and applies it when it is valid and newer. Returns the
    /// active generation afterwards.
    pub(super) fn reload(&self) -> Option<u64> {
        let read = std::fs::read(&self.path);
        let mut state = self.write();
        let outcome = match read {
            Err(error) => Err((
                None,
                format!("cannot read {}: {error}", self.path.display()),
            )),
            Ok(bytes) => {
                let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
                if state.active.as_ref().is_some_and(|p| p.digest == digest) {
                    Ok(None)
                } else if state.failed_digest.as_deref() == Some(digest.as_str()) {
                    return state.active.as_ref().map(|p| p.generation());
                } else {
                    EgressPolicy::parse(&bytes)
                        .and_then(|policy| match &state.active {
                            Some(active) if policy.generation() <= active.generation() => {
                                Err(format!(
                                    "changed policy keeps generation {} but must exceed active generation {}",
                                    policy.generation(),
                                    active.generation()
                                ))
                            }
                            _ => Ok(Some(policy)),
                        })
                        .map_err(|error| (Some(digest), error))
                }
            }
        };
        match outcome {
            Ok(Some(policy)) => {
                info!(
                    generation = policy.generation(),
                    "gateway egress policy applied"
                );
                let keep = policy
                    .file
                    .principals
                    .iter()
                    .map(|p| format!("principal:{}:", p.name))
                    .chain(
                        policy
                            .file
                            .models
                            .iter()
                            .map(|m| format!("model:{}:", m.model)),
                    )
                    .collect::<Vec<_>>();
                state
                    .windows
                    .retain(|key, _| keep.iter().any(|prefix| key.starts_with(prefix)));
                state.active = Some(Arc::new(policy));
                state.failed_digest = None;
                state.last_error = None;
            }
            Ok(None) => {
                state.failed_digest = None;
                state.last_error = None;
            }
            Err((digest, error)) => {
                warn!(error = %error, "gateway egress policy reload rejected; keeping the active generation");
                state.failed_digest = digest;
                state.last_error = Some(error);
            }
        }
        state.active.as_ref().map(|p| p.generation())
    }

    // The lock is never held across an await, and every write leaves the state
    // consistent, so a poisoned lock is still safe to use.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, PolicyState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, PolicyState> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Polls the file until the process exits.
    pub(super) fn spawn_watcher(&self) {
        let store = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(POLICY_POLL_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                store.reload();
            }
        });
    }

    /// Resolves a presented key to its principal.
    pub(super) fn identify(
        &self,
        key: &str,
        default_project: &str,
    ) -> Result<GatewayIdentity, IdentityError> {
        let state = self.read();
        let policy = state.active.as_ref().ok_or(IdentityError::NoValidPolicy)?;
        let index = policy
            .principal_by_key
            .get(&hash_gateway_key(key))
            .ok_or(IdentityError::UnknownKey)?;
        let principal = &policy.file.principals[*index];
        Ok(GatewayIdentity {
            agent: principal.name.clone(),
            project: principal
                .project
                .clone()
                .unwrap_or_else(|| default_project.to_string()),
            user_id: format!("agent:{}", principal.name),
            key_id: principal.name.clone(),
            tier: DEFAULT_GATEWAY_TIER.to_string(),
        })
    }

    /// Admits one request against the active policy and charges its limits.
    /// Returns the generation that admitted it.
    pub(super) fn admit(&self, request: PolicyRequest<'_>) -> Result<u64, PolicyDenial> {
        let mut state = self.write();
        let policy = state.active.clone().ok_or(PolicyDenial::NoValidPolicy)?;
        let principal = policy
            .principal(request.principal)
            .ok_or(PolicyDenial::UnknownPrincipal)?;
        let routed = principal.routes.iter().any(|route| {
            route.provider == request.provider
                && request.model.is_none_or(|model| {
                    route.models.iter().any(|allowed| {
                        allowed == "*" || names_model(allowed, request.provider, model)
                    })
                })
        });
        if !routed {
            return Err(PolicyDenial::RouteDenied(format!(
                "principal {} may not reach {}{}",
                principal.name,
                request.provider,
                request
                    .model
                    .map(|m| format!(" model {m}"))
                    .unwrap_or_default()
            )));
        }
        let allowed_classes = policy.egress.get(request.provider);
        if !allowed_classes.is_some_and(|classes| classes.contains(request.data_class)) {
            return Err(PolicyDenial::DataClassDenied(format!(
                "data class {} may not leave toward {}",
                request.data_class, request.provider
            )));
        }
        let subjects = policy.limit_subjects(principal, request.provider, request.model);
        let now = Instant::now();
        for subject in &subjects {
            let window = state
                .windows
                .entry(subject.key.clone())
                .or_insert(RateLimitWindow {
                    started_at: now,
                    requests: 0,
                });
            if now.duration_since(window.started_at) >= subject.window {
                window.started_at = now;
                window.requests = 0;
            }
            if window.requests >= subject.requests {
                return Err(PolicyDenial::LimitExceeded(subject.key.clone()));
            }
        }
        for subject in &subjects {
            if let Some(window) = state.windows.get_mut(&subject.key) {
                window.requests += 1;
            }
        }
        Ok(policy.generation())
    }

    /// Whether the active policy names `principal` as a log reader.
    pub(super) fn is_log_reader(&self, principal: &str) -> bool {
        self.read()
            .active
            .as_ref()
            .and_then(|policy| policy.principal(principal))
            .is_some_and(|principal| principal.log_reader)
    }

    /// `/readyz` body for policy mode: ready while a valid generation is active.
    pub(super) fn readiness(&self) -> (StatusCode, serde_json::Value) {
        let state = self.read();
        match &state.active {
            Some(policy) => (
                StatusCode::OK,
                serde_json::json!({
                    "status": "ready",
                    "governance": "policy",
                    "policy_generation": policy.generation(),
                    "policy_reload_error": state.last_error,
                }),
            ),
            None => (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({
                    "status": "not_ready",
                    "reason": "no_valid_policy",
                    "policy_reload_error": state.last_error,
                }),
            ),
        }
    }

    /// The published view of the active policy, or `None` without one.
    pub(super) fn published_view(&self) -> Option<serde_json::Value> {
        self.read()
            .active
            .as_ref()
            .map(|policy| policy.published_view())
    }
}

/// `GET /_chisei/policy`: the active policy without keys, for any principal
/// of that policy (Chisei reads it as an ordinary principal).
pub(super) async fn published_policy(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response<Body> {
    let Some(policy) = &state.runtime.policy else {
        return json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "the gateway is not in policy mode",
        );
    };
    let Some(key) = client_key(&headers) else {
        return IdentityError::MissingKey.response();
    };
    if let Err(error) = policy.identify(key, &state.config.default_project) {
        return error.response();
    }
    match policy.published_view() {
        Some(view) => json_response(StatusCode::OK, view),
        None => PolicyDenial::NoValidPolicy.rejection().response(),
    }
}

/// Policy-mode stand-in for the control-plane decision: admits the request
/// against the local policy and returns the preflight the decision path would.
/// The admitted route is the requested one; policy mode never rewrites models.
#[allow(clippy::too_many_arguments)]
pub(super) fn policy_preflight(
    policy: &PolicyStore,
    identity: &GatewayIdentity,
    preflight_context: &mut UsageContext,
    body: Vec<u8>,
    provider: ProviderKind,
    canonical_model: Option<&str>,
    model_metadata_request: bool,
    data_class: &str,
) -> Result<
    (
        PolicyPreflight,
        ContextEgressPreflight,
        Option<BudgetPreflight>,
    ),
    GatewayRejection,
> {
    let model = if model_metadata_request {
        None
    } else {
        Some(canonical_model.ok_or_else(|| {
            GatewayRejection::json(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "gateway policy mode requires an explicit, known request model",
            )
        })?)
    };
    let generation = policy
        .admit(PolicyRequest {
            principal: &identity.agent,
            provider: capability_provider_id(provider),
            model,
            data_class,
        })
        .map_err(PolicyDenial::rejection)?;
    let policy_version = format!("{POLICY_FORMAT}:{generation}");
    preflight_context.provider = provider;
    preflight_context.resolved_model = model.map(str::to_string);
    preflight_context.policy_version = Some(policy_version.clone());
    preflight_context.egress_applied = true;
    let resolved = PolicyPreflight {
        body: body.clone(),
        resolved_model: model.map(str::to_string),
        resolved_provider: provider,
        route_bias: None,
        policy_scope: None,
        policy_version: Some(policy_version),
        fallback_models: Vec::new(),
        data_class: Some(data_class.to_string()),
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
    };
    Ok((resolved, ContextEgressPreflight { body }, None))
}
