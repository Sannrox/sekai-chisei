use crate::llm::ollama::InstalledModel;
use crate::provider_profile::{
    PricingProfile, ProviderCapabilities, ProviderRegistry, provider_registry_snapshot,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

const DEFAULT_TTL_SECS: u64 = 300;
const DISCOVERY_TIMEOUT_SECS: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailableModel {
    pub provider: String,
    pub upstream_model: String,
    pub canonical_model: String,
    pub lifecycle: String,
    pub routable: bool,
    pub discovery_source: String,
    pub capabilities: Option<ProviderCapabilities>,
    pub pricing: Option<PricingProfile>,
    pub cost_rank: Option<i32>,
    pub capability_rank: Option<i32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAvailabilitySnapshot {
    pub refreshed_at: Option<String>,
    pub models_by_provider: BTreeMap<String, Vec<AvailableModel>>,
    #[serde(default)]
    pub authoritative_providers: Vec<String>,
}

impl ModelAvailabilitySnapshot {
    pub fn routable_models(&self) -> Vec<AvailableModel> {
        self.models_by_provider
            .values()
            .flatten()
            .filter(|model| model.routable)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ModelDiscoveryConfig {
    pub openai_base_url: String,
    pub openai_api_key: Option<String>,
    pub anthropic_base_url: String,
    pub anthropic_api_key: Option<String>,
    pub ollama_url: String,
    pub native_configured: bool,
}

#[derive(Default)]
struct AvailabilityCache {
    entries: HashMap<u64, AvailabilityCacheEntry>,
    latest: ModelAvailabilitySnapshot,
}

#[derive(Default)]
struct AvailabilityCacheEntry {
    snapshot: ModelAvailabilitySnapshot,
    refreshed_at: Option<Instant>,
}

static CACHE: LazyLock<RwLock<AvailabilityCache>> =
    LazyLock::new(|| RwLock::new(AvailabilityCache::default()));
static REFRESH: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

pub fn model_availability_snapshot() -> ModelAvailabilitySnapshot {
    let snapshot = CACHE
        .read()
        .expect("model availability cache lock is not poisoned")
        .latest
        .clone();
    revalidate_snapshot(snapshot, &provider_registry_snapshot())
}

fn revalidate_snapshot(
    mut snapshot: ModelAvailabilitySnapshot,
    registry: &ProviderRegistry,
) -> ModelAvailabilitySnapshot {
    for (provider, models) in &mut snapshot.models_by_provider {
        *models = models
            .iter()
            .filter_map(|cached| {
                available_model(
                    registry,
                    provider,
                    cached.upstream_model.clone(),
                    &cached.discovery_source,
                )
                .map(|mut model| {
                    model.capabilities = cached.capabilities.clone();
                    model.pricing = cached.pricing.clone();
                    model.cost_rank = cached.cost_rank;
                    model.capability_rank = cached.capability_rank;
                    model
                })
            })
            .collect();
    }
    snapshot
}

fn discovery_cache_key(config: &ModelDiscoveryConfig) -> u64 {
    let mut hasher = DefaultHasher::new();
    config.openai_base_url.hash(&mut hasher);
    config.openai_api_key.hash(&mut hasher);
    config.anthropic_base_url.hash(&mut hasher);
    config.anthropic_api_key.hash(&mut hasher);
    config.ollama_url.hash(&mut hasher);
    config.native_configured.hash(&mut hasher);
    std::env::var_os("XAI_API_KEY").hash(&mut hasher);
    std::env::var_os("META_MODEL_API_KEY").hash(&mut hasher);
    hasher.finish()
}

pub async fn refresh_model_availability(
    config: &ModelDiscoveryConfig,
    force: bool,
) -> ModelAvailabilitySnapshot {
    let _refresh = REFRESH.lock().await;
    let cache_key = discovery_cache_key(config);
    let ttl = Duration::from_secs(
        std::env::var("CHISEI_MODEL_DISCOVERY_TTL_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_TTL_SECS),
    );
    if !force {
        let cache = CACHE
            .read()
            .expect("model availability cache lock is not poisoned");
        if let Some(entry) = cache.entries.get(&cache_key)
            && entry.refreshed_at.is_some_and(|at| at.elapsed() < ttl)
        {
            return revalidate_snapshot(entry.snapshot.clone(), &provider_registry_snapshot());
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(DISCOVERY_TIMEOUT_SECS))
        .build();
    let Ok(client) = client else {
        return CACHE
            .read()
            .expect("model availability cache lock is not poisoned")
            .entries
            .get(&cache_key)
            .map(|entry| entry.snapshot.clone())
            .unwrap_or_default();
    };
    let discovery_deadline = Duration::from_secs(DISCOVERY_TIMEOUT_SECS);
    let (openai, anthropic, ollama) = tokio::join!(
        tokio::time::timeout(discovery_deadline, discover_openai_models(&client, config)),
        tokio::time::timeout(
            discovery_deadline,
            discover_anthropic_models(&client, config)
        ),
        tokio::time::timeout(
            discovery_deadline,
            crate::llm::ollama::list_models(&config.ollama_url)
        ),
    );
    let openai = openai.unwrap_or_else(|_| Err("OpenAI model discovery timed out".into()));
    let anthropic = anthropic.unwrap_or_else(|_| Err("Anthropic model discovery timed out".into()));
    let ollama = ollama.unwrap_or_else(|_| Err("Ollama model discovery timed out".into()));

    let registry = provider_registry_snapshot();
    let mut discovered: HashMap<String, (Vec<String>, bool)> = HashMap::new();
    let mut ollama_ranks = HashMap::new();
    match openai {
        Ok(models) => {
            discovered.insert("openai".to_string(), (models, true));
        }
        Err(_) if config.openai_api_key.is_some() => {
            discovered.insert(
                "openai".to_string(),
                (vec!["gpt-4.1-mini".into(), "gpt-4.1".into()], false),
            );
        }
        Err(_) => {}
    }
    match anthropic {
        Ok(models) => {
            discovered.insert("anthropic".to_string(), (models, true));
        }
        Err(_) if config.anthropic_api_key.is_some() => {
            discovered.insert(
                "anthropic".to_string(),
                (vec!["claude-sonnet-4-20250514".into()], false),
            );
        }
        Err(_) => {}
    }
    if let Ok(models) = ollama {
        for model in &models {
            ollama_ranks.insert(model.name.clone(), ollama_model_ranks(model));
        }
        discovered.insert(
            "ollama".to_string(),
            (models.into_iter().map(|model| model.name).collect(), true),
        );
    }
    if config.native_configured {
        discovered.insert("native".to_string(), (vec!["native-default".into()], false));
    }
    if std::env::var_os("XAI_API_KEY").is_some() {
        discovered.insert("xai".to_string(), (vec!["grok-4.5".to_string()], true));
    }
    if std::env::var_os("META_MODEL_API_KEY").is_some() {
        discovered.insert(
            "meta".to_string(),
            (vec!["muse-spark-1.1".to_string()], true),
        );
    }

    let mut cache = CACHE
        .write()
        .expect("model availability cache lock is not poisoned");
    let entry = cache.entries.entry(cache_key).or_default();
    for (provider, (models, live)) in discovered {
        if !live && let Some(existing) = entry.snapshot.models_by_provider.get(&provider) {
            let revalidated = existing
                .iter()
                .filter_map(|cached| {
                    available_model(
                        &registry,
                        &provider,
                        cached.upstream_model.clone(),
                        &cached.discovery_source,
                    )
                    .map(|mut model| {
                        model.capabilities = cached.capabilities.clone();
                        model.pricing = cached.pricing.clone();
                        model.cost_rank = cached.cost_rank;
                        model.capability_rank = cached.capability_rank;
                        model
                    })
                })
                .collect();
            entry
                .snapshot
                .models_by_provider
                .insert(provider, revalidated);
            continue;
        }
        if live && !entry.snapshot.authoritative_providers.contains(&provider) {
            entry
                .snapshot
                .authoritative_providers
                .push(provider.clone());
            entry.snapshot.authoritative_providers.sort();
        }
        entry.snapshot.models_by_provider.insert(
            provider.clone(),
            models
                .into_iter()
                .filter_map(|model| {
                    let source = if matches!(provider.as_str(), "xai" | "meta") {
                        "registry_singleton"
                    } else if live {
                        "provider_catalog"
                    } else {
                        "static_fallback"
                    };
                    let ranks = ollama_ranks.get(&model).copied();
                    available_model(&registry, &provider, model, source).map(|mut available| {
                        if let Some((cost_rank, capability_rank)) = ranks {
                            available.cost_rank = Some(cost_rank);
                            available.capability_rank = Some(capability_rank);
                        }
                        available
                    })
                })
                .collect(),
        );
    }
    entry.snapshot.refreshed_at = Some(chrono::Utc::now().to_rfc3339());
    entry.refreshed_at = Some(Instant::now());
    let snapshot = entry.snapshot.clone();
    cache.latest = snapshot.clone();
    snapshot
}

fn available_model(
    registry: &ProviderRegistry,
    provider: &str,
    upstream_model: String,
    discovery_source: &str,
) -> Option<AvailableModel> {
    let profile = registry.effective_profile(provider)?;
    let canonical_model = format!("{provider}/{upstream_model}");
    let lifecycle = registry
        .lifecycle_state_for_target("model", &canonical_model)
        .unwrap_or(&profile.lifecycle)
        .to_string();
    let routable = supports_text_generation(provider, &upstream_model)
        && registry.resolve_model(&canonical_model).is_ok();
    Some(AvailableModel {
        provider: provider.to_string(),
        upstream_model,
        canonical_model,
        lifecycle,
        routable,
        discovery_source: discovery_source.into(),
        capabilities: None,
        pricing: None,
        cost_rank: None,
        capability_rank: None,
    })
}

fn ollama_model_ranks(model: &InstalledModel) -> (i32, i32) {
    let cost_rank = (model.parameter_size_b.unwrap_or(1000.0) * 100.0) as i32;
    let capability_rank = (model.parameter_size_b.unwrap_or(0.0) * 100.0) as i32
        + model.context_length / 1024
        + if model.capabilities.iter().any(|cap| cap == "thinking") {
            20
        } else {
            0
        };
    (cost_rank, capability_rank)
}

fn supports_text_generation(provider: &str, model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    match provider {
        "openai" => {
            lower.starts_with("gpt-")
                || lower.starts_with("ft:gpt-")
                || lower.starts_with("chatgpt-")
                || lower.starts_with("o1")
                || lower.starts_with("o3")
                || lower.starts_with("o4")
                || lower.contains("codex")
        }
        "anthropic" => lower.starts_with("claude-"),
        "ollama" | "native" | "xai" | "meta" => true,
        _ => false,
    }
}

#[derive(Deserialize)]
struct CatalogResponse {
    #[serde(default)]
    data: Vec<CatalogModel>,
    #[serde(default)]
    has_more: bool,
    last_id: Option<String>,
}

#[derive(Deserialize)]
struct CatalogModel {
    id: String,
}

async fn discover_openai_models(
    client: &reqwest::Client,
    config: &ModelDiscoveryConfig,
) -> Result<Vec<String>, String> {
    let key = config
        .openai_api_key
        .as_deref()
        .ok_or_else(|| "OpenAI discovery is not configured".to_string())?;
    discover_catalog(
        client
            .get(format!(
                "{}/models",
                config.openai_base_url.trim_end_matches('/')
            ))
            .bearer_auth(key),
        "after",
    )
    .await
}

async fn discover_anthropic_models(
    client: &reqwest::Client,
    config: &ModelDiscoveryConfig,
) -> Result<Vec<String>, String> {
    let key = config
        .anthropic_api_key
        .as_deref()
        .ok_or_else(|| "Anthropic discovery is not configured".to_string())?;
    discover_catalog(
        client
            .get(format!(
                "{}/models",
                config.anthropic_base_url.trim_end_matches('/')
            ))
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01"),
        "after_id",
    )
    .await
}

async fn discover_catalog(
    builder: reqwest::RequestBuilder,
    cursor_parameter: &str,
) -> Result<Vec<String>, String> {
    let mut models = Vec::new();
    let mut cursor = None;
    let mut seen_cursors = std::collections::HashSet::new();
    for _ in 0..100 {
        let mut request = builder
            .try_clone()
            .ok_or_else(|| "model catalog request cannot be cloned".to_string())?;
        if let Some(cursor) = cursor.as_deref() {
            request = request.query(&[(cursor_parameter, cursor)]);
        }
        let response = request.send().await.map_err(|error| error.to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("model catalog returned {status}"));
        }
        let response: CatalogResponse = response.json().await.map_err(|error| error.to_string())?;
        models.extend(response.data.into_iter().map(|model| model.id));
        if !response.has_more {
            return Ok(models);
        }
        let next_cursor = response
            .last_id
            .ok_or_else(|| "paginated model catalog omitted last_id".to_string())?;
        if !seen_cursors.insert(next_cursor.clone()) {
            return Err("paginated model catalog repeated its cursor".into());
        }
        cursor = Some(next_cursor);
    }
    Err("model catalog exceeded 100 pages".into())
}

pub fn ollama_models(snapshot: &ModelAvailabilitySnapshot) -> Vec<InstalledModel> {
    snapshot
        .models_by_provider
        .get("ollama")
        .into_iter()
        .flatten()
        .filter(|model| model.routable)
        .map(|model| InstalledModel {
            name: model.upstream_model.clone(),
            parameter_size_b: None,
            context_length: model.capabilities.as_ref().map_or(0, |capabilities| {
                capabilities.context_tokens.min(i32::MAX as u64) as i32
            }),
            capabilities: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
pub fn replace_model_availability_for_test(snapshot: ModelAvailabilitySnapshot) {
    let mut cache = CACHE
        .write()
        .expect("model availability cache lock is not poisoned");
    cache.latest = snapshot;
}

#[cfg(test)]
mod tests {
    use super::{
        ModelDiscoveryConfig, available_model, discover_catalog, refresh_model_availability,
    };
    use crate::provider_profile::{ProviderRegistry, RegistryLifecycleOverride};
    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{StatusCode, Uri};
    use axum::response::Response;
    use axum::routing::get;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn catalog(State(calls): State<Arc<AtomicUsize>>, uri: Uri) -> Response<Body> {
        calls.fetch_add(1, Ordering::SeqCst);
        let body = if uri.path() == "/api/tags" {
            r#"{"models":[{"name":"llama-test"}]}"#
        } else {
            r#"{"data":[{"id":"model-from-catalog"}]}"#
        };
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    async fn paginated_catalog(uri: Uri) -> Response<Body> {
        let body = if uri.query().is_some() {
            r#"{"data":[{"id":"second"}],"has_more":false}"#
        } else {
            r#"{"data":[{"id":"first"}],"has_more":true,"last_id":"first"}"#
        };
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    async fn empty_catalog(uri: Uri) -> Response<Body> {
        let body = if uri.path() == "/api/tags" {
            r#"{"models":[]}"#
        } else {
            r#"{"data":[]}"#
        };
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn refresh_is_ttl_bounded_and_capability_matrix_uses_the_snapshot() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/{*path}", get(catalog))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base = format!("http://{address}");
        let config = ModelDiscoveryConfig {
            openai_base_url: format!("{base}/v1"),
            openai_api_key: Some("openai-secret".into()),
            anthropic_base_url: format!("{base}/v1"),
            anthropic_api_key: Some("anthropic-secret".into()),
            ollama_url: base,
            native_configured: false,
        };

        let first = refresh_model_availability(&config, true).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(
            first
                .models_by_provider
                .get("openai")
                .unwrap()
                .iter()
                .any(|model| model.upstream_model == "model-from-catalog")
        );
        let second = refresh_model_availability(&config, false).await;
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        let matrix = crate::provider_profile::CapabilityMatrix::with_model_availability(first);
        assert!(matrix.available_models.iter().any(|model| {
            model.provider == "openai"
                && model.upstream_model == "model-from-catalog"
                && model.lifecycle == "enabled"
        }));
        let serialized = serde_json::to_string(&matrix).unwrap();
        assert!(!serialized.contains("openai-secret"));
        assert!(!serialized.contains("anthropic-secret"));
    }

    #[tokio::test]
    async fn catalog_discovery_follows_pagination() {
        let app = Router::new().route("/models", get(paginated_catalog));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let models = discover_catalog(
            reqwest::Client::new().get(format!("http://{address}/models")),
            "after_id",
        )
        .await
        .unwrap();
        assert_eq!(models, ["first", "second"]);
    }

    #[tokio::test]
    async fn successful_empty_catalog_is_authoritative() {
        let app = Router::new().route("/{*path}", get(empty_catalog));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base = format!("http://{address}");
        let snapshot = refresh_model_availability(
            &ModelDiscoveryConfig {
                openai_base_url: format!("{base}/v1"),
                openai_api_key: Some("openai-secret".into()),
                anthropic_base_url: format!("{base}/v1"),
                anthropic_api_key: Some("anthropic-secret".into()),
                ollama_url: base,
                native_configured: false,
            },
            true,
        )
        .await;
        assert!(snapshot.authoritative_providers.contains(&"openai".into()));
        assert!(snapshot.models_by_provider["openai"].is_empty());
    }

    #[test]
    fn registry_lifecycle_disables_an_offered_model() {
        let mut registry = ProviderRegistry::built_in();
        registry
            .lifecycle_overrides
            .push(RegistryLifecycleOverride {
                target_kind: "model".into(),
                target: "openai/gpt-disabled".into(),
                state: "disabled".into(),
                version: 1,
                actor: "test".into(),
                reason: "test lifecycle".into(),
                changed_at: "2026-07-21T00:00:00Z".into(),
            });
        let model = available_model(
            &registry,
            "openai",
            "gpt-disabled".into(),
            "provider_catalog",
        )
        .unwrap();
        assert_eq!(model.lifecycle, "disabled");
        assert!(!model.routable);
    }

    #[test]
    fn non_generation_catalog_entries_are_visible_but_not_routable() {
        let registry = ProviderRegistry::built_in();
        let model = available_model(
            &registry,
            "openai",
            "text-embedding-3-small".into(),
            "provider_catalog",
        )
        .unwrap();
        assert!(!model.routable);
        assert_eq!(model.capabilities, None);
        assert_eq!(model.pricing, None);

        let fine_tuned = available_model(
            &registry,
            "openai",
            "ft:gpt-4.1-mini:team:project:id".into(),
            "provider_catalog",
        )
        .unwrap();
        assert!(fine_tuned.routable);
    }
}
