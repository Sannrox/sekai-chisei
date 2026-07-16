//! Provider-neutral capability contracts used before gateway upstream contact.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, RwLock};

pub const CAPABILITY_MATRIX_VERSION: &str = "chisei.provider-capabilities/v1";
pub const PROVIDER_REGISTRY_VERSION: &str = "chisei.provider-registry/v3";
const PROVIDER_REGISTRY_FRESH_LOCK: &str = "chisei.provider-registry-lock/v2:fresh";
const PROVIDER_REGISTRY_PUBLICATION_STALE_AFTER: std::time::Duration =
    std::time::Duration::from_secs(60 * 60);
pub const RESPONSES_REQUEST_FIELDS: &[&str] = &[
    "model",
    "input",
    "instructions",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "max_output_tokens",
    "stream",
    "metadata",
    "previous_response_id",
    "reasoning",
    "text",
    "temperature",
    "top_p",
    "truncation",
    "store",
];

pub fn normalize_responses_request(body: &[u8]) -> Result<Vec<u8>, String> {
    validate_responses_request_fields(body)?;
    let mut value: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| format!("invalid JSON: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "Responses request must be a JSON object".to_string())?;
    if object
        .get("store")
        .is_some_and(|value| value.as_bool() != Some(false))
    {
        return Err("Responses store must be false".into());
    }
    object.insert("store".into(), serde_json::Value::Bool(false));
    serde_json::to_vec(&value).map_err(|error| error.to_string())
}

pub fn validate_responses_request_fields(body: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| format!("invalid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "Responses request must be a JSON object".to_string())?;
    let mut unsupported = object
        .keys()
        .filter(|field| !RESPONSES_REQUEST_FIELDS.contains(&field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    unsupported.sort();
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(format!(
        "unsupported Responses request fields: {}",
        unsupported.join(", ")
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub responses: bool,
    pub streaming: bool,
    pub tools: bool,
    pub parallel_tools: bool,
    pub structured_output: bool,
    pub reasoning_controls: bool,
    pub modalities: Vec<String>,
    pub provider_continuation: bool,
    pub reports_usage: bool,
    pub partial_usage: bool,
    pub context_tokens: u64,
    pub output_tokens: Option<u64>,
    #[serde(default)]
    pub built_in_tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEndpointProfile {
    pub base_url_env: String,
    pub default_base_url: Option<String>,
    pub api_key_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageNormalizationProfile {
    pub version: String,
    pub input_tokens: bool,
    pub output_tokens: bool,
    pub reasoning_tokens: bool,
    pub cache_read_tokens: bool,
    pub cache_write_tokens: bool,
    pub partial_responses: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingProfile {
    pub version: String,
    pub source: String,
    pub observed_at: Option<String>,
    #[serde(default)]
    pub dimensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderGovernanceProfile {
    pub metadata_status: String,
    pub data_retention: Option<String>,
    pub training_use: Option<String>,
    #[serde(default)]
    pub regions: Vec<String>,
    pub zero_data_retention_eligible: Option<bool>,
    pub contractual_status: Option<String>,
    pub terms_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderProfile {
    pub provider: String,
    pub profile_version: String,
    pub lifecycle: String,
    pub transport: String,
    pub model_namespace: Option<String>,
    pub accepted_model_patterns: Vec<String>,
    #[serde(default)]
    pub excluded_model_prefixes: Vec<String>,
    pub endpoint: ProviderEndpointProfile,
    pub protocol_surfaces: Vec<String>,
    #[serde(default)]
    pub request_adaptations: Vec<String>,
    #[serde(default)]
    pub response_adaptations: Vec<String>,
    pub capabilities: ProviderCapabilities,
    pub usage_normalization: UsageNormalizationProfile,
    pub error_normalization_version: String,
    pub pricing: PricingProfile,
    pub governance: ProviderGovernanceProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRegistry {
    pub version: String,
    pub profiles: Vec<ProviderProfile>,
    #[serde(default)]
    pub state_version: u64,
    #[serde(default)]
    pub lifecycle_overrides: Vec<RegistryLifecycleOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryLifecycleOverride {
    pub target_kind: String,
    pub target: String,
    pub state: String,
    pub version: u64,
    pub actor: String,
    pub reason: String,
    pub changed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryLifecycleMutation {
    #[serde(flatten)]
    pub lifecycle_override: RegistryLifecycleOverride,
    pub durability_confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durability_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderRegistryState {
    registry_version: String,
    state_version: u64,
    lifecycle_overrides: Vec<RegistryLifecycleOverride>,
}

static AUTHORITATIVE_PROVIDER_REGISTRY: LazyLock<RwLock<ProviderRegistry>> =
    LazyLock::new(|| RwLock::new(ProviderRegistry::built_in()));
static ASYNC_PROVIDER_REGISTRY_REFRESH: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
tokio::task_local! {
    static REQUEST_PROVIDER_REGISTRY: ProviderRegistry;
    static REQUEST_CANARY_ADMISSION: bool;
}

pub async fn with_provider_registry_snapshot<F, T>(registry: ProviderRegistry, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    REQUEST_PROVIDER_REGISTRY.scope(registry, future).await
}

pub async fn with_canary_admission<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    REQUEST_CANARY_ADMISSION.scope(true, future).await
}

pub fn provider_registry_snapshot() -> ProviderRegistry {
    if let Ok(registry) = REQUEST_PROVIDER_REGISTRY.try_with(Clone::clone) {
        return registry;
    }
    AUTHORITATIVE_PROVIDER_REGISTRY
        .read()
        .expect("provider registry lock is not poisoned")
        .clone()
}

pub fn provider_registry_state_version() -> u64 {
    provider_registry_snapshot().state_version
}

pub fn provider_registry_state_path(db_path: &str) -> PathBuf {
    if let Some(path) =
        std::env::var_os("CHISEI_PROVIDER_REGISTRY_STATE_PATH").filter(|path| !path.is_empty())
    {
        return PathBuf::from(path);
    }
    Path::new(db_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("provider-registry-state.json")
}

pub fn refresh_provider_registry(path: &Path) -> Result<(), String> {
    let registry = load_provider_registry_snapshot(path)?;
    *AUTHORITATIVE_PROVIDER_REGISTRY
        .write()
        .map_err(|_| "provider registry lock is poisoned".to_string())? = registry;
    Ok(())
}

fn load_provider_registry_snapshot(path: &Path) -> Result<ProviderRegistry, String> {
    let locks = open_registry_locks(path)?;
    locks.lock()?;
    let registry = read_or_initialize_provider_registry(
        path,
        locks.legacy_state_is_ambiguous()?,
        legacy_registry_initialization_allowed(),
    )?;
    Ok(registry)
}

pub async fn refresh_provider_registry_async(path: &Path) -> Result<ProviderRegistry, String> {
    let _refresh = ASYNC_PROVIDER_REGISTRY_REFRESH.lock().await;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || load_provider_registry_snapshot(&path))
        .await
        .map_err(|error| format!("provider registry refresh task failed: {error}"))?
}

pub fn validate_provider_registry_storage(path: &Path) -> Result<(), String> {
    ensure_parent_exists(path)?;
    let source = registry_parent(path).join(format!(
        ".provider-registry-link-source-{}",
        uuid::Uuid::new_v4()
    ));
    let target = registry_parent(path).join(format!(
        ".provider-registry-link-target-{}",
        uuid::Uuid::new_v4()
    ));
    let probe_result: Result<(), String> = (|| {
        let source_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&source)
            .map_err(|error| format!("create provider registry storage probe: {error}"))?;
        source_file
            .sync_all()
            .map_err(|error| format!("persist provider registry storage probe: {error}"))?;
        std::fs::hard_link(&source, &target).map_err(|error| {
            format!(
                "provider registry state directory must support same-directory hard links: {error}"
            )
        })?;
        Ok(())
    })();
    let target_cleanup = remove_file_if_present(&target)
        .map_err(|error| format!("remove provider registry link probe: {error}"));
    let source_cleanup = remove_file_if_present(&source)
        .map_err(|error| format!("remove provider registry source probe: {error}"));
    probe_result?;
    target_cleanup?;
    source_cleanup?;
    Ok(())
}

pub fn resolve_registered_model(requested: &str) -> Result<ResolvedProviderModel, String> {
    provider_registry_snapshot().resolve_model(requested)
}

pub fn resolve_registered_model_for_provider(
    requested: &str,
    wire_provider: &str,
) -> Result<ResolvedProviderModel, String> {
    provider_registry_snapshot().resolve_model_for_provider(requested, wire_provider)
}

pub fn ensure_registered_provider_available(provider: &str) -> Result<(), String> {
    provider_registry_snapshot().ensure_provider_available(provider)
}

pub fn update_registry_lifecycle(
    state_path: &Path,
    target_kind: &str,
    target: &str,
    state: &str,
    actor: &str,
    reason: &str,
    changed_at: &str,
) -> Result<RegistryLifecycleOverride, String> {
    update_registry_lifecycle_with_outcome(
        state_path,
        target_kind,
        target,
        state,
        actor,
        reason,
        changed_at,
    )
    .map(|mutation| mutation.lifecycle_override)
}

pub fn update_registry_lifecycle_with_outcome(
    state_path: &Path,
    target_kind: &str,
    target: &str,
    state: &str,
    actor: &str,
    reason: &str,
    changed_at: &str,
) -> Result<RegistryLifecycleMutation, String> {
    update_registry_lifecycle_with_expected_version(
        state_path,
        target_kind,
        target,
        state,
        actor,
        reason,
        (changed_at, None),
    )
}

fn update_registry_lifecycle_with_expected_version(
    state_path: &Path,
    target_kind: &str,
    target: &str,
    state: &str,
    actor: &str,
    reason: &str,
    commit: (&str, Option<u64>),
) -> Result<RegistryLifecycleMutation, String> {
    let (changed_at, expected_state_version) = commit;
    validate_lifecycle_update_fields(target_kind, target, state, actor, reason)?;
    let locks = open_registry_locks(state_path)?;
    locks.lock()?;
    let mut registry = read_or_initialize_provider_registry(
        state_path,
        locks.legacy_state_is_ambiguous()?,
        legacy_registry_initialization_allowed(),
    )?;
    if expected_state_version.is_some_and(|expected| registry.state_version != expected) {
        return Err("provider registry changed after lifecycle preconditions were verified".into());
    }
    registry.validate_lifecycle_target(target_kind, target)?;
    if state == "enabled" {
        let provider = match target_kind {
            "provider" => Some(target),
            "profile" => registry
                .profiles
                .iter()
                .find(|profile| profile.profile_version == target)
                .map(|profile| profile.provider.as_str()),
            "model" | "capability" => target.split_once(['/', ':']).map(|(provider, _)| provider),
            _ => None,
        };
        if provider
            .and_then(|provider| registry.profile(provider))
            .is_some_and(|profile| profile.lifecycle == "experimental")
            && !provider.is_some_and(|provider| {
                registry
                    .effective_profile(provider)
                    .is_some_and(|profile| profile.lifecycle == "canary")
            })
        {
            return Err("experimental providers must enter canary before enabled promotion".into());
        }
    }
    let target = if target_kind == "model" {
        canonical_model_target(target)?
    } else {
        target.to_string()
    };
    registry.state_version = registry
        .state_version
        .checked_add(1)
        .ok_or_else(|| "provider registry state version is exhausted".to_string())?;
    let lifecycle_override = RegistryLifecycleOverride {
        target_kind: target_kind.into(),
        target,
        state: state.into(),
        version: registry.state_version,
        actor: actor.into(),
        reason: reason.into(),
        changed_at: changed_at.into(),
    };
    registry
        .lifecycle_overrides
        .push(lifecycle_override.clone());
    let write_outcome = write_provider_registry_state(state_path, &registry)?;
    let publication_warning = match AUTHORITATIVE_PROVIDER_REGISTRY.write() {
        Ok(mut authoritative) => {
            *authoritative = registry;
            None
        }
        Err(_) => Some(
            "provider registry state was applied but the process snapshot lock is poisoned"
                .to_string(),
        ),
    };
    let durability_confirmed = write_outcome.durability_warning.is_none();
    Ok(RegistryLifecycleMutation {
        lifecycle_override,
        durability_confirmed,
        durability_warning: write_outcome.durability_warning,
        publication_warning,
    })
}

pub async fn update_registry_lifecycle_async(
    state_path: PathBuf,
    target_kind: String,
    target: String,
    state: String,
    actor: String,
    reason: String,
    commit: (String, Option<u64>),
) -> Result<RegistryLifecycleMutation, String> {
    tokio::task::spawn_blocking(move || {
        let (changed_at, expected_state_version) = commit;
        update_registry_lifecycle_with_expected_version(
            &state_path,
            &target_kind,
            &target,
            &state,
            &actor,
            &reason,
            (&changed_at, expected_state_version),
        )
    })
    .await
    .map_err(|error| format!("provider registry lifecycle worker failed: {error}"))?
}

#[cfg(test)]
fn read_provider_registry(path: &Path) -> Result<ProviderRegistry, String> {
    let locks = open_registry_locks(path)?;
    locks.lock()?;
    read_or_initialize_provider_registry(path, locks.legacy_state_is_ambiguous()?, false)
}

struct ProviderRegistryLocks {
    legacy: File,
    current: File,
}

impl ProviderRegistryLocks {
    fn lock(&self) -> Result<(), String> {
        self.legacy
            .lock()
            .map_err(|error| format!("lock legacy provider registry state: {error}"))?;
        self.current
            .lock()
            .map_err(|error| format!("lock provider registry state: {error}"))
    }

    fn legacy_state_is_ambiguous(&self) -> Result<bool, String> {
        let mut bytes = Vec::new();
        let mut legacy = &self.legacy;
        legacy
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("seek legacy provider registry lock: {error}"))?;
        legacy
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read legacy provider registry lock: {error}"))?;
        if bytes.is_empty() {
            return Ok(true);
        }
        Ok(bytes != PROVIDER_REGISTRY_FRESH_LOCK.as_bytes())
    }
}

fn open_registry_locks(path: &Path) -> Result<ProviderRegistryLocks, String> {
    let legacy_path = registry_legacy_lock_path(path);
    let lock_path = registry_lock_path(path);
    ensure_parent_exists(&lock_path)?;
    let legacy = open_or_publish_legacy_lock(&legacy_path)?;
    let current = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| format!("open provider registry lock: {error}"))?;
    Ok(ProviderRegistryLocks { legacy, current })
}

fn open_or_publish_legacy_lock(path: &Path) -> Result<File, String> {
    cleanup_stale_registry_publications(path)?;
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(lock) => return Ok(lock),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("open legacy provider registry lock: {error}")),
    }
    publish_prepared_legacy_lock_with(path, || {})
}

fn publish_prepared_legacy_lock_with(
    path: &Path,
    before_publish: impl FnOnce(),
) -> Result<File, String> {
    let temp_path = registry_publication_path(path, &uuid::Uuid::new_v4().to_string());
    let mut temp = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&temp_path)
        .map_err(|error| format!("prepare legacy provider registry lock: {error}"))?;
    temp.lock()
        .map_err(|error| format!("lock legacy provider registry publication: {error}"))?;
    if let Err(error) = temp
        .write_all(PROVIDER_REGISTRY_FRESH_LOCK.as_bytes())
        .and_then(|_| temp.sync_all())
    {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("initialize legacy provider registry lock: {error}"));
    }
    before_publish();
    match std::fs::hard_link(&temp_path, path) {
        Ok(()) => {
            if let Err(error) = sync_parent_directory(path) {
                let _ = std::fs::remove_file(&temp_path);
                return Err(error);
            }
            let _ = std::fs::remove_file(&temp_path);
            temp.unlock()
                .map_err(|error| format!("unlock published provider registry lock: {error}"))?;
            Ok(temp)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&temp_path);
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|error| format!("open published legacy provider registry lock: {error}"))
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temp_path);
            Err(format!("publish legacy provider registry lock: {error}"))
        }
    }
}

fn registry_publication_path(path: &Path, suffix: &str) -> PathBuf {
    let mut publication = path.as_os_str().to_os_string();
    publication.push(format!(".publish-{suffix}"));
    PathBuf::from(publication)
}

fn cleanup_stale_registry_publications(path: &Path) -> Result<(), String> {
    let mut legacy_base = path.to_path_buf();
    legacy_base.set_extension("");
    let entries = std::fs::read_dir(registry_parent(path))
        .map_err(|error| format!("list provider registry publication files: {error}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("read provider registry publication: {error}"))?;
        let entry_path = entry.path();
        let Some(publication_id) = entry_path
            .extension()
            .and_then(|extension| extension.to_str())
            .and_then(|extension| extension.strip_prefix("publish-"))
        else {
            continue;
        };
        let Ok(parsed_id) = uuid::Uuid::parse_str(publication_id) else {
            continue;
        };
        if parsed_id.get_version_num() != 4 || parsed_id.to_string() != publication_id {
            continue;
        }
        let mut publication_base = entry_path.clone();
        publication_base.set_extension("");
        if publication_base.file_name() != path.file_name()
            && publication_base.file_name() != legacy_base.file_name()
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect provider registry publication: {error}"))?;
        if !file_type.is_file() {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|error| format!("inspect provider registry publication: {error}"))?;
        let stale = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= PROVIDER_REGISTRY_PUBLICATION_STALE_AFTER);
        if stale {
            let mut publication = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&entry_path)
                .map_err(|error| format!("open stale provider registry publication: {error}"))?;
            match publication.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => continue,
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(format!("lock stale provider registry publication: {error}"));
                }
            }
            let mut marker = Vec::with_capacity(PROVIDER_REGISTRY_FRESH_LOCK.len() + 1);
            Read::take(
                &mut publication,
                (PROVIDER_REGISTRY_FRESH_LOCK.len() + 1) as u64,
            )
            .read_to_end(&mut marker)
            .map_err(|error| format!("read stale provider registry publication: {error}"))?;
            if marker != PROVIDER_REGISTRY_FRESH_LOCK.as_bytes() {
                continue;
            }
            #[cfg(unix)]
            quarantine_and_remove_publication(&entry_path, &publication)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn quarantine_and_remove_publication(entry_path: &Path, opened: &File) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    let quarantine = registry_parent(entry_path).join(format!(
        ".provider-registry-cleanup-{}",
        uuid::Uuid::new_v4()
    ));
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&quarantine)
        .map_err(|error| format!("create provider registry cleanup quarantine: {error}"))?;
    if let Err(error) =
        std::fs::set_permissions(&quarantine, std::fs::Permissions::from_mode(0o700))
    {
        let _ = std::fs::remove_dir(&quarantine);
        return Err(format!(
            "secure provider registry cleanup quarantine: {error}"
        ));
    }
    let claimed = quarantine.join("publication");
    match std::fs::rename(entry_path, &claimed) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::remove_dir(&quarantine).map_err(|cleanup_error| {
                format!("remove empty provider registry cleanup quarantine: {cleanup_error}")
            })?;
            return Ok(());
        }
        Err(error) => {
            let _ = std::fs::remove_dir(&quarantine);
            return Err(format!(
                "claim stale provider registry publication: {error}"
            ));
        }
    }

    let opened_metadata = opened
        .metadata()
        .map_err(|error| format!("inspect opened provider registry publication: {error}"))?;
    let claimed_metadata = std::fs::symlink_metadata(&claimed)
        .map_err(|error| format!("inspect claimed provider registry publication: {error}"))?;
    if opened_metadata.dev() != claimed_metadata.dev()
        || opened_metadata.ino() != claimed_metadata.ino()
    {
        if std::fs::hard_link(&claimed, entry_path).is_ok() {
            std::fs::remove_file(&claimed).map_err(|error| {
                format!("remove restored provider registry publication claim: {error}")
            })?;
            std::fs::remove_dir(&quarantine)
                .map_err(|error| format!("remove provider registry cleanup quarantine: {error}"))?;
        }
        return Ok(());
    }

    std::fs::remove_file(&claimed)
        .map_err(|error| format!("remove claimed provider registry publication: {error}"))?;
    std::fs::remove_dir(&quarantine)
        .map_err(|error| format!("remove provider registry cleanup quarantine: {error}"))?;
    Ok(())
}

fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn read_or_initialize_provider_registry(
    path: &Path,
    legacy_lock_exists: bool,
    allow_legacy_initialization: bool,
) -> Result<ProviderRegistry, String> {
    let initialization_path = registry_initialization_path(path);
    let initialized = registry_initialization_marker_exists(&initialization_path)?;
    match read_provider_registry_unlocked(path) {
        Ok(registry) => {
            if !initialized {
                write_registry_initialization_marker(&initialization_path)?;
            }
            Ok(registry)
        }
        Err(error)
            if !initialized
                && is_missing_registry_error(&error)
                && (!legacy_lock_exists || allow_legacy_initialization) =>
        {
            let registry = ProviderRegistry::built_in();
            write_provider_registry_state(path, &registry)?;
            write_registry_initialization_marker(&initialization_path)?;
            Ok(registry)
        }
        Err(error) if !initialized && is_missing_registry_error(&error) => Err(format!(
            "{error}; legacy lock state is ambiguous, recover the state file or set CHISEI_PROVIDER_REGISTRY_ALLOW_LEGACY_INITIALIZATION=1 once"
        )),
        Err(error) => Err(error),
    }
}

fn legacy_registry_initialization_allowed() -> bool {
    std::env::var("CHISEI_PROVIDER_REGISTRY_ALLOW_LEGACY_INITIALIZATION").as_deref() == Ok("1")
}

fn read_provider_registry_unlocked(path: &Path) -> Result<ProviderRegistry, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("provider registry state is missing: {error}"));
        }
        Err(error) => return Err(format!("read provider registry state: {error}")),
    };
    let state: ProviderRegistryState = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse provider registry state: {error}"))?;
    if state.registry_version != PROVIDER_REGISTRY_VERSION {
        return Err(format!(
            "provider registry state version {:?} does not match {:?}",
            state.registry_version, PROVIDER_REGISTRY_VERSION
        ));
    }
    let mut registry = ProviderRegistry::built_in();
    validate_persisted_lifecycle_history(&registry, &state)?;
    registry.state_version = state.state_version;
    registry.lifecycle_overrides = state.lifecycle_overrides;
    Ok(registry)
}

fn is_missing_registry_error(error: &str) -> bool {
    error.starts_with("provider registry state is missing:")
}

fn validate_persisted_lifecycle_history(
    registry: &ProviderRegistry,
    state: &ProviderRegistryState,
) -> Result<(), String> {
    let mut previous_version = 0;
    for lifecycle_override in &state.lifecycle_overrides {
        validate_lifecycle_update_fields(
            &lifecycle_override.target_kind,
            &lifecycle_override.target,
            &lifecycle_override.state,
            &lifecycle_override.actor,
            &lifecycle_override.reason,
        )?;
        registry.validate_lifecycle_target(
            &lifecycle_override.target_kind,
            &lifecycle_override.target,
        )?;
        if lifecycle_override.version != previous_version + 1 {
            return Err("provider registry lifecycle versions must be consecutive from 1".into());
        }
        previous_version = lifecycle_override.version;
    }
    if previous_version != state.state_version {
        return Err("provider registry state version must match its latest lifecycle entry".into());
    }
    Ok(())
}

struct RegistryStateWriteOutcome {
    durability_warning: Option<String>,
}

fn write_provider_registry_state(
    path: &Path,
    registry: &ProviderRegistry,
) -> Result<RegistryStateWriteOutcome, String> {
    ensure_parent_exists(path)?;
    let state = ProviderRegistryState {
        registry_version: registry.version.clone(),
        state_version: registry.state_version,
        lifecycle_overrides: registry.lifecycle_overrides.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&state)
        .map_err(|error| format!("serialize provider registry state: {error}"))?;
    let temp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|error| format!("create provider registry state: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("secure provider registry state: {error}"))?;
    }
    if let Err(error) = temp.write_all(&bytes).and_then(|_| temp.sync_all()) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("write provider registry state: {error}"));
    }
    if let Err(error) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("replace provider registry state: {error}"));
    }
    let durability_warning = sync_parent_directory(path).err();
    Ok(RegistryStateWriteOutcome { durability_warning })
}

fn registry_lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock.v2");
    PathBuf::from(lock)
}

fn registry_legacy_lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
}

fn registry_initialization_path(path: &Path) -> PathBuf {
    let mut marker = path.as_os_str().to_os_string();
    marker.push(".initialized");
    PathBuf::from(marker)
}

fn write_registry_initialization_marker(path: &Path) -> Result<(), String> {
    ensure_parent_exists(path)?;
    let temp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let mut temp = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|error| format!("create provider registry initialization marker: {error}"))?;
    if let Err(error) = temp
        .write_all(PROVIDER_REGISTRY_VERSION.as_bytes())
        .and_then(|_| temp.sync_all())
    {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!(
            "write provider registry initialization marker: {error}"
        ));
    }
    if let Err(error) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!(
            "replace provider registry initialization marker: {error}"
        ));
    }
    sync_parent_directory(path)
}

fn registry_initialization_marker_exists(path: &Path) -> Result<bool, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "read provider registry initialization marker: {error}"
            ));
        }
    };
    if bytes != PROVIDER_REGISTRY_VERSION.as_bytes() {
        return Err("provider registry initialization marker version does not match".into());
    }
    Ok(true)
}

fn ensure_parent_exists(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(registry_parent(path))
        .map_err(|error| format!("create provider registry state directory: {error}"))?;
    Ok(())
}

fn registry_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let directory = File::open(registry_parent(path))
            .map_err(|error| format!("open provider registry state directory: {error}"))?;
        directory
            .sync_all()
            .map_err(|error| format!("persist provider registry state directory: {error}"))?;
    }
    Ok(())
}

pub fn validate_registry_lifecycle_update(
    target_kind: &str,
    target: &str,
    state: &str,
    actor: &str,
    reason: &str,
) -> Result<(), String> {
    validate_lifecycle_update_fields(target_kind, target, state, actor, reason)?;
    let registry = provider_registry_snapshot();
    registry.validate_lifecycle_target(target_kind, target)?;
    Ok(())
}

fn validate_lifecycle_update_fields(
    target_kind: &str,
    target: &str,
    state: &str,
    actor: &str,
    reason: &str,
) -> Result<(), String> {
    const TARGET_KINDS: &[&str] = &["provider", "profile", "model", "capability"];
    const STATES: &[&str] = &[
        "experimental",
        "canary",
        "enabled",
        "degraded",
        "disabled",
        "retiring",
    ];
    if !TARGET_KINDS.contains(&target_kind) {
        return Err(format!("unsupported lifecycle target kind {target_kind:?}"));
    }
    if !STATES.contains(&state) {
        return Err(format!("unsupported lifecycle state {state:?}"));
    }
    if target.trim().is_empty() || reason.trim().is_empty() || actor.trim().is_empty() {
        return Err("lifecycle target, actor, and reason must be non-empty".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProviderModel {
    pub provider: String,
    pub requested_model: String,
    pub canonical_model: String,
    pub upstream_model: String,
    pub requested_alias: Option<String>,
    pub profile_version: String,
}

impl ProviderRegistry {
    pub fn lifecycle_state_for_target(&self, target_kind: &str, target: &str) -> Option<&str> {
        let canonical;
        let target = if target_kind == "model" {
            canonical = canonical_model_target(target).ok()?;
            canonical.as_str()
        } else {
            target
        };
        self.latest_lifecycle_override(target_kind, target)
            .map(|lifecycle| lifecycle.state.as_str())
    }

    pub fn built_in() -> Self {
        Self {
            version: PROVIDER_REGISTRY_VERSION.into(),
            profiles: vec![
                profile(
                    "openai",
                    "openai-compatible",
                    Some("openai/"),
                    (
                        "CHISEI_OPENAI_BASE_URL",
                        Some("https://api.openai.com/v1"),
                        Some("OPENAI_API_KEY"),
                    ),
                    &["responses", "chat_completions", "models"],
                    &[],
                    ProviderCapabilities {
                        responses: true,
                        streaming: true,
                        tools: true,
                        parallel_tools: true,
                        structured_output: true,
                        reasoning_controls: true,
                        modalities: vec!["text".into(), "image".into()],
                        // The upstream supports opaque response ids, but the
                        // gateway cannot safely expose them until ownership is
                        // bound to the authenticated caller.
                        provider_continuation: false,
                        reports_usage: true,
                        partial_usage: true,
                        context_tokens: 400_000,
                        output_tokens: Some(128_000),
                        built_in_tools: vec![],
                    },
                ),
                profile(
                    "ollama",
                    "openai-compatible",
                    Some("ollama/"),
                    (
                        "CHISEI_OLLAMA_BASE_URL",
                        Some("http://127.0.0.1:11434/v1"),
                        None,
                    ),
                    &["responses", "chat_completions", "models"],
                    &["strip_model_namespace"],
                    ProviderCapabilities {
                        responses: true,
                        streaming: true,
                        tools: true,
                        parallel_tools: false,
                        structured_output: true,
                        reasoning_controls: false,
                        modalities: vec!["text".into()],
                        provider_continuation: false,
                        reports_usage: true,
                        partial_usage: false,
                        context_tokens: 128_000,
                        output_tokens: Some(32_000),
                        built_in_tools: vec![],
                    },
                ),
                profile(
                    "native",
                    "openai-compatible",
                    Some("native/"),
                    ("NATIVE_LLM_URL", None, None),
                    &["responses", "chat_completions"],
                    &[],
                    ProviderCapabilities {
                        responses: true,
                        streaming: true,
                        tools: false,
                        parallel_tools: false,
                        structured_output: false,
                        reasoning_controls: false,
                        modalities: vec!["text".into()],
                        provider_continuation: false,
                        reports_usage: true,
                        partial_usage: false,
                        context_tokens: 128_000,
                        output_tokens: Some(32_000),
                        built_in_tools: vec![],
                    },
                ),
                profile(
                    "anthropic",
                    "anthropic-messages",
                    Some("anthropic/"),
                    (
                        "CHISEI_ANTHROPIC_BASE_URL",
                        Some("https://api.anthropic.com/v1"),
                        Some("ANTHROPIC_API_KEY"),
                    ),
                    &["messages", "count_tokens"],
                    &[],
                    ProviderCapabilities {
                        responses: false,
                        streaming: true,
                        tools: true,
                        parallel_tools: true,
                        structured_output: true,
                        reasoning_controls: true,
                        modalities: vec!["text".into(), "image".into()],
                        provider_continuation: false,
                        reports_usage: true,
                        partial_usage: true,
                        context_tokens: 200_000,
                        output_tokens: Some(64_000),
                        built_in_tools: vec![],
                    },
                ),
                xai_profile(),
                meta_profile(),
            ],
            state_version: 0,
            lifecycle_overrides: Vec::new(),
        }
    }

    pub fn profile(&self, provider: &str) -> Option<&ProviderProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.provider == provider)
    }

    pub fn effective_profile(&self, provider: &str) -> Option<ProviderProfile> {
        let mut profile = self.profile(provider)?.clone();
        let provider_override = self.latest_lifecycle_override("provider", &profile.provider);
        let profile_override = self.latest_lifecycle_override("profile", &profile.profile_version);
        let effective_lifecycle = if provider_override
            .is_some_and(|lifecycle_override| lifecycle_override.state == "disabled")
            || profile_override
                .is_some_and(|lifecycle_override| lifecycle_override.state == "disabled")
        {
            "disabled".into()
        } else {
            [provider_override, profile_override]
                .into_iter()
                .flatten()
                .max_by_key(|lifecycle_override| lifecycle_override.version)
                .map(|lifecycle_override| lifecycle_override.state.clone())
                .unwrap_or_else(|| profile.lifecycle.clone())
        };
        profile.lifecycle = effective_lifecycle;
        let mut seen_capabilities = HashSet::new();
        for lifecycle_override in self.lifecycle_overrides.iter().rev() {
            if lifecycle_override.target_kind != "capability"
                || !seen_capabilities.insert(lifecycle_override.target.clone())
            {
                continue;
            }
            let canary_admitted = REQUEST_CANARY_ADMISSION
                .try_with(|allowed| *allowed)
                .unwrap_or(false);
            if (lifecycle_override.state == "disabled"
                || lifecycle_override.state == "experimental"
                || (lifecycle_override.state == "canary" && !canary_admitted))
                && let Some((target_provider, capability)) =
                    lifecycle_override.target.split_once(':')
                && target_provider == profile.provider
            {
                disable_capability(&mut profile.capabilities, capability);
            }
        }
        Some(profile)
    }

    pub fn resolve_model(&self, requested: &str) -> Result<ResolvedProviderModel, String> {
        validate_model_identifier(requested)?;
        let (provider, upstream_model) = resolve_provider_model(requested)?;
        let profile = self
            .profile(provider)
            .ok_or_else(|| format!("provider profile {provider:?} is not registered"))?;
        self.ensure_provider_available(provider)?;
        let canonical_model = format!("{provider}/{upstream_model}");
        if !profile
            .accepted_model_patterns
            .iter()
            .any(|pattern| model_pattern_matches(pattern, requested, &canonical_model))
            || profile
                .excluded_model_prefixes
                .iter()
                .any(|prefix| requested.starts_with(prefix) || canonical_model.starts_with(prefix))
        {
            return Err(format!(
                "model {requested:?} is not admitted by provider profile {:?}",
                profile.profile_version
            ));
        }
        if let Some(lifecycle_override) = self.latest_lifecycle_override("model", &canonical_model)
        {
            let canary_admitted = REQUEST_CANARY_ADMISSION
                .try_with(|allowed| *allowed)
                .unwrap_or(false);
            if lifecycle_override.state == "disabled"
                || lifecycle_override.state == "experimental"
                || (lifecycle_override.state == "canary" && !canary_admitted)
            {
                return Err(format!(
                    "{} {:?} is {} at registry state version {}",
                    lifecycle_override.target_kind,
                    lifecycle_override.target,
                    lifecycle_override.state,
                    lifecycle_override.version
                ));
            }
        }
        Ok(ResolvedProviderModel {
            provider: provider.into(),
            requested_model: requested.into(),
            requested_alias: (requested != canonical_model).then(|| requested.into()),
            canonical_model,
            upstream_model: upstream_model.into(),
            profile_version: profile.profile_version.clone(),
        })
    }

    pub fn resolve_model_for_provider(
        &self,
        requested: &str,
        wire_provider: &str,
    ) -> Result<ResolvedProviderModel, String> {
        match self.resolve_model(requested) {
            Ok(resolved) => Ok(resolved),
            Err(error)
                if error.starts_with("unregistered bare model identifier")
                    && !requested.contains('/')
                    && !requested.eq_ignore_ascii_case("kiro")
                    && self.profile(wire_provider).is_some() =>
            {
                self.resolve_model(&format!("{wire_provider}/{requested}"))
                    .map(|mut resolved| {
                        resolved.requested_model = requested.into();
                        resolved.requested_alias = Some(requested.into());
                        resolved
                    })
            }
            Err(error) => Err(error),
        }
    }

    pub fn ensure_provider_available(&self, provider: &str) -> Result<(), String> {
        let profile = self
            .effective_profile(provider)
            .ok_or_else(|| format!("provider profile {provider:?} is not registered"))?;
        if profile.lifecycle == "disabled" {
            return Err(format!("provider {provider:?} is disabled"));
        }
        if profile.lifecycle == "experimental" {
            return Err(format!(
                "provider {provider:?} is experimental and requires an explicit lifecycle promotion"
            ));
        }
        if profile.lifecycle == "canary"
            && !REQUEST_CANARY_ADMISSION
                .try_with(|allowed| *allowed)
                .unwrap_or(false)
        {
            return Err(format!(
                "provider {provider:?} is canary-only and requires explicit bounded admission"
            ));
        }
        Ok(())
    }

    pub fn model_or_provider_is_disabled(&self, requested: &str) -> bool {
        if validate_model_identifier(requested).is_err() {
            return false;
        }
        let Ok((provider, upstream_model)) = resolve_provider_model(requested) else {
            return false;
        };
        if self
            .effective_profile(provider)
            .is_some_and(|profile| profile.lifecycle == "disabled")
        {
            return true;
        }
        let canonical_model = format!("{provider}/{upstream_model}");
        self.latest_lifecycle_override("model", &canonical_model)
            .is_some_and(|lifecycle| lifecycle.state == "disabled")
    }

    pub fn model_or_provider_is_disabled_for_provider(
        &self,
        requested: &str,
        wire_provider: &str,
    ) -> bool {
        if self.model_or_provider_is_disabled(requested) {
            return true;
        }
        !requested.contains('/')
            && self.profile(wire_provider).is_some()
            && self.model_or_provider_is_disabled(&format!("{wire_provider}/{requested}"))
    }

    pub fn model_or_provider_is_unavailable_for_provider(
        &self,
        requested: &str,
        wire_provider: &str,
    ) -> bool {
        if validate_model_identifier(requested).is_err() {
            return false;
        }
        let canary_admitted = REQUEST_CANARY_ADMISSION
            .try_with(|allowed| *allowed)
            .unwrap_or(false);
        let unavailable = |state: &str| {
            matches!(state, "disabled" | "experimental") || (state == "canary" && !canary_admitted)
        };
        let check = |model: &str| {
            let Ok((provider, upstream_model)) = resolve_provider_model(model) else {
                return false;
            };
            if self
                .effective_profile(provider)
                .is_some_and(|profile| unavailable(&profile.lifecycle))
            {
                return true;
            }
            let canonical_model = format!("{provider}/{upstream_model}");
            self.latest_lifecycle_override("model", &canonical_model)
                .is_some_and(|lifecycle| unavailable(&lifecycle.state))
        };
        check(requested)
            || (!requested.contains('/')
                && self.profile(wire_provider).is_some()
                && check(&format!("{wire_provider}/{requested}")))
    }

    fn validate_lifecycle_target(&self, target_kind: &str, target: &str) -> Result<(), String> {
        let valid = match target_kind {
            "provider" => self.profile(target).is_some(),
            "profile" => self
                .profiles
                .iter()
                .any(|profile| profile.profile_version == target),
            "model" => {
                validate_model_identifier(target).is_ok()
                    && resolve_provider_model(target)
                        .is_ok_and(|(provider, _)| self.profile(provider).is_some())
            }
            "capability" => target
                .split_once(':')
                .is_some_and(|(provider, capability)| {
                    self.profile(provider).is_some() && is_known_capability(capability)
                }),
            _ => false,
        };
        valid
            .then_some(())
            .ok_or_else(|| format!("unknown {target_kind} lifecycle target {target:?}"))
    }

    fn latest_lifecycle_override(
        &self,
        target_kind: &str,
        target: &str,
    ) -> Option<&RegistryLifecycleOverride> {
        self.lifecycle_overrides
            .iter()
            .rev()
            .find(|candidate| candidate.target_kind == target_kind && candidate.target == target)
    }
}

fn model_pattern_matches(pattern: &str, requested: &str, canonical: &str) -> bool {
    pattern.strip_suffix('*').map_or_else(
        || requested == pattern || canonical == pattern,
        |prefix| requested.starts_with(prefix) || canonical.starts_with(prefix),
    )
}

fn canonical_model_target(model: &str) -> Result<String, String> {
    validate_model_identifier(model)?;
    let (provider, upstream_model) = resolve_provider_model(model)?;
    Ok(format!("{provider}/{upstream_model}"))
}

pub fn resolve_provider_id(model: &str) -> Result<&'static str, String> {
    validate_model_identifier(model)?;
    resolve_provider_model(model).map(|(provider, _)| provider)
}

fn resolve_provider_model(model: &str) -> Result<(&'static str, &str), String> {
    let identifier = model
        .split_once('/')
        .map(|(_, identifier)| identifier)
        .unwrap_or(model);
    if identifier.eq_ignore_ascii_case("kiro") {
        return Err("Kiro is a tool identifier, not a model".into());
    }
    if let Some((namespace, upstream_model)) = model.split_once('/') {
        if upstream_model.is_empty() {
            return Err("model namespace must include a model identifier".into());
        }
        return match namespace {
            "openai" => Ok(("openai", upstream_model)),
            "anthropic" => Ok(("anthropic", upstream_model)),
            "ollama" => Ok(("ollama", upstream_model)),
            "native" => Ok(("native", upstream_model)),
            "xai" => Ok(("xai", upstream_model)),
            "meta" => Ok(("meta", upstream_model)),
            _ => Err(format!("unknown provider namespace {namespace:?}")),
        };
    }
    if model.starts_with("claude") || ANTHROPIC_BARE_ALIASES.contains(&model) {
        Ok(("anthropic", model))
    } else if model.starts_with("native-") || model.starts_with("fallback:") {
        Ok(("native", model))
    } else if is_openai_alias(model) {
        Ok(("openai", model))
    } else {
        Err(format!(
            "unregistered bare model identifier {model:?}; use an advertised provider alias"
        ))
    }
}

const ANTHROPIC_BARE_ALIASES: &[&str] = &["sonnet", "haiku", "opus", "fable"];

const OPENAI_ALIAS_PREFIXES: &[&str] = &[
    "gpt-",
    "o1",
    "o2",
    "o3",
    "o4",
    "o5",
    "ft:gpt-",
    "codex-",
    "text-embedding-",
    "tts-",
];

fn is_openai_alias(model: &str) -> bool {
    OPENAI_ALIAS_PREFIXES
        .iter()
        .any(|prefix| model.starts_with(prefix))
}

fn validate_model_identifier(model: &str) -> Result<(), String> {
    if model.is_empty()
        || model.len() > 128
        || !model.chars().all(|character| {
            character.is_alphanumeric() || matches!(character, '-' | '_' | '.' | '/' | ':')
        })
    {
        return Err(format!("invalid model name: {model:?}"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPath {
    pub provider: String,
    pub profile_version: String,
    pub lifecycle: String,
    pub capabilities: ProviderCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMatrix {
    pub version: String,
    pub paths: Vec<CapabilityPath>,
    pub registry_version: String,
    pub registry_state_version: u64,
    pub lifecycle_overrides: Vec<RegistryLifecycleOverride>,
    pub profiles: Vec<ProviderProfile>,
}

impl CapabilityMatrix {
    pub fn built_in() -> Self {
        let registry = provider_registry_snapshot();
        let profiles = registry
            .profiles
            .iter()
            .filter_map(|profile| registry.effective_profile(&profile.provider))
            .collect::<Vec<_>>();
        let paths = profiles
            .iter()
            .map(|profile| CapabilityPath {
                provider: profile.provider.clone(),
                profile_version: profile.profile_version.clone(),
                lifecycle: profile.lifecycle.clone(),
                capabilities: profile.capabilities.clone(),
            })
            .collect();
        Self {
            version: CAPABILITY_MATRIX_VERSION.into(),
            paths,
            registry_version: registry.version,
            registry_state_version: registry.state_version,
            lifecycle_overrides: public_lifecycle_overrides(registry.lifecycle_overrides),
            profiles,
        }
    }

    pub fn capabilities(&self, provider: &str) -> Option<&ProviderCapabilities> {
        self.paths
            .iter()
            .find(|path| path.provider == provider)
            .map(|path| &path.capabilities)
    }
}

fn public_lifecycle_overrides(
    lifecycle_overrides: Vec<RegistryLifecycleOverride>,
) -> Vec<RegistryLifecycleOverride> {
    lifecycle_overrides
        .into_iter()
        .map(|mut lifecycle_override| {
            lifecycle_override.reason = "redacted".into();
            lifecycle_override
        })
        .collect()
}

fn is_known_capability(capability: &str) -> bool {
    matches!(
        capability,
        "responses"
            | "streaming"
            | "tools"
            | "parallel_tools"
            | "structured_output"
            | "reasoning_controls"
            | "provider_continuation"
            | "reports_usage"
            | "partial_usage"
    ) || capability.starts_with("built_in_tool/")
}

fn disable_capability(capabilities: &mut ProviderCapabilities, capability: &str) {
    match capability {
        "responses" => capabilities.responses = false,
        "streaming" => capabilities.streaming = false,
        "tools" => capabilities.tools = false,
        "parallel_tools" => capabilities.parallel_tools = false,
        "structured_output" => capabilities.structured_output = false,
        "reasoning_controls" => capabilities.reasoning_controls = false,
        "provider_continuation" => capabilities.provider_continuation = false,
        "reports_usage" => capabilities.reports_usage = false,
        "partial_usage" => capabilities.partial_usage = false,
        capability if capability.starts_with("built_in_tool/") => {
            let tool = capability.trim_start_matches("built_in_tool/");
            capabilities
                .built_in_tools
                .retain(|candidate| candidate != tool);
        }
        _ => {}
    }
}

fn profile(
    provider: &str,
    transport: &str,
    model_namespace: Option<&str>,
    endpoint: (&str, Option<&str>, Option<&str>),
    protocol_surfaces: &[&str],
    request_adaptations: &[&str],
    capabilities: ProviderCapabilities,
) -> ProviderProfile {
    let (base_url_env, default_base_url, api_key_env) = endpoint;
    let reports_reasoning = capabilities.reasoning_controls;
    let reports_partial = capabilities.partial_usage;
    let reports_cache_reads = matches!(provider, "openai" | "anthropic" | "xai" | "meta");
    let reports_cache_writes = provider == "anthropic";
    let accepted_model_patterns = match provider {
        "openai" => std::iter::once("openai/*".to_string())
            .chain(
                OPENAI_ALIAS_PREFIXES
                    .iter()
                    .map(|prefix| format!("{prefix}*")),
            )
            .collect(),
        "ollama" => vec!["ollama/*".into()],
        "anthropic" => std::iter::once("anthropic/*".to_string())
            .chain(std::iter::once("claude*".to_string()))
            .chain(ANTHROPIC_BARE_ALIASES.iter().map(|alias| (*alias).into()))
            .collect(),
        "native" => vec!["native/*".into(), "native-*".into(), "fallback:*".into()],
        "xai" => vec!["xai/grok-4.5".into()],
        "meta" => vec!["meta/muse-spark-1.1".into()],
        _ => vec!["fallback:*".into()],
    };
    let excluded_model_prefixes = Vec::new();
    ProviderProfile {
        provider: provider.into(),
        profile_version: format!("{provider}.builtin/v3"),
        lifecycle: "enabled".into(),
        transport: transport.into(),
        model_namespace: model_namespace.map(str::to_string),
        accepted_model_patterns,
        excluded_model_prefixes,
        endpoint: ProviderEndpointProfile {
            base_url_env: base_url_env.into(),
            default_base_url: default_base_url.map(str::to_string),
            api_key_env: api_key_env.map(str::to_string),
        },
        protocol_surfaces: protocol_surfaces
            .iter()
            .map(|value| (*value).into())
            .collect(),
        request_adaptations: request_adaptations
            .iter()
            .map(|value| (*value).into())
            .collect(),
        response_adaptations: Vec::new(),
        capabilities,
        usage_normalization: UsageNormalizationProfile {
            version: "chisei.usage-normalization/v1".into(),
            input_tokens: true,
            output_tokens: true,
            reasoning_tokens: reports_reasoning,
            cache_read_tokens: reports_cache_reads,
            cache_write_tokens: reports_cache_writes,
            partial_responses: reports_partial,
        },
        error_normalization_version: "chisei.gateway-errors/v1".into(),
        pricing: PricingProfile {
            version: format!("{provider}.unpriced/v1"),
            source: "unconfigured".into(),
            observed_at: None,
            dimensions: Vec::new(),
        },
        governance: ProviderGovernanceProfile {
            metadata_status: "unknown".into(),
            data_retention: None,
            training_use: None,
            regions: Vec::new(),
            zero_data_retention_eligible: None,
            contractual_status: None,
            terms_version: None,
        },
    }
}

fn xai_profile() -> ProviderProfile {
    let mut profile = profile(
        "xai",
        "openai-compatible",
        Some("xai/"),
        (
            "CHISEI_XAI_BASE_URL",
            Some("https://api.x.ai/v1"),
            Some("XAI_API_KEY"),
        ),
        &["responses", "chat_completions", "models"],
        &[],
        ProviderCapabilities {
            responses: true,
            streaming: true,
            tools: true,
            parallel_tools: true,
            structured_output: true,
            reasoning_controls: true,
            modalities: vec!["text".into(), "image".into()],
            provider_continuation: false,
            reports_usage: true,
            partial_usage: true,
            context_tokens: 500_000,
            output_tokens: None,
            built_in_tools: Vec::new(),
        },
    );
    profile.profile_version = "xai.grok-4.5/v1".into();
    profile
        .request_adaptations
        .push("built_in_tools_require_explicit_admission".into());
    profile.pricing = PricingProfile {
        version: "xai.grok-4.5/2026-07-09".into(),
        source: "https://docs.x.ai/developers/models/grok-4.5".into(),
        observed_at: Some("2026-07-14T00:00:00Z".into()),
        dimensions: vec![
            "input_tokens_usd_per_million=2.00".into(),
            "cached_input_tokens_usd_per_million=0.50".into(),
            "output_tokens_usd_per_million=6.00".into(),
            "higher_context_pricing_above_tokens=200000".into(),
        ],
    };
    profile.governance.metadata_status = "partial".into();
    profile.governance.regions = vec!["us-east-1".into(), "us-west-2".into()];
    profile
}

fn meta_profile() -> ProviderProfile {
    let mut profile = profile(
        "meta",
        "openai-compatible-preview",
        Some("meta/"),
        ("CHISEI_META_BASE_URL", None, Some("META_MODEL_API_KEY")),
        &["responses", "chat_completions"],
        &[],
        ProviderCapabilities {
            responses: true,
            streaming: true,
            tools: true,
            parallel_tools: true,
            structured_output: true,
            reasoning_controls: true,
            modalities: vec!["text".into(), "image".into(), "video".into()],
            provider_continuation: false,
            reports_usage: true,
            partial_usage: false,
            context_tokens: 1_000_000,
            output_tokens: None,
            built_in_tools: Vec::new(),
        },
    );
    profile.profile_version = "meta.muse-spark-1.1/preview-v1".into();
    profile.lifecycle = "experimental".into();
    profile
        .request_adaptations
        .push("built_in_tools_require_explicit_admission".into());
    profile.pricing = PricingProfile {
        version: "meta.muse-spark-1.1/unverified-preview-v1".into(),
        source: "https://ai.meta.com/blog/introducing-muse-spark-meta-model-api/".into(),
        observed_at: Some("2026-07-14T00:00:00Z".into()),
        dimensions: Vec::new(),
    };
    profile.governance.metadata_status = "preview_unknown".into();
    profile.governance.contractual_status = Some("public_preview".into());
    profile
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityRequirements {
    pub responses: bool,
    pub streaming: bool,
    pub tools: bool,
    pub parallel_tools: bool,
    pub structured_output: bool,
    pub reasoning_controls: bool,
    pub modalities: Vec<String>,
    pub provider_continuation: bool,
    pub built_in_tools: Vec<String>,
    pub max_output_tokens: Option<u64>,
}

impl CapabilityRequirements {
    pub fn from_responses_body(body: &[u8]) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|error| format!("invalid JSON: {error}"))?;
        let tools = value
            .get("tools")
            .and_then(|tools| tools.as_array())
            .cloned()
            .unwrap_or_default();
        let has_tool_outputs = value.get("input").is_some_and(contains_tool_call_output);
        let mut built_in_tools = tools
            .iter()
            .filter_map(|tool| tool.get("type").and_then(|value| value.as_str()))
            .filter(|kind| !matches!(*kind, "function" | "custom"))
            .map(str::to_string)
            .collect::<Vec<_>>();
        if let Some(input) = value.get("input") {
            collect_continuation_built_in_tools(input, &mut built_in_tools);
        }
        built_in_tools.sort();
        built_in_tools.dedup();
        let mut modalities = vec!["text".to_string()];
        if let Some(input) = value.get("input") {
            collect_modalities(input, &mut modalities);
        }
        if let Some(variables) = value.pointer("/prompt/variables") {
            collect_modalities(variables, &mut modalities);
        }
        modalities.sort();
        modalities.dedup();
        let max_output_tokens = match value.get("max_output_tokens") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .ok_or_else(|| "max_output_tokens must be an unsigned integer".to_string())?,
            ),
        };
        Ok(Self {
            responses: true,
            streaming: value
                .get("stream")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            tools: !tools.is_empty() || has_tool_outputs,
            parallel_tools: !tools.is_empty()
                && !tool_choice_disables_tools(&value)
                && value
                    .get("parallel_tool_calls")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(true),
            structured_output: requires_structured_output(&value),
            reasoning_controls: value.get("reasoning").is_some(),
            provider_continuation: value
                .get("previous_response_id")
                .is_some_and(|value| !value.is_null()),
            modalities,
            built_in_tools,
            max_output_tokens,
        })
    }

    pub fn from_openai_chat_body(body: &[u8]) -> Result<Self, String> {
        Self::from_chat_body(body, ChatCapabilityWire::OpenAi)
    }

    pub fn from_anthropic_messages_body(body: &[u8]) -> Result<Self, String> {
        Self::from_chat_body(body, ChatCapabilityWire::Anthropic)
    }

    fn from_chat_body(body: &[u8], wire: ChatCapabilityWire) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|error| format!("invalid JSON: {error}"))?;
        let mut tools = value
            .get("tools")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        if matches!(wire, ChatCapabilityWire::OpenAi)
            && let Some(functions) = value.get("functions").and_then(serde_json::Value::as_array)
        {
            tools.extend(functions.iter().cloned());
        }
        let built_in_tools = tools
            .iter()
            .filter_map(|tool| tool.get("type").and_then(serde_json::Value::as_str))
            .filter(|kind| *kind != "function" && *kind != "custom")
            .map(str::to_string)
            .collect::<Vec<_>>();
        let mut modalities = vec!["text".to_string()];
        if let Some(messages) = value.get("messages") {
            collect_modalities(messages, &mut modalities);
        }
        if matches!(wire, ChatCapabilityWire::OpenAi)
            && let Some(requested) = value
                .get("modalities")
                .and_then(serde_json::Value::as_array)
        {
            modalities.extend(
                requested
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string),
            );
        }
        modalities.sort();
        modalities.dedup();
        let max_fields = match wire {
            ChatCapabilityWire::OpenAi => ["max_completion_tokens", "max_tokens"],
            ChatCapabilityWire::Anthropic => ["max_tokens", "max_tokens"],
        };
        let max_output_tokens = max_fields.into_iter().find_map(|field| {
            value
                .get(field)
                .filter(|value| !value.is_null())
                .map(|value| (field, value))
        });
        let max_output_tokens = match max_output_tokens {
            None => None,
            Some((field, value)) => Some(
                value
                    .as_u64()
                    .ok_or_else(|| format!("{field} must be an unsigned integer"))?,
            ),
        };
        let parallel_tools = if tools.is_empty() || tool_choice_disables_tools(&value) {
            false
        } else {
            match wire {
                ChatCapabilityWire::OpenAi => value
                    .get("parallel_tool_calls")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
                ChatCapabilityWire::Anthropic => !value
                    .pointer("/tool_choice/disable_parallel_tool_use")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            }
        };
        let structured_output = requires_structured_output(&value)
            || matches!(wire, ChatCapabilityWire::Anthropic)
                && (value.pointer("/output_config/format").is_some()
                    || value.get("output_format").is_some());
        let reasoning_controls = match wire {
            ChatCapabilityWire::OpenAi => value.get("reasoning_effort").is_some(),
            ChatCapabilityWire::Anthropic => {
                value.get("thinking").is_some() || value.pointer("/output_config/effort").is_some()
            }
        };
        Ok(Self {
            streaming: value
                .get("stream")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            tools: !tools.is_empty() || contains_chat_tool_use(&value),
            parallel_tools,
            structured_output,
            reasoning_controls,
            modalities,
            built_in_tools,
            max_output_tokens,
            ..Self::default()
        })
    }

    pub fn unsupported_by(&self, capabilities: &ProviderCapabilities) -> Vec<String> {
        let mut missing = Vec::new();
        for (required, supported, name) in [
            (self.responses, capabilities.responses, "responses"),
            (self.streaming, capabilities.streaming, "streaming"),
            (self.tools, capabilities.tools, "tools"),
            (
                self.parallel_tools,
                capabilities.parallel_tools,
                "parallel_tools",
            ),
            (
                self.structured_output,
                capabilities.structured_output,
                "structured_output",
            ),
            (
                self.reasoning_controls,
                capabilities.reasoning_controls,
                "reasoning_controls",
            ),
            (
                self.provider_continuation,
                capabilities.provider_continuation,
                "provider_continuation",
            ),
        ] {
            if required && !supported {
                missing.push(name.to_string());
            }
        }
        for modality in &self.modalities {
            if !capabilities.modalities.contains(modality) {
                missing.push(format!("modality:{modality}"));
            }
        }
        for tool in &self.built_in_tools {
            if !capabilities.built_in_tools.contains(tool) {
                missing.push(format!("built_in_tool:{tool}"));
            }
        }
        if let Some(requested) = self.max_output_tokens {
            match capabilities.output_tokens {
                Some(supported) if requested > supported => {
                    missing.push(format!("max_output_tokens:{requested}>{supported}"));
                }
                None => missing.push(format!("max_output_tokens:{requested}>unknown")),
                Some(_) => {}
            }
        }
        missing
    }
}

#[derive(Clone, Copy)]
enum ChatCapabilityWire {
    OpenAi,
    Anthropic,
}

fn requires_structured_output(value: &serde_json::Value) -> bool {
    [value.pointer("/text/format"), value.get("response_format")]
        .into_iter()
        .flatten()
        .any(|format| {
            format
                .get("type")
                .and_then(|value| value.as_str())
                .is_none_or(|kind| kind != "text")
        })
}

fn collect_modalities(value: &serde_json::Value, modalities: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_modalities(value, modalities);
            }
        }
        serde_json::Value::Object(values) => {
            if let Some(kind) = values.get("type").and_then(|value| value.as_str()) {
                match kind {
                    "input_image" | "image_url" | "image" => modalities.push("image".into()),
                    "input_audio" | "audio" => modalities.push("audio".into()),
                    "input_video" | "video_url" | "video" => modalities.push("video".into()),
                    "input_file" | "file_url" | "file" => modalities.push("file".into()),
                    _ => {}
                }
            }
            for value in values.values() {
                collect_modalities(value, modalities);
            }
        }
        _ => {}
    }
}

fn contains_tool_call_output(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(values) => values.iter().any(contains_tool_call_output),
        serde_json::Value::Object(values) => {
            values
                .get("type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind.ends_with("_call_output"))
                || values.values().any(contains_tool_call_output)
        }
        _ => false,
    }
}

fn collect_continuation_built_in_tools(value: &serde_json::Value, tools: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_continuation_built_in_tools(value, tools);
            }
        }
        serde_json::Value::Object(values) => {
            if let Some(kind) = values.get("type").and_then(serde_json::Value::as_str) {
                match kind {
                    "computer_call_output" => tools.push("computer_use_preview".into()),
                    "mcp_approval_response" | "mcp_call_output" => tools.push("mcp".into()),
                    kind if kind.ends_with("_call_output")
                        && !matches!(kind, "function_call_output" | "custom_tool_call_output") =>
                    {
                        tools.push(kind.trim_end_matches("_call_output").to_string());
                    }
                    _ => {}
                }
            }
            for value in values.values() {
                collect_continuation_built_in_tools(value, tools);
            }
        }
        _ => {}
    }
}

fn contains_chat_tool_use(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(values) => values.iter().any(contains_chat_tool_use),
        serde_json::Value::Object(values) => {
            values
                .get("type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        "tool_use" | "tool_result" | "function_call" | "function"
                    )
                })
                || values.get("tool_calls").is_some_and(non_empty_tool_field)
                || values
                    .get("function_call")
                    .is_some_and(non_empty_tool_field)
                || values.get("tool_call_id").is_some_and(non_empty_tool_field)
                || values
                    .get("role")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|role| role == "function")
                || values.values().any(contains_chat_tool_use)
        }
        _ => false,
    }
}

fn non_empty_tool_field(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::String(value) => !value.trim().is_empty(),
        serde_json::Value::Array(values) => !values.is_empty(),
        serde_json::Value::Object(values) => !values.is_empty(),
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(_) => true,
    }
}

fn tool_choice_disables_tools(value: &serde_json::Value) -> bool {
    let disables = |choice: Option<&serde_json::Value>| match choice {
        Some(serde_json::Value::String(choice)) => choice == "none",
        Some(serde_json::Value::Object(choice)) => choice
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|choice| choice == "none"),
        _ => false,
    };
    disables(value.get("tool_choice")) || disables(value.get("function_call"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_required_capabilities_from_responses_requests() {
        let body = br#"{
            "stream": true,
            "parallel_tool_calls": true,
            "previous_response_id": "resp_1",
            "reasoning": {"effort":"high"},
            "text": {"format":{"type":"json_schema"}},
            "tools":[{"type":"function"},{"type":"web_search"}],
            "input":[{"role":"user","content":[{"type":"input_image"}]}]
        }"#;
        let required = CapabilityRequirements::from_responses_body(body).unwrap();
        assert!(required.streaming);
        assert!(required.parallel_tools);
        assert!(required.provider_continuation);
        assert!(required.structured_output);
        assert_eq!(required.modalities, vec!["image", "text"]);
        assert_eq!(required.built_in_tools, vec!["web_search"]);
    }

    #[test]
    fn derives_video_capability_from_responses_requests() {
        let required = CapabilityRequirements::from_responses_body(
            br#"{"input":[{"role":"user","content":[{"type":"input_video"}]}]}"#,
        )
        .unwrap();
        assert_eq!(required.modalities, vec!["text", "video"]);

        let metadata_only = CapabilityRequirements::from_responses_body(
            br#"{"input":"hello","metadata":{"type":"video"}}"#,
        )
        .unwrap();
        assert_eq!(metadata_only.modalities, vec!["text"]);
    }

    #[test]
    fn derives_file_capability_and_rejects_unadvertised_file_inputs() {
        let required = CapabilityRequirements::from_responses_body(
            br#"{"input":[{"role":"user","content":[{"type":"input_file","file_id":"file_1"}]}]}"#,
        )
        .unwrap();
        assert_eq!(required.modalities, vec!["file", "text"]);
        assert_eq!(
            required.unsupported_by(
                &ProviderRegistry::built_in()
                    .profile("openai")
                    .unwrap()
                    .capabilities
            ),
            vec!["modality:file"]
        );

        let metadata_only = CapabilityRequirements::from_responses_body(
            br#"{"input":"hello","metadata":{"type":"file"}}"#,
        )
        .unwrap();
        assert_eq!(metadata_only.modalities, vec!["text"]);
    }

    #[test]
    fn built_in_profiles_publish_versioned_isolated_endpoints() {
        let registry = ProviderRegistry::built_in();
        assert_eq!(registry.version, PROVIDER_REGISTRY_VERSION);
        let openai = registry.profile("openai").unwrap();
        let ollama = registry.profile("ollama").unwrap();
        let anthropic = registry.profile("anthropic").unwrap();
        assert_eq!(
            openai.endpoint.api_key_env.as_deref(),
            Some("OPENAI_API_KEY")
        );
        assert_eq!(
            anthropic.endpoint.api_key_env.as_deref(),
            Some("ANTHROPIC_API_KEY")
        );
        assert_eq!(ollama.endpoint.api_key_env, None);
        assert_ne!(openai.endpoint.base_url_env, ollama.endpoint.base_url_env);
        assert_ne!(openai.profile_version, anthropic.profile_version);
        assert_eq!(openai.model_namespace.as_deref(), Some("openai/"));
        assert_eq!(ollama.model_namespace.as_deref(), Some("ollama/"));
        assert!(
            openai
                .accepted_model_patterns
                .contains(&"openai/*".to_string())
        );
        assert!(openai.usage_normalization.cache_read_tokens);
        assert!(openai.protocol_surfaces.contains(&"responses".to_string()));
        assert!(
            anthropic
                .protocol_surfaces
                .contains(&"messages".to_string())
        );
        let xai = registry.profile("xai").unwrap();
        let meta = registry.profile("meta").unwrap();
        assert_eq!(xai.endpoint.api_key_env.as_deref(), Some("XAI_API_KEY"));
        assert_eq!(
            xai.endpoint.default_base_url.as_deref(),
            Some("https://api.x.ai/v1")
        );
        assert_ne!(xai.endpoint.api_key_env, openai.endpoint.api_key_env);
        assert_ne!(xai.endpoint.base_url_env, openai.endpoint.base_url_env);
        assert_eq!(xai.capabilities.context_tokens, 500_000);
        assert_eq!(meta.lifecycle, "experimental");
        assert_eq!(meta.endpoint.default_base_url, None);
        assert_eq!(
            meta.governance.contractual_status.as_deref(),
            Some("public_preview")
        );
    }

    #[test]
    fn hosted_models_are_exactly_admitted_and_preview_requires_promotion() {
        let mut registry = ProviderRegistry::built_in();
        let xai = registry.resolve_model("xai/grok-4.5").unwrap();
        assert_eq!(xai.provider, "xai");
        assert_eq!(xai.upstream_model, "grok-4.5");
        assert!(registry.resolve_model("xai/grok-future").is_err());
        assert!(registry.resolve_model("meta/muse-spark-1.1").is_err());

        registry
            .lifecycle_overrides
            .push(RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "meta".into(),
                state: "enabled".into(),
                version: 1,
                actor: "operator".into(),
                reason: "explicit preview opt-in".into(),
                changed_at: "2026-07-14T00:00:00Z".into(),
            });
        registry.state_version = 1;
        let meta = registry.resolve_model("meta/muse-spark-1.1").unwrap();
        assert_eq!(meta.provider, "meta");
        assert!(registry.resolve_model("meta/muse-spark-2").is_err());
    }

    #[tokio::test]
    async fn canary_models_require_request_scoped_bounded_admission() {
        let mut registry = ProviderRegistry::built_in();
        registry
            .lifecycle_overrides
            .push(RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "meta".into(),
                state: "canary".into(),
                version: 1,
                actor: "operator".into(),
                reason: "bounded validation".into(),
                changed_at: "2026-07-14T00:00:00Z".into(),
            });
        registry.state_version = 1;
        assert!(registry.resolve_model("meta/muse-spark-1.1").is_err());
        let admitted = with_provider_registry_snapshot(registry, async {
            with_canary_admission(async {
                provider_registry_snapshot().resolve_model("meta/muse-spark-1.1")
            })
            .await
        })
        .await;
        assert!(admitted.is_ok());
    }

    #[tokio::test]
    async fn scoped_canary_overrides_require_request_admission() {
        let mut registry = ProviderRegistry::built_in();
        registry.lifecycle_overrides.extend([
            RegistryLifecycleOverride {
                target_kind: "model".into(),
                target: "openai/gpt-5.5".into(),
                state: "canary".into(),
                version: 1,
                actor: "operator".into(),
                reason: "bounded model validation".into(),
                changed_at: "2026-07-14T00:00:00Z".into(),
            },
            RegistryLifecycleOverride {
                target_kind: "capability".into(),
                target: "openai:responses".into(),
                state: "canary".into(),
                version: 2,
                actor: "operator".into(),
                reason: "bounded capability validation".into(),
                changed_at: "2026-07-14T00:00:00Z".into(),
            },
        ]);
        registry.state_version = 2;
        assert!(registry.resolve_model("openai/gpt-5.5").is_err());
        assert!(
            !registry
                .effective_profile("openai")
                .unwrap()
                .capabilities
                .responses
        );
        with_provider_registry_snapshot(registry, async {
            with_canary_admission(async {
                let snapshot = provider_registry_snapshot();
                assert!(snapshot.resolve_model("openai/gpt-5.5").is_ok());
                assert!(
                    snapshot
                        .effective_profile("openai")
                        .unwrap()
                        .capabilities
                        .responses
                );
            })
            .await
        })
        .await;
    }

    #[test]
    fn hosted_profile_fixtures_match_registry_contracts() {
        let registry = ProviderRegistry::built_in();
        for fixture in [
            include_str!("../tests/fixtures/providers/xai-grok-4.5-v1.json"),
            include_str!("../tests/fixtures/providers/meta-muse-spark-1.1-preview-v1.json"),
        ] {
            let fixture: serde_json::Value = serde_json::from_str(fixture).unwrap();
            let profile_version = fixture["profile_version"].as_str().unwrap();
            let profile = registry
                .profiles
                .iter()
                .find(|profile| profile.profile_version == profile_version)
                .unwrap();
            let request = serde_json::to_vec(&fixture["request"]).unwrap();
            let requirements = CapabilityRequirements::from_responses_body(&request).unwrap();
            assert!(
                requirements
                    .unsupported_by(&profile.capabilities)
                    .is_empty()
            );
            assert_eq!(fixture["request"]["store"], false);
            assert!(fixture["error"]["status"].as_u64().is_some());
            assert_eq!(
                fixture["sse_events"].as_array().unwrap().last().unwrap(),
                "response.completed"
            );
        }
    }

    #[test]
    fn capability_matrix_is_derived_from_the_profile_registry() {
        let matrix = CapabilityMatrix::built_in();
        assert_eq!(matrix.registry_version, PROVIDER_REGISTRY_VERSION);
        assert_eq!(matrix.paths.len(), matrix.profiles.len());
        for profile in &matrix.profiles {
            assert_eq!(
                matrix.capabilities(&profile.provider),
                Some(&profile.capabilities)
            );
        }
    }

    #[test]
    fn capability_discovery_redacts_private_lifecycle_reasons() {
        let overrides = public_lifecycle_overrides(vec![RegistryLifecycleOverride {
            target_kind: "provider".into(),
            target: "openai".into(),
            state: "degraded".into(),
            version: 1,
            actor: "operator".into(),
            reason: "incident token sk-private".into(),
            changed_at: "2026-07-13T00:00:00Z".into(),
        }]);

        assert_eq!(overrides[0].reason, "redacted");
        assert!(
            !serde_json::to_string(&overrides)
                .unwrap()
                .contains("sk-private")
        );
    }

    #[test]
    fn registry_resolves_namespaces_and_legacy_aliases() {
        let registry = ProviderRegistry::built_in();
        for (requested, provider, canonical, upstream) in [
            ("openai/gpt-5.5", "openai", "openai/gpt-5.5", "gpt-5.5"),
            ("gpt-5.5", "openai", "openai/gpt-5.5", "gpt-5.5"),
            (
                "anthropic/claude-sonnet-4",
                "anthropic",
                "anthropic/claude-sonnet-4",
                "claude-sonnet-4",
            ),
            ("sonnet", "anthropic", "anthropic/sonnet", "sonnet"),
            ("haiku", "anthropic", "anthropic/haiku", "haiku"),
            ("opus", "anthropic", "anthropic/opus", "opus"),
            ("fable", "anthropic", "anthropic/fable", "fable"),
            ("ollama/llama3.2", "ollama", "ollama/llama3.2", "llama3.2"),
            ("native/mistral", "native", "native/mistral", "mistral"),
            (
                "native-default",
                "native",
                "native/native-default",
                "native-default",
            ),
            (
                "fallback:cheap",
                "native",
                "native/fallback:cheap",
                "fallback:cheap",
            ),
            ("o3-mini", "openai", "openai/o3-mini", "o3-mini"),
            (
                "codex-mini-latest",
                "openai",
                "openai/codex-mini-latest",
                "codex-mini-latest",
            ),
            (
                "ft:gpt-5.5:org:custom",
                "openai",
                "openai/ft:gpt-5.5:org:custom",
                "ft:gpt-5.5:org:custom",
            ),
            (
                "text-embedding-3-large",
                "openai",
                "openai/text-embedding-3-large",
                "text-embedding-3-large",
            ),
            ("openai/o3-mini", "openai", "openai/o3-mini", "o3-mini"),
        ] {
            let resolved = registry.resolve_model(requested).unwrap();
            assert_eq!(resolved.provider, provider);
            assert_eq!(resolved.canonical_model, canonical);
            assert_eq!(resolved.upstream_model, upstream);
        }
        assert!(
            registry
                .resolve_model("unadvertised-anthropic-alias")
                .unwrap_err()
                .contains("unregistered bare model identifier")
        );
    }

    #[tokio::test]
    async fn async_refresh_returns_the_snapshot_for_its_state_path() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-path-snapshot-{}",
            uuid::Uuid::new_v4()
        ));
        let enabled_path = directory.join("enabled.json");
        let disabled_path = directory.join("disabled.json");
        refresh_provider_registry_async(&enabled_path)
            .await
            .unwrap();
        let mut disabled_state = refresh_provider_registry_async(&disabled_path)
            .await
            .unwrap();
        disabled_state.state_version = 1;
        disabled_state
            .lifecycle_overrides
            .push(RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "openai".into(),
                state: "disabled".into(),
                version: 1,
                actor: "operator".into(),
                reason: "test isolation".into(),
                changed_at: "2026-07-14T00:00:00Z".into(),
            });
        write_provider_registry_state(&disabled_path, &disabled_state).unwrap();

        let enabled = refresh_provider_registry_async(&enabled_path)
            .await
            .unwrap();
        let disabled = refresh_provider_registry_async(&disabled_path)
            .await
            .unwrap();

        assert!(enabled.resolve_model("openai/gpt-5.5").is_ok());
        assert!(disabled.resolve_model("openai/gpt-5.5").is_err());
        assert!(enabled.resolve_model("openai/gpt-5.5").is_ok());
        with_provider_registry_snapshot(enabled, async {
            let foreign = refresh_provider_registry_async(&disabled_path)
                .await
                .unwrap();
            assert!(foreign.resolve_model("openai/gpt-5.5").is_err());
            assert!(resolve_registered_model("openai/gpt-5.5").is_ok());
        })
        .await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn wire_provider_preserves_legacy_openai_compatible_bare_models() {
        let registry = ProviderRegistry::built_in();
        for model in [
            "mistral-large",
            "deepseek-chat",
            "llama-3.3-70b",
            "qwen2",
            "phi3",
            "mixtral",
        ] {
            let resolved = registry
                .resolve_model_for_provider(model, "openai")
                .unwrap();
            assert_eq!(resolved.provider, "openai");
            assert_eq!(resolved.canonical_model, format!("openai/{model}"));
            assert_eq!(resolved.requested_alias.as_deref(), Some(model));
        }
        assert_eq!(
            registry
                .resolve_model_for_provider("claude-sonnet-4", "openai")
                .unwrap()
                .provider,
            "anthropic"
        );

        let mut disabled = registry;
        disabled.state_version = 1;
        disabled
            .lifecycle_overrides
            .push(RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "anthropic".into(),
                state: "disabled".into(),
                version: 1,
                actor: "operator".into(),
                reason: "test".into(),
                changed_at: "2026-07-14T00:00:00Z".into(),
            });
        assert!(
            disabled
                .resolve_model_for_provider("claude-sonnet-4", "openai")
                .unwrap_err()
                .contains("disabled")
        );
    }

    #[test]
    fn unavailable_lifecycle_classification_includes_gated_states() {
        for state in ["disabled", "experimental", "canary"] {
            let mut registry = ProviderRegistry::built_in();
            registry.state_version = 1;
            registry
                .lifecycle_overrides
                .push(RegistryLifecycleOverride {
                    target_kind: "provider".into(),
                    target: "openai".into(),
                    state: state.into(),
                    version: 1,
                    actor: "operator".into(),
                    reason: "test".into(),
                    changed_at: "2026-07-14T00:00:00Z".into(),
                });
            assert!(registry.model_or_provider_is_unavailable_for_provider("gpt-5.5", "openai"));
        }

        let registry = ProviderRegistry::built_in();
        assert!(
            !registry.model_or_provider_is_unavailable_for_provider("meta/bad model", "openai")
        );
    }

    #[test]
    fn registry_rejects_unknown_or_empty_namespaces() {
        let registry = ProviderRegistry::built_in();
        assert!(
            registry
                .resolve_model("unknown/model")
                .unwrap_err()
                .contains("unknown provider namespace")
        );
        assert!(registry.resolve_model("openai/").is_err());
        assert!(registry.resolve_model("kiro").is_err());
        assert!(registry.resolve_model("Kiro").is_err());
        assert!(registry.resolve_model("native/Kiro").is_err());
        assert!(registry.resolve_model("openai/kiro").is_err());
        assert!(registry.resolve_model("mistral").is_err());
    }

    #[test]
    fn empty_optional_chat_tool_fields_do_not_require_tools() {
        let body = br#"{
            "messages":[{
                "role":"assistant",
                "content":"done",
                "tool_calls":[],
                "function_call":null,
                "tool_call_id":""
            }]
        }"#;

        let required = CapabilityRequirements::from_openai_chat_body(body).unwrap();

        assert!(!required.tools);
    }

    #[test]
    fn lifecycle_overrides_disable_and_restore_registry_targets() {
        let mut registry = ProviderRegistry::built_in();
        registry
            .lifecycle_overrides
            .push(RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "openai".into(),
                state: "disabled".into(),
                version: 1,
                actor: "test".into(),
                reason: "incident".into(),
                changed_at: "2026-07-13T00:00:00Z".into(),
            });
        assert!(registry.ensure_provider_available("openai").is_err());
        assert!(registry.model_or_provider_is_disabled("gpt-5.5"));
        assert!(!registry.model_or_provider_is_disabled("disabled-model"));
        assert!(
            registry
                .resolve_model("gpt-5.5")
                .unwrap_err()
                .contains("disabled")
        );
        registry
            .lifecycle_overrides
            .push(RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "openai".into(),
                state: "enabled".into(),
                version: 2,
                actor: "test".into(),
                reason: "recovered".into(),
                changed_at: "2026-07-13T00:01:00Z".into(),
            });
        assert!(registry.resolve_model("gpt-5.5").is_ok());
        assert_eq!(
            registry.effective_profile("openai").unwrap().lifecycle,
            "enabled"
        );
        registry.lifecycle_overrides.extend([
            RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "openai".into(),
                state: "disabled".into(),
                version: 3,
                actor: "test".into(),
                reason: "second incident".into(),
                changed_at: "2026-07-13T00:02:00Z".into(),
            },
            RegistryLifecycleOverride {
                target_kind: "model".into(),
                target: "openai/gpt-5.5".into(),
                state: "enabled".into(),
                version: 4,
                actor: "test".into(),
                reason: "model healthy".into(),
                changed_at: "2026-07-13T00:03:00Z".into(),
            },
        ]);
        assert!(
            registry
                .resolve_model("gpt-5.5")
                .unwrap_err()
                .contains("provider")
        );
    }

    #[test]
    fn experimental_provider_cannot_skip_canary_admission() {
        let directory =
            std::env::temp_dir().join(format!("sekai-provider-admission-{}", uuid::Uuid::new_v4()));
        let path = directory.join("registry.json");
        refresh_provider_registry(&path).unwrap();
        let direct = update_registry_lifecycle(
            &path,
            "provider",
            "meta",
            "enabled",
            "operator",
            "direct promotion",
            "2026-07-14T00:00:00Z",
        );
        assert!(direct.unwrap_err().contains("must enter canary"));
        update_registry_lifecycle(
            &path,
            "provider",
            "meta",
            "canary",
            "operator",
            "bounded admission",
            "2026-07-14T00:01:00Z",
        )
        .unwrap();
        update_registry_lifecycle(
            &path,
            "provider",
            "meta",
            "enabled",
            "operator",
            "evaluation passed",
            "2026-07-14T00:02:00Z",
        )
        .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn persisted_lifecycle_history_preserves_matching_target_transitions() {
        let lifecycle_override = |state: &str, version| RegistryLifecycleOverride {
            target_kind: "provider".into(),
            target: "openai".into(),
            state: state.into(),
            version,
            actor: "test".into(),
            reason: "lifecycle transition".into(),
            changed_at: "2026-07-13T00:00:00Z".into(),
        };
        let mut overrides = vec![lifecycle_override("disabled", 1)];

        overrides.push(lifecycle_override("enabled", 2));

        assert_eq!(overrides.len(), 2);
        assert_eq!(overrides[0].state, "disabled");
        assert_eq!(overrides[1].state, "enabled");
        assert_eq!(overrides[1].version, 2);
    }

    #[test]
    fn provider_registry_state_round_trip_preserves_full_history() {
        let directory =
            std::env::temp_dir().join(format!("sekai-provider-registry-{}", uuid::Uuid::new_v4()));
        let path = directory.join("state.json");
        let mut registry = ProviderRegistry::built_in();
        registry.state_version = 2;
        registry.lifecycle_overrides = vec![
            RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "openai".into(),
                state: "disabled".into(),
                version: 1,
                actor: "test".into(),
                reason: "incident".into(),
                changed_at: "2026-07-14T00:00:00Z".into(),
            },
            RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "openai".into(),
                state: "enabled".into(),
                version: 2,
                actor: "test".into(),
                reason: "recovered".into(),
                changed_at: "2026-07-14T00:01:00Z".into(),
            },
        ];

        write_provider_registry_state(&path, &registry).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let loaded = read_provider_registry(&path).unwrap();

        assert_eq!(loaded.state_version, 2);
        assert_eq!(loaded.lifecycle_overrides, registry.lifecycle_overrides);
        assert_eq!(
            loaded.effective_profile("openai").unwrap().lifecycle,
            "enabled"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_registry_state_rejects_truncated_history_versions() {
        let registry = ProviderRegistry::built_in();
        let state = ProviderRegistryState {
            registry_version: PROVIDER_REGISTRY_VERSION.into(),
            state_version: 2,
            lifecycle_overrides: vec![RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "openai".into(),
                state: "disabled".into(),
                version: 1,
                actor: "test".into(),
                reason: "incident".into(),
                changed_at: "2026-07-14T00:00:00Z".into(),
            }],
        };

        assert!(
            validate_persisted_lifecycle_history(&registry, &state)
                .unwrap_err()
                .contains("latest lifecycle entry")
        );
    }

    #[test]
    fn provider_registry_state_rejects_a_missing_first_history_version() {
        let registry = ProviderRegistry::built_in();
        let state = ProviderRegistryState {
            registry_version: PROVIDER_REGISTRY_VERSION.into(),
            state_version: 2,
            lifecycle_overrides: vec![RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "openai".into(),
                state: "enabled".into(),
                version: 2,
                actor: "test".into(),
                reason: "restore".into(),
                changed_at: "2026-07-14T00:00:00Z".into(),
            }],
        };

        assert!(
            validate_persisted_lifecycle_history(&registry, &state)
                .unwrap_err()
                .contains("consecutive")
        );
    }

    #[test]
    fn provider_registry_state_fails_closed_after_initialized_file_disappears() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-missing-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join("state.json");

        let initialized = read_provider_registry(&path).unwrap();
        assert_eq!(initialized.state_version, 0);
        assert!(path.exists());
        std::fs::remove_file(&path).unwrap();

        assert!(
            read_provider_registry(&path)
                .unwrap_err()
                .contains("state is missing")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_registry_storage_probe_removes_both_links() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-probe-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join("state.json");

        validate_provider_registry_storage(&path).unwrap();

        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn legacy_empty_lock_requires_explicit_state_initialization() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-legacy-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join("state.json");
        std::fs::create_dir_all(&directory).unwrap();
        File::create(registry_legacy_lock_path(&path)).unwrap();

        assert!(
            read_provider_registry(&path)
                .unwrap_err()
                .contains("state is missing")
        );
        let locks = open_registry_locks(&path).unwrap();
        locks.lock().unwrap();
        assert!(locks.legacy_state_is_ambiguous().unwrap());
        let initialized = read_or_initialize_provider_registry(&path, true, true).unwrap();

        assert_eq!(initialized.state_version, 0);
        assert!(path.exists());
        assert!(registry_initialization_path(&path).exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn current_protocol_lock_allows_concurrent_fresh_initialization() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-current-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join("state.json");
        std::fs::create_dir_all(&directory).unwrap();
        File::create(registry_lock_path(&path)).unwrap();

        let initialized = read_provider_registry(&path).unwrap();

        assert_eq!(initialized.state_version, 0);
        assert!(path.exists());
        assert!(registry_initialization_path(&path).exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn current_protocol_waits_for_a_legacy_writer_lock() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-mixed-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join("state.json");
        std::fs::create_dir_all(&directory).unwrap();
        let legacy = File::create(registry_legacy_lock_path(&path)).unwrap();
        legacy.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            sender.send(read_provider_registry(&reader_path)).unwrap();
        });

        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        drop(legacy);
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap()
                .unwrap_err()
                .contains("legacy lock state is ambiguous")
        );
        reader.join().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_fresh_initializers_share_atomically_published_lock() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-concurrent-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join("state.json");
        std::fs::create_dir_all(&directory).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let publishers = (0..2)
            .map(|_| {
                let lock_path = registry_legacy_lock_path(&path);
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    publish_prepared_legacy_lock_with(&lock_path, || {
                        barrier.wait();
                    })
                })
            })
            .collect::<Vec<_>>();

        barrier.wait();
        for publisher in publishers {
            publisher.join().unwrap().unwrap();
        }
        assert_eq!(
            std::fs::read(registry_legacy_lock_path(&path)).unwrap(),
            PROVIDER_REGISTRY_FRESH_LOCK.as_bytes()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn interrupted_lock_publication_does_not_poison_fresh_initialization() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-interrupted-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join("state.json");
        std::fs::create_dir_all(&directory).unwrap();
        let publication_id = uuid::Uuid::new_v4().to_string();
        let orphan = registry_publication_path(&registry_legacy_lock_path(&path), &publication_id);
        let legacy_orphan = registry_legacy_lock_path(&path)
            .with_extension(format!("publish-{}", uuid::Uuid::new_v4()));
        std::fs::write(&orphan, PROVIDER_REGISTRY_FRESH_LOCK).unwrap();
        std::fs::write(&legacy_orphan, PROVIDER_REGISTRY_FRESH_LOCK).unwrap();
        let old = std::time::SystemTime::now()
            .checked_sub(PROVIDER_REGISTRY_PUBLICATION_STALE_AFTER * 2)
            .unwrap();
        File::open(&orphan)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        File::open(&legacy_orphan)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();

        let initialized = read_provider_registry(&path).unwrap();

        assert_eq!(initialized.state_version, 0);
        assert!(!orphan.exists());
        assert!(!legacy_orphan.exists());
        assert_eq!(
            std::fs::read(registry_legacy_lock_path(&path)).unwrap(),
            PROVIDER_REGISTRY_FRESH_LOCK.as_bytes()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn stale_cleanup_preserves_active_and_unrelated_publications() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-active-publication-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join("state.json");
        let lock_path = registry_legacy_lock_path(&path);
        std::fs::create_dir_all(&directory).unwrap();
        let active = registry_publication_path(&lock_path, &uuid::Uuid::new_v4().to_string());
        let unrelated = registry_publication_path(&lock_path, "backup");
        let noncanonical =
            registry_publication_path(&lock_path, "00000000000000000000000000000000");
        let canonical_unrelated =
            registry_publication_path(&lock_path, &uuid::Uuid::new_v4().to_string());
        let binary_unrelated =
            registry_publication_path(&lock_path, &uuid::Uuid::new_v4().to_string());
        std::fs::write(&active, PROVIDER_REGISTRY_FRESH_LOCK).unwrap();
        std::fs::write(&unrelated, "operator backup").unwrap();
        std::fs::write(&noncanonical, "operator backup").unwrap();
        std::fs::write(&canonical_unrelated, "operator backup").unwrap();
        std::fs::write(&binary_unrelated, [0xff, 0x00, 0x80]).unwrap();
        let active_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&active)
            .unwrap();
        active_file.lock().unwrap();
        let old = std::time::SystemTime::now()
            .checked_sub(PROVIDER_REGISTRY_PUBLICATION_STALE_AFTER * 2)
            .unwrap();
        active_file
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        File::open(&noncanonical)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        File::open(&canonical_unrelated)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        File::open(&binary_unrelated)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();

        cleanup_stale_registry_publications(&lock_path).unwrap();

        assert!(active.exists());
        assert!(unrelated.exists());
        assert!(noncanonical.exists());
        assert!(canonical_unrelated.exists());
        assert!(binary_unrelated.exists());
        drop(active_file);
        cleanup_stale_registry_publications(&lock_path).unwrap();
        assert!(!active.exists());
        assert!(unrelated.exists());
        assert!(noncanonical.exists());
        assert!(canonical_unrelated.exists());
        assert!(binary_unrelated.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_preserves_a_raced_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-symlink-race-{}",
            uuid::Uuid::new_v4()
        ));
        let publication = directory.join("publication");
        let target = directory.join("original-inode");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(&publication, PROVIDER_REGISTRY_FRESH_LOCK).unwrap();
        std::fs::hard_link(&publication, &target).unwrap();
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&publication)
            .unwrap();
        std::fs::remove_file(&publication).unwrap();
        symlink(target.file_name().unwrap(), &publication).unwrap();

        quarantine_and_remove_publication(&publication, &opened).unwrap();

        assert!(
            std::fs::symlink_metadata(&publication)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_to_string(&publication).unwrap(),
            PROVIDER_REGISTRY_FRESH_LOCK
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_cleanup_survives_restrictive_umask() {
        const CHILD_PATH: &str = "SEKAI_QUARANTINE_UMASK_CHILD_PATH";
        const CHILD_TOKEN: &str = "SEKAI_QUARANTINE_UMASK_CHILD_TOKEN";
        let token = uuid::Uuid::new_v4().to_string();
        let directory =
            std::env::temp_dir().join(format!("sekai-provider-registry-restrictive-umask-{token}"));
        let publication = directory.join("publication");
        let owner_marker = directory.join(".owner");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(&publication, PROVIDER_REGISTRY_FRESH_LOCK).unwrap();
        std::fs::write(&owner_marker, &token).unwrap();
        let test_binary = std::env::current_exe().unwrap();
        let status = std::process::Command::new("sh")
            .args([
                "-c",
                "umask 0777; exec \"$1\" --ignored --exact provider_profile::tests::quarantine_cleanup_restrictive_umask_child --nocapture",
                "sh",
            ])
            .arg(test_binary)
            .env(CHILD_PATH, &publication)
            .env(CHILD_TOKEN, &token)
            .status()
            .unwrap();

        assert!(status.success());
        assert!(!publication.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess helper for restrictive umask coverage"]
    fn quarantine_cleanup_restrictive_umask_child() {
        const CHILD_PATH: &str = "SEKAI_QUARANTINE_UMASK_CHILD_PATH";
        const CHILD_TOKEN: &str = "SEKAI_QUARANTINE_UMASK_CHILD_TOKEN";
        let (Some(token), Some(path)) = (
            std::env::var(CHILD_TOKEN).ok(),
            std::env::var_os(CHILD_PATH),
        ) else {
            return;
        };
        let parsed = uuid::Uuid::parse_str(&token).expect("invalid restrictive-umask child token");
        assert_eq!(parsed.get_version_num(), 4);
        assert_eq!(parsed.to_string(), token);
        let publication = PathBuf::from(path);
        assert_eq!(publication.file_name().unwrap(), "publication");
        let expected_directory = format!("sekai-provider-registry-restrictive-umask-{token}");
        let expected_parent = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(&expected_directory);
        assert_eq!(
            publication.parent().unwrap().canonicalize().unwrap(),
            expected_parent
        );
        assert_eq!(
            std::fs::read_to_string(publication.parent().unwrap().join(".owner")).unwrap(),
            token
        );
        assert_eq!(
            std::fs::read(&publication).unwrap(),
            PROVIDER_REGISTRY_FRESH_LOCK.as_bytes()
        );
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&publication)
            .unwrap();

        quarantine_and_remove_publication(&publication, &opened).unwrap();

        assert!(!publication.exists());
        assert!(
            std::fs::read_dir(publication.parent().unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".provider-registry-cleanup-"))
        );
    }

    // macOS rejects this raw byte filename with `Illegal byte sequence` before
    // the registry code runs; Linux accepts it and exercises the non-UTF path.
    #[cfg(target_os = "linux")]
    #[test]
    fn registry_storage_accepts_non_utf8_state_paths() {
        use std::os::unix::ffi::OsStringExt;

        let directory = std::env::temp_dir().join(format!(
            "sekai-provider-registry-non-utf8-{}",
            uuid::Uuid::new_v4()
        ));
        let path = directory.join(std::ffi::OsString::from_vec(vec![
            b's', b't', b'a', b't', b'e', 0xff,
        ]));

        let initialized = read_provider_registry(&path).unwrap();

        assert_eq!(initialized.state_version, 0);
        assert!(path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn capability_kill_switches_change_discovery_without_rewriting_profiles() {
        let mut registry = ProviderRegistry::built_in();
        registry
            .lifecycle_overrides
            .push(RegistryLifecycleOverride {
                target_kind: "capability".into(),
                target: "openai:parallel_tools".into(),
                state: "disabled".into(),
                version: 1,
                actor: "test".into(),
                reason: "provider regression".into(),
                changed_at: "2026-07-13T00:00:00Z".into(),
            });
        assert!(
            !registry
                .effective_profile("openai")
                .unwrap()
                .capabilities
                .parallel_tools
        );
        registry
            .lifecycle_overrides
            .push(RegistryLifecycleOverride {
                target_kind: "capability".into(),
                target: "openai:parallel_tools".into(),
                state: "enabled".into(),
                version: 2,
                actor: "test".into(),
                reason: "provider recovered".into(),
                changed_at: "2026-07-13T00:01:00Z".into(),
            });
        assert!(
            registry
                .effective_profile("openai")
                .unwrap()
                .capabilities
                .parallel_tools
        );
        assert!(
            ProviderRegistry::built_in()
                .profile("openai")
                .unwrap()
                .capabilities
                .parallel_tools
        );
    }

    #[test]
    fn lifecycle_model_targets_are_canonicalized() {
        assert_eq!(canonical_model_target("gpt-5.5").unwrap(), "openai/gpt-5.5");
        assert_eq!(
            canonical_model_target("openai/gpt-5.5").unwrap(),
            "openai/gpt-5.5"
        );
    }

    #[test]
    fn effective_lifecycle_uses_the_newest_non_disabled_scope() {
        let mut registry = ProviderRegistry::built_in();
        registry.lifecycle_overrides.extend([
            RegistryLifecycleOverride {
                target_kind: "profile".into(),
                target: "openai.builtin/v3".into(),
                state: "enabled".into(),
                version: 1,
                actor: "test".into(),
                reason: "profile enabled".into(),
                changed_at: "2026-07-13T00:00:00Z".into(),
            },
            RegistryLifecycleOverride {
                target_kind: "provider".into(),
                target: "openai".into(),
                state: "degraded".into(),
                version: 2,
                actor: "test".into(),
                reason: "provider degraded".into(),
                changed_at: "2026-07-13T00:01:00Z".into(),
            },
        ]);
        assert_eq!(
            registry.effective_profile("openai").unwrap().lifecycle,
            "degraded"
        );
    }

    #[test]
    fn rejects_capability_downgrades_before_routing() {
        let matrix = CapabilityMatrix::built_in();
        let required = CapabilityRequirements {
            responses: true,
            streaming: true,
            tools: true,
            parallel_tools: true,
            modalities: vec!["text".into()],
            ..Default::default()
        };
        assert!(
            required
                .unsupported_by(matrix.capabilities("openai").unwrap())
                .is_empty()
        );
        assert_eq!(
            required.unsupported_by(matrix.capabilities("ollama").unwrap()),
            vec!["parallel_tools"]
        );
        assert!(
            required
                .unsupported_by(matrix.capabilities("anthropic").unwrap())
                .contains(&"responses".to_string())
        );
    }

    #[test]
    fn plain_text_format_does_not_require_structured_output() {
        let required =
            CapabilityRequirements::from_responses_body(br#"{"text":{"format":{"type":"text"}}}"#)
                .unwrap();
        assert!(!required.structured_output);
        let required = CapabilityRequirements::from_responses_body(
            br#"{"text":{"format":{"type":"json_schema"}}}"#,
        )
        .unwrap();
        assert!(required.structured_output);
    }

    #[test]
    fn parallel_flag_without_tools_is_not_a_requirement() {
        let required = CapabilityRequirements::from_responses_body(
            br#"{"parallel_tool_calls":true,"input":"hello"}"#,
        )
        .unwrap();
        assert!(!required.tools);
        assert!(!required.parallel_tools);
        let matrix = CapabilityMatrix::built_in();
        assert!(
            required
                .unsupported_by(matrix.capabilities("ollama").unwrap())
                .is_empty()
        );
    }

    #[test]
    fn chat_wire_requirements_cover_tools_streaming_and_reasoning() {
        let openai = CapabilityRequirements::from_openai_chat_body(
            br#"{
                "tools":[{"type":"function","function":{"name":"read"}}],
                "parallel_tool_calls":true,
                "stream":true,
                "reasoning_effort":"high",
                "max_completion_tokens":4096
            }"#,
        )
        .unwrap();
        assert!(openai.tools);
        assert!(openai.parallel_tools);
        assert!(openai.streaming);
        assert!(openai.reasoning_controls);
        assert_eq!(openai.max_output_tokens, Some(4096));

        let anthropic = CapabilityRequirements::from_anthropic_messages_body(
            br#"{
                "messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_1","content":"ok"}]}],
                "stream":true,
                "thinking":{"type":"enabled","budget_tokens":1024},
                "max_tokens":2048
            }"#,
        )
        .unwrap();
        assert!(anthropic.tools);
        assert!(anthropic.streaming);
        assert!(anthropic.reasoning_controls);
        assert_eq!(anthropic.max_output_tokens, Some(2048));
    }

    #[test]
    fn chat_wire_requirements_detect_images_and_structured_output() {
        let openai = CapabilityRequirements::from_openai_chat_body(
            br#"{
                "messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,x"}}]}],
                "response_format":{"type":"json_schema","json_schema":{"name":"answer"}}
            }"#,
        )
        .unwrap();

        assert!(openai.modalities.contains(&"image".to_string()));
        assert!(openai.structured_output);
    }

    #[test]
    fn chat_wire_requirements_apply_protocol_defaults_and_legacy_shapes() {
        let legacy = CapabilityRequirements::from_openai_chat_body(
            br#"{
                "functions":[{"name":"read","parameters":{"type":"object"}}],
                "messages":[{"role":"function","name":"read","content":"ok"}],
                "max_completion_tokens":null,
                "max_tokens":100000
            }"#,
        )
        .unwrap();
        assert!(legacy.tools);
        assert!(legacy.parallel_tools);
        assert_eq!(legacy.max_output_tokens, Some(100000));
        let legacy_disabled = CapabilityRequirements::from_openai_chat_body(
            br#"{"functions":[{"name":"read"}],"function_call":"none"}"#,
        )
        .unwrap();
        assert!(legacy_disabled.tools);
        assert!(!legacy_disabled.parallel_tools);

        let anthropic = CapabilityRequirements::from_anthropic_messages_body(
            br#"{
                "tools":[{"name":"read","input_schema":{"type":"object"}}],
                "tool_choice":{"type":"auto","disable_parallel_tool_use":true},
                "messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"x"}}]}],
                "output_config":{"effort":"high","format":{"type":"json_schema"}},
                "max_tokens":1024
            }"#,
        )
        .unwrap();
        assert!(anthropic.tools);
        assert!(!anthropic.parallel_tools);
        assert!(anthropic.structured_output);
        assert!(anthropic.reasoning_controls);
        assert!(anthropic.modalities.contains(&"image".to_string()));

        let openai_audio = CapabilityRequirements::from_openai_chat_body(
            br#"{"messages":[],"modalities":["text","audio"]}"#,
        )
        .unwrap();
        assert!(openai_audio.modalities.contains(&"audio".to_string()));

        let openai_disabled = CapabilityRequirements::from_openai_chat_body(
            br#"{"tools":[{"type":"function","function":{"name":"read"}}],"tool_choice":"none"}"#,
        )
        .unwrap();
        assert!(openai_disabled.tools);
        assert!(!openai_disabled.parallel_tools);
        let anthropic_disabled = CapabilityRequirements::from_anthropic_messages_body(
            br#"{"tools":[{"name":"read","input_schema":{"type":"object"}}],"tool_choice":{"type":"none"}}"#,
        )
        .unwrap();
        assert!(anthropic_disabled.tools);
        assert!(!anthropic_disabled.parallel_tools);
        let responses_disabled = CapabilityRequirements::from_responses_body(
            br#"{"tools":[{"type":"function","name":"read"}],"tool_choice":"none"}"#,
        )
        .unwrap();
        assert!(responses_disabled.tools);
        assert!(!responses_disabled.parallel_tools);
    }

    #[test]
    fn tool_outputs_require_tool_capability_without_new_schemas() {
        let required = CapabilityRequirements::from_responses_body(
            br#"{"input":[{"type":"function_call_output","call_id":"call_1","output":"ok"}]}"#,
        )
        .unwrap();
        assert!(required.tools);
        assert_eq!(
            required.unsupported_by(CapabilityMatrix::built_in().capabilities("native").unwrap()),
            vec!["tools"]
        );

        let built_in = CapabilityRequirements::from_responses_body(
            br#"{"input":[{"type":"computer_call_output","call_id":"call_2","output":[]},{"type":"mcp_approval_response","approval_request_id":"approval_1","approve":true}]}"#,
        )
        .unwrap();
        assert_eq!(built_in.built_in_tools, vec!["computer_use_preview", "mcp"]);
    }

    #[test]
    fn output_limits_are_enforced_before_provider_contact() {
        let required = CapabilityRequirements::from_responses_body(
            br#"{"max_output_tokens":64000,"input":"hello"}"#,
        )
        .unwrap();
        let matrix = CapabilityMatrix::built_in();
        assert!(
            required
                .unsupported_by(matrix.capabilities("ollama").unwrap())
                .contains(&"max_output_tokens:64000>32000".to_string())
        );
        assert!(
            required
                .unsupported_by(matrix.capabilities("openai").unwrap())
                .is_empty()
        );
    }

    #[test]
    fn non_integer_output_limits_are_rejected() {
        for body in [
            br#"{"max_output_tokens":64000.0}"#.as_slice(),
            br#"{"max_output_tokens":6.4e4}"#.as_slice(),
            br#"{"max_output_tokens":-1}"#.as_slice(),
            br#"{"max_output_tokens":"64000"}"#.as_slice(),
        ] {
            assert_eq!(
                CapabilityRequirements::from_responses_body(body),
                Err("max_output_tokens must be an unsigned integer".to_string())
            );
        }
    }

    #[test]
    fn request_field_allowlist_blocks_retention_and_provider_extensions() {
        assert!(
            validate_responses_request_fields(
                br#"{"model":"gpt-5.5","input":"hi","service_tier":"flex"}"#
            )
            .unwrap_err()
            .contains("service_tier")
        );
        assert!(
            validate_responses_request_fields(
                br#"{"model":"gpt-5.5","input":"hi","stream":true,"reasoning":{"effort":"high"}}"#
            )
            .is_ok()
        );
    }

    #[test]
    fn responses_requests_are_forced_to_disable_provider_storage() {
        let normalized =
            normalize_responses_request(br#"{"model":"gpt-5.5","input":"hi"}"#).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&normalized).unwrap();
        assert_eq!(value["store"], false);
        assert!(
            normalize_responses_request(br#"{"model":"gpt-5.5","input":"hi","store":false}"#)
                .is_ok()
        );
        assert!(
            normalize_responses_request(br#"{"model":"gpt-5.5","input":"hi","store":true}"#)
                .is_err()
        );
    }
}
