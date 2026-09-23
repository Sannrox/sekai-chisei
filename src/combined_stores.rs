//! Combined-mode physical store composition.
//!
//! Destination variables open two stores. A shared path or database is refused.
//! Legacy `DB_PATH` / `DATABASE_URL` remain one physical identity until
//! relocation copies families (#1006). Combined mode never invents a second
//! file from a single path.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use postgres::Config as PostgresConfig;

use crate::db::runtime_db::RuntimeDb;
use crate::db::store::{ChiseiStore, SekaiStore, split_shared_runtime};
use crate::runtime_backend::{
    BackendIdentity, COMMUNITY_REQUIRED_SURFACES, RuntimeBackend, RuntimeBackendConfig,
};

/// Operator-visible identity of one physical store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreIdentity {
    Sqlite {
        canonical_path: String,
    },
    Postgres {
        host: String,
        port: u16,
        database: String,
    },
}

impl fmt::Display for StoreIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite { canonical_path } => write!(f, "sqlite:{canonical_path}"),
            Self::Postgres {
                host,
                port,
                database,
            } => write!(f, "postgres:{host}:{port}/{database}"),
        }
    }
}

/// How combined `sekai-chisei` opened its durable stores.
pub enum CombinedStoreLayout {
    /// One physical store behind both typed handles. Migration compatibility.
    Shared {
        backend: RuntimeBackend,
        identity: StoreIdentity,
    },
    /// Two distinct physical stores. The combined-mode target.
    Split {
        sekai: RuntimeBackend,
        chisei: RuntimeBackend,
        sekai_identity: StoreIdentity,
        chisei_identity: StoreIdentity,
        matched_generation: Arc<AtomicI64>,
    },
}

const UNCACHED_MATCHED_GENERATION: i64 = i64::MIN;

pub const SEKAI_POOL_ENV: &str = "SEKAI_POSTGRES_SEKAI_CONNECTIONS";
pub const CHISEI_POOL_ENV: &str = "SEKAI_POSTGRES_CHISEI_CONNECTIONS";

/// Divide one process connection budget across two Split backends.
///
/// Without per-plane sizes the budget splits in half; a one-connection
/// budget still opens one connection per store. An operator who has measured
/// one plane waiting on its pool (`sekai_db_pool_checkout_seconds`) sizes it
/// explicitly: one size takes that many connections and leaves the rest to
/// the other plane; two sizes must fit the budget together. Sizes that exceed
/// the budget or leave a plane without a connection refuse to start.
/// Pool size of a single-plane process: its own plane's size when set, else
/// the whole process budget.
pub(crate) fn owned_plane_pool_size(total: u32, own: Option<u32>) -> Result<u32, String> {
    match own {
        None => Ok(total),
        Some(0) => Err(format!(
            "{SEKAI_POOL_ENV} / {CHISEI_POOL_ENV} must give the store at least one connection"
        )),
        Some(own) if own > total => Err(format!(
            "plane pool size ({own}) exceeds SEKAI_POSTGRES_MAX_CONNECTIONS ({total})"
        )),
        Some(own) => Ok(own),
    }
}

pub(crate) fn split_connection_pool_budget(
    total: u32,
    sekai: Option<u32>,
    chisei: Option<u32>,
) -> Result<(u32, u32), String> {
    let fits = |sekai: u32, chisei: u32| {
        if sekai == 0 || chisei == 0 {
            Err(format!(
                "{SEKAI_POOL_ENV} and {CHISEI_POOL_ENV} must leave each Split store at least one connection"
            ))
        } else if u64::from(sekai) + u64::from(chisei) > u64::from(total) {
            Err(format!(
                "{SEKAI_POOL_ENV} ({sekai}) + {CHISEI_POOL_ENV} ({chisei}) exceed SEKAI_POSTGRES_MAX_CONNECTIONS ({total})"
            ))
        } else {
            Ok((sekai, chisei))
        }
    };
    match (sekai, chisei) {
        (None, None) => {
            let half = total / 2;
            Ok(if half == 0 {
                (1, 1)
            } else {
                (total - half, half)
            })
        }
        (Some(sekai), Some(chisei)) => fits(sekai, chisei),
        (Some(sekai), None) => fits(sekai, total.saturating_sub(sekai)),
        (None, Some(chisei)) => fits(total.saturating_sub(chisei), chisei),
    }
}

fn new_matched_generation_cache() -> Arc<AtomicI64> {
    Arc::new(AtomicI64::new(UNCACHED_MATCHED_GENERATION))
}

/// Testable inputs for [`CombinedStoreLayout`].
#[derive(Clone, Debug)]
pub struct CombinedStoreSources {
    pub backend: Option<BackendIdentity>,
    pub default_sqlite_path: String,
    pub legacy_sqlite_path: Option<String>,
    pub legacy_postgres_url: Option<String>,
    pub sekai_sqlite_path: Option<String>,
    pub chisei_sqlite_path: Option<String>,
    pub sekai_postgres_url: Option<String>,
    pub chisei_postgres_url: Option<String>,
    pub postgres_max_connections: u32,
    /// Split-only pool sizes carved out of `postgres_max_connections`.
    pub sekai_pool_connections: Option<u32>,
    pub chisei_pool_connections: Option<u32>,
    pub postgres_ca_cert_path: Option<String>,
    /// Constructed fixtures keep Shared. `from_env` sets this only when
    /// `SEKAI_SHARED_STORE=1` so Combined does not silently boot one identity.
    pub allow_shared_compatibility: bool,
}

impl Default for CombinedStoreSources {
    fn default() -> Self {
        Self {
            backend: None,
            default_sqlite_path: String::new(),
            legacy_sqlite_path: None,
            legacy_postgres_url: None,
            sekai_sqlite_path: None,
            chisei_sqlite_path: None,
            sekai_postgres_url: None,
            chisei_postgres_url: None,
            postgres_max_connections: 0,
            sekai_pool_connections: None,
            chisei_pool_connections: None,
            postgres_ca_cert_path: None,
            allow_shared_compatibility: true,
        }
    }
}

impl CombinedStoreSources {
    pub fn from_env(default_sqlite_path: &str) -> Result<Self, String> {
        let backend = BackendIdentity::parse(
            &std::env::var("SEKAI_DB_BACKEND").unwrap_or_else(|_| "sqlite".into()),
        )?;
        let connections = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|value| {
                    value
                        .trim()
                        .parse::<u32>()
                        .map_err(|error| format!("{name}: {error}"))
                })
                .transpose()
        };
        let postgres_max_connections = connections("SEKAI_POSTGRES_MAX_CONNECTIONS")?.unwrap_or(16);
        Ok(Self {
            backend: Some(backend),
            default_sqlite_path: default_sqlite_path.to_string(),
            legacy_sqlite_path: optional_trimmed_env("DB_PATH"),
            legacy_postgres_url: optional_trimmed_env("DATABASE_URL"),
            sekai_sqlite_path: optional_trimmed_env("SEKAI_DB_PATH"),
            chisei_sqlite_path: optional_trimmed_env("CHISEI_DB_PATH"),
            sekai_postgres_url: optional_trimmed_env("SEKAI_DATABASE_URL"),
            chisei_postgres_url: optional_trimmed_env("CHISEI_DATABASE_URL"),
            postgres_max_connections,
            sekai_pool_connections: connections(SEKAI_POOL_ENV)?,
            chisei_pool_connections: connections(CHISEI_POOL_ENV)?,
            postgres_ca_cert_path: optional_trimmed_env("SEKAI_POSTGRES_CA_CERT"),
            allow_shared_compatibility: std::env::var("SEKAI_SHARED_STORE").unwrap_or_default()
                == "1",
        })
    }

    fn split_pool_budget(&self) -> Result<(u32, u32), String> {
        split_connection_pool_budget(
            self.postgres_max_connections,
            self.sekai_pool_connections,
            self.chisei_pool_connections,
        )
    }

    pub fn open(self) -> Result<CombinedStoreLayout, String> {
        let backend = self.backend.unwrap_or(BackendIdentity::Sqlite);
        let dest_paths = (
            self.sekai_sqlite_path.as_deref(),
            self.chisei_sqlite_path.as_deref(),
        );
        let dest_urls = (
            self.sekai_postgres_url.as_deref(),
            self.chisei_postgres_url.as_deref(),
        );

        match (dest_paths, dest_urls, backend) {
            ((Some(_), None) | (None, Some(_)), _, _) => Err(
                "SEKAI_DB_PATH and CHISEI_DB_PATH must be set together; combined mode does not invent a second file from one path".into(),
            ),
            (_, (Some(_), None) | (None, Some(_)), _) => Err(
                "SEKAI_DATABASE_URL and CHISEI_DATABASE_URL must be set together; combined mode does not invent a second database from one URL".into(),
            ),
            ((Some(_), Some(_)), (Some(_), Some(_)), _) => Err(
                "SQLite destination paths and PostgreSQL destination URLs cannot both be configured".into(),
            ),
            ((Some(sekai), Some(chisei)), (None, None), BackendIdentity::Sqlite) => {
                if self.legacy_postgres_url.is_some() {
                    return Err(
                        "DATABASE_URL cannot be combined with SEKAI_DB_PATH / CHISEI_DB_PATH".into(),
                    );
                }
                open_split_sqlite(
                    sekai,
                    chisei,
                    self.split_pool_budget()?,
                    self.postgres_ca_cert_path.as_deref(),
                )
            }
            ((Some(_), Some(_)), (None, None), BackendIdentity::Postgres) => Err(
                "SEKAI_DB_PATH / CHISEI_DB_PATH require SEKAI_DB_BACKEND=sqlite".into(),
            ),
            ((None, None), (Some(sekai), Some(chisei)), BackendIdentity::Postgres) => {
                if self.legacy_sqlite_path.is_some() {
                    return Err(
                        "DB_PATH cannot be combined with SEKAI_DATABASE_URL / CHISEI_DATABASE_URL"
                            .into(),
                    );
                }
                open_split_postgres(
                    sekai,
                    chisei,
                    self.split_pool_budget()?,
                    self.postgres_ca_cert_path.as_deref(),
                )
            }
            ((None, None), (Some(_), Some(_)), BackendIdentity::Sqlite) => Err(
                "SEKAI_DATABASE_URL / CHISEI_DATABASE_URL require SEKAI_DB_BACKEND=postgres".into(),
            ),
            ((None, None), (None, None), _) => {
                if self.sekai_pool_connections.is_some() || self.chisei_pool_connections.is_some()
                {
                    return Err(format!(
                        "{SEKAI_POOL_ENV} and {CHISEI_POOL_ENV} size Split store pools; a shared store uses SEKAI_POSTGRES_MAX_CONNECTIONS"
                    ));
                }
                if !self.allow_shared_compatibility {
                    return Err(
                        "combined mode refuses a shared store unless SEKAI_SHARED_STORE=1; set SEKAI_DB_PATH and CHISEI_DB_PATH, or SEKAI_DATABASE_URL and CHISEI_DATABASE_URL"
                            .into(),
                    );
                }
                let config = RuntimeBackendConfig::from_sources(
                    backend,
                    self.legacy_sqlite_path.as_deref(),
                    &self.default_sqlite_path,
                    self.legacy_postgres_url.as_deref(),
                    self.postgres_max_connections,
                    self.postgres_ca_cert_path.as_deref(),
                )?;
                let identity = match backend {
                    BackendIdentity::Sqlite => sqlite_identity(
                        config
                            .sqlite_path
                            .as_deref()
                            .unwrap_or(&self.default_sqlite_path),
                    )?,
                    BackendIdentity::Postgres => postgres_identity(
                        config
                            .postgres_url
                            .as_deref()
                            .ok_or("SEKAI_DB_BACKEND=postgres requires DATABASE_URL")?,
                    )?,
                };
                let backend = RuntimeBackend::initialize(config)?;
                let layout = CombinedStoreLayout::Shared { backend, identity };
                crate::store_relocate::refuse_shared_writer_if_fenced(&layout)?;
                Ok(layout)
            }
        }
    }
}

impl fmt::Debug for CombinedStoreLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CombinedStoreLayout")
            .field("mode", &self.mode_name())
            .field("sekai", self.sekai_identity())
            .field("chisei", self.chisei_identity())
            .finish()
    }
}

impl CombinedStoreLayout {
    pub fn from_env(default_sqlite_path: &str) -> Result<Self, String> {
        CombinedStoreSources::from_env(default_sqlite_path)?.open()
    }

    pub fn shared(backend: RuntimeBackend, identity: StoreIdentity) -> Self {
        Self::Shared { backend, identity }
    }

    pub fn from_backend(backend: RuntimeBackend) -> Self {
        Self::Shared {
            backend,
            identity: StoreIdentity::Sqlite {
                canonical_path: ":memory:".into(),
            },
        }
    }

    pub fn is_split(&self) -> bool {
        matches!(self, Self::Split { .. })
    }

    pub fn mode_name(&self) -> &'static str {
        match self {
            Self::Shared { .. } => "shared-compatibility",
            Self::Split { .. } => "split",
        }
    }

    pub fn sekai_identity(&self) -> &StoreIdentity {
        match self {
            Self::Shared { identity, .. } => identity,
            Self::Split { sekai_identity, .. } => sekai_identity,
        }
    }

    pub fn chisei_identity(&self) -> &StoreIdentity {
        match self {
            Self::Shared { identity, .. } => identity,
            Self::Split {
                chisei_identity, ..
            } => chisei_identity,
        }
    }

    pub fn sekai_runtime(&self) -> Arc<RuntimeDb> {
        match self {
            Self::Shared { backend, .. } => backend.database(),
            Self::Split { sekai, .. } => sekai.database(),
        }
    }

    pub fn chisei_runtime(&self) -> Arc<RuntimeDb> {
        match self {
            Self::Shared { backend, .. } => backend.database(),
            Self::Split { chisei, .. } => chisei.database(),
        }
    }

    #[cfg(test)]
    pub(crate) fn connection_pool_maxes(&self) -> (u32, u32) {
        match self {
            Self::Shared { backend, .. } => {
                let max = backend.connection_pool_max();
                (max, max)
            }
            Self::Split { sekai, chisei, .. } => {
                (sekai.connection_pool_max(), chisei.connection_pool_max())
            }
        }
    }

    pub(crate) fn cached_matched_generation(&self) -> Option<i64> {
        match self {
            Self::Split {
                matched_generation, ..
            } => {
                let generation = matched_generation.load(Ordering::Acquire);
                (generation != UNCACHED_MATCHED_GENERATION).then_some(generation)
            }
            Self::Shared { .. } => None,
        }
    }

    pub(crate) fn cache_matched_generation(&self, generation: i64) {
        if let Self::Split {
            matched_generation, ..
        } = self
        {
            matched_generation.store(generation, Ordering::Release);
        }
    }

    pub(crate) fn invalidate_matched_generation(&self) {
        if let Self::Split {
            matched_generation, ..
        } = self
        {
            matched_generation.store(UNCACHED_MATCHED_GENERATION, Ordering::Release);
        }
    }

    pub fn handles(&self) -> (SekaiStore, ChiseiStore) {
        match self {
            Self::Shared { backend, .. } => split_shared_runtime(backend.database()),
            Self::Split { sekai, chisei, .. } => (
                SekaiStore::from_shared_runtime(sekai.database()),
                ChiseiStore::from_shared_runtime(chisei.database()),
            ),
        }
    }

    /// Filesystem anchor for provider-registry state. PostgreSQL uses the
    /// caller default because the store identity is a URL, not a file.
    pub fn registry_anchor_path(&self) -> Option<&str> {
        match self.sekai_identity() {
            StoreIdentity::Sqlite { canonical_path } if canonical_path != ":memory:" => {
                Some(canonical_path.as_str())
            }
            _ => None,
        }
    }

    pub fn validate_required_surfaces(&self) -> Result<(), String> {
        match self {
            Self::Shared { backend, .. } => backend
                .capabilities()
                .validate_required(COMMUNITY_REQUIRED_SURFACES),
            Self::Split { sekai, chisei, .. } => {
                sekai
                    .capabilities()
                    .validate_required(COMMUNITY_REQUIRED_SURFACES)?;
                chisei
                    .capabilities()
                    .validate_required(COMMUNITY_REQUIRED_SURFACES)
            }
        }
    }
}

/// Path used for provider-registry state beside the Sekai (or shared) file.
pub fn registry_db_anchor(default_sqlite_path: &str) -> String {
    optional_trimmed_env("SEKAI_DB_PATH").unwrap_or_else(|| default_sqlite_path.to_string())
}

fn open_split_sqlite(
    sekai_path: &str,
    chisei_path: &str,
    (sekai_pool, chisei_pool): (u32, u32),
    postgres_ca_cert_path: Option<&str>,
) -> Result<CombinedStoreLayout, String> {
    let sekai_identity = sqlite_identity(sekai_path)?;
    let chisei_identity = sqlite_identity(chisei_path)?;
    refuse_shared_identity(&sekai_identity, &chisei_identity)?;
    let sekai = RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Sqlite,
        Some(sekai_path),
        sekai_path,
        None,
        sekai_pool,
        postgres_ca_cert_path,
    )?)?;
    let chisei = RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Sqlite,
        Some(chisei_path),
        chisei_path,
        None,
        chisei_pool,
        postgres_ca_cert_path,
    )?)?;
    let sekai_identity = sqlite_identity(sekai_path)?;
    let chisei_identity = sqlite_identity(chisei_path)?;
    refuse_shared_identity(&sekai_identity, &chisei_identity)?;
    sekai
        .database()
        .set_pool_plane(crate::obs::labels::PoolPlane::Sekai);
    chisei
        .database()
        .set_pool_plane(crate::obs::labels::PoolPlane::Chisei);
    Ok(CombinedStoreLayout::Split {
        sekai,
        chisei,
        sekai_identity,
        chisei_identity,
        matched_generation: new_matched_generation_cache(),
    })
}

fn open_split_postgres(
    sekai_url: &str,
    chisei_url: &str,
    (sekai_pool, chisei_pool): (u32, u32),
    postgres_ca_cert_path: Option<&str>,
) -> Result<CombinedStoreLayout, String> {
    let sekai_identity = postgres_identity(sekai_url)?;
    let chisei_identity = postgres_identity(chisei_url)?;
    refuse_shared_identity(&sekai_identity, &chisei_identity)?;
    let sekai = RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Postgres,
        None,
        "unused.db",
        Some(sekai_url),
        sekai_pool,
        postgres_ca_cert_path,
    )?)?;
    let chisei = RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
        BackendIdentity::Postgres,
        None,
        "unused.db",
        Some(chisei_url),
        chisei_pool,
        postgres_ca_cert_path,
    )?)?;
    sekai
        .database()
        .set_pool_plane(crate::obs::labels::PoolPlane::Sekai);
    chisei
        .database()
        .set_pool_plane(crate::obs::labels::PoolPlane::Chisei);
    Ok(CombinedStoreLayout::Split {
        sekai,
        chisei,
        sekai_identity,
        chisei_identity,
        matched_generation: new_matched_generation_cache(),
    })
}

fn refuse_shared_identity(sekai: &StoreIdentity, chisei: &StoreIdentity) -> Result<(), String> {
    if sekai == chisei || sqlite_same_inode(sekai, chisei) {
        Err(format!(
            "combined mode refuses a shared store identity ({sekai}); set distinct SEKAI_DB_PATH and CHISEI_DB_PATH, or distinct SEKAI_DATABASE_URL and CHISEI_DATABASE_URL. A single DB_PATH or DATABASE_URL remains migration compatibility until relocation"
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn sqlite_same_inode(sekai: &StoreIdentity, chisei: &StoreIdentity) -> bool {
    match (sekai, chisei) {
        (
            StoreIdentity::Sqlite {
                canonical_path: sekai_path,
            },
            StoreIdentity::Sqlite {
                canonical_path: chisei_path,
            },
        ) if sekai_path != ":memory:" && chisei_path != ":memory:" => {
            same_file::is_same_file(Path::new(sekai_path), Path::new(chisei_path)).unwrap_or(false)
        }
        _ => false,
    }
}

pub(crate) fn sqlite_identity(path: &str) -> Result<StoreIdentity, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("SQLite destination path must not be empty".into());
    }
    if trimmed == ":memory:" {
        return Ok(StoreIdentity::Sqlite {
            canonical_path: ":memory:".into(),
        });
    }
    Ok(StoreIdentity::Sqlite {
        canonical_path: canonical_sqlite_path(trimmed)?,
    })
}

fn canonical_sqlite_path(path: &str) -> Result<String, String> {
    let raw = PathBuf::from(path);
    if let Ok(canon) = raw.canonicalize() {
        return Ok(canon.to_string_lossy().into_owned());
    }
    let abs = if raw.is_absolute() {
        raw
    } else {
        std::env::current_dir()
            .map_err(|error| format!("resolve SQLite path {path}: {error}"))?
            .join(raw)
    };
    Ok(normalize_path(&abs).to_string_lossy().into_owned())
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn canonicalize_postgres_host(host: &str) -> String {
    let host = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    match host.as_str() {
        "localhost" | "127.0.0.1" | "::1" | "0:0:0:0:0:0:0:1" => "127.0.0.1".into(),
        other => other.to_string(),
    }
}

pub(crate) fn postgres_identity(url: &str) -> Result<StoreIdentity, String> {
    let config = PostgresConfig::from_str(url)
        .map_err(|error| format!("invalid PostgreSQL destination URL: {error}"))?;
    let host = match config.get_hosts().first() {
        Some(postgres::config::Host::Tcp(host)) => canonicalize_postgres_host(host),
        Some(postgres::config::Host::Unix(path)) => path.display().to_string(),
        None => canonicalize_postgres_host("localhost"),
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    let database = config
        .get_dbname()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "PostgreSQL destination URL must include a database name".to_string())?
        .to_string();
    Ok(StoreIdentity::Postgres {
        host,
        port,
        database,
    })
}

pub(crate) fn optional_trimmed_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite_pair(sekai: &str, chisei: &str) -> CombinedStoreSources {
        CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: "unused.db".into(),
            sekai_sqlite_path: Some(sekai.into()),
            chisei_sqlite_path: Some(chisei.into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
    }

    #[test]
    fn legacy_sqlite_stays_one_physical_store() {
        let layout = CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: ":memory:".into(),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap();
        assert!(!layout.is_split());
        assert_eq!(layout.mode_name(), "shared-compatibility");
        let (sekai, chisei) = layout.handles();
        assert!(Arc::ptr_eq(&sekai.runtime_arc(), &chisei.runtime_arc()));
    }

    #[test]
    fn env_style_shared_boot_is_refused_without_explicit_compat() {
        let err = CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: ":memory:".into(),
            postgres_max_connections: 16,
            allow_shared_compatibility: false,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap_err();
        assert!(err.contains("SEKAI_SHARED_STORE=1"), "{err}");
    }

    #[test]
    fn destination_sqlite_paths_open_two_stores() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = sqlite_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap())
            .open()
            .unwrap();
        assert!(layout.is_split());
        assert_ne!(layout.sekai_identity(), layout.chisei_identity());
        let (sekai_store, chisei_store) = layout.handles();
        assert!(!Arc::ptr_eq(
            &sekai_store.runtime_arc(),
            &chisei_store.runtime_arc()
        ));
        let (sekai_pool, chisei_pool) = layout.connection_pool_maxes();
        assert_eq!((sekai_pool, chisei_pool), (8, 8));
        assert!(sekai_pool.saturating_add(chisei_pool) <= 16);
    }

    #[test]
    fn split_sqlite_shares_an_odd_process_pool_budget() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = CombinedStoreSources {
            postgres_max_connections: 15,
            ..sqlite_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap())
        }
        .open()
        .unwrap();
        let (sekai_pool, chisei_pool) = layout.connection_pool_maxes();
        assert_eq!((sekai_pool, chisei_pool), (8, 7));
        assert!(sekai_pool.saturating_add(chisei_pool) <= 15);
    }

    #[test]
    fn shared_sqlite_keeps_the_full_process_pool_budget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.db");
        let layout = CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: path.to_str().unwrap().into(),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap();
        assert!(!layout.is_split());
        assert_eq!(layout.connection_pool_maxes(), (16, 16));
    }

    #[test]
    fn split_connection_pool_budget_divides_the_process_ceiling() {
        assert_eq!(split_connection_pool_budget(16, None, None), Ok((8, 8)));
        assert_eq!(split_connection_pool_budget(15, None, None), Ok((8, 7)));
        assert_eq!(split_connection_pool_budget(1, None, None), Ok((1, 1)));
    }

    #[test]
    fn a_single_plane_process_takes_its_own_plane_size_within_the_budget() {
        assert_eq!(owned_plane_pool_size(16, None), Ok(16));
        assert_eq!(owned_plane_pool_size(16, Some(12)), Ok(12));
        assert!(owned_plane_pool_size(16, Some(20)).is_err());
        assert!(owned_plane_pool_size(16, Some(0)).is_err());
    }

    #[test]
    fn a_shared_store_refuses_per_plane_pool_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.db");
        let err = CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: path.to_str().unwrap().into(),
            postgres_max_connections: 16,
            sekai_pool_connections: Some(12),
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap_err();
        assert!(err.contains("size Split store pools"), "{err}");
    }

    #[test]
    fn per_plane_pool_sizes_fit_the_process_ceiling_or_refuse() {
        // One size takes its share and leaves the rest to the other plane.
        assert_eq!(
            split_connection_pool_budget(16, Some(12), None),
            Ok((12, 4))
        );
        assert_eq!(split_connection_pool_budget(16, None, Some(4)), Ok((12, 4)));
        // Two sizes may leave headroom under the ceiling.
        assert_eq!(
            split_connection_pool_budget(16, Some(10), Some(4)),
            Ok((10, 4))
        );
        // Over the ceiling, or a plane left without a connection, refuses.
        let over = split_connection_pool_budget(16, Some(12), Some(8)).unwrap_err();
        assert!(
            over.contains("exceed SEKAI_POSTGRES_MAX_CONNECTIONS (16)"),
            "{over}"
        );
        for (sekai, chisei) in [(Some(16), None), (None, Some(16)), (Some(0), Some(4))] {
            let starved = split_connection_pool_budget(16, sekai, chisei).unwrap_err();
            assert!(starved.contains("at least one connection"), "{starved}");
        }
    }

    #[test]
    fn same_destination_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.db");
        let err = sqlite_pair(path.to_str().unwrap(), path.to_str().unwrap())
            .open()
            .unwrap_err();
        assert!(err.contains("refuses a shared store identity"), "{err}");
    }

    #[test]
    fn hardlink_destinations_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        std::fs::write(&sekai, []).unwrap();
        std::fs::hard_link(&sekai, &chisei).unwrap();
        let err = sqlite_pair(sekai.to_str().unwrap(), chisei.to_str().unwrap())
            .open()
            .unwrap_err();
        assert!(err.contains("refuses a shared store identity"), "{err}");
    }

    #[test]
    fn relative_and_absolute_same_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.db");
        std::fs::write(&path, []).unwrap();
        let relative = path.strip_prefix(std::env::current_dir().unwrap()).ok();
        let Some(relative) = relative else {
            return;
        };
        let err = sqlite_pair(path.to_str().unwrap(), relative.to_str().unwrap())
            .open()
            .unwrap_err();
        assert!(err.contains("refuses a shared store identity"), "{err}");
    }

    #[test]
    fn both_memory_destinations_are_refused() {
        let err = sqlite_pair(":memory:", ":memory:").open().unwrap_err();
        assert!(err.contains("refuses a shared store identity"), "{err}");
    }

    #[test]
    fn partial_destination_paths_are_refused() {
        let err = CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: "unused.db".into(),
            sekai_sqlite_path: Some("sekai.db".into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap_err();
        assert!(err.contains("must be set together"), "{err}");
    }

    #[test]
    fn postgres_urls_to_the_same_database_are_refused() {
        let err = CombinedStoreSources {
            backend: Some(BackendIdentity::Postgres),
            default_sqlite_path: "unused.db".into(),
            sekai_postgres_url: Some("postgres://alice@localhost:5432/sekai".into()),
            chisei_postgres_url: Some("postgres://bob@localhost/sekai".into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap_err();
        assert!(err.contains("refuses a shared store identity"), "{err}");
    }

    #[test]
    fn postgres_identity_ignores_credentials() {
        let left = postgres_identity("postgres://alice:secret@db.example:5432/chisei").unwrap();
        let right = postgres_identity("postgres://bob@db.example:5432/chisei").unwrap();
        assert_eq!(left, right);
        let other = postgres_identity("postgres://alice@db.example:5432/sekai").unwrap();
        assert_ne!(left, other);
    }

    #[test]
    fn postgres_identity_treats_loopback_aliases_as_one_host() {
        let localhost = postgres_identity("postgres://alice@localhost:5432/sekai").unwrap();
        let ipv4 = postgres_identity("postgres://bob@127.0.0.1:5432/sekai").unwrap();
        let ipv6 = postgres_identity("postgres://carol@[::1]:5432/sekai").unwrap();
        assert_eq!(localhost, ipv4);
        assert_eq!(localhost, ipv6);
        let other_db = postgres_identity("postgres://alice@127.0.0.1:5432/chisei").unwrap();
        assert_ne!(localhost, other_db);
        let remote = postgres_identity("postgres://alice@db.example:5432/sekai").unwrap();
        assert_ne!(localhost, remote);
    }

    #[test]
    fn postgres_loopback_alias_pair_is_refused() {
        let err = CombinedStoreSources {
            backend: Some(BackendIdentity::Postgres),
            default_sqlite_path: "unused.db".into(),
            sekai_postgres_url: Some("postgres://alice@localhost:5432/sekai".into()),
            chisei_postgres_url: Some("postgres://bob@127.0.0.1:5432/sekai".into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap_err();
        assert!(err.contains("refuses a shared store identity"), "{err}");
    }
}
