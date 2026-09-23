//! Process-plane isolation for independently runnable Sekai and Chisei servers.
//!
//! Combined `sekai-chisei` still opens the typed two-store contract. The
//! `sekai-plane` and `chisei-plane` binaries each open only their own store and
//! credentials, stamp that ownership, and refuse the other plane's
//! destination variables or a store already stamped for the other plane.

use crate::combined_stores::{
    CombinedStoreLayout, CombinedStoreSources, StoreIdentity, optional_trimmed_env,
};
use crate::db::store_plane::{StorePlaneRole, ensure_store_plane};
use crate::runtime_backend::{
    BackendIdentity, COMMUNITY_REQUIRED_SURFACES, RuntimeBackend, RuntimeBackendConfig,
};
use crate::store_relocate::open_layout_or_fence;

/// Which gRPC plane this process serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessPlane {
    Combined,
    Sekai,
    Chisei,
}

impl ProcessPlane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Combined => "combined",
            Self::Sekai => "sekai",
            Self::Chisei => "chisei",
        }
    }

    pub fn serves_sekai(self) -> bool {
        matches!(self, Self::Combined | Self::Sekai)
    }

    pub fn serves_chisei(self) -> bool {
        matches!(self, Self::Combined | Self::Chisei)
    }

    pub fn store_role(self) -> Option<StorePlaneRole> {
        match self {
            Self::Combined => None,
            Self::Sekai => Some(StorePlaneRole::Sekai),
            Self::Chisei => Some(StorePlaneRole::Chisei),
        }
    }

    pub fn open_layout(self, default_sqlite_path: &str) -> Result<CombinedStoreLayout, String> {
        match self {
            Self::Combined => {
                let layout = open_layout_or_fence(default_sqlite_path)?;
                stamp_combined(&layout)?;
                Ok(layout)
            }
            Self::Sekai | Self::Chisei => {
                let sources = CombinedStoreSources::from_env(default_sqlite_path)?;
                open_owned_layout(self.store_role().expect("owned plane"), sources)
            }
        }
    }
}

fn stamp_combined(layout: &CombinedStoreLayout) -> Result<(), String> {
    if !layout.is_split() {
        return Ok(());
    }
    ensure_store_plane(&layout.sekai_runtime(), StorePlaneRole::Sekai)?;
    ensure_store_plane(&layout.chisei_runtime(), StorePlaneRole::Chisei)?;
    Ok(())
}

fn open_owned_layout(
    role: StorePlaneRole,
    sources: CombinedStoreSources,
) -> Result<CombinedStoreLayout, String> {
    refuse_foreign_destinations(role, &sources)?;
    let backend = sources.backend.unwrap_or(BackendIdentity::Sqlite);
    let default_sqlite_path = sources.default_sqlite_path.as_str();
    let (path, url) = match role {
        StorePlaneRole::Sekai => (
            sources
                .sekai_sqlite_path
                .as_deref()
                .or(sources.legacy_sqlite_path.as_deref())
                .unwrap_or(default_sqlite_path),
            sources
                .sekai_postgres_url
                .as_deref()
                .or(sources.legacy_postgres_url.as_deref()),
        ),
        StorePlaneRole::Chisei => match (
            sources.chisei_sqlite_path.as_deref(),
            sources.chisei_postgres_url.as_deref(),
            backend,
        ) {
            (None, None, BackendIdentity::Sqlite) => {
                return Err(
                    "chisei process requires CHISEI_DB_PATH; it does not open SEKAI_DB_PATH or DB_PATH"
                        .into(),
                );
            }
            (None, None, BackendIdentity::Postgres) => {
                return Err(
                    "chisei process requires CHISEI_DATABASE_URL; it does not open SEKAI_DATABASE_URL or DATABASE_URL"
                        .into(),
                );
            }
            (Some(path), _, BackendIdentity::Sqlite) => (path, None),
            (_, Some(url), BackendIdentity::Postgres) => (default_sqlite_path, Some(url)),
            (Some(_), _, BackendIdentity::Postgres) => {
                return Err(
                    "chisei process with SEKAI_DB_BACKEND=postgres requires CHISEI_DATABASE_URL"
                        .into(),
                );
            }
            (_, Some(_), BackendIdentity::Sqlite) => {
                return Err(
                    "chisei process with SEKAI_DB_BACKEND=sqlite requires CHISEI_DB_PATH".into(),
                );
            }
        },
    };

    let pool_size = crate::combined_stores::owned_plane_pool_size(
        sources.postgres_max_connections,
        match role {
            StorePlaneRole::Sekai => sources.sekai_pool_connections,
            StorePlaneRole::Chisei => sources.chisei_pool_connections,
        },
    )?;
    let layout = match (backend, url) {
        (BackendIdentity::Postgres, Some(url)) => {
            let identity = crate::combined_stores::postgres_identity(url)?;
            let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
                BackendIdentity::Postgres,
                None,
                "unused.db",
                Some(url),
                pool_size,
                sources.postgres_ca_cert_path.as_deref(),
            )?)?;
            backend
                .capabilities()
                .validate_required(COMMUNITY_REQUIRED_SURFACES)?;
            CombinedStoreLayout::shared(backend, identity)
        }
        (BackendIdentity::Postgres, None) => {
            return Err(match role {
                StorePlaneRole::Sekai => {
                    "sekai process with SEKAI_DB_BACKEND=postgres requires SEKAI_DATABASE_URL or DATABASE_URL"
                        .into()
                }
                StorePlaneRole::Chisei => {
                    "chisei process with SEKAI_DB_BACKEND=postgres requires CHISEI_DATABASE_URL"
                        .into()
                }
            });
        }
        (BackendIdentity::Sqlite, _) => {
            let identity = crate::combined_stores::sqlite_identity(path)?;
            let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_sources(
                BackendIdentity::Sqlite,
                Some(path),
                path,
                None,
                pool_size,
                sources.postgres_ca_cert_path.as_deref(),
            )?)?;
            backend
                .capabilities()
                .validate_required(COMMUNITY_REQUIRED_SURFACES)?;
            CombinedStoreLayout::shared(backend, identity)
        }
    };
    ensure_store_plane(&layout.sekai_runtime(), role)?;
    layout.sekai_runtime().set_pool_plane(match role {
        StorePlaneRole::Sekai => crate::obs::labels::PoolPlane::Sekai,
        StorePlaneRole::Chisei => crate::obs::labels::PoolPlane::Chisei,
    });
    Ok(layout)
}

fn refuse_foreign_destinations(
    role: StorePlaneRole,
    sources: &CombinedStoreSources,
) -> Result<(), String> {
    match role {
        StorePlaneRole::Sekai
            if sources.chisei_sqlite_path.is_some() || sources.chisei_postgres_url.is_some() =>
        {
            Err(
                "sekai process refuses Chisei destination variables; set only SEKAI_DB_PATH or SEKAI_DATABASE_URL"
                    .into(),
            )
        }
        StorePlaneRole::Chisei
            if sources.sekai_sqlite_path.is_some() || sources.sekai_postgres_url.is_some() =>
        {
            Err(
                "chisei process refuses Sekai destination variables; set only CHISEI_DB_PATH or CHISEI_DATABASE_URL"
                    .into(),
            )
        }
        _ => Ok(()),
    }
}

pub fn wrong_plane_message(plane: ProcessPlane) -> String {
    format!("wrong-plane: this process serves {}", plane.as_str())
}

pub fn plane_registry_anchor(plane: ProcessPlane, default_sqlite_path: &str) -> String {
    match plane {
        ProcessPlane::Chisei => optional_trimmed_env("CHISEI_DB_PATH")
            .unwrap_or_else(|| default_sqlite_path.to_string()),
        ProcessPlane::Combined | ProcessPlane::Sekai => {
            crate::combined_stores::registry_db_anchor(default_sqlite_path)
        }
    }
}

pub fn plane_store_identity(plane: ProcessPlane, layout: &CombinedStoreLayout) -> &StoreIdentity {
    match plane {
        ProcessPlane::Chisei => layout.chisei_identity(),
        ProcessPlane::Combined | ProcessPlane::Sekai => layout.sekai_identity(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_backend::BackendIdentity;

    fn sqlite_owned(path: &str) -> CombinedStoreSources {
        CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: path.into(),
            sekai_sqlite_path: Some(path.into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
    }

    fn chisei_owned(path: &str) -> CombinedStoreSources {
        CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: path.into(),
            chisei_sqlite_path: Some(path.into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
    }

    #[test]
    fn sekai_process_refuses_chisei_destination_env() {
        let err = open_owned_layout(
            StorePlaneRole::Sekai,
            CombinedStoreSources {
                backend: Some(BackendIdentity::Sqlite),
                default_sqlite_path: "sekai.db".into(),
                sekai_sqlite_path: Some("sekai.db".into()),
                chisei_sqlite_path: Some("chisei.db".into()),
                postgres_max_connections: 16,
                ..CombinedStoreSources::default()
            },
        )
        .unwrap_err();
        assert!(err.contains("refuses Chisei destination"), "{err}");
    }

    #[test]
    fn chisei_process_refuses_sekai_destination_env() {
        let err = open_owned_layout(
            StorePlaneRole::Chisei,
            CombinedStoreSources {
                backend: Some(BackendIdentity::Sqlite),
                default_sqlite_path: "chisei.db".into(),
                sekai_sqlite_path: Some("sekai.db".into()),
                chisei_sqlite_path: Some("chisei.db".into()),
                postgres_max_connections: 16,
                ..CombinedStoreSources::default()
            },
        )
        .unwrap_err();
        assert!(err.contains("refuses Sekai destination"), "{err}");
    }

    #[test]
    fn neither_process_opens_the_other_stamped_file() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        open_owned_layout(StorePlaneRole::Sekai, sqlite_owned(sekai.to_str().unwrap())).unwrap();
        open_owned_layout(
            StorePlaneRole::Chisei,
            chisei_owned(chisei.to_str().unwrap()),
        )
        .unwrap();

        let err = open_owned_layout(
            StorePlaneRole::Sekai,
            sqlite_owned(chisei.to_str().unwrap()),
        )
        .unwrap_err();
        assert!(err.contains("stamped for chisei"), "{err}");

        let err = open_owned_layout(
            StorePlaneRole::Chisei,
            chisei_owned(sekai.to_str().unwrap()),
        )
        .unwrap_err();
        assert!(err.contains("stamped for sekai"), "{err}");
    }

    #[test]
    fn combined_split_stamps_each_destination() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: "unused.db".into(),
            sekai_sqlite_path: Some(sekai.to_str().unwrap().into()),
            chisei_sqlite_path: Some(chisei.to_str().unwrap().into()),
            postgres_max_connections: 16,
            ..CombinedStoreSources::default()
        }
        .open()
        .unwrap();
        stamp_combined(&layout).unwrap();
        let err = open_owned_layout(
            StorePlaneRole::Sekai,
            sqlite_owned(chisei.to_str().unwrap()),
        )
        .unwrap_err();
        assert!(err.contains("stamped for chisei"), "{err}");
    }
}
