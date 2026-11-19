//! Process-plane isolation for independently runnable Sekai and Chisei servers.
//!
//! Combined `sekai-chisei` still opens the typed two-store contract. The
//! `sekai-plane` and `chisei-plane` binaries each open only their own store and
//! credentials, stamp that ownership, and refuse the other plane's
//! destination variables or a store already stamped for the other plane.

use crate::combined_stores::{CombinedStoreLayout, CombinedStoreSources, StoreIdentity};
use crate::db::store_plane::{StorePlaneRole, ensure_store_plane};
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

    /// Chisei-plane requires a hop target (ADR 0096 rule 4). Combined and
    /// Sekai planes ignore the value. Reference-platform analog: governed compute
    /// modules that use OSDK require the platform endpoint variable at process start.
    pub fn require_sekai_endpoint(self, endpoint: Option<&str>) -> Result<(), String> {
        match self {
            Self::Chisei => {
                let trimmed = endpoint.map(str::trim).filter(|value| !value.is_empty());
                if trimmed.is_none() {
                    return Err(
                        "chisei process requires SEKAI_ENDPOINT; set it to the Sekai gRPC address (for example http://127.0.0.1:50051)"
                            .into(),
                    );
                }
                Ok(())
            }
            Self::Combined | Self::Sekai => Ok(()),
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
                crate::combined_stores::open_owned_layout(
                    self.store_role().expect("owned plane"),
                    sources,
                )
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

pub fn wrong_plane_message(plane: ProcessPlane) -> String {
    format!("wrong-plane: this process serves {}", plane.as_str())
}

pub fn plane_registry_anchor(plane: ProcessPlane, default_sqlite_path: &str) -> String {
    match plane {
        ProcessPlane::Chisei => crate::combined_stores::optional_trimmed_env("CHISEI_DB_PATH")
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
    use crate::combined_stores::open_owned_layout;
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
    fn chisei_process_requires_sekai_endpoint() {
        let err = ProcessPlane::Chisei
            .require_sekai_endpoint(None)
            .unwrap_err();
        assert!(err.contains("SEKAI_ENDPOINT"), "{err}");
        assert!(
            ProcessPlane::Chisei
                .require_sekai_endpoint(Some("http://127.0.0.1:50051"))
                .is_ok()
        );
        assert!(ProcessPlane::Combined.require_sekai_endpoint(None).is_ok());
        assert!(ProcessPlane::Sekai.require_sekai_endpoint(None).is_ok());
        assert!(
            ProcessPlane::Chisei
                .require_sekai_endpoint(Some("   "))
                .is_err()
        );
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
        assert!(
            err.contains("stamped for sekai") || err.contains("missed relocation"),
            "{err}"
        );
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
