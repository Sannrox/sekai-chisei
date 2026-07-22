//! Versioned runtime-backend selection and compatibility contracts.
//!
//! The community executable intentionally constructs only the complete SQLite
//! runtime. PostgreSQL implementations may advertise partial storage support,
//! but cannot be selected here until they satisfy every required reusable
//! surface.

use crate::db::sekai::SekaiDb;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;

pub const RUNTIME_BACKEND_CONTRACT_VERSION: &str = "sekai.runtime-backend/v1";

pub const COMMUNITY_REQUIRED_SURFACES: &[&str] = &[
    "chisei.budget",
    "chisei.execution",
    "chisei.policy",
    "gateway.governance",
    "operations.health",
    "sekai.audit",
    "sekai.authorization",
    "sekai.coordination",
    "sekai.graph",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendIdentity {
    Sqlite,
    Postgres,
}

impl BackendIdentity {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sqlite" => Ok(Self::Sqlite),
            "postgres" | "postgresql" => Ok(Self::Postgres),
            other => Err(format!(
                "unsupported SEKAI_DB_BACKEND {other:?}; expected sqlite or postgres"
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendCapabilities {
    pub contract_version: String,
    pub backend: BackendIdentity,
    pub reusable_surfaces: Vec<String>,
}

impl BackendCapabilities {
    pub fn validate_required(&self, required_surfaces: &[&str]) -> Result<(), String> {
        if self.contract_version != RUNTIME_BACKEND_CONTRACT_VERSION {
            return Err(format!(
                "incompatible runtime backend contract version {:?}; expected {:?}",
                self.contract_version, RUNTIME_BACKEND_CONTRACT_VERSION
            ));
        }

        let advertised: BTreeSet<&str> =
            self.reusable_surfaces.iter().map(String::as_str).collect();
        let missing: Vec<&str> = required_surfaces
            .iter()
            .copied()
            .filter(|surface| !advertised.contains(surface))
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "runtime backend {:?} is missing required reusable surfaces: {}",
                self.backend,
                missing.join(", ")
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeBackendConfig {
    pub backend: BackendIdentity,
    pub sqlite_path: Option<String>,
    pub postgres_url: Option<String>,
}

impl RuntimeBackendConfig {
    pub fn from_env(default_sqlite_path: &str) -> Result<Self, String> {
        let backend = BackendIdentity::parse(
            &std::env::var("SEKAI_DB_BACKEND").unwrap_or_else(|_| "sqlite".into()),
        )?;
        let explicit_sqlite_path = std::env::var("DB_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let postgres_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Self::from_sources(
            backend,
            explicit_sqlite_path.as_deref(),
            default_sqlite_path,
            postgres_url.as_deref(),
        )
    }

    pub fn from_sources(
        backend: BackendIdentity,
        explicit_sqlite_path: Option<&str>,
        default_sqlite_path: &str,
        postgres_url: Option<&str>,
    ) -> Result<Self, String> {
        if explicit_sqlite_path.is_some() && postgres_url.is_some() {
            return Err("DB_PATH and DATABASE_URL cannot both be configured".into());
        }

        match backend {
            BackendIdentity::Sqlite => {
                if postgres_url.is_some() {
                    return Err(
                        "DATABASE_URL requires SEKAI_DB_BACKEND=postgres; SQLite is the default"
                            .into(),
                    );
                }
                Ok(Self {
                    backend,
                    sqlite_path: Some(
                        explicit_sqlite_path
                            .unwrap_or(default_sqlite_path)
                            .to_string(),
                    ),
                    postgres_url: None,
                })
            }
            BackendIdentity::Postgres => {
                if explicit_sqlite_path.is_some() {
                    return Err("DB_PATH is incompatible with SEKAI_DB_BACKEND=postgres".into());
                }
                let postgres_url = postgres_url
                    .ok_or_else(|| "SEKAI_DB_BACKEND=postgres requires DATABASE_URL".to_string())?;
                Ok(Self {
                    backend,
                    sqlite_path: None,
                    postgres_url: Some(postgres_url.to_string()),
                })
            }
        }
    }
}

#[derive(Clone)]
pub struct RuntimeBackend {
    db: Arc<SekaiDb>,
    capabilities: BackendCapabilities,
}

impl RuntimeBackend {
    pub fn initialize(config: RuntimeBackendConfig) -> Result<Self, String> {
        match config.backend {
            BackendIdentity::Sqlite => {
                let db = Arc::new(SekaiDb::new(
                    config
                        .sqlite_path
                        .as_deref()
                        .ok_or("SQLite backend requires DB_PATH")?,
                )?);
                let capabilities = BackendCapabilities {
                    contract_version: RUNTIME_BACKEND_CONTRACT_VERSION.into(),
                    backend: BackendIdentity::Sqlite,
                    reusable_surfaces: COMMUNITY_REQUIRED_SURFACES
                        .iter()
                        .map(|surface| (*surface).to_string())
                        .collect(),
                };
                capabilities.validate_required(COMMUNITY_REQUIRED_SURFACES)?;
                Ok(Self { db, capabilities })
            }
            BackendIdentity::Postgres => Err(
                "PostgreSQL runtime backend is incomplete and cannot serve the community reusable surface"
                    .into(),
            ),
        }
    }

    pub fn capabilities(&self) -> &BackendCapabilities {
        &self.capabilities
    }

    pub fn database(&self) -> Arc<SekaiDb> {
        self.db.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_default_exposes_complete_versioned_capabilities() {
        let config =
            RuntimeBackendConfig::from_sources(BackendIdentity::Sqlite, None, ":memory:", None)
                .unwrap();
        let runtime = RuntimeBackend::initialize(config).unwrap();

        assert_eq!(runtime.capabilities().backend, BackendIdentity::Sqlite);
        runtime
            .capabilities()
            .validate_required(COMMUNITY_REQUIRED_SURFACES)
            .unwrap();

        let fixture: BackendCapabilities = serde_json::from_str(include_str!(
            "../tests/fixtures/runtime_backend/sqlite-v1.json"
        ))
        .unwrap();
        assert_eq!(runtime.capabilities(), &fixture);
    }

    #[test]
    fn rejects_partial_and_conflicting_backend_configuration() {
        let missing_url =
            RuntimeBackendConfig::from_sources(BackendIdentity::Postgres, None, "unused.db", None);
        assert!(missing_url.unwrap_err().contains("requires DATABASE_URL"));

        let conflicting = RuntimeBackendConfig::from_sources(
            BackendIdentity::Postgres,
            Some("sekai.db"),
            "unused.db",
            Some("postgres://localhost/sekai"),
        );
        assert!(conflicting.unwrap_err().contains("cannot both"));
    }

    #[test]
    fn rejects_incomplete_postgres_before_connecting() {
        let config = RuntimeBackendConfig::from_sources(
            BackendIdentity::Postgres,
            None,
            "unused.db",
            Some("postgres://must-not-be-contacted.invalid/sekai"),
        )
        .unwrap();

        let error = RuntimeBackend::initialize(config).err().unwrap();
        assert!(error.contains("incomplete"));
        assert!(
            COMMUNITY_REQUIRED_SURFACES
                .iter()
                .all(|surface| !surface.contains("tenant") && !surface.contains("identity"))
        );
    }

    #[test]
    fn capability_validation_rejects_missing_or_incompatible_surfaces() {
        let mut capabilities = BackendCapabilities {
            contract_version: RUNTIME_BACKEND_CONTRACT_VERSION.into(),
            backend: BackendIdentity::Postgres,
            reusable_surfaces: vec!["sekai.graph".into()],
        };
        assert!(
            capabilities
                .validate_required(COMMUNITY_REQUIRED_SURFACES)
                .unwrap_err()
                .contains("sekai.authorization")
        );

        capabilities.contract_version = "sekai.runtime-backend/v2".into();
        assert!(
            capabilities
                .validate_required(&["sekai.graph"])
                .unwrap_err()
                .contains("incompatible")
        );
    }
}
