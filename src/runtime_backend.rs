//! Versioned runtime-backend selection and compatibility contracts.
//!
//! Operators may select SQLite (default) or PostgreSQL for the complete
//! reusable community control plane. Incomplete capability advertisements and
//! conflicting configuration fail closed before listeners bind.

use crate::db::chisei_rpc_inventory::postgres_complete_chisei_capabilities;
use crate::db::postgres::PostgresDb;
use crate::db::reusable::postgres_reusable_capabilities;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::db::sekai_rpc_inventory::postgres_complete_sekai_capabilities;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_version: Option<i64>,
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

    /// Enterprise composition may reject incomplete or outdated backends.
    pub fn compatible_with(
        &self,
        required_contract: &str,
        required_surfaces: &[&str],
        minimum_migration_version: Option<i64>,
    ) -> Result<(), String> {
        if self.contract_version != required_contract {
            return Err(format!(
                "backend contract {} incompatible with required {required_contract}",
                self.contract_version
            ));
        }
        self.validate_required(required_surfaces)?;
        if let Some(minimum) = minimum_migration_version {
            let version = self.migration_version.ok_or_else(|| {
                "backend does not advertise a migration version required by composition".to_string()
            })?;
            if version < minimum {
                return Err(format!(
                    "backend migration version {version} is older than required {minimum}"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeBackendConfig {
    pub backend: BackendIdentity,
    pub sqlite_path: Option<String>,
    pub postgres_url: Option<String>,
    pub postgres_max_connections: u32,
    pub postgres_ca_cert_path: Option<String>,
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
        let postgres_max_connections = std::env::var("SEKAI_POSTGRES_MAX_CONNECTIONS")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value
                    .parse::<u32>()
                    .map_err(|error| format!("SEKAI_POSTGRES_MAX_CONNECTIONS: {error}"))
            })
            .transpose()?
            .unwrap_or(16);
        let postgres_ca_cert_path = std::env::var("SEKAI_POSTGRES_CA_CERT")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Self::from_sources(
            backend,
            explicit_sqlite_path.as_deref(),
            default_sqlite_path,
            postgres_url.as_deref(),
            postgres_max_connections,
            postgres_ca_cert_path.as_deref(),
        )
    }

    pub fn from_sources(
        backend: BackendIdentity,
        explicit_sqlite_path: Option<&str>,
        default_sqlite_path: &str,
        postgres_url: Option<&str>,
        postgres_max_connections: u32,
        postgres_ca_cert_path: Option<&str>,
    ) -> Result<Self, String> {
        if explicit_sqlite_path.is_some() && postgres_url.is_some() {
            return Err("DB_PATH and DATABASE_URL cannot both be configured".into());
        }
        if postgres_max_connections == 0 {
            return Err("SEKAI_POSTGRES_MAX_CONNECTIONS must be greater than zero".into());
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
                    postgres_max_connections,
                    postgres_ca_cert_path: None,
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
                    postgres_max_connections,
                    postgres_ca_cert_path: postgres_ca_cert_path.map(str::to_string),
                })
            }
        }
    }
}

#[derive(Clone)]
pub struct RuntimeBackend {
    db: Arc<RuntimeDb>,
    capabilities: BackendCapabilities,
}

impl RuntimeBackend {
    pub fn initialize(config: RuntimeBackendConfig) -> Result<Self, String> {
        match config.backend {
            BackendIdentity::Sqlite => {
                let sqlite = Arc::new(SekaiDb::new(
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
                    migration_version: None,
                };
                capabilities.validate_required(COMMUNITY_REQUIRED_SURFACES)?;
                reject_tenant_surfaces(&capabilities)?;
                Ok(Self {
                    db: Arc::new(RuntimeDb::Sqlite(sqlite)),
                    capabilities,
                })
            }
            BackendIdentity::Postgres => {
                let url = config
                    .postgres_url
                    .as_deref()
                    .ok_or("PostgreSQL backend requires DATABASE_URL")?;
                let postgres = if let Some(ca_path) = config.postgres_ca_cert_path.as_deref() {
                    let certificate = std::fs::read(ca_path)
                        .map_err(|error| format!("read SEKAI_POSTGRES_CA_CERT: {error}"))?;
                    PostgresDb::connect_with_ca_certificate(
                        url,
                        config.postgres_max_connections,
                        &certificate,
                    )?
                } else {
                    PostgresDb::connect(url, config.postgres_max_connections)?
                };
                let migration_version = postgres.latest_migration_version()?;
                let capabilities = community_postgres_capabilities(Some(migration_version))?;
                capabilities.validate_required(COMMUNITY_REQUIRED_SURFACES)?;
                reject_tenant_surfaces(&capabilities)?;
                postgres.ping()?;
                Ok(Self {
                    db: Arc::new(RuntimeDb::Postgres(Arc::new(postgres))),
                    capabilities,
                })
            }
        }
    }

    pub fn capabilities(&self) -> &BackendCapabilities {
        &self.capabilities
    }

    pub fn database(&self) -> Arc<RuntimeDb> {
        self.db.clone()
    }
}

/// Complete community-advertised surfaces for PostgreSQL: reusable Sekai + Chisei
/// inventories plus operations health.
pub fn community_postgres_capabilities(
    migration_version: Option<i64>,
) -> Result<BackendCapabilities, String> {
    let sekai = postgres_complete_sekai_capabilities()?;
    let chisei = postgres_complete_chisei_capabilities()?;
    let foundations = postgres_reusable_capabilities();
    let mut surfaces = BTreeSet::new();
    for surface in sekai
        .reusable_surfaces
        .iter()
        .chain(chisei.reusable_surfaces.iter())
        .chain(foundations.reusable_surfaces.iter())
    {
        surfaces.insert(surface.clone());
    }
    surfaces.insert("operations.health".into());
    surfaces.insert("gateway.governance".into());
    for surface in COMMUNITY_REQUIRED_SURFACES {
        surfaces.insert((*surface).to_string());
    }
    let mut reusable_surfaces = surfaces.into_iter().collect::<Vec<_>>();
    reusable_surfaces.sort();
    Ok(BackendCapabilities {
        contract_version: RUNTIME_BACKEND_CONTRACT_VERSION.into(),
        backend: BackendIdentity::Postgres,
        reusable_surfaces,
        migration_version,
    })
}

fn reject_tenant_surfaces(capabilities: &BackendCapabilities) -> Result<(), String> {
    for surface in &capabilities.reusable_surfaces {
        let lower = surface.to_ascii_lowercase();
        for banned in ["tenant", "oidc", "oauth"] {
            if lower.contains(banned) {
                return Err(format!(
                    "community runtime must not advertise {banned} surface {surface}"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_default_exposes_complete_versioned_capabilities() {
        let config = RuntimeBackendConfig::from_sources(
            BackendIdentity::Sqlite,
            None,
            ":memory:",
            None,
            16,
            None,
        )
        .unwrap();
        let runtime = RuntimeBackend::initialize(config).unwrap();

        assert_eq!(runtime.capabilities().backend, BackendIdentity::Sqlite);
        runtime
            .capabilities()
            .validate_required(COMMUNITY_REQUIRED_SURFACES)
            .unwrap();
        assert!(matches!(runtime.database().as_ref(), RuntimeDb::Sqlite(_)));
    }

    #[test]
    fn rejects_partial_and_conflicting_backend_configuration() {
        let missing_url = RuntimeBackendConfig::from_sources(
            BackendIdentity::Postgres,
            None,
            "unused.db",
            None,
            16,
            None,
        );
        assert!(missing_url.unwrap_err().contains("requires DATABASE_URL"));

        let conflicting = RuntimeBackendConfig::from_sources(
            BackendIdentity::Postgres,
            Some("sekai.db"),
            "unused.db",
            Some("postgres://localhost/sekai"),
            16,
            None,
        );
        assert!(conflicting.unwrap_err().contains("cannot both"));
    }

    #[test]
    fn community_postgres_capabilities_cover_required_surfaces() {
        let capabilities = community_postgres_capabilities(Some(17)).unwrap();
        capabilities
            .validate_required(COMMUNITY_REQUIRED_SURFACES)
            .unwrap();
        assert_eq!(capabilities.backend, BackendIdentity::Postgres);
        assert_eq!(capabilities.migration_version, Some(17));
        assert!(
            capabilities
                .reusable_surfaces
                .iter()
                .all(|surface| !surface.to_ascii_lowercase().contains("tenant"))
        );
        for surface in ["chisei.execution", "sekai.graph", "gateway.governance"] {
            assert!(
                capabilities
                    .reusable_surfaces
                    .iter()
                    .any(|item| item == surface)
            );
        }
        let fixture: BackendCapabilities = serde_json::from_str(include_str!(
            "../tests/fixtures/runtime_backend/postgres-community-complete-v1.json"
        ))
        .unwrap();
        assert_eq!(capabilities, fixture);
    }

    #[test]
    fn composition_rejects_old_or_incomplete_backends() {
        let mut capabilities = community_postgres_capabilities(Some(10)).unwrap();
        assert!(
            capabilities
                .compatible_with(
                    RUNTIME_BACKEND_CONTRACT_VERSION,
                    COMMUNITY_REQUIRED_SURFACES,
                    Some(17)
                )
                .unwrap_err()
                .contains("older than required")
        );
        capabilities.migration_version = Some(17);
        capabilities
            .reusable_surfaces
            .retain(|s| s != "sekai.graph");
        assert!(
            capabilities
                .compatible_with(
                    RUNTIME_BACKEND_CONTRACT_VERSION,
                    COMMUNITY_REQUIRED_SURFACES,
                    Some(17)
                )
                .unwrap_err()
                .contains("missing required")
        );
    }

    #[test]
    fn capability_validation_rejects_missing_or_incompatible_surfaces() {
        let mut capabilities = BackendCapabilities {
            contract_version: RUNTIME_BACKEND_CONTRACT_VERSION.into(),
            backend: BackendIdentity::Postgres,
            reusable_surfaces: vec!["sekai.graph".into()],
            migration_version: None,
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
