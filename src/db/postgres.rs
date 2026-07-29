use std::str::FromStr;
use std::time::Duration;

use native_tls::Certificate;
use native_tls::TlsConnector;
use postgres::{Config as PostgresConfig, config::SslMode};
use postgres_native_tls::MakeTlsConnector;
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use uuid::Uuid;

use crate::db::sekai::PrincipalCredential;

const MIGRATION_LOCK_ID: i64 = 0x5345_4b41_4948_4101;
const CONTROL_PLANE_SCHEMA: &str = include_str!("postgres/0001_control_plane.sql");
const SAMPLE_LEASE_SCHEMA: &str = include_str!("postgres/0002_sample_leases.sql");
const UNIQUE_GRANT_SCHEMA: &str = include_str!("postgres/0003_unique_grants.sql");
const PORTFOLIO_PROMPT_VARIANT_SCHEMA: &str =
    include_str!("postgres/0004_portfolio_prompt_variants.sql");
const TENANT_SCHEMA: &str = include_str!("postgres/0005_tenants.sql");
const NAMESPACE_OWNERSHIP_SCHEMA: &str = include_str!("postgres/0006_namespace_ownership.sql");
const TENANT_MEMBERSHIP_SCHEMA: &str = include_str!("postgres/0007_tenant_memberships.sql");
const TENANT_CREDENTIAL_SCHEMA: &str = include_str!("postgres/0008_tenant_credentials.sql");
const GRAPH_PARITY_SCHEMA: &str = include_str!("postgres/0009_graph_parity.sql");
const SEKAI_PARITY_SCHEMA: &str = include_str!("postgres/0010_sekai_parity.sql");
const COORDINATION_PARITY_SCHEMA: &str = include_str!("postgres/0011_coordination_parity.sql");
const EVIDENCE_PARITY_SCHEMA: &str = include_str!("postgres/0012_evidence_parity.sql");
const RETENTION_DEDUPLICATION_PARITY_SCHEMA: &str =
    include_str!("postgres/0013_retention_deduplication_parity.sql");
const ACTION_GOVERNANCE_PARITY_SCHEMA: &str =
    include_str!("postgres/0014_action_governance_parity.sql");
const CAPABILITY_PACKAGE_PARITY_SCHEMA: &str =
    include_str!("postgres/0015_capability_package_parity.sql");
const TEAM_NAMESPACE_PARITY_SCHEMA: &str = include_str!("postgres/0016_team_namespace_parity.sql");
const CHISEI_EXECUTION_PARITY_SCHEMA: &str =
    include_str!("postgres/0017_chisei_execution_parity.sql");
const BUDGET_TOPOLOGY_SCHEMA: &str = include_str!("postgres/0018_budget_topology.sql");
const LEASE_SITE_ID_SCHEMA: &str = include_str!("postgres/0019_lease_site_id.sql");
const GOVERNED_ACTION_TYPES_SCHEMA: &str = include_str!("postgres/0020_governed_action_types.sql");
const GOVERNED_ACTION_INSTANCES_SCHEMA: &str =
    include_str!("postgres/0021_governed_action_instances.sql");
const ACTION_EFFECTS_SCHEMA: &str = include_str!("postgres/0022_action_effects.sql");
const PARKED_WORK_CONTINUATION_SCHEMA: &str =
    include_str!("postgres/0023_parked_work_continuation.sql");

#[derive(Clone, Copy)]
struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "control_plane",
        sql: CONTROL_PLANE_SCHEMA,
    },
    Migration {
        version: 2,
        name: "sample_leases",
        sql: SAMPLE_LEASE_SCHEMA,
    },
    Migration {
        version: 3,
        name: "unique_grants",
        sql: UNIQUE_GRANT_SCHEMA,
    },
    Migration {
        version: 4,
        name: "portfolio_prompt_variants",
        sql: PORTFOLIO_PROMPT_VARIANT_SCHEMA,
    },
    Migration {
        version: 5,
        name: "tenants",
        sql: TENANT_SCHEMA,
    },
    Migration {
        version: 6,
        name: "namespace_ownership",
        sql: NAMESPACE_OWNERSHIP_SCHEMA,
    },
    Migration {
        version: 7,
        name: "tenant_memberships",
        sql: TENANT_MEMBERSHIP_SCHEMA,
    },
    Migration {
        version: 8,
        name: "tenant_credentials",
        sql: TENANT_CREDENTIAL_SCHEMA,
    },
    Migration {
        version: 9,
        name: "graph_parity",
        sql: GRAPH_PARITY_SCHEMA,
    },
    Migration {
        version: 10,
        name: "sekai_parity",
        sql: SEKAI_PARITY_SCHEMA,
    },
    Migration {
        version: 11,
        name: "coordination_parity",
        sql: COORDINATION_PARITY_SCHEMA,
    },
    Migration {
        version: 12,
        name: "evidence_parity",
        sql: EVIDENCE_PARITY_SCHEMA,
    },
    Migration {
        version: 13,
        name: "retention_deduplication_parity",
        sql: RETENTION_DEDUPLICATION_PARITY_SCHEMA,
    },
    Migration {
        version: 14,
        name: "action_governance_parity",
        sql: ACTION_GOVERNANCE_PARITY_SCHEMA,
    },
    Migration {
        version: 15,
        name: "capability_package_parity",
        sql: CAPABILITY_PACKAGE_PARITY_SCHEMA,
    },
    Migration {
        version: 16,
        name: "team_namespace_parity",
        sql: TEAM_NAMESPACE_PARITY_SCHEMA,
    },
    Migration {
        version: 17,
        name: "chisei_execution_parity",
        sql: CHISEI_EXECUTION_PARITY_SCHEMA,
    },
    Migration {
        version: 18,
        name: "budget_topology",
        sql: BUDGET_TOPOLOGY_SCHEMA,
    },
    Migration {
        version: 19,
        name: "lease_site_id",
        sql: LEASE_SITE_ID_SCHEMA,
    },
    Migration {
        version: 20,
        name: "governed_action_types",
        sql: GOVERNED_ACTION_TYPES_SCHEMA,
    },
    Migration {
        version: 21,
        name: "governed_action_instances",
        sql: GOVERNED_ACTION_INSTANCES_SCHEMA,
    },
    Migration {
        version: 22,
        name: "action_effects",
        sql: ACTION_EFFECTS_SCHEMA,
    },
    Migration {
        version: 23,
        name: "parked_work_continuation",
        sql: PARKED_WORK_CONTINUATION_SCHEMA,
    },
];

type Manager = PostgresConnectionManager<MakeTlsConnector>;

/// Shared PostgreSQL connection pool used by the HA storage backend.
///
/// Construction verifies connectivity and runs forward-only migrations while
/// holding a transaction-scoped advisory lock. Concurrent replicas can start
/// together; only one applies migrations and the others observe the committed
/// schema before serving requests.
pub struct PostgresDb {
    pool: Pool<Manager>,
}

impl std::fmt::Debug for PostgresDb {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresDb")
            .field("pool_state", &self.pool_state())
            .finish()
    }
}

impl PostgresDb {
    pub fn connect(database_url: &str, max_connections: u32) -> Result<Self, String> {
        let tls = TlsConnector::builder()
            .build()
            .map(MakeTlsConnector::new)
            .map_err(|error| format!("build PostgreSQL TLS connector: {error}"))?;
        Self::connect_with_tls(database_url, max_connections, tls)
    }

    /// Connect with an explicitly supplied PEM CA certificate.
    ///
    /// This keeps certificate trust explicit for isolated conformance
    /// environments without permitting plaintext or disabled verification.
    pub fn connect_with_ca_certificate(
        database_url: &str,
        max_connections: u32,
        ca_certificate_pem: &[u8],
    ) -> Result<Self, String> {
        let certificate = Certificate::from_pem(ca_certificate_pem)
            .map_err(|error| format!("parse PostgreSQL test CA certificate: {error}"))?;
        let mut builder = TlsConnector::builder();
        builder.add_root_certificate(certificate);
        let tls = builder
            .build()
            .map(MakeTlsConnector::new)
            .map_err(|error| format!("build PostgreSQL test TLS connector: {error}"))?;
        Self::connect_with_tls(database_url, max_connections, tls)
    }

    fn connect_with_tls(
        database_url: &str,
        max_connections: u32,
        tls: MakeTlsConnector,
    ) -> Result<Self, String> {
        if database_url.trim().is_empty() {
            return Err("PostgreSQL database URL must not be empty".into());
        }
        if max_connections == 0 {
            return Err("PostgreSQL pool size must be greater than zero".into());
        }
        let config = secure_config(database_url)?;
        let manager = PostgresConnectionManager::new(config, tls);
        let pool = Pool::builder()
            .max_size(max_connections)
            // The synchronous postgres client owns an internal Tokio runtime.
            // Establish the configured pool before the application runtime
            // starts so request-time acquisition never initializes a client
            // from an async executor thread.
            .min_idle(Some(max_connections))
            .connection_timeout(Duration::from_secs(10))
            .build(manager)
            .map_err(|error| format!("connect to PostgreSQL: {error}"))?;
        let db = Self { pool };
        db.migrate()?;
        Ok(db)
    }

    pub fn ping(&self) -> Result<(), String> {
        self.connection()?
            .simple_query("SELECT 1")
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn pool_state(&self) -> (u32, u32) {
        let state = self.pool.state();
        (state.connections, state.idle_connections)
    }

    /// Highest applied forward migration version for capability advertisement.
    pub fn latest_migration_version(&self) -> Result<i64, String> {
        self.connection()?
            .query_opt(
                "SELECT COALESCE(MAX(version), 0) FROM sekai_schema_migrations",
                &[],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0))
            .ok_or_else(|| "sekai_schema_migrations is unavailable".to_string())
    }

    pub fn get_principal_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT id, principal, token_hash, status, created, rotated_at, revoked_at, tenant_id
                 FROM sekai_principal_credentials
                 WHERE token_hash = $1 AND tenant_id = '' AND status = 'active'
                 ORDER BY created DESC LIMIT 1",
                &[&token_hash],
            )
            .map(|row| row.map(row_to_principal_credential))
            .map_err(|error| error.to_string())
    }

    pub fn principal_credentials_activity_epoch(&self) -> Result<i64, String> {
        let mut connection = self.connection()?;
        connection
            .query_one(
                "SELECT GREATEST(
                    COALESCE(MAX(created), 0),
                    COALESCE(MAX(rotated_at), 0),
                    COALESCE(MAX(revoked_at), 0)
                 ) FROM sekai_principal_credentials",
                &[],
            )
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
    }

    pub fn create_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
        now: i64,
    ) -> Result<PrincipalCredential, String> {
        let id = format!("credential-{}", Uuid::new_v4().simple());
        let mut connection = self.connection()?;
        let row = connection
            .query_one(
                "INSERT INTO sekai_principal_credentials
                    (id, principal, token_hash, status, created, rotated_at, revoked_at)
                 VALUES ($1, $2, $3, 'active', $4, $4, 0)
                 RETURNING id, principal, token_hash, status, created, rotated_at, revoked_at, tenant_id",
                &[&id, &principal, &token_hash, &now],
            )
            .map_err(|error| format!("create principal credential: {error}"))?;
        Ok(row_to_principal_credential(row))
    }

    pub fn rotate_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
    ) -> Result<PrincipalCredential, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let id = format!("credential-{}", Uuid::new_v4().simple());
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                &[&principal],
            )
            .map_err(|error| format!("lock credential rotation: {error}"))?;
        transaction
            .execute(
                "UPDATE sekai_principal_credentials
                 SET status = 'revoked', revoked_at = $2
                 WHERE principal = $1 AND tenant_id = '' AND status = 'active'",
                &[&principal, &now],
            )
            .map_err(|error| error.to_string())?;
        let row = transaction
            .query_one(
                "INSERT INTO sekai_principal_credentials
                    (id, principal, token_hash, status, created, rotated_at, revoked_at)
                 VALUES ($1, $2, $3, 'active', $4, $4, 0)
                 RETURNING id, principal, token_hash, status, created, rotated_at, revoked_at, tenant_id",
                &[&id, &principal, &token_hash, &now],
            )
            .map_err(|error| error.to_string())?;
        let credential = row_to_principal_credential(row);
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(credential)
    }

    pub fn revoke_principal_credential(
        &self,
        principal: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut connection = self.connection()?;
        let row = connection
            .query_opt(
                "UPDATE sekai_principal_credentials
                 SET status = 'revoked', revoked_at = $2
                 WHERE id = (
                    SELECT id FROM sekai_principal_credentials
                    WHERE principal = $1 AND tenant_id = '' AND status = 'active'
                    ORDER BY created DESC LIMIT 1 FOR UPDATE
                 )
                 RETURNING id, principal, token_hash, status, created, rotated_at, revoked_at, tenant_id",
                &[&principal, &now],
            )
            .map_err(|error| error.to_string())?;
        Ok(row.map(row_to_principal_credential))
    }

    pub fn list_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        let mut connection = self.connection()?;
        connection
            .query(
                "SELECT id, principal, token_hash, status, created, rotated_at, revoked_at, tenant_id
                 FROM sekai_principal_credentials
                 WHERE tenant_id = ''
                   AND ($1::text IS NULL OR principal = $1)
                   AND ($2::text IS NULL OR status = $2)
                 ORDER BY created, id",
                &[&principal, &status],
            )
            .map(|rows| rows.into_iter().map(row_to_principal_credential).collect())
            .map_err(|error| error.to_string())
    }

    pub fn list_active_credentials(&self) -> Result<Vec<PrincipalCredential>, String> {
        self.list_credentials(None, Some("active"))
    }

    pub(crate) fn connection(&self) -> Result<PooledConnection<Manager>, String> {
        self.pool
            .get()
            .map_err(|error| format!("acquire PostgreSQL connection: {error}"))
    }

    fn migrate(&self) -> Result<(), String> {
        self.migrate_with(MIGRATIONS)
    }

    fn migrate_with(&self, migrations: &[Migration]) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| format!("begin PostgreSQL migration: {error}"))?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_ID])
            .map_err(|error| format!("lock PostgreSQL migrations: {error}"))?;
        transaction
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS sekai_schema_migrations (
                    version BIGINT PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at BIGINT NOT NULL
                );",
            )
            .map_err(|error| format!("initialize PostgreSQL migrations: {error}"))?;
        let rows = transaction
            .query(
                "SELECT version, name FROM sekai_schema_migrations ORDER BY version",
                &[],
            )
            .map_err(|error| format!("read PostgreSQL migration state: {error}"))?;
        if rows.len() > migrations.len() {
            let version: i64 = rows[migrations.len()].get(0);
            return Err(format!(
                "PostgreSQL schema version {version} is newer than supported version {}; upgrade sekai-chisei before startup",
                migrations.last().map_or(0, |migration| migration.version)
            ));
        }
        for (index, row) in rows.iter().enumerate() {
            let version: i64 = row.get(0);
            let name: String = row.get(1);
            let expected = &migrations[index];
            if version != expected.version || name != expected.name {
                return Err(format!(
                    "incompatible PostgreSQL migration history at position {}: found version {version} ({name}), expected version {} ({}); restore a compatible schema before startup",
                    index + 1,
                    expected.version,
                    expected.name
                ));
            }
        }
        for migration in &migrations[rows.len()..] {
            tracing::info!(
                version = migration.version,
                name = migration.name,
                "applying PostgreSQL migration"
            );
            transaction.batch_execute(migration.sql).map_err(|error| {
                format!(
                    "apply PostgreSQL migration {} ({}): {error}",
                    migration.version, migration.name
                )
            })?;
            transaction
                .execute(
                    "INSERT INTO sekai_schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)",
                    &[&migration.version, &migration.name, &chrono::Utc::now().timestamp_millis()],
                )
                .map_err(|error| {
                    format!(
                        "record PostgreSQL migration {} ({}): {error}",
                        migration.version, migration.name
                    )
                })?;
        }
        transaction
            .commit()
            .map_err(|error| format!("commit PostgreSQL migrations: {error}"))?;
        tracing::info!(
            schema_version = migrations.last().map_or(0, |migration| migration.version),
            newly_applied = migrations.len() - rows.len(),
            "PostgreSQL migrations complete"
        );
        Ok(())
    }
}

fn row_to_principal_credential(row: postgres::Row) -> PrincipalCredential {
    PrincipalCredential {
        id: row.get(0),
        principal: row.get(1),
        token_hash: row.get(2),
        status: row.get(3),
        created: row.get(4),
        rotated_at: row.get(5),
        revoked_at: row.get(6),
        tenant_id: row.get(7),
    }
}

fn secure_config(database_url: &str) -> Result<PostgresConfig, String> {
    let mut config = PostgresConfig::from_str(database_url).map_err(|error| error.to_string())?;
    config.ssl_mode(SslMode::Require);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex};

    const TEST_DATABASE_URL_ENV: &str = "SEKAI_TEST_POSTGRES_URL";
    static POSTGRES_MIGRATION_TEST: Mutex<()> = Mutex::new(());

    fn test_database() -> PostgresDb {
        let database_url = std::env::var(TEST_DATABASE_URL_ENV).unwrap_or_else(|_| {
            panic!("{TEST_DATABASE_URL_ENV} must point to an isolated PostgreSQL test database")
        });
        if let Ok(ca_certificate_path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            let ca_certificate = std::fs::read(&ca_certificate_path).unwrap_or_else(|error| {
                panic!("read PostgreSQL test CA certificate {ca_certificate_path}: {error}")
            });
            PostgresDb::connect_with_ca_certificate(&database_url, 4, &ca_certificate).unwrap()
        } else {
            PostgresDb::connect(&database_url, 4).unwrap()
        }
    }

    fn reset_database(db: &PostgresDb) {
        db.connection()
            .unwrap()
            .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            .unwrap();
    }

    fn migration_rows(db: &PostgresDb) -> Vec<(i64, String)> {
        db.connection()
            .unwrap()
            .query(
                "SELECT version, name FROM sekai_schema_migrations ORDER BY version",
                &[],
            )
            .unwrap()
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    }

    #[test]
    fn rejects_invalid_configuration_before_connecting() {
        assert!(
            PostgresDb::connect("", 10)
                .unwrap_err()
                .contains("must not be empty")
        );
        assert!(
            PostgresDb::connect("postgresql://localhost/sekai", 0)
                .unwrap_err()
                .contains("greater than zero")
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn prewarms_configured_connections_before_returning() {
        let database = test_database();
        assert_eq!(database.pool_state(), (4, 4));
    }

    #[test]
    fn migration_lock_id_is_stable_and_nonzero() {
        assert_ne!(MIGRATION_LOCK_ID, 0);
        assert_eq!(MIGRATION_LOCK_ID, 0x5345_4b41_4948_4101);
    }

    #[test]
    fn tls_is_required_even_when_url_requests_plaintext() {
        let config = secure_config("postgresql://localhost/sekai?sslmode=disable").unwrap();
        assert_eq!(config.get_ssl_mode(), SslMode::Require);
    }

    #[test]
    fn control_plane_migration_covers_every_durable_table() {
        for table in [
            "sekai_objects",
            "sekai_principal_credentials",
            "sekai_decisions",
            "sekai_attestations",
            "sekai_work_units",
            "sekai_reservations",
            "chisei_eval_suites",
            "chisei_eval_runs",
            "chisei_eval_iterations",
            "chisei_budget_limits",
            "chisei_budget_usage",
        ] {
            assert!(
                CONTROL_PLANE_SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL table {table}"
            );
        }
        assert!(!CONTROL_PLANE_SCHEMA.contains("AUTOINCREMENT"));
        assert!(!CONTROL_PLANE_SCHEMA.contains("INSERT OR"));
        assert!(SAMPLE_LEASE_SCHEMA.contains("lease_expires_at"));
        assert!(SAMPLE_LEASE_SCHEMA.contains("IF NOT EXISTS"));
        assert!(PORTFOLIO_PROMPT_VARIANT_SCHEMA.contains("DEFAULT 'legacy@1'"));
        assert!(TENANT_SCHEMA.contains("CREATE TABLE IF NOT EXISTS sekai_tenants"));
        assert!(TENANT_SCHEMA.contains("CREATE TABLE IF NOT EXISTS sekai_tenant_requests"));
        assert!(
            NAMESPACE_OWNERSHIP_SCHEMA
                .contains("CREATE TABLE IF NOT EXISTS sekai_namespace_ownership")
        );
        assert!(NAMESPACE_OWNERSHIP_SCHEMA.contains("trg_tenant_object_write"));
        assert!(NAMESPACE_OWNERSHIP_SCHEMA.contains("trg_tenant_link_write"));
        assert!(
            TENANT_MEMBERSHIP_SCHEMA
                .contains("CREATE TABLE IF NOT EXISTS sekai_tenant_memberships")
        );
        assert!(
            PORTFOLIO_PROMPT_VARIANT_SCHEMA
                .contains("ADD PRIMARY KEY (namespace, task_class, model, prompt_variant)")
        );
        for table in [
            "sekai_action_policies",
            "sekai_action_approvals",
            "sekai_action_blast_radius",
            "sekai_action_governance_audit",
        ] {
            assert!(
                ACTION_GOVERNANCE_PARITY_SCHEMA
                    .contains(&format!("CREATE TABLE IF NOT EXISTS {table}"))
            );
        }
        for excluded in ["tenant", "oauth", "oidc"] {
            assert!(!ACTION_GOVERNANCE_PARITY_SCHEMA.contains(excluded));
        }
        for table in [
            "sekai_capability_package_versions",
            "sekai_capability_package_installations",
            "sekai_capability_package_events",
        ] {
            assert!(
                CAPABILITY_PACKAGE_PARITY_SCHEMA
                    .contains(&format!("CREATE TABLE IF NOT EXISTS {table}"))
            );
        }
        for excluded in ["tenant", "oauth", "oidc", "chisei", "gateway"] {
            assert!(!CAPABILITY_PACKAGE_PARITY_SCHEMA.contains(excluded));
        }
        assert!(
            TEAM_NAMESPACE_PARITY_SCHEMA
                .contains("CREATE TABLE IF NOT EXISTS sekai_team_principals")
        );
        for excluded in ["tenant", "oauth", "oidc", "chisei", "gateway"] {
            assert!(!TEAM_NAMESPACE_PARITY_SCHEMA.contains(excluded));
        }
        for table in [
            "chisei_operation_receipts",
            "chisei_gateway_request_aliases",
            "chisei_budget_usage_events",
            "chisei_budget_attributions",
            "chisei_kioku_memories",
            "chisei_external_action_authorizations",
            "chisei_external_action_permits",
        ] {
            assert!(
                CHISEI_EXECUTION_PARITY_SCHEMA
                    .contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL table {table}"
            );
        }
        for excluded in ["tenant", "oauth", "oidc"] {
            assert!(!CHISEI_EXECUTION_PARITY_SCHEMA.contains(excluded));
        }
        assert!(!CHISEI_EXECUTION_PARITY_SCHEMA.contains("AUTOINCREMENT"));
        assert!(!CHISEI_EXECUTION_PARITY_SCHEMA.contains("INSERT OR"));
        for table in ["chisei_budget_pools", "chisei_budget_transfers"] {
            assert!(
                BUDGET_TOPOLOGY_SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL table {table}"
            );
        }
        assert!(BUDGET_TOPOLOGY_SCHEMA.contains("home_site_id"));
        assert!(BUDGET_TOPOLOGY_SCHEMA.contains("pool_id"));
        for excluded in ["tenant", "oauth", "oidc"] {
            assert!(!BUDGET_TOPOLOGY_SCHEMA.contains(excluded));
        }
    }

    #[test]
    fn migration_manifest_is_contiguous_and_named() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(migration.version, index as i64 + 1);
            assert!(!migration.name.is_empty());
            assert!(!migration.sql.trim().is_empty());
        }
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn fresh_database_applies_every_migration_once() {
        let _guard = POSTGRES_MIGRATION_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let db = test_database();
        reset_database(&db);

        db.migrate().unwrap();
        db.migrate().unwrap();

        let expected: Vec<_> = MIGRATIONS
            .iter()
            .map(|migration| (migration.version, migration.name.to_owned()))
            .collect();
        assert_eq!(migration_rows(&db), expected);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn upgrades_every_supported_prior_version_without_reset() {
        let _guard = POSTGRES_MIGRATION_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let db = test_database();

        for prior_version in 0..MIGRATIONS.len() {
            reset_database(&db);
            db.migrate_with(&MIGRATIONS[..prior_version]).unwrap();
            let marker = format!("upgrade-marker-{prior_version}");
            db.connection()
                .unwrap()
                .execute(
                    "CREATE TABLE migration_upgrade_marker (value TEXT NOT NULL)",
                    &[],
                )
                .unwrap();
            db.connection()
                .unwrap()
                .execute(
                    "INSERT INTO migration_upgrade_marker (value) VALUES ($1)",
                    &[&marker],
                )
                .unwrap();

            db.migrate().unwrap();

            let preserved: String = db
                .connection()
                .unwrap()
                .query_one("SELECT value FROM migration_upgrade_marker", &[])
                .unwrap()
                .get(0);
            assert_eq!(preserved, marker);
            assert_eq!(migration_rows(&db).len(), MIGRATIONS.len());
        }
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn concurrent_migrators_serialize_and_converge() {
        let _guard = POSTGRES_MIGRATION_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let db = test_database();
        reset_database(&db);
        let database_url = std::env::var(TEST_DATABASE_URL_ENV).unwrap();
        let ca_certificate = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT")
            .ok()
            .map(|path| std::fs::read(path).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let database_url = database_url.clone();
            let ca_certificate = ca_certificate.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                match ca_certificate {
                    Some(certificate) => {
                        PostgresDb::connect_with_ca_certificate(&database_url, 2, &certificate)
                    }
                    None => PostgresDb::connect(&database_url, 2),
                }
            }));
        }
        barrier.wait();
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        assert_eq!(migration_rows(&db).len(), MIGRATIONS.len());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn reusable_credentials_exclude_tenant_rows() {
        let _guard = POSTGRES_MIGRATION_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let db = test_database();
        reset_database(&db);
        db.migrate().unwrap();
        db.connection()
            .unwrap()
            .execute(
                "INSERT INTO sekai_principal_credentials
                    (id,principal,token_hash,status,created,rotated_at,revoked_at,tenant_id)
                 VALUES ('tenant-credential','shared-principal','tenant-hash','active',1,1,0,'tenant-a')",
                &[],
            )
            .unwrap();

        assert!(
            db.get_principal_credential("tenant-hash")
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_credentials(Some("shared-principal"), None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn failed_migration_rolls_back_schema_and_version() {
        let _guard = POSTGRES_MIGRATION_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let db = test_database();
        reset_database(&db);
        db.migrate().unwrap();
        let mut migrations = MIGRATIONS.to_vec();
        let failing_version = MIGRATIONS.len() as i64 + 1;
        migrations.push(Migration {
            version: failing_version,
            name: "deliberate_failure_fixture",
            sql: "CREATE TABLE migration_must_roll_back (id BIGINT); SELECT missing_function();",
        });

        let error = db.migrate_with(&migrations).unwrap_err();

        assert!(error.contains(&format!(
            "migration {failing_version} (deliberate_failure_fixture)"
        )));
        assert_eq!(migration_rows(&db).len(), MIGRATIONS.len());
        let table: Option<String> = db
            .connection()
            .unwrap()
            .query_one(
                "SELECT to_regclass('public.migration_must_roll_back')::text",
                &[],
            )
            .unwrap()
            .get(0);
        assert!(table.is_none());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn rejects_future_and_incompatible_migration_history() {
        let _guard = POSTGRES_MIGRATION_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let db = test_database();
        reset_database(&db);
        db.migrate().unwrap();
        let future_version = MIGRATIONS.len() as i64 + 1;
        db.connection()
            .unwrap()
            .execute(
                "INSERT INTO sekai_schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)",
                &[&future_version, &"future", &0_i64],
            )
            .unwrap();
        let error = db.migrate().unwrap_err();
        assert!(
            error.contains(&format!(
                "newer than supported version {}",
                MIGRATIONS.len()
            )),
            "{error}"
        );

        reset_database(&db);
        db.migrate_with(&MIGRATIONS[..1]).unwrap();
        db.connection()
            .unwrap()
            .execute(
                "UPDATE sekai_schema_migrations SET name = 'operator_modified' WHERE version = 1",
                &[],
            )
            .unwrap();
        let error = db.migrate().unwrap_err();
        assert!(
            error.contains("incompatible PostgreSQL migration history"),
            "{error}"
        );
        assert!(error.contains("restore a compatible schema"), "{error}");

        reset_database(&db);
        db.migrate().unwrap();
    }
}
