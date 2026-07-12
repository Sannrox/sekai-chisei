use std::str::FromStr;
use std::time::Duration;

use native_tls::TlsConnector;
use postgres::{Config as PostgresConfig, config::SslMode};
use postgres_native_tls::MakeTlsConnector;
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use uuid::Uuid;

use crate::db::sekai::PrincipalCredential;

const MIGRATION_LOCK_ID: i64 = 0x5345_4b41_4948_4101;
const CONTROL_PLANE_SCHEMA: &str = include_str!("postgres/0001_control_plane.sql");

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
        if database_url.trim().is_empty() {
            return Err("PostgreSQL database URL must not be empty".into());
        }
        if max_connections == 0 {
            return Err("PostgreSQL pool size must be greater than zero".into());
        }
        let config = secure_config(database_url)?;
        let tls = TlsConnector::builder()
            .build()
            .map(MakeTlsConnector::new)
            .map_err(|error| format!("build PostgreSQL TLS connector: {error}"))?;
        let manager = PostgresConnectionManager::new(config, tls);
        let pool = Pool::builder()
            .max_size(max_connections)
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

    pub fn get_principal_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT id, principal, token_hash, status, created, rotated_at, revoked_at
                 FROM sekai_principal_credentials
                 WHERE token_hash = $1 AND status = 'active'
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
                 VALUES ($1, $2, $3, 'active', $4, 0, 0)
                 RETURNING id, principal, token_hash, status, created, rotated_at, revoked_at",
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
        let active = transaction
            .query_opt(
                "SELECT id FROM sekai_principal_credentials
                 WHERE principal = $1 AND status = 'active'
                 ORDER BY created DESC LIMIT 1 FOR UPDATE",
                &[&principal],
            )
            .map_err(|error| error.to_string())?;
        if active.is_none() {
            return Err(format!("no active credential for {principal:?}"));
        }
        transaction
            .execute(
                "UPDATE sekai_principal_credentials
                 SET status = 'rotated', rotated_at = $2
                 WHERE principal = $1 AND status = 'active'",
                &[&principal, &now],
            )
            .map_err(|error| error.to_string())?;
        let row = transaction
            .query_one(
                "INSERT INTO sekai_principal_credentials
                    (id, principal, token_hash, status, created, rotated_at, revoked_at)
                 VALUES ($1, $2, $3, 'active', $4, 0, 0)
                 RETURNING id, principal, token_hash, status, created, rotated_at, revoked_at",
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
                    WHERE principal = $1 AND status = 'active'
                    ORDER BY created DESC LIMIT 1 FOR UPDATE
                 )
                 RETURNING id, principal, token_hash, status, created, rotated_at, revoked_at",
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
                "SELECT id, principal, token_hash, status, created, rotated_at, revoked_at
                 FROM sekai_principal_credentials
                 WHERE ($1::text IS NULL OR principal = $1)
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
        let applied = transaction
            .query_opt(
                "SELECT version FROM sekai_schema_migrations WHERE version = $1",
                &[&1_i64],
            )
            .map_err(|error| format!("read PostgreSQL migration state: {error}"))?
            .is_some();
        if !applied {
            transaction
                .batch_execute(CONTROL_PLANE_SCHEMA)
                .map_err(|error| format!("apply PostgreSQL control-plane schema: {error}"))?;
            transaction
                .execute(
                    "INSERT INTO sekai_schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)",
                    &[&1_i64, &"control_plane", &chrono::Utc::now().timestamp_millis()],
                )
                .map_err(|error| format!("record PostgreSQL migration: {error}"))?;
        }
        transaction
            .commit()
            .map_err(|error| format!("commit PostgreSQL migrations: {error}"))
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
    }
}
