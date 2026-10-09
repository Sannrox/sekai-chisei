use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use native_tls::Certificate;
use native_tls::TlsConnector;
use postgres::{Config as PostgresConfig, config::SslMode};
use postgres_native_tls::MakeTlsConnector;
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use uuid::Uuid;

use crate::db::schema_plane::SchemaPlane;
use crate::db::sekai::PrincipalCredential;

const MIGRATION_LOCK_ID: i64 = 0x5345_4b41_4948_4101;
const CONTROL_PLANE_SCHEMA: &str = include_str!("postgres/0001_control_plane.sql");
const CONTROL_PLANE_CHISEI_SCHEMA: &str = include_str!("postgres/0001_control_plane_chisei.sql");
const OPERATION_RECEIPTS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS chisei_operation_receipts (
    operation_id TEXT PRIMARY KEY,
    request_id TEXT,
    lookup_request_id TEXT,
    initiating_actor TEXT,
    caller_scope TEXT,
    alias_retired BIGINT NOT NULL DEFAULT 0,
    namespace TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chisei_operation_receipts_namespace
    ON chisei_operation_receipts(namespace, updated_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_request
    ON chisei_operation_receipts(request_id) WHERE request_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_lookup
    ON chisei_operation_receipts(caller_scope, lookup_request_id)
    WHERE lookup_request_id IS NOT NULL AND alias_retired = 0;
";
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
const EVALUATION_PLANS_SCHEMA: &str = include_str!("postgres/0024_evaluation_plans.sql");
const EVALUATION_MANIFESTS_SCHEMA: &str = include_str!("postgres/0025_evaluation_manifests.sql");
const EVALUATION_EXECUTIONS_SCHEMA: &str = include_str!("postgres/0026_evaluation_executions.sql");
const GOVERNED_SUBJECT_PROVENANCE_SCHEMA: &str =
    include_str!("postgres/0027_governed_subject_provenance.sql");
const REMOVE_LEGACY_ACTIONS_SCHEMA: &str = include_str!("postgres/0028_remove_legacy_actions.sql");
const OBJECT_SYNC_SCHEMA: &str = include_str!("postgres/0029_object_sync.sql");
const SOURCE_CHANGE_FEED_SCHEMA: &str = include_str!("postgres/0030_source_change_feed.sql");
const DEFINITION_BRANCHES_SCHEMA: &str = include_str!("postgres/0031_definition_branches.sql");
const OBJECT_SECURITY_SCHEMA: &str = include_str!("postgres/0032_object_security.sql");
const DEFINITION_PROPOSALS_SCHEMA: &str = include_str!("postgres/0033_definition_proposals.sql");
const DEFINITION_PROPOSAL_MERGE_EVIDENCE_SCHEMA: &str =
    include_str!("postgres/0034_definition_proposal_merge_evidence.sql");
const OBJECT_QUERY_CURSOR_SCHEMA: &str = include_str!("postgres/0035_object_query_cursor.sql");
const SOURCE_BATCH_QUARANTINE_SCHEMA: &str =
    include_str!("postgres/0036_source_batch_quarantine.sql");
const FACT_MIGRATION_SCHEMA: &str = include_str!("postgres/0037_fact_migration.sql");
const FACT_MIGRATION_AUDIT_SCHEMA: &str = include_str!("postgres/0038_fact_migration_audit.sql");
const EVENT_STREAMS_SCHEMA: &str = include_str!("postgres/0039_event_streams.sql");
const WORKFLOW_ACTIONS_SCHEMA: &str = include_str!("postgres/0040_workflow_actions.sql");
const POLICY_DECISION_AUDIT_SCHEMA: &str = include_str!("postgres/0041_policy_decision_audit.sql");
const OBJECT_TYPE_INDEX_SCHEMA: &str = include_str!("postgres/0042_object_type_index.sql");
const OBJECT_TYPE_INDEX_JOIN_SCHEMA: &str =
    include_str!("postgres/0043_object_type_index_join.sql");
const OBJECT_TYPE_INDEX_JOIN_VALUE_SCHEMA: &str =
    include_str!("postgres/0044_object_type_index_join_value.sql");
const OBJECT_TYPE_INDEX_JOIN_GENERATION_SCHEMA: &str =
    include_str!("postgres/0045_object_type_index_join_generation.sql");
const CHISEI_OPERATION_RESERVATIONS_SCHEMA: &str =
    include_str!("postgres/0046_chisei_operation_reservations.sql");
const STORE_CUTOVER_SCHEMA: &str = include_str!("postgres/0047_store_cutover.sql");
const STORE_CUTOVER_PAIRING_SCHEMA: &str = include_str!("postgres/0048_store_cutover_pairing.sql");
const CHISEI_ROUTING_PROFILES_SCHEMA: &str =
    include_str!("postgres/0049_chisei_routing_profiles.sql");
const GOVERNED_TRANSFORMS_SCHEMA: &str = include_str!("postgres/0050_governed_transforms.sql");
const OBSERVATION_EXTERNAL_ID_SCHEMA: &str =
    include_str!("postgres/0051_observation_external_id.sql");
const GOVERNED_DOCUMENTS_SCHEMA: &str = include_str!("postgres/0052_governed_documents.sql");

#[derive(Clone, Copy)]
enum MigrationOwner {
    Sekai,
    Chisei,
    Both,
}

#[derive(Clone, Copy)]
struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
    extra_sql: Option<&'static str>,
    owner: MigrationOwner,
}

const fn mig(
    version: i64,
    name: &'static str,
    sql: &'static str,
    owner: MigrationOwner,
) -> Migration {
    Migration {
        version,
        name,
        sql,
        extra_sql: None,
        owner,
    }
}

impl Migration {
    fn statements(self, plane: SchemaPlane) -> Vec<&'static str> {
        match (self.owner, self.extra_sql, plane) {
            (MigrationOwner::Sekai, _, SchemaPlane::Chisei) => Vec::new(),
            (MigrationOwner::Chisei, _, SchemaPlane::Sekai) => Vec::new(),
            (MigrationOwner::Both, Some(extra), SchemaPlane::Shared) => {
                vec![self.sql, extra]
            }
            (MigrationOwner::Both, Some(extra), SchemaPlane::Chisei) => vec![extra],
            (MigrationOwner::Both, Some(_), SchemaPlane::Sekai) => vec![self.sql],
            _ => vec![self.sql],
        }
    }
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "control_plane",
        sql: CONTROL_PLANE_SCHEMA,
        extra_sql: Some(CONTROL_PLANE_CHISEI_SCHEMA),
        owner: MigrationOwner::Both,
    },
    mig(
        2,
        "sample_leases",
        SAMPLE_LEASE_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(
        3,
        "unique_grants",
        UNIQUE_GRANT_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        4,
        "portfolio_prompt_variants",
        PORTFOLIO_PROMPT_VARIANT_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(5, "tenants", TENANT_SCHEMA, MigrationOwner::Sekai),
    mig(
        6,
        "namespace_ownership",
        NAMESPACE_OWNERSHIP_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        7,
        "tenant_memberships",
        TENANT_MEMBERSHIP_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        8,
        "tenant_credentials",
        TENANT_CREDENTIAL_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        9,
        "graph_parity",
        GRAPH_PARITY_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        10,
        "sekai_parity",
        SEKAI_PARITY_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        11,
        "coordination_parity",
        COORDINATION_PARITY_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        12,
        "evidence_parity",
        EVIDENCE_PARITY_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        13,
        "retention_deduplication_parity",
        RETENTION_DEDUPLICATION_PARITY_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        14,
        "action_governance_parity",
        ACTION_GOVERNANCE_PARITY_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        15,
        "team_namespace_parity",
        TEAM_NAMESPACE_PARITY_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        16,
        "chisei_execution_parity",
        CHISEI_EXECUTION_PARITY_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(
        17,
        "budget_topology",
        BUDGET_TOPOLOGY_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(
        18,
        "lease_site_id",
        LEASE_SITE_ID_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        19,
        "governed_action_types",
        GOVERNED_ACTION_TYPES_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        20,
        "governed_action_instances",
        GOVERNED_ACTION_INSTANCES_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        21,
        "action_effects",
        ACTION_EFFECTS_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        22,
        "parked_work_continuation",
        PARKED_WORK_CONTINUATION_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        23,
        "evaluation_plans",
        EVALUATION_PLANS_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(
        24,
        "evaluation_manifests",
        EVALUATION_MANIFESTS_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(
        25,
        "evaluation_executions",
        EVALUATION_EXECUTIONS_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(
        26,
        "governed_subject_provenance",
        GOVERNED_SUBJECT_PROVENANCE_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(
        27,
        "remove_legacy_actions",
        REMOVE_LEGACY_ACTIONS_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(28, "object_sync", OBJECT_SYNC_SCHEMA, MigrationOwner::Sekai),
    mig(
        29,
        "source_change_feed",
        SOURCE_CHANGE_FEED_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        30,
        "definition_branches",
        DEFINITION_BRANCHES_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        31,
        "object_security",
        OBJECT_SECURITY_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        32,
        "definition_proposals",
        DEFINITION_PROPOSALS_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        33,
        "definition_proposal_merge_evidence",
        DEFINITION_PROPOSAL_MERGE_EVIDENCE_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        34,
        "object_query_cursor",
        OBJECT_QUERY_CURSOR_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        35,
        "source_batch_quarantine",
        SOURCE_BATCH_QUARANTINE_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        36,
        "fact_migration",
        FACT_MIGRATION_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        37,
        "fact_migration_audit",
        FACT_MIGRATION_AUDIT_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        38,
        "event_streams",
        EVENT_STREAMS_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        39,
        "workflow_actions",
        WORKFLOW_ACTIONS_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        40,
        "policy_decision_audit",
        POLICY_DECISION_AUDIT_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        41,
        "object_type_index",
        OBJECT_TYPE_INDEX_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        42,
        "object_type_index_join",
        OBJECT_TYPE_INDEX_JOIN_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        43,
        "object_type_index_join_value",
        OBJECT_TYPE_INDEX_JOIN_VALUE_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        44,
        "object_type_index_join_generation",
        OBJECT_TYPE_INDEX_JOIN_GENERATION_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        45,
        "chisei_operation_reservations",
        CHISEI_OPERATION_RESERVATIONS_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(
        46,
        "store_cutover",
        STORE_CUTOVER_SCHEMA,
        MigrationOwner::Both,
    ),
    mig(
        47,
        "store_cutover_pairing",
        STORE_CUTOVER_PAIRING_SCHEMA,
        MigrationOwner::Both,
    ),
    // Versions run one behind the file prefixes: `0049_*.sql` is version 48.
    mig(
        48,
        "chisei_routing_profiles",
        CHISEI_ROUTING_PROFILES_SCHEMA,
        MigrationOwner::Chisei,
    ),
    mig(
        49,
        "governed_transforms",
        GOVERNED_TRANSFORMS_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        50,
        "observation_external_id",
        OBSERVATION_EXTERNAL_ID_SCHEMA,
        MigrationOwner::Sekai,
    ),
    mig(
        51,
        "governed_documents",
        GOVERNED_DOCUMENTS_SCHEMA,
        MigrationOwner::Sekai,
    ),
];

type Manager = PostgresConnectionManager<MakeTlsConnector>;

/// Runs `work` where the synchronous PostgreSQL client may block.
///
/// That client drives its own runtime and panics when used inside a Tokio
/// runtime context, which is where gRPC handlers run. On the server's
/// multi-threaded runtime, `block_in_place` leaves the runtime context for
/// the duration of `work`. Elsewhere (blocking tasks, tests, the CLI) `work`
/// runs directly.
pub(crate) fn off_runtime<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

/// Unambiguous text identity for a transaction advisory lock. PostgreSQL
/// text rejects NUL, so parts are length-prefixed rather than NUL-joined.
pub(crate) fn advisory_lock_key(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| format!("{}:{part}", part.len()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Serializes dataset-row writers with incremental transform reads so a
/// checkpoint cannot skip an identity allocated by an uncommitted append.
pub(crate) fn lock_dataset_rows(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
) -> Result<(), String> {
    let lock_key = advisory_lock_key(&["dataset_rows", dataset_id]);
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
        &[&lock_key],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

/// Shared PostgreSQL connection pool used by the HA storage backend.
///
/// Construction verifies connectivity and runs forward-only migrations while
/// holding a transaction-scoped advisory lock. Concurrent replicas can start
/// together; only one applies migrations and the others observe the committed
/// schema before serving requests.
pub struct PostgresDb {
    pool: Pool<Manager>,
    plane: std::sync::OnceLock<crate::obs::labels::PoolPlane>,
    schema_plane: SchemaPlane,
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
        Self::connect_for_plane(database_url, max_connections, SchemaPlane::Shared)
    }

    pub fn connect_for_plane(
        database_url: &str,
        max_connections: u32,
        schema_plane: SchemaPlane,
    ) -> Result<Self, String> {
        let tls = TlsConnector::builder()
            .build()
            .map(MakeTlsConnector::new)
            .map_err(|error| format!("build PostgreSQL TLS connector: {error}"))?;
        Self::connect_with_tls(database_url, max_connections, tls, schema_plane)
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
        Self::connect_with_tls(database_url, max_connections, tls, SchemaPlane::Shared)
    }

    pub fn connect_with_ca_certificate_for_plane(
        database_url: &str,
        max_connections: u32,
        ca_certificate_pem: &[u8],
        schema_plane: SchemaPlane,
    ) -> Result<Self, String> {
        let certificate = Certificate::from_pem(ca_certificate_pem)
            .map_err(|error| format!("parse PostgreSQL test CA certificate: {error}"))?;
        let mut builder = TlsConnector::builder();
        builder.add_root_certificate(certificate);
        let tls = builder
            .build()
            .map(MakeTlsConnector::new)
            .map_err(|error| format!("build PostgreSQL test TLS connector: {error}"))?;
        Self::connect_with_tls(database_url, max_connections, tls, schema_plane)
    }

    fn connect_with_tls(
        database_url: &str,
        max_connections: u32,
        tls: MakeTlsConnector,
        schema_plane: SchemaPlane,
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
        let mut prewarmed = Vec::with_capacity(max_connections as usize);
        for _ in 0..max_connections {
            prewarmed.push(
                pool.get()
                    .map_err(|error| format!("prewarm PostgreSQL pool: {error}"))?,
            );
        }
        drop(prewarmed);
        let db = Self {
            pool,
            plane: std::sync::OnceLock::new(),
            schema_plane,
        };
        db.migrate()?;
        crate::db::schema_plane::reject_populated_foreign_postgres(&db, schema_plane)?;
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

    pub(crate) fn max_connections(&self) -> u32 {
        self.pool.max_size()
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

    /// Labels this pool's checkout signals with the store plane it serves.
    /// Unlabeled pools report as Shared.
    pub(crate) fn set_pool_plane(&self, plane: crate::obs::labels::PoolPlane) {
        let _ = self.plane.set(plane);
    }

    pub(crate) fn connection(&self) -> Result<PooledConnection<Manager>, String> {
        use crate::obs::labels::{Outcome, PoolPlane};
        let started = std::time::Instant::now();
        let plane = self.plane.get().copied().unwrap_or(PoolPlane::Shared);
        match self.pool.get() {
            Ok(connection) => {
                let state = self.pool.state();
                let in_use = state.connections.saturating_sub(state.idle_connections);
                crate::obs::signals::record_pool_checkout(
                    plane,
                    Outcome::Ok,
                    started.elapsed(),
                    f64::from(in_use) / f64::from(self.pool.max_size().max(1)),
                );
                Ok(connection)
            }
            Err(error) => {
                crate::obs::signals::record_pool_checkout(
                    plane,
                    Outcome::Timeout,
                    started.elapsed(),
                    1.0,
                );
                Err(format!("acquire PostgreSQL connection: {error}"))
            }
        }
    }

    fn migrate(&self) -> Result<(), String> {
        self.migrate_with(MIGRATIONS)
    }

    fn migrate_with(&self, migrations: &[Migration]) -> Result<(), String> {
        let plane = self.schema_plane;
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
        let known: HashMap<i64, &Migration> = migrations
            .iter()
            .map(|migration| (migration.version, migration))
            .collect();
        let mut applied = HashMap::new();
        for row in &rows {
            let version: i64 = row.get(0);
            let name: String = row.get(1);
            match known.get(&version) {
                None => {
                    return Err(format!(
                        "PostgreSQL schema version {version} is newer than supported version {}; upgrade sekai-chisei before startup",
                        migrations.last().map_or(0, |migration| migration.version)
                    ));
                }
                Some(expected) if expected.name != name => {
                    return Err(format!(
                        "incompatible PostgreSQL migration history: found version {version} ({name}), expected version {} ({}); restore a compatible schema before startup",
                        expected.version, expected.name
                    ));
                }
                Some(_) => {
                    applied.insert(version, name);
                }
            }
        }
        let mut newly_applied = 0usize;
        for migration in migrations {
            if applied.contains_key(&migration.version) {
                catch_up_split_bootstrap(&mut transaction, migration, plane)?;
                continue;
            }
            let statements = migration.statements(plane);
            if statements.is_empty() {
                continue;
            }
            tracing::info!(
                version = migration.version,
                name = migration.name,
                "applying PostgreSQL migration"
            );
            for sql in statements {
                transaction.batch_execute(sql).map_err(|error| {
                    format!(
                        "apply PostgreSQL migration {} ({}): {error}",
                        migration.version, migration.name
                    )
                })?;
            }
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
            newly_applied += 1;
        }
        if !postgres_relation_exists(&mut transaction, "chisei_operation_receipts")? {
            transaction
                .batch_execute(OPERATION_RECEIPTS_SCHEMA)
                .map_err(|error| format!("ensure PostgreSQL chisei_operation_receipts: {error}"))?;
        }
        transaction
            .commit()
            .map_err(|error| format!("commit PostgreSQL migrations: {error}"))?;
        tracing::info!(
            schema_version = migrations.last().map_or(0, |migration| migration.version),
            newly_applied,
            "PostgreSQL migrations complete"
        );
        Ok(())
    }
}

/// A plane-scoped open records a Both version after applying only its half.
/// Shared (relocate source) and the other plane still need the missing half
/// before later owner-specific versions can run.
fn catch_up_split_bootstrap(
    transaction: &mut postgres::Transaction<'_>,
    migration: &Migration,
    plane: SchemaPlane,
) -> Result<(), String> {
    let Some(extra) = migration.extra_sql else {
        return Ok(());
    };
    if !matches!(migration.owner, MigrationOwner::Both) {
        return Ok(());
    }
    if plane.includes_sekai() && !postgres_relation_exists(transaction, "sekai_objects")? {
        transaction.batch_execute(migration.sql).map_err(|error| {
            format!(
                "catch up PostgreSQL Sekai bootstrap {} ({}): {error}",
                migration.version, migration.name
            )
        })?;
    }
    if plane.includes_chisei() && !postgres_relation_exists(transaction, "chisei_eval_suites")? {
        transaction.batch_execute(extra).map_err(|error| {
            format!(
                "catch up PostgreSQL Chisei bootstrap {} ({}): {error}",
                migration.version, migration.name
            )
        })?;
    }
    Ok(())
}

const EVALUATION_RESOLUTION_SHARE_LOCK_TABLES: &[&str] = &[
    "sekai_objects",
    "sekai_links",
    "sekai_grants",
    "sekai_evidence_submissions",
    "chisei_evaluator_definitions",
    "chisei_evaluator_availability",
    "chisei_evaluation_plans",
];

pub(crate) fn evaluation_resolution_share_lock_sql(tables: &[&str]) -> Option<String> {
    if tables.is_empty() {
        None
    } else {
        Some(format!("LOCK TABLE {} IN SHARE MODE", tables.join(", ")))
    }
}

/// SHARE-lock every evaluation-resolution table that exists on this dest.
/// Combined Split Chisei dests omit Sekai graph tables; locking the full
/// historical list would fail with undefined_table.
pub(crate) fn lock_existing_evaluation_resolution_tables(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<(), String> {
    let mut existing = Vec::new();
    for table in EVALUATION_RESOLUTION_SHARE_LOCK_TABLES {
        if postgres_relation_exists(transaction, table)? {
            existing.push(*table);
        }
    }
    let Some(sql) = evaluation_resolution_share_lock_sql(&existing) else {
        return Ok(());
    };
    transaction
        .batch_execute(&sql)
        .map_err(|error| error.to_string())
}

fn postgres_relation_exists(
    transaction: &mut postgres::Transaction<'_>,
    table: &str,
) -> Result<bool, String> {
    transaction
        .query_opt(
            "SELECT 1 FROM pg_tables WHERE schemaname = current_schema() AND tablename = $1",
            &[&table],
        )
        .map_err(|error| format!("inspect PostgreSQL relation {table}: {error}"))
        .map(|row| row.is_some())
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

/// A throwaway database on the conformance server named by
/// `SEKAI_TEST_POSTGRES_URL`, dropped when the guard goes out of scope.
#[cfg(test)]
pub(crate) struct ScratchDatabase {
    admin_url: String,
    ca_certificate: Option<Vec<u8>>,
    name: String,
    url: String,
}

#[cfg(test)]
impl ScratchDatabase {
    pub(crate) fn create() -> Self {
        let admin_url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must identify a PostgreSQL test server");
        let ca_certificate = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT")
            .ok()
            .map(|path| std::fs::read(path).expect("read PostgreSQL test CA certificate"));
        let name = format!("sekai_scratch_{}", uuid::Uuid::new_v4().simple());
        let (base, query) = match admin_url.split_once('?') {
            Some((base, query)) => (base, format!("?{query}")),
            None => (admin_url.as_str(), String::new()),
        };
        let prefix = base.rsplit_once('/').expect("database URL path").0;
        let url = format!("{prefix}/{name}{query}");
        let scratch = Self {
            admin_url,
            ca_certificate,
            name,
            url,
        };
        scratch.admin(&format!("CREATE DATABASE {}", scratch.name));
        scratch
    }

    pub(crate) fn connect(&self) -> PostgresDb {
        self.connect_for_plane(SchemaPlane::Shared)
            .expect("connect scratch database")
    }

    pub(crate) fn connect_for_plane(
        &self,
        schema_plane: SchemaPlane,
    ) -> Result<PostgresDb, String> {
        off_runtime(|| match &self.ca_certificate {
            Some(pem) => {
                PostgresDb::connect_with_ca_certificate_for_plane(&self.url, 4, pem, schema_plane)
            }
            None => PostgresDb::connect_for_plane(&self.url, 4, schema_plane),
        })
    }

    fn admin(&self, statement: &str) {
        off_runtime(|| {
            let admin = match &self.ca_certificate {
                Some(pem) => PostgresDb::connect_with_ca_certificate(&self.admin_url, 1, pem),
                None => PostgresDb::connect(&self.admin_url, 1),
            }
            .expect("connect PostgreSQL test server");
            admin
                .connection()
                .expect("admin connection")
                .batch_execute(statement)
                .expect("scratch database statement");
        });
    }
}

#[cfg(test)]
impl Drop for ScratchDatabase {
    fn drop(&mut self) {
        self.admin(&format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.name
        ));
    }
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
    fn advisory_lock_keys_are_nul_free_and_unambiguous() {
        let key = advisory_lock_key(&["ns", "request", "alice", "k-1"]);
        assert!(!key.contains('\0'));
        assert_ne!(
            advisory_lock_key(&["a,1:b", "c"]),
            advisory_lock_key(&["a", "b,1:c"])
        );
        assert_ne!(
            advisory_lock_key(&["ns", "branch", "published_head"]),
            advisory_lock_key(&["ns", "published_head"])
        );
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
        ] {
            assert!(
                CONTROL_PLANE_SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL table {table}"
            );
        }
        assert!(
            CONTROL_PLANE_SCHEMA.contains("CREATE TABLE IF NOT EXISTS chisei_operation_receipts"),
            "Sekai-plane v1 must create the per-store receipt table"
        );
        for table in [
            "sekai_decisions",
            "sekai_ledger_anchors",
            "chisei_eval_suites",
            "chisei_eval_runs",
            "chisei_eval_iterations",
            "chisei_budget_limits",
            "chisei_budget_usage",
        ] {
            assert!(
                CONTROL_PLANE_CHISEI_SCHEMA
                    .contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL Chisei control-plane table {table}"
            );
        }
        assert!(!CONTROL_PLANE_SCHEMA.contains("chisei_budget_limits"));
        assert!(!CONTROL_PLANE_CHISEI_SCHEMA.contains("sekai_objects"));
        assert!(REMOVE_LEGACY_ACTIONS_SCHEMA.contains("DROP TABLE IF EXISTS sekai_action_types"));
        assert!(
            REMOVE_LEGACY_ACTIONS_SCHEMA.contains("DROP TABLE IF EXISTS sekai_action_approvals")
        );
        assert!(!CONTROL_PLANE_SCHEMA.contains("AUTOINCREMENT"));
        assert!(!CONTROL_PLANE_SCHEMA.contains("INSERT OR"));
        for table in [
            "sekai_source_bindings",
            "sekai_source_batch_transactions",
            "sekai_source_identities",
            "sekai_source_record_results",
            "sekai_source_checkpoints",
        ] {
            assert!(
                OBJECT_SYNC_SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL object-sync table {table}"
            );
        }
        assert!(
            OBJECT_SYNC_SCHEMA
                .contains("status IN ('OPEN', 'COMMITTED', 'ABORTED', 'QUARANTINED')")
        );
        assert!(SOURCE_BATCH_QUARANTINE_SCHEMA.contains("QUARANTINED"));
        assert!(OBJECT_SYNC_SCHEMA.contains("outcome IN ('success', 'denial', 'unavailable')"));
        assert!(!OBJECT_SYNC_SCHEMA.contains("unknown"));
        for table in [
            "sekai_event_stream_bindings",
            "sekai_event_stream_checkpoints",
            "sekai_event_stream_admitted_events",
            "sekai_event_subscriptions",
        ] {
            assert!(
                EVENT_STREAMS_SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL event-stream table {table}"
            );
        }
        for table in [
            "sekai_workflow_action_bindings",
            "sekai_workflow_action_callbacks",
            "sekai_workflow_action_commands",
        ] {
            assert!(
                WORKFLOW_ACTIONS_SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL workflow-action table {table}"
            );
        }
        assert!(WORKFLOW_ACTIONS_SCHEMA.contains("sekai_workflow_action_bindings_identity"));
        for table in [
            "sekai_governed_transform",
            "sekai_governed_transform_run",
            "sekai_governed_transform_checkpoint",
        ] {
            assert!(
                GOVERNED_TRANSFORMS_SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL governed-transform table {table}"
            );
        }
        for table in ["sekai_governed_documents", "sekai_governed_renditions"] {
            assert!(
                GOVERNED_DOCUMENTS_SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL governed-document table {table}"
            );
        }
        assert!(
            DEFINITION_PROPOSALS_SCHEMA
                .contains("CREATE TABLE IF NOT EXISTS sekai_definition_proposals")
        );
        assert!(
            DEFINITION_PROPOSAL_MERGE_EVIDENCE_SCHEMA
                .contains("ADD COLUMN IF NOT EXISTS receipt_id")
        );
        assert!(
            DEFINITION_PROPOSAL_MERGE_EVIDENCE_SCHEMA
                .contains("ADD COLUMN IF NOT EXISTS close_reason_code")
        );
        assert!(!OBJECT_SYNC_SCHEMA.contains("partial"));
        assert!(SOURCE_CHANGE_FEED_SCHEMA.contains("CREATE TABLE sekai_source_sync_generations"));
        assert!(SOURCE_CHANGE_FEED_SCHEMA.contains("ADD COLUMN sync_generation BIGINT"));
        assert!(SOURCE_CHANGE_FEED_SCHEMA.contains("ADD COLUMN source_sequence BIGINT"));
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
        assert!(
            CHISEI_OPERATION_RESERVATIONS_SCHEMA
                .contains("CREATE TABLE IF NOT EXISTS chisei_operation_reservations")
        );
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
            extra_sql: None,
            owner: MigrationOwner::Both,
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

    fn postgres_user_tables(db: &PostgresDb) -> Vec<String> {
        db.connection()
            .unwrap()
            .query(
                "SELECT tablename FROM pg_tables
                 WHERE schemaname = current_schema()
                 ORDER BY tablename",
                &[],
            )
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect()
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn fresh_sekai_plane_omits_chisei_tables() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect_for_plane(SchemaPlane::Sekai).unwrap();
        let tables = postgres_user_tables(&db);
        assert!(
            tables.iter().any(|table| table == "sekai_objects"),
            "{tables:?}"
        );
        assert!(
            tables.iter().any(|table| table == "sekai_decisions"),
            "{tables:?}"
        );
        assert!(
            tables
                .iter()
                .any(|table| table == "chisei_operation_receipts"),
            "{tables:?}"
        );
        assert!(
            tables.iter().all(|table| !table.starts_with("chisei_")
                || table == "chisei_relocate_families"
                || table == "chisei_operation_receipts"),
            "{tables:?}"
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn fresh_chisei_plane_omits_sekai_fact_tables() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect_for_plane(SchemaPlane::Chisei).unwrap();
        let tables = postgres_user_tables(&db);
        assert!(
            tables.iter().any(|table| table == "sekai_decisions"),
            "{tables:?}"
        );
        assert!(
            tables.iter().any(|table| table == "chisei_budget_limits"),
            "{tables:?}"
        );
        assert!(
            !tables.iter().any(|table| table == "sekai_objects"),
            "{tables:?}"
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn dual_schema_postgres_opens_when_foreign_tables_are_empty() {
        let scratch = ScratchDatabase::create();
        drop(scratch.connect());
        scratch.connect_for_plane(SchemaPlane::Sekai).unwrap();
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn dual_schema_postgres_opens_as_chisei_when_only_retention_seeds_exist() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.connection()
            .unwrap()
            .execute(
                "INSERT INTO sekai_retention_policies
                 (dataset, namespace, data_class, retention_days, updated)
                 VALUES ('audit', '', '', 365, 1),
                        ('llm_calls', '', '', 90, 1),
                        ('task_observations', '', '', 90, 1)",
                &[],
            )
            .unwrap();
        drop(db);
        scratch.connect_for_plane(SchemaPlane::Chisei).unwrap();
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn dual_schema_postgres_refuses_as_chisei_when_custom_retention_policy_exists() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.connection()
            .unwrap()
            .execute(
                "INSERT INTO sekai_retention_policies
                 (dataset, namespace, data_class, retention_days, updated)
                 VALUES ('audit', 'legal', '', 30, 1)",
                &[],
            )
            .unwrap();
        drop(db);
        let error = scratch.connect_for_plane(SchemaPlane::Chisei).unwrap_err();
        assert!(error.contains("missed relocation"), "{error}");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn dual_schema_postgres_refuses_as_chisei_when_retention_days_were_changed() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.connection()
            .unwrap()
            .execute(
                "INSERT INTO sekai_retention_policies
                 (dataset, namespace, data_class, retention_days, updated)
                 VALUES ('audit', '', '', 30, 1)",
                &[],
            )
            .unwrap();
        drop(db);
        let error = scratch.connect_for_plane(SchemaPlane::Chisei).unwrap_err();
        assert!(error.contains("missed relocation"), "{error}");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn dual_schema_postgres_opens_as_chisei_with_historical_startup_artifacts() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.connection()
            .unwrap()
            .batch_execute(
                "INSERT INTO sekai_object_security_runtime_secrets (name, secret_value)
                 VALUES ('object_query_cursor_hmac', 'historical-hmac');
                 INSERT INTO sekai_principal_credentials
                 (id, principal, token_hash, status, created, rotated_at, revoked_at)
                 VALUES ('cred-gateway', 'chisei-gateway', 'hash', 'active', 1, 1, 0);",
            )
            .unwrap();
        drop(db);
        scratch.connect_for_plane(SchemaPlane::Chisei).unwrap();
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn dual_schema_postgres_refuses_as_chisei_when_other_principal_credential_exists() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.connection()
            .unwrap()
            .execute(
                "INSERT INTO sekai_principal_credentials
                 (id, principal, token_hash, status, created, rotated_at, revoked_at)
                 VALUES ('cred-alice', 'alice', 'hash', 'active', 1, 1, 0)",
                &[],
            )
            .unwrap();
        drop(db);
        let error = scratch.connect_for_plane(SchemaPlane::Chisei).unwrap_err();
        assert!(error.contains("missed relocation"), "{error}");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn sekai_plane_postgres_then_shared_applies_chisei_bootstrap() {
        let scratch = ScratchDatabase::create();
        drop(scratch.connect_for_plane(SchemaPlane::Sekai).unwrap());
        let db = scratch.connect();
        let tables = postgres_user_tables(&db);
        assert!(
            tables.iter().any(|table| table == "chisei_eval_suites"),
            "{tables:?}"
        );
        assert!(
            tables.iter().any(|table| table == "chisei_budget_limits"),
            "{tables:?}"
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn dual_schema_postgres_refuses_when_foreign_tables_hold_rows() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.connection()
            .unwrap()
            .execute(
                "INSERT INTO chisei_budget_limits (scope_id, max_amount, period_type)
                 VALUES ('user:missed', 1, 'daily')",
                &[],
            )
            .unwrap();
        drop(db);
        let error = scratch.connect_for_plane(SchemaPlane::Sekai).unwrap_err();
        assert!(error.contains("missed relocation"), "{error}");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn dual_schema_postgres_opens_after_relocate_fence() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.connection()
            .unwrap()
            .batch_execute(
                "INSERT INTO chisei_budget_limits (scope_id, max_amount, period_type)
                 VALUES ('user:leftover', 1, 'daily');
                 INSERT INTO sekai_store_cutover (id, generation, fence_raised, raised_at_ms)
                 VALUES (1, 1, 1, 0);",
            )
            .unwrap();
        drop(db);
        scratch.connect_for_plane(SchemaPlane::Sekai).unwrap();
    }

    #[test]
    fn sample_leases_migration_is_chisei_owned() {
        let migration = MIGRATIONS
            .iter()
            .copied()
            .find(|migration| migration.name == "sample_leases")
            .expect("sample_leases");
        assert!(matches!(migration.owner, MigrationOwner::Chisei));
        assert!(SAMPLE_LEASE_SCHEMA.contains("chisei_sample_observations"));
        assert!(migration.statements(SchemaPlane::Sekai).is_empty());
        assert_eq!(
            migration.statements(SchemaPlane::Chisei),
            vec![SAMPLE_LEASE_SCHEMA]
        );
    }

    #[test]
    fn evaluation_resolution_share_lock_sql_omits_missing_tables() {
        assert_eq!(super::evaluation_resolution_share_lock_sql(&[]), None);
        let sql = super::evaluation_resolution_share_lock_sql(&[
            "chisei_evaluator_definitions",
            "chisei_evaluator_availability",
            "chisei_evaluation_plans",
        ])
        .expect("chisei dest still has evaluator tables");
        assert_eq!(
            sql,
            "LOCK TABLE chisei_evaluator_definitions, chisei_evaluator_availability, chisei_evaluation_plans IN SHARE MODE"
        );
        assert!(!sql.contains("sekai_objects"));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn chisei_plane_evaluation_snapshot_locks_without_sekai_tables() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect_for_plane(SchemaPlane::Chisei).unwrap();
        let mut connection = db.connection().unwrap();
        let mut transaction = connection.transaction().unwrap();
        super::lock_existing_evaluation_resolution_tables(&mut transaction).unwrap();
        transaction.commit().unwrap();
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_list_all_objects_returns_matching_kind() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        let object = |id: &str, kind: &str| crate::domain::Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: "demo".into(),
            external_id: format!("{kind}:{id}"),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        db.create_object(&object("policy-a", "policy")).unwrap();
        db.create_object(&object("policy-b", "policy")).unwrap();
        db.create_object(&object("widget", "widget")).unwrap();
        let objects = db
            .list_all_objects(&crate::domain::ListFilter {
                kind: Some("policy".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(objects.len(), 2);
    }
}
