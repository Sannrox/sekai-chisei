//! Shared-class operation receipts. Family DDL lives in chisei-core persist.

use rusqlite::Connection;

use super::sekai::SekaiDb;

impl SekaiDb {
    /// Per-store receipt table, including Combined Split admission receipts
    /// on the Sekai dest. Legacy files may lack later columns; add those
    /// before creating indexes that name them.
    pub fn migrate_operation_receipts(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_operation_receipts (
                    operation_id TEXT PRIMARY KEY,
                    request_id TEXT,
                    lookup_request_id TEXT,
                    initiating_actor TEXT,
                    caller_scope TEXT,
                    alias_retired INTEGER NOT NULL DEFAULT 0,
                    namespace TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );",
        )
        .map_err(|e| e.to_string())?;
        Self::ensure_operation_receipt_columns(&conn)?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_chisei_operation_receipts_namespace
                    ON chisei_operation_receipts(namespace, updated_at);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_request
                    ON chisei_operation_receipts(request_id) WHERE request_id IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_lookup
                    ON chisei_operation_receipts(caller_scope, lookup_request_id)
                    WHERE caller_scope IS NOT NULL AND lookup_request_id IS NOT NULL;",
        )
        .map_err(|e| e.to_string())
    }

    fn ensure_operation_receipt_columns(conn: &Connection) -> Result<(), String> {
        for statement in [
            "ALTER TABLE chisei_operation_receipts ADD COLUMN request_id TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN lookup_request_id TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN initiating_actor TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN caller_scope TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN alias_retired INTEGER NOT NULL DEFAULT 0",
        ] {
            match conn.execute(statement, []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                    if message.contains("duplicate column name") => {}
                Err(err) => return Err(err.to_string()),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
const TEST_CHISEI_SQL_FUNCTION_TABLES: &str = "
CREATE TABLE IF NOT EXISTS chisei_external_action_permits (
    permit_id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE,
    issuance_idempotency_key TEXT NOT NULL, permit_json TEXT NOT NULL, issued_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_external_action_redemptions (
    permit_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, execution_id TEXT NOT NULL,
    redemption_json TEXT NOT NULL, redeemed_at_ms INTEGER NOT NULL,
    invocation_ordinal INTEGER NOT NULL, redemption_id TEXT,
    evidence_due_at_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(permit_id,idempotency_key), UNIQUE(permit_id,execution_id),
    UNIQUE(permit_id,invocation_ordinal)
);
CREATE TABLE IF NOT EXISTS chisei_external_action_revocations (
    revocation_handle TEXT PRIMARY KEY, reason TEXT NOT NULL, revoked_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_external_action_kill_switches (
    scope_kind TEXT NOT NULL, scope_value TEXT NOT NULL, reason TEXT NOT NULL,
    enabled_at_ms INTEGER NOT NULL, PRIMARY KEY(scope_kind,scope_value)
);
CREATE TABLE IF NOT EXISTS chisei_external_action_delegated_permits (
    permit_id TEXT PRIMARY KEY, parent_permit_id TEXT NOT NULL,
    permit_json TEXT NOT NULL, issued_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_external_action_one_child_per_parent
ON chisei_external_action_delegated_permits(parent_permit_id);
CREATE TABLE IF NOT EXISTS chisei_external_permit_policies (
    scope TEXT PRIMARY KEY, policy_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_external_action_reservations (
    actor TEXT NOT NULL,
    namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    mutations INTEGER NOT NULL,
    deletes INTEGER NOT NULL,
    PRIMARY KEY(actor, namespace, operation_id)
);
CREATE TABLE IF NOT EXISTS chisei_external_action_authorizations (
    actor TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    authorization_id TEXT NOT NULL UNIQUE,
    record_json TEXT,
    claimed_at_ms INTEGER NOT NULL,
    PRIMARY KEY(actor, operation_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS chisei_external_action_releases (
    authorization_id TEXT PRIMARY KEY,
    released_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_external_action_blast_claims (
    authorization_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    mutations INTEGER NOT NULL,
    deletes INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_budget_limits (
    scope_id TEXT NOT NULL,
    metric TEXT NOT NULL DEFAULT 'tokens',
    parent_scope_id TEXT NOT NULL DEFAULT '',
    max_amount INTEGER NOT NULL,
    period_type TEXT NOT NULL,
    home_site_id TEXT NOT NULL DEFAULT '',
    pool_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scope_id, metric)
);
CREATE TABLE IF NOT EXISTS chisei_budget_usage (
    scope_id TEXT NOT NULL,
    metric TEXT NOT NULL DEFAULT 'tokens',
    period_start INTEGER NOT NULL,
    amount_used INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope_id, metric, period_start)
);
CREATE TABLE IF NOT EXISTS chisei_budget_usage_events (
    idempotency_key TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    amount INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_budget_attributions (
    source_scope_id TEXT NOT NULL,
    applied_scope_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    period_start INTEGER NOT NULL,
    amount_used INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (source_scope_id, applied_scope_id, metric, period_start)
);
CREATE TABLE IF NOT EXISTS chisei_budget_work_unit_defaults (
    scope_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    max_amount INTEGER NOT NULL,
    period_type TEXT NOT NULL,
    home_site_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scope_id, metric)
);
CREATE TABLE IF NOT EXISTS chisei_budget_pools (
    pool_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    max_amount INTEGER NOT NULL,
    period_type TEXT NOT NULL DEFAULT 'daily',
    PRIMARY KEY (pool_id, metric)
);
CREATE TABLE IF NOT EXISTS chisei_budget_transfers (
    transfer_id TEXT PRIMARY KEY,
    metric TEXT NOT NULL,
    pool_id TEXT NOT NULL DEFAULT '',
    from_scope_id TEXT NOT NULL,
    to_scope_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_receipt_chain (
    namespace TEXT NOT NULL,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, seq)
);
CREATE INDEX IF NOT EXISTS idx_chisei_receipt_chain_receipt
    ON chisei_receipt_chain(namespace, receipt_id);
CREATE TABLE IF NOT EXISTS chisei_receipt_chain_checkpoints (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    head_seq INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, kind, head_seq)
);
CREATE TABLE IF NOT EXISTS chisei_receipt_chain_keys (
    key_id TEXT PRIMARY KEY,
    public_key_hex TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    retired_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS chisei_governed_subject_provenance_exports (
    actor TEXT NOT NULL,
    export_id TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    namespace TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY(actor, export_id)
);
CREATE INDEX IF NOT EXISTS idx_chisei_governed_subject_provenance_namespace
    ON chisei_governed_subject_provenance_exports(namespace, created_at_ms);
CREATE TABLE IF NOT EXISTS chisei_operation_reservations (
    namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    actor TEXT NOT NULL,
    budget_subject TEXT NOT NULL DEFAULT '',
    incurred_usage INTEGER NOT NULL DEFAULT 0,
    sekai_instance_id TEXT NOT NULL DEFAULT '',
    sekai_status TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    charge_key TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (namespace, operation_id)
);
CREATE INDEX IF NOT EXISTS idx_chisei_operation_reservations_status
    ON chisei_operation_reservations(status, expires_at_ms);
";

#[cfg(test)]
impl SekaiDb {
    /// Tables for Chisei SQL functions that still compile into this crate.
    /// Production family DDL is applied by Chisei persist on store open.
    pub fn apply_chisei_sql_function_tables_for_tests(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(TEST_CHISEI_SQL_FUNCTION_TABLES)
            .map_err(|error| error.to_string())
    }

    pub fn memory_for_chisei_sql_functions() -> Self {
        let db = Self::new(":memory:").expect("memory sqlite");
        db.apply_chisei_sql_function_tables_for_tests()
            .expect("chisei sql function tables");
        db
    }

    pub fn open_for_chisei_sql_functions(path: &str) -> Self {
        let db = Self::new(path).expect("open sqlite");
        db.apply_chisei_sql_function_tables_for_tests()
            .expect("chisei sql function tables");
        db
    }
}
