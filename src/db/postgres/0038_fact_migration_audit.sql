CREATE TABLE IF NOT EXISTS sekai_fact_migration_audit (
    event_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    migration_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    from_revision_digest TEXT NOT NULL,
    to_revision_digest TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fact_migration_audit_history
    ON sekai_fact_migration_audit(namespace, migration_id, created_at_ms, event_id);
