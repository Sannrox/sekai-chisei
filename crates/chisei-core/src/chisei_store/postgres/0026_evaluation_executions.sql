CREATE TABLE IF NOT EXISTS chisei_evaluation_executions (
    manifest_digest TEXT PRIMARY KEY
        REFERENCES chisei_evaluation_manifests(manifest_digest),
    operation_id TEXT NOT NULL UNIQUE
        REFERENCES chisei_operation_receipts(operation_id),
    namespace TEXT NOT NULL,
    executor_version TEXT NOT NULL,
    started_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_executions_namespace
    ON chisei_evaluation_executions(namespace, created_at_ms, operation_id);
