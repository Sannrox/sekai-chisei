CREATE TABLE IF NOT EXISTS sekai_transform_usage_pending (
    run_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    completed_at_ms BIGINT NOT NULL
);
