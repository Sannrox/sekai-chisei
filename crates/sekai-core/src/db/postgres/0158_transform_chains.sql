CREATE TABLE IF NOT EXISTS sekai_transform_chain (
    namespace TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, chain_id)
);
CREATE TABLE IF NOT EXISTS sekai_transform_chain_run (
    run_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '',
    identity TEXT NOT NULL,
    status TEXT NOT NULL,
    failed_step TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL,
    completed_at_ms BIGINT NOT NULL DEFAULT 0,
    input_digest TEXT NOT NULL DEFAULT '',
    output_digest TEXT NOT NULL DEFAULT '',
    UNIQUE (namespace, chain_id, identity)
);
CREATE TABLE IF NOT EXISTS sekai_transform_chain_step_run (
    chain_run_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    transform_run_id TEXT NOT NULL,
    status TEXT NOT NULL,
    claimed_at_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (chain_run_id, step_name)
);
CREATE INDEX IF NOT EXISTS sekai_transform_chain_step_run_transform
    ON sekai_transform_chain_step_run (transform_run_id);
