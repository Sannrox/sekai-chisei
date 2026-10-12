ALTER TABLE sekai_governed_transform_run
    ADD COLUMN IF NOT EXISTS profile TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS engine TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_image TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS dispatch_status TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS sekai_transform_work (
    run_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    definition_json TEXT NOT NULL DEFAULT '',
    engine TEXT NOT NULL,
    runtime_image TEXT NOT NULL,
    status TEXT NOT NULL,
    claim_owner TEXT NOT NULL DEFAULT '',
    claim_generation BIGINT NOT NULL DEFAULT 0,
    fencing_token TEXT NOT NULL DEFAULT '',
    claim_expires_at_ms BIGINT NOT NULL DEFAULT 0,
    lease_expiries BIGINT NOT NULL DEFAULT 0,
    created_at_ms BIGINT NOT NULL
);

ALTER TABLE sekai_transform_work
    ADD COLUMN IF NOT EXISTS definition_json TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_transform_work_claim
    ON sekai_transform_work (namespace, status, created_at_ms);

CREATE TABLE IF NOT EXISTS sekai_transform_run_input (
    run_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    row_id BIGINT NOT NULL,
    values_json TEXT NOT NULL,
    PRIMARY KEY (run_id, alias, row_id)
);
