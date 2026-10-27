ALTER TABLE sekai_governed_transform_run
    ADD COLUMN IF NOT EXISTS trigger_cause TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS trigger_ref TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS sekai_transform_schedule_cursor (
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    last_bucket BIGINT NOT NULL,
    PRIMARY KEY (namespace, transform_id)
);

CREATE TABLE IF NOT EXISTS sekai_transform_trigger_pending (
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    cause TEXT NOT NULL,
    cause_ref TEXT NOT NULL,
    first_seen_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, transform_id)
);

CREATE TABLE IF NOT EXISTS sekai_transform_output_state (
    namespace TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    freshness TEXT NOT NULL,
    upstream_version TEXT NOT NULL DEFAULT '',
    blocked_run_id TEXT NOT NULL DEFAULT '',
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, dataset_id)
);

CREATE TABLE IF NOT EXISTS sekai_transform_namespace_limit (
    namespace TEXT PRIMARY KEY,
    max_concurrent BIGINT NOT NULL
);
