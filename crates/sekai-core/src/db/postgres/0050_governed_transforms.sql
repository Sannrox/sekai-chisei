CREATE TABLE IF NOT EXISTS sekai_governed_transform (
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    input_dataset_id TEXT NOT NULL,
    output_dataset_id TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, transform_id)
);

CREATE TABLE IF NOT EXISTS sekai_governed_transform_run (
    run_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    input_digest TEXT NOT NULL,
    output_digest TEXT NOT NULL,
    last_input_row_id BIGINT NOT NULL,
    incremental SMALLINT NOT NULL,
    quarantined SMALLINT NOT NULL,
    quality_rule TEXT NOT NULL,
    rows_in INTEGER NOT NULL,
    rows_out INTEGER NOT NULL,
    lineage_parent TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_governed_transform_run_namespace
    ON sekai_governed_transform_run (namespace, created_at_ms DESC);

CREATE TABLE IF NOT EXISTS sekai_governed_transform_checkpoint (
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    last_input_row_id BIGINT NOT NULL,
    live_run_id TEXT NOT NULL,
    live_output_digest TEXT NOT NULL,
    PRIMARY KEY (namespace, transform_id)
);
