CREATE TABLE IF NOT EXISTS sekai_transform_run_refusals (
    run_id TEXT PRIMARY KEY,
    refusal_json TEXT NOT NULL,
    refused_at_ms BIGINT NOT NULL
);
