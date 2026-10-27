CREATE TABLE IF NOT EXISTS sekai_transform_run_finish (
    run_id TEXT PRIMARY KEY,
    claimed_at_ms BIGINT,
    finished_at_ms BIGINT,
    compute_ms BIGINT
);
