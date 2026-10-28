-- Caller-scoped ad-hoc governed transform runs (#1964, ADR 0138): one row
-- per run identity, naming its run and scratch output. Additive.
CREATE TABLE IF NOT EXISTS sekai_adhoc_transform_run (
    identity TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    caller TEXT NOT NULL,
    session_label TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    run_id TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
