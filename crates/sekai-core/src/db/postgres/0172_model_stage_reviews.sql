CREATE TABLE IF NOT EXISTS sekai_model_stage_reviews (
    namespace TEXT NOT NULL,
    model_name TEXT NOT NULL,
    stage TEXT NOT NULL,
    version_id TEXT NOT NULL,
    state TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    submitted_at_ms BIGINT NOT NULL,
    decided_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    decided_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, model_name, stage, version_id)
);
