-- Recorded eval dataset definitions (ADR 0153, #3513): one row per
-- (namespace, name, version), written once. Rows hold case references only.
CREATE TABLE IF NOT EXISTS chisei_eval_recorded_datasets (
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    case_count BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, name, version)
);
