-- Eval dataset definitions put through the plane (#2306): one row per
-- (namespace, name, version), written once.
CREATE TABLE IF NOT EXISTS chisei_eval_dataset_definitions (
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
