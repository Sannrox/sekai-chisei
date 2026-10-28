-- Placement labels a worker registers for its runtime id (#1733). Listing and
-- claiming transform work read them; a runtime with no row has no labels.
CREATE TABLE IF NOT EXISTS sekai_transform_runtime (
    namespace TEXT NOT NULL,
    runtime_id TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, runtime_id)
);
