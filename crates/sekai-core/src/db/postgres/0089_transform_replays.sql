CREATE TABLE IF NOT EXISTS sekai_transform_replays (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    output_dataset_id TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    record_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_transform_replays_transform
    ON sekai_transform_replays(namespace, transform_id, created_at_ms);
