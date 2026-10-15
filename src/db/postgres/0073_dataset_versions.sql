CREATE TABLE IF NOT EXISTS sekai_dataset_versions (
    dataset_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    tenant TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    restored_from_version_id TEXT NOT NULL DEFAULT '',
    row_count INTEGER NOT NULL,
    purged INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (dataset_id, version_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_dataset_versions_seq
    ON sekai_dataset_versions(dataset_id, seq);
CREATE TABLE IF NOT EXISTS sekai_dataset_version_rows (
    dataset_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    row_id BIGINT NOT NULL,
    data TEXT NOT NULL,
    partition_key TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (dataset_id, version_id, row_id)
);
CREATE TABLE IF NOT EXISTS sekai_dataset_version_policy (
    dataset_id TEXT PRIMARY KEY,
    retain_count INTEGER NOT NULL DEFAULT 0
);
