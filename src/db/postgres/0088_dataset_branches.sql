CREATE TABLE IF NOT EXISTS sekai_dataset_branches (
    dataset_id TEXT NOT NULL,
    name TEXT NOT NULL,
    base_version_id TEXT NOT NULL DEFAULT '',
    written INTEGER NOT NULL DEFAULT 0,
    incarnation TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    tenant TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (dataset_id, name)
);
CREATE TABLE IF NOT EXISTS sekai_dataset_branch_rows (
    dataset_id TEXT NOT NULL,
    name TEXT NOT NULL,
    row_id BIGINT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (dataset_id, name, row_id)
);
CREATE TABLE IF NOT EXISTS sekai_dataset_branch_proposals (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL,
    branch TEXT NOT NULL,
    parent_version_id TEXT NOT NULL DEFAULT '',
    branch_digest TEXT NOT NULL,
    proposer TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    merged_by TEXT NOT NULL DEFAULT '',
    merged_version_id TEXT NOT NULL DEFAULT '',
    receipt_id TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL,
    merged_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sekai_dataset_branch_proposals_branch
    ON sekai_dataset_branch_proposals(dataset_id, branch, status);
