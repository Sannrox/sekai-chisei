CREATE TABLE IF NOT EXISTS sekai_dataset_rollback_proposals (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL,
    restore_from_version_id TEXT NOT NULL,
    base_version_id TEXT NOT NULL,
    proposer TEXT NOT NULL,
    tenant TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    decided_by TEXT NOT NULL DEFAULT '',
    decision_reason TEXT NOT NULL DEFAULT '',
    restored_version_id TEXT NOT NULL DEFAULT '',
    receipt_id TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL,
    decided_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_dataset_rollback_proposals_one_open
    ON sekai_dataset_rollback_proposals(dataset_id, tenant, restore_from_version_id, base_version_id)
    WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_sekai_dataset_rollback_proposals_dataset
    ON sekai_dataset_rollback_proposals(dataset_id, tenant, created_at_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_sekai_dataset_rollback_proposals_pending
    ON sekai_dataset_rollback_proposals(tenant, status, created_at_ms DESC, id DESC);
