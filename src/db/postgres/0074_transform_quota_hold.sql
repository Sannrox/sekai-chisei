CREATE TABLE IF NOT EXISTS sekai_transform_quota_hold (
    run_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    reserved_concurrency INTEGER NOT NULL,
    claim_generation BIGINT NOT NULL,
    refund_request INTEGER NOT NULL DEFAULT 0,
    refund_tokens INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, claim_generation)
);
