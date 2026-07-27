-- Multi-region budget topology (#294): home site pins, pooled ceilings,
-- and audited capacity transfers. No global active/active SC mode.

ALTER TABLE chisei_budget_limits
    ADD COLUMN IF NOT EXISTS home_site_id TEXT NOT NULL DEFAULT '';
ALTER TABLE chisei_budget_limits
    ADD COLUMN IF NOT EXISTS pool_id TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS chisei_budget_pools (
    pool_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    max_amount BIGINT NOT NULL,
    period_type TEXT NOT NULL DEFAULT 'daily',
    PRIMARY KEY (pool_id, metric)
);

CREATE TABLE IF NOT EXISTS chisei_budget_transfers (
    transfer_id TEXT PRIMARY KEY,
    metric TEXT NOT NULL,
    pool_id TEXT NOT NULL DEFAULT '',
    from_scope_id TEXT NOT NULL,
    to_scope_id TEXT NOT NULL,
    amount BIGINT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);
