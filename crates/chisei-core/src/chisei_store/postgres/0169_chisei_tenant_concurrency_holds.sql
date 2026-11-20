-- Holder-keyed in-flight concurrency holds (#2753): one row per tenant
-- admission key, renewed while work runs and ignored once until_ms passes.
CREATE TABLE IF NOT EXISTS chisei_tenant_concurrency_holds (
    tenant_id TEXT NOT NULL,
    hold_key TEXT NOT NULL,
    holder TEXT NOT NULL,
    until_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, hold_key)
);
CREATE INDEX IF NOT EXISTS idx_chisei_tenant_concurrency_holds_live
    ON chisei_tenant_concurrency_holds (tenant_id, until_ms);
