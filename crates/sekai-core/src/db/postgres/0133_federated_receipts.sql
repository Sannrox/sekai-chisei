-- Federated aggregate receipts (#1996, ADR 0134 §8): one per query and
-- tenant, opened before any partial leaves and closed once. Additive.
CREATE TABLE IF NOT EXISTS sekai_federated_receipts (
    query_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    state TEXT NOT NULL,
    opened_at_ms BIGINT NOT NULL,
    receipt_json TEXT NOT NULL,
    PRIMARY KEY (query_id, tenant)
);
CREATE INDEX IF NOT EXISTS sekai_federated_receipts_open
    ON sekai_federated_receipts (state, opened_at_ms);
CREATE INDEX IF NOT EXISTS sekai_federated_receipts_tenant
    ON sekai_federated_receipts (tenant, opened_at_ms);
