-- Governed export (#1627, ADR 0130): the append-only export grant history
-- and export receipts, each open under its exporter's lease until closed. Additive: a binary without these
-- tables keeps working during a rolling deploy, and a rollback leaves them
-- unused.
CREATE TABLE IF NOT EXISTS sekai_export_grants (
    namespace TEXT NOT NULL,
    principal TEXT NOT NULL,
    seq BIGINT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, principal, seq)
);
CREATE TABLE IF NOT EXISTS sekai_export_receipts (
    operation_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    lease_until_ms BIGINT NOT NULL,
    receipt_json TEXT NOT NULL,
    closing_json TEXT,
    closed INTEGER NOT NULL DEFAULT 0
);
