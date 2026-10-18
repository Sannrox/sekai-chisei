CREATE TABLE IF NOT EXISTS chisei_receipt_chain (
    namespace TEXT NOT NULL,
    seq BIGINT NOT NULL,
    kind TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, seq)
);
CREATE INDEX IF NOT EXISTS idx_chisei_receipt_chain_receipt
    ON chisei_receipt_chain(namespace, receipt_id);
CREATE TABLE IF NOT EXISTS chisei_receipt_chain_checkpoints (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    head_seq BIGINT NOT NULL,
    head_hash TEXT NOT NULL,
    entry_count BIGINT NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, kind, head_seq)
);
CREATE TABLE IF NOT EXISTS chisei_receipt_chain_keys (
    key_id TEXT PRIMARY KEY,
    public_key_hex TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    retired_at_ms BIGINT
);
