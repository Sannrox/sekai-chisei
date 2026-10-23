CREATE TABLE IF NOT EXISTS sekai_fence_bindings (
    namespace TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    after_lsn BIGINT,
    after_index BIGINT NOT NULL DEFAULT 0,
    run_id TEXT NOT NULL DEFAULT '',
    run_lease_until_ms BIGINT NOT NULL DEFAULT 0,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, binding_id)
);

CREATE TABLE IF NOT EXISTS sekai_fence_binding_receipts (
    namespace TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    lsn BIGINT NOT NULL,
    event_index BIGINT NOT NULL,
    receipt_json TEXT NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, binding_id, revision, lsn, event_index)
);
