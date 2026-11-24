CREATE TABLE IF NOT EXISTS sekai_source_discoveries (
    discovery_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    source_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL,
    failure TEXT NOT NULL DEFAULT '',
    claim_owner TEXT NOT NULL DEFAULT '',
    claim_generation BIGINT NOT NULL DEFAULT 0,
    claim_fencing_token TEXT NOT NULL DEFAULT '',
    claim_expires_at_ms BIGINT NOT NULL DEFAULT 0,
    claim_lease_expiries BIGINT NOT NULL DEFAULT 0,
    runtime TEXT NOT NULL DEFAULT '',
    discovery_json TEXT NOT NULL DEFAULT '',
    samples_json TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL,
    finished_at_ms BIGINT NOT NULL DEFAULT 0,
    expires_at_ms BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS sekai_source_discoveries_open
    ON sekai_source_discoveries (namespace, source_id, requested_by)
    WHERE status IN ('pending', 'running');
CREATE INDEX IF NOT EXISTS sekai_source_discoveries_claimable
    ON sekai_source_discoveries (namespace, status, created_at_ms, discovery_id);
CREATE INDEX IF NOT EXISTS sekai_source_discoveries_expiry
    ON sekai_source_discoveries (expires_at_ms);
