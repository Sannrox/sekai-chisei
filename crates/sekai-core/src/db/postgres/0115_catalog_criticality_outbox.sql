-- Catalog criticality outbox (#1688). Additive: a binary without this table
-- keeps working during a rolling deploy, and a rollback leaves it unused.
CREATE TABLE IF NOT EXISTS sekai_catalog_criticality_outbox (
    event_id TEXT NOT NULL PRIMARY KEY,
    namespace TEXT NOT NULL,
    entry_id TEXT NOT NULL,
    entry_kind TEXT NOT NULL,
    source_system TEXT NOT NULL,
    source_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    declared TEXT NOT NULL DEFAULT '',
    derived TEXT NOT NULL DEFAULT '',
    effective TEXT NOT NULL DEFAULT '',
    evidence_digest TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    UNIQUE (entry_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_sekai_catalog_criticality_outbox_ns
    ON sekai_catalog_criticality_outbox (namespace, created_at_ms, event_id);
