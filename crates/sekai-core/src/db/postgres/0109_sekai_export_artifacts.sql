-- Saved export definitions and their run artifacts (#1628, ADR 0130).
-- Additive: a binary without these tables keeps working during a rolling
-- deploy, and a rollback leaves them unused.
CREATE TABLE IF NOT EXISTS sekai_export_definitions (
    namespace TEXT NOT NULL,
    definition_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, definition_id)
);
CREATE TABLE IF NOT EXISTS sekai_export_artifacts (
    receipt_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    definition_id TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_export_artifacts_expiry
    ON sekai_export_artifacts (expires_at_ms);
CREATE TABLE IF NOT EXISTS sekai_export_artifact_chunks (
    receipt_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    data BYTEA NOT NULL,
    PRIMARY KEY (receipt_id, seq)
);
