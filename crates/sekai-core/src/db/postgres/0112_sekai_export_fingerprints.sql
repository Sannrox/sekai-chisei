-- Watermarked export fingerprint policies and per-export records (#1466, ADR 0131).
-- Additive: a binary without these tables keeps working during a rolling
-- deploy, and a rollback leaves them unused.
CREATE TABLE IF NOT EXISTS sekai_export_fingerprint_policies (
    namespace TEXT NOT NULL,
    marking TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, marking)
);
CREATE TABLE IF NOT EXISTS sekai_export_fingerprints (
    operation_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_export_fingerprints_namespace
    ON sekai_export_fingerprints (namespace);
