-- Scheduled export ticks and adapter acknowledgement (#1628, ADR 0103).
-- Additive: a binary without these objects keeps working during a rolling
-- deploy, and a rollback leaves them unused.
ALTER TABLE sekai_export_artifacts
    ADD COLUMN IF NOT EXISTS acked_at_ms BIGINT;
CREATE TABLE IF NOT EXISTS sekai_export_schedule_cursor (
    namespace TEXT NOT NULL,
    definition_id TEXT NOT NULL,
    last_bucket BIGINT NOT NULL,
    PRIMARY KEY (namespace, definition_id)
);
CREATE INDEX IF NOT EXISTS idx_sekai_export_artifacts_deliverable
    ON sekai_export_artifacts (namespace, acked_at_ms, expires_at_ms);
