-- Saved-export delivery health per Source (ADR 0148): the last delivery
-- the Source's runtime finished or failed. Additive; every column
-- defaults, so a plane without them keeps writing the row.
ALTER TABLE sekai_sources
    ADD COLUMN IF NOT EXISTS delivery_last_success_at_ms BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS delivery_last_failure_at_ms BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS delivery_last_failure TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS delivery_last_runtime TEXT NOT NULL DEFAULT '';
