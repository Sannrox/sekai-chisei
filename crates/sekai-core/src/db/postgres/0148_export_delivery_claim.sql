-- Saved-export deliveries as the export_delivery work kind (#2194,
-- ADR 0149): the claim record on the artifact row. Additive and nullable,
-- so no row moves: a binary without these columns keeps working during a
-- rolling deploy, a row it writes reads as unclaimed, and a rollback leaves
-- them unused.
ALTER TABLE sekai_export_artifacts
    ADD COLUMN IF NOT EXISTS claim_owner TEXT,
    ADD COLUMN IF NOT EXISTS claim_generation BIGINT,
    ADD COLUMN IF NOT EXISTS fencing_token TEXT,
    ADD COLUMN IF NOT EXISTS claim_expires_at_ms BIGINT,
    ADD COLUMN IF NOT EXISTS lease_expiries BIGINT;
