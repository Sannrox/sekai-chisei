ALTER TABLE chisei_sample_observations
    ADD COLUMN IF NOT EXISTS lease_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE chisei_sample_observations
    ADD COLUMN IF NOT EXISTS lease_expires_at BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_chisei_sample_observations_claimable
    ON chisei_sample_observations(scored, lease_expires_at, timestamp, request_id);
