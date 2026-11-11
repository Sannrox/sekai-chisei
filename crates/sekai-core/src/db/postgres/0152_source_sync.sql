-- Source sync as a claimable work kind (ADR 0148, ADR 0149): the claim
-- record and the last outcome live in the Source row. Additive; every
-- column defaults, so a plane without them keeps writing the row, and the
-- tick copies a row's interval from its spec while sync_every_ms is 0.
ALTER TABLE sekai_sources
    ADD COLUMN IF NOT EXISTS sync_every_ms BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sync_due_bucket BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sync_claimed_bucket BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sync_done_bucket BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sync_claim_owner TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS sync_claim_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sync_fencing_token TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS sync_claim_expires_at_ms BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sync_lease_expiries BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sync_last_success_at_ms BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sync_last_failure_at_ms BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sync_last_failure TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS sync_last_runtime TEXT NOT NULL DEFAULT '';

