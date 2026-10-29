-- Parked agent turns (#2007, ADR 0142): the Action a turn parked on, kept so
-- its next claim carries the continuation, and how often it parked.
-- Additive: older binaries neither read nor write these columns, and never
-- treat a parked turn as claimable.
ALTER TABLE sekai_agent_turn
    ADD COLUMN IF NOT EXISTS parked_action_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sekai_agent_turn
    ADD COLUMN IF NOT EXISTS park_count BIGINT NOT NULL DEFAULT 0;
