-- Agent-turn queue for site agent instances (#1950, ADR 0137): one row per
-- turn identity, claimed with a generation and fencing token. Additive.
CREATE TABLE IF NOT EXISTS sekai_agent_turn (
    turn_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    cause TEXT NOT NULL,
    cause_ref TEXT NOT NULL,
    due_at_ms BIGINT NOT NULL,
    admitted_by TEXT NOT NULL,
    status TEXT NOT NULL,
    claim_owner TEXT NOT NULL DEFAULT '',
    claim_generation BIGINT NOT NULL DEFAULT 0,
    fencing_token TEXT NOT NULL DEFAULT '',
    claim_expires_at_ms BIGINT NOT NULL DEFAULT 0,
    lease_expiries BIGINT NOT NULL DEFAULT 0,
    created_at_ms BIGINT NOT NULL,
    finished_at_ms BIGINT NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sekai_agent_turn_queue
    ON sekai_agent_turn (status, due_at_ms);
