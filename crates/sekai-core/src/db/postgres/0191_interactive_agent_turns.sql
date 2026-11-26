-- Interactive agent turns (#3046, ADR 0173): a member runs an agent from a
-- certified definition revision, and the turn acts as that member. A table
-- of its own, because older planes map every sekai_agent_turn row strictly
-- and would fail on an instance-less row. Additive.
CREATE TABLE IF NOT EXISTS sekai_interactive_agent_turn (
    turn_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    member_id TEXT NOT NULL,
    definition_revision_digest TEXT NOT NULL,
    agent_member TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
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
    reason TEXT NOT NULL DEFAULT '',
    parked_action_id TEXT NOT NULL DEFAULT '',
    park_count BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sekai_interactive_agent_turn_claim
    ON sekai_interactive_agent_turn (namespace, due_at_ms, turn_id)
    WHERE status IN ('pending', 'claimed', 'parked');
CREATE INDEX IF NOT EXISTS sekai_interactive_agent_turn_member
    ON sekai_interactive_agent_turn (namespace, member_id, created_at_ms DESC, turn_id DESC);
