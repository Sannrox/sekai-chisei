-- Claimable turns by namespace and due time (#2031). Finished history is
-- excluded so listing and SKIP LOCKED claim-next do not scan it. Parked
-- rows are included so claim-next's oldest-due pick can walk this index.
CREATE INDEX IF NOT EXISTS sekai_agent_turn_claim
    ON sekai_agent_turn (namespace, due_at_ms, turn_id)
    WHERE status IN ('pending', 'claimed', 'parked');
