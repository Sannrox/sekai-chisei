-- An instance's turns, newest first, for the operator read of what a site
-- agent instance has been doing (#2001). An index only: older binaries
-- neither need nor notice it.
CREATE INDEX IF NOT EXISTS sekai_agent_turn_instance
    ON sekai_agent_turn (namespace, instance_id, created_at_ms DESC, turn_id DESC);
