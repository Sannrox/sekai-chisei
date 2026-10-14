CREATE INDEX IF NOT EXISTS idx_definition_proposal_merged_history
    ON sekai_definition_proposals (namespace, status, updated_at_ms DESC, proposal_id DESC);
