-- Open items of each review kind (#2203), read by ListPendingDecisions newest
-- first. Additive: an older binary ignores them.
CREATE INDEX IF NOT EXISTS idx_action_instances_ns_status
    ON sekai_action_instances (namespace, status, created_at_ms DESC, instance_id DESC);
CREATE INDEX IF NOT EXISTS idx_sekai_plan_reviews_pending
    ON sekai_plan_reviews (namespace, decision, submitted_at_ms DESC, plan_id DESC);
CREATE INDEX IF NOT EXISTS idx_definition_proposal_open
    ON sekai_definition_proposals (namespace, status, created_at_ms DESC, proposal_id DESC);
CREATE INDEX IF NOT EXISTS idx_sekai_dataset_branch_proposals_open
    ON sekai_dataset_branch_proposals (tenant, status, created_at_ms DESC, id DESC);
