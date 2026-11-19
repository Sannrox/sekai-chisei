-- Retained judge rationale for rationale/v1 stochastic steps (#2630): one row
-- per (operation, node, trial slot), written once and deleted at its TTL or
-- when its source evidence is removed.
CREATE TABLE IF NOT EXISTS chisei_evaluation_rationales (
    operation_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    trial_index BIGINT NOT NULL,
    namespace TEXT NOT NULL,
    rationale TEXT NOT NULL,
    rationale_digest TEXT NOT NULL,
    evidence_object_ids TEXT NOT NULL,
    classification TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    PRIMARY KEY (operation_id, node_id, trial_index)
);
CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_rationales_expiry
    ON chisei_evaluation_rationales (expires_at_ms);
