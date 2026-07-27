-- Governed ActionInstance admission (#397). Distinct from graph ExecuteAction.

CREATE TABLE IF NOT EXISTS sekai_action_instances (
    instance_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    type_id TEXT NOT NULL,
    version TEXT NOT NULL,
    principal TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    status TEXT NOT NULL,
    deny_reason TEXT NOT NULL DEFAULT '',
    evidence_submission_ids_json TEXT NOT NULL,
    policy_decision TEXT NOT NULL DEFAULT '',
    budget_decision TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL,
    decided_at_ms BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    UNIQUE (namespace, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_action_instances_ns
    ON sekai_action_instances(namespace, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_action_instances_op
    ON sekai_action_instances(operation_id);

CREATE INDEX IF NOT EXISTS idx_action_instances_type
    ON sekai_action_instances(namespace, type_id, version);
