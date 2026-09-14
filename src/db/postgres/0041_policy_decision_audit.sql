CREATE TABLE IF NOT EXISTS sekai_policy_decision_audit (
    event_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    principal TEXT NOT NULL,
    principal_digest TEXT NOT NULL,
    activation_digest TEXT NOT NULL,
    policy_revision_digest TEXT NOT NULL,
    outcome TEXT NOT NULL,
    denied_by TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_decision_audit_ns_principal
    ON sekai_policy_decision_audit(namespace, principal, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_policy_decision_audit_ns_object
    ON sekai_policy_decision_audit(namespace, object_id, created_at_ms);
