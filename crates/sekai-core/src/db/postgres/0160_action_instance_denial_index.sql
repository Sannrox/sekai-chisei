-- An agent's denials of one Action type since a time (#2444), read on each
-- auto-apply admission. Additive: an older binary ignores it.
CREATE INDEX IF NOT EXISTS idx_action_instances_principal_status_decided
    ON sekai_action_instances (namespace, type_id, principal, status, decided_at_ms);
