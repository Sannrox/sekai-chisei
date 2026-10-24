-- Typed ActionInstance effects (#398).

CREATE TABLE IF NOT EXISTS sekai_action_effects (
    effect_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    failure_reason TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    body_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_action_effects_instance
    ON sekai_action_effects(instance_id, created_at_ms);

CREATE INDEX IF NOT EXISTS idx_action_effects_kind_status
    ON sekai_action_effects(kind, status);

CREATE INDEX IF NOT EXISTS idx_action_effects_ns
    ON sekai_action_effects(namespace, created_at_ms DESC);
