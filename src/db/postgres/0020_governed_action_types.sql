-- Governed Action type registry (#396). Distinct from graph sekai_action_types.

CREATE TABLE IF NOT EXISTS sekai_governed_action_types (
    namespace TEXT NOT NULL,
    type_id TEXT NOT NULL,
    version TEXT NOT NULL,
    body_json TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    disabled_at_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace, type_id, version)
);

CREATE INDEX IF NOT EXISTS idx_governed_action_types_ns
    ON sekai_governed_action_types(namespace);

CREATE INDEX IF NOT EXISTS idx_governed_action_types_enabled
    ON sekai_governed_action_types(namespace, type_id, enabled);
