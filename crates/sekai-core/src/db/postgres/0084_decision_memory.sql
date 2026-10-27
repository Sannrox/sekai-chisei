CREATE TABLE IF NOT EXISTS sekai_action_decision_memory (
    memory_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    type_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    decided_at_ms BIGINT NOT NULL,
    body_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decision_memory_type
    ON sekai_action_decision_memory(namespace, type_id, decided_at_ms DESC);
