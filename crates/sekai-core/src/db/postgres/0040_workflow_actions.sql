CREATE TABLE IF NOT EXISTS sekai_workflow_action_bindings (
    namespace TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(namespace, binding_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS sekai_workflow_action_bindings_identity
ON sekai_workflow_action_bindings (
    namespace,
    (record_json::jsonb->>'profile_id'),
    (record_json::jsonb->>'source_instance'),
    (record_json::jsonb->>'step_id')
);
CREATE TABLE IF NOT EXISTS sekai_workflow_action_callbacks (
    namespace TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    cursor_value BIGINT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(namespace, binding_id, cursor_value),
    FOREIGN KEY(namespace, binding_id)
        REFERENCES sekai_workflow_action_bindings(namespace, binding_id)
);
CREATE TABLE IF NOT EXISTS sekai_workflow_action_commands (
    namespace TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    command TEXT NOT NULL,
    expected_cursor BIGINT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(namespace, binding_id, command, expected_cursor),
    FOREIGN KEY(namespace, binding_id)
        REFERENCES sekai_workflow_action_bindings(namespace, binding_id)
);
