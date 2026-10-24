CREATE TABLE IF NOT EXISTS sekai_action_bindings (
    namespace TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    snapshot_revision TEXT NOT NULL DEFAULT '',
    last_page_digest TEXT NOT NULL DEFAULT '',
    pending_events_json TEXT NOT NULL DEFAULT '[]',
    read_marker_json TEXT NOT NULL DEFAULT '',
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, binding_id)
);
