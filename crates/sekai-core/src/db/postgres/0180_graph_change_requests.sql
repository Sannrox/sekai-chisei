-- One row per applied ApplyGraphChanges call (#3062), written in the same
-- transaction as its changes. `(namespace, request_id)` replays the stored
-- receipt; the unique `action_instance_id` lets an Action instance apply once.
CREATE TABLE IF NOT EXISTS sekai_graph_change_requests (
    namespace TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    action_instance_id TEXT UNIQUE,
    actor TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, request_id)
);
