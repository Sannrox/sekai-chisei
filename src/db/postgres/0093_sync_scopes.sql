CREATE TABLE IF NOT EXISTS sekai_sync_scopes (
    namespace TEXT NOT NULL,
    owner TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    definition TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, owner, scope_id)
);
CREATE TABLE IF NOT EXISTS sekai_sync_positions (
    position_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    owner TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    authorization_pin TEXT NOT NULL,
    successor_id TEXT,
    origin_id TEXT,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS sekai_sync_positions_by_scope
    ON sekai_sync_positions (namespace, owner, scope_id);
CREATE TABLE IF NOT EXISTS sekai_sync_delivered (
    position_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (position_id, object_id)
);
CREATE TABLE IF NOT EXISTS sekai_sync_members (
    position_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (position_id, object_id)
);
