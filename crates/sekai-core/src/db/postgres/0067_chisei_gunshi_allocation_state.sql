CREATE TABLE IF NOT EXISTS chisei_gunshi_allocation_state (
    namespace TEXT PRIMARY KEY,
    revision_id TEXT NOT NULL,
    changed_at_ms BIGINT NOT NULL,
    state_json TEXT NOT NULL
);
