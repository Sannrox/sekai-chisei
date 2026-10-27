CREATE TABLE IF NOT EXISTS sekai_write_freeze (
    scope_kind TEXT NOT NULL,
    scope_value TEXT NOT NULL,
    mode TEXT NOT NULL,
    reason TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    updated_ms BIGINT NOT NULL,
    PRIMARY KEY (scope_kind, scope_value)
);
