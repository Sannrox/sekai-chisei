-- Team-namespace bootstrap support for managed principals.
-- Shared-runtime identity federation remains absent.

CREATE TABLE IF NOT EXISTS sekai_team_principals (
    principal TEXT PRIMARY KEY,
    created BIGINT NOT NULL
);
