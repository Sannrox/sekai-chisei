ALTER TABLE sekai_grants ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT '';
ALTER TABLE sekai_grants ADD COLUMN IF NOT EXISTS not_after_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sekai_grants ADD COLUMN IF NOT EXISTS exception_reason TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS sekai_namespace_grant_policy (
    namespace TEXT PRIMARY KEY,
    max_duration_ms BIGINT NOT NULL,
    require_terms BOOLEAN NOT NULL
);
