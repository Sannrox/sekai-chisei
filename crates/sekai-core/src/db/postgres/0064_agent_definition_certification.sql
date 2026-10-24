CREATE TABLE IF NOT EXISTS sekai_agent_definition_certifications (
    namespace TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    suite_id TEXT NOT NULL,
    certification_id TEXT NOT NULL,
    baseline_status TEXT NOT NULL,
    latest_status TEXT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT NOT NULL DEFAULT 0,
    bound_by TEXT NOT NULL,
    bound_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, revision_digest)
);
