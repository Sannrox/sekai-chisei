CREATE TABLE IF NOT EXISTS sekai_transform_shadow_reports (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    active_definition_digest TEXT NOT NULL,
    candidate_member_digest TEXT NOT NULL,
    passing BOOLEAN NOT NULL,
    record_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_transform_shadow_reports_pair
    ON sekai_transform_shadow_reports(namespace, transform_id, active_definition_digest, candidate_member_digest);
CREATE TABLE IF NOT EXISTS sekai_transform_shadow_requirements (
    namespace TEXT PRIMARY KEY,
    required_by TEXT NOT NULL,
    required_at_ms BIGINT NOT NULL
);
