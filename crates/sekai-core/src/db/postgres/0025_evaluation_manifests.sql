CREATE TABLE IF NOT EXISTS chisei_evaluation_manifests (
    manifest_digest TEXT PRIMARY KEY,
    manifest_id TEXT NOT NULL UNIQUE,
    namespace TEXT NOT NULL,
    plan_version_id TEXT NOT NULL,
    subject_identity TEXT NOT NULL,
    evaluation_time_ms BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_manifests_namespace
    ON chisei_evaluation_manifests(
        namespace, plan_version_id, subject_identity, evaluation_time_ms
    );

CREATE TABLE IF NOT EXISTS chisei_evaluation_manifest_requests (
    namespace TEXT NOT NULL,
    actor TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL
        REFERENCES chisei_evaluation_manifests(manifest_digest),
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, actor, request_id)
);
CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_manifest_requests_manifest
    ON chisei_evaluation_manifest_requests(manifest_digest);
