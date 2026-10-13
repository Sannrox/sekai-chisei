CREATE TABLE IF NOT EXISTS chisei_model_release_trust (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    roots_json TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_model_runtime_evidence (
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    ingested_at_ms BIGINT NOT NULL,
    PRIMARY KEY (provider, model, profile_version, artifact_digest, endpoint)
);
CREATE TABLE IF NOT EXISTS chisei_model_evaluation_export (
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    exported_at_ms BIGINT NOT NULL,
    PRIMARY KEY (provider, model, profile_version, artifact_digest, endpoint)
);
CREATE TABLE IF NOT EXISTS chisei_model_release_feedback (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    actor TEXT NOT NULL,
    note TEXT NOT NULL,
    recorded_at_ms BIGINT NOT NULL
);
ALTER TABLE chisei_routing_profiles
    ADD COLUMN IF NOT EXISTS require_runtime_evidence BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE chisei_routing_profiles
    ADD COLUMN IF NOT EXISTS evidence_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE chisei_routing_profiles
    ADD COLUMN IF NOT EXISTS evidence_model TEXT NOT NULL DEFAULT '';
ALTER TABLE chisei_routing_profiles
    ADD COLUMN IF NOT EXISTS evidence_profile_version TEXT NOT NULL DEFAULT '';
ALTER TABLE chisei_routing_profiles
    ADD COLUMN IF NOT EXISTS evidence_artifact_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE chisei_routing_profiles
    ADD COLUMN IF NOT EXISTS evidence_endpoint TEXT NOT NULL DEFAULT '';
