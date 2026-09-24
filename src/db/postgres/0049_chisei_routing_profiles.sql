CREATE TABLE IF NOT EXISTS chisei_routing_profiles (
    namespace TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    endpoint_origin TEXT NOT NULL,
    model_patterns_json TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    registered_by TEXT NOT NULL,
    registered_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT,
    PRIMARY KEY (namespace, profile_id)
);
