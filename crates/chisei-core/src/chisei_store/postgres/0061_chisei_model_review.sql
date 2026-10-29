CREATE TABLE IF NOT EXISTS chisei_model_review (
    namespace TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    artifact_digest TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, provider, model, artifact_digest)
);
CREATE TABLE IF NOT EXISTS chisei_model_family_enablement (
    namespace TEXT NOT NULL,
    region_label TEXT NOT NULL,
    family_id TEXT NOT NULL,
    status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, region_label, family_id)
);
