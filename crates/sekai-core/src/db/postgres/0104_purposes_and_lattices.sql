CREATE TABLE IF NOT EXISTS sekai_purpose_authorizations (
    authorization_id TEXT PRIMARY KEY,
    contract_version TEXT NOT NULL,
    actor TEXT NOT NULL,
    purpose TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT '',
    not_before_ms BIGINT NOT NULL,
    not_after_ms BIGINT NOT NULL,
    policy_activation_digest TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sekai_purpose_authorizations_lookup
    ON sekai_purpose_authorizations (actor, purpose, namespace);

CREATE TABLE IF NOT EXISTS sekai_classification_lattices (
    namespace TEXT PRIMARY KEY,
    contract_version TEXT NOT NULL,
    digest TEXT NOT NULL,
    lattice_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
