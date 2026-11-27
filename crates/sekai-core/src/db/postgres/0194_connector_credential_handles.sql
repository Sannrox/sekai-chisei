-- Plane-held connector credential handles sealed to a runtime fleet
-- public key (ADR 0175, #3553). Additive. Older planes do not read them.
CREATE TABLE IF NOT EXISTS sekai_runtime_fleet_key (
    key_id TEXT PRIMARY KEY,
    public_key BYTEA NOT NULL,
    registered_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sekai_credential_handle (
    name TEXT PRIMARY KEY,
    namespaces_json TEXT NOT NULL,
    destinations_json TEXT NOT NULL,
    fleet_key_id TEXT NOT NULL,
    slots_json TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    issued_at_ms BIGINT NOT NULL,
    issued_by TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at_ms BIGINT NOT NULL DEFAULT 0,
    revoked_by TEXT NOT NULL DEFAULT ''
);
