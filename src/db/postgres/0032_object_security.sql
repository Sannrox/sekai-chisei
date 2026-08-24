CREATE TABLE IF NOT EXISTS sekai_object_security_policies (
    namespace TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    revision TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, policy_digest),
    UNIQUE(namespace, object_kind, revision)
);
CREATE INDEX IF NOT EXISTS idx_object_security_policy_kind
    ON sekai_object_security_policies(namespace, object_kind, created_at_ms);

CREATE TABLE IF NOT EXISTS sekai_object_security_revocations (
    namespace TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    revoked_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, policy_digest),
    FOREIGN KEY(namespace, policy_digest)
        REFERENCES sekai_object_security_policies(namespace, policy_digest)
);

CREATE TABLE IF NOT EXISTS sekai_object_security_profiles (
    namespace TEXT PRIMARY KEY,
    profile_digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    activated_by TEXT NOT NULL,
    activated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sekai_object_security_requests (
    namespace TEXT NOT NULL,
    actor TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, actor, idempotency_key)
);

CREATE TABLE IF NOT EXISTS sekai_object_security_audit (
    event_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_object_security_audit_namespace
    ON sekai_object_security_audit(namespace, created_at_ms, event_id);

CREATE TABLE IF NOT EXISTS sekai_object_security_runtime_secrets (
    name TEXT PRIMARY KEY,
    secret_value TEXT NOT NULL
);
