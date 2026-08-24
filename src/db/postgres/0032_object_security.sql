CREATE TABLE IF NOT EXISTS sekai_object_security_revisions (
    namespace TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    kind TEXT NOT NULL,
    canonical_policy_json BYTEA NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, revision_digest)
);

CREATE TABLE IF NOT EXISTS sekai_object_security_rules (
    namespace TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    rule_index INTEGER NOT NULL,
    operation TEXT NOT NULL,
    PRIMARY KEY(namespace, revision_digest, rule_index)
);

CREATE TABLE IF NOT EXISTS sekai_object_security_predicates (
    namespace TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    rule_index INTEGER NOT NULL,
    predicate_index INTEGER NOT NULL,
    predicate_kind TEXT NOT NULL,
    property_key TEXT NOT NULL DEFAULT '',
    fixed_value TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(namespace, revision_digest, rule_index, predicate_index)
);

CREATE TABLE IF NOT EXISTS sekai_object_security_activations (
    namespace TEXT PRIMARY KEY,
    activation_id TEXT NOT NULL,
    activated_by TEXT NOT NULL,
    activated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sekai_object_security_active_policies (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    PRIMARY KEY(namespace, kind)
);

CREATE TABLE IF NOT EXISTS sekai_object_security_requests (
    namespace TEXT NOT NULL,
    actor TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, actor, operation, idempotency_key)
);

CREATE TABLE IF NOT EXISTS sekai_object_security_audit (
    event_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    revision_digest TEXT NOT NULL DEFAULT '',
    policy_count INTEGER NOT NULL,
    reason_code TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);

-- Parse object property JSON without aborting the surrounding query when the
-- stored TEXT is malformed or contains jsonb-rejected Unicode escapes.
CREATE OR REPLACE FUNCTION sekai_jsonb_object(properties TEXT)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    parsed jsonb;
BEGIN
    parsed := properties::jsonb;
    IF jsonb_typeof(parsed) IS DISTINCT FROM 'object' THEN
        RETURN NULL;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM jsonb_each(parsed) AS entry
        WHERE jsonb_typeof(entry.value) IS DISTINCT FROM 'string'
    ) THEN
        RETURN NULL;
    END IF;
    RETURN parsed;
EXCEPTION
    WHEN others THEN
        RETURN NULL;
END;
$$;
