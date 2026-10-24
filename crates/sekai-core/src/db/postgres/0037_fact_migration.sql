CREATE TABLE IF NOT EXISTS sekai_object_revision_bindings (
    object_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    revision_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_fact_migrations (
    namespace TEXT NOT NULL,
    migration_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, migration_id)
);
CREATE TABLE IF NOT EXISTS sekai_fact_migration_snapshots (
    namespace TEXT NOT NULL,
    migration_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    properties_json TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    PRIMARY KEY(namespace, migration_id, object_id)
);
CREATE TABLE IF NOT EXISTS sekai_fact_migration_requests (
    namespace TEXT NOT NULL,
    actor TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, actor, idempotency_key)
);
