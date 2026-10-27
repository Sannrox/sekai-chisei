CREATE TABLE IF NOT EXISTS sekai_service_principals (
    principal TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    namespaces_json TEXT NOT NULL,
    action_types_json TEXT NOT NULL,
    registered_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
