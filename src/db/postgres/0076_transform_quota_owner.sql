CREATE TABLE IF NOT EXISTS sekai_transform_quota_owner (
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    PRIMARY KEY (namespace, transform_id)
);
