CREATE TABLE IF NOT EXISTS chisei_operation_reservations (
    namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    actor TEXT NOT NULL,
    budget_subject TEXT NOT NULL DEFAULT '',
    incurred_usage BIGINT NOT NULL DEFAULT 0,
    sekai_instance_id TEXT NOT NULL DEFAULT '',
    sekai_status TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, operation_id)
);

CREATE INDEX IF NOT EXISTS idx_chisei_operation_reservations_status
    ON chisei_operation_reservations(status, expires_at_ms);
