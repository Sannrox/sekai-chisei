CREATE TABLE IF NOT EXISTS chisei_usage_events (
    event_id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    unit TEXT NOT NULL,
    quantity BIGINT NOT NULL,
    source TEXT NOT NULL,
    receipt_operation_id TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    event_time_ms BIGINT NOT NULL,
    corrects_event_id TEXT,
    CHECK (unit IN ('tokens', 'requests')),
    CHECK (source IN ('measured', 'provider_reported', 'estimated', 'correction'))
);
CREATE INDEX IF NOT EXISTS idx_usage_events_tenant_time
    ON chisei_usage_events(tenant_id, event_time_ms, event_id);
CREATE INDEX IF NOT EXISTS idx_usage_events_receipt
    ON chisei_usage_events(receipt_operation_id);
