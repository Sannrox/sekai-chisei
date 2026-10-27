CREATE TABLE IF NOT EXISTS sekai_tenants (
    id TEXT PRIMARY KEY,
    contract_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','suspended','closure_pending')),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_tenant_requests (
    idempotency_key TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES sekai_tenants(id),
    response_contract_version TEXT NOT NULL,
    response_state TEXT NOT NULL,
    response_created_at_ms BIGINT NOT NULL,
    response_updated_at_ms BIGINT NOT NULL
);
