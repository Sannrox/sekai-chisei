CREATE TABLE IF NOT EXISTS sekai_tenant_memberships (
    tenant_id TEXT NOT NULL REFERENCES sekai_tenants(id),
    subject_id TEXT NOT NULL,
    contract_version TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'billing_viewer')),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT,
    PRIMARY KEY (tenant_id, subject_id)
);

CREATE INDEX IF NOT EXISTS idx_sekai_tenant_memberships_subject
    ON sekai_tenant_memberships(subject_id, status);
