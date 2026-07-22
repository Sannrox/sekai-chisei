ALTER TABLE sekai_principal_credentials
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_sekai_principal_credentials_tenant
    ON sekai_principal_credentials(tenant_id, principal);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_principal_credentials_active_tenant
    ON sekai_principal_credentials(tenant_id, principal)
    WHERE tenant_id <> '' AND status = 'active';
