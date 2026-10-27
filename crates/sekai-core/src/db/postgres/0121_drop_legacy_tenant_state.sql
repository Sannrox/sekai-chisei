-- Sekai owns no tenant, membership or tenant-credential state on any
-- backend (ADR 0099, #1613). Startup refuses populated legacy rows before
-- migrating; this check repeats it inside the migration, so the tables are
-- dropped only when they hold nothing.
-- Writes are excluded on every affected table from the check through the
-- drops, so no row can commit in between and be dropped unseen.
LOCK TABLE sekai_tenants, sekai_tenant_requests, sekai_tenant_memberships,
    sekai_namespace_ownership, sekai_principal_credentials IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM sekai_tenants)
       OR EXISTS (SELECT 1 FROM sekai_tenant_requests)
       OR EXISTS (SELECT 1 FROM sekai_tenant_memberships)
       OR EXISTS (SELECT 1 FROM sekai_namespace_ownership)
       OR EXISTS (SELECT 1 FROM sekai_principal_credentials WHERE tenant_id <> '')
    THEN
        RAISE EXCEPTION USING
            MESSAGE = 'legacy PostgreSQL tenant state detected; no legacy tenant data was changed',
            HINT = 'Back up the database and move tenant records to the identity extension (docs/tenant-migration.md).';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS trg_tenant_object_write ON sekai_objects;
DROP TRIGGER IF EXISTS trg_tenant_link_write ON sekai_links;
DROP FUNCTION IF EXISTS enforce_active_tenant_object_write();
DROP FUNCTION IF EXISTS enforce_active_tenant_link_write();
DROP TABLE IF EXISTS sekai_namespace_ownership;
DROP TABLE IF EXISTS sekai_tenant_memberships;
DROP TABLE IF EXISTS sekai_tenant_requests;
DROP TABLE IF EXISTS sekai_tenants;
DROP INDEX IF EXISTS idx_sekai_principal_credentials_tenant;
