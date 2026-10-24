CREATE TABLE IF NOT EXISTS sekai_namespace_ownership (
    namespace TEXT PRIMARY KEY,
    contract_version TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES sekai_tenants(id),
    migrated_from_namespace TEXT NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_namespace_ownership_tenant
    ON sekai_namespace_ownership(tenant_id);

CREATE OR REPLACE FUNCTION enforce_active_tenant_object_write()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE candidate_namespace TEXT; previous_namespace TEXT;
BEGIN
    candidate_namespace := CASE WHEN TG_OP = 'DELETE' THEN OLD.namespace ELSE NEW.namespace END;
    previous_namespace := CASE WHEN TG_OP = 'UPDATE' THEN OLD.namespace ELSE candidate_namespace END;
    IF EXISTS (
        SELECT 1 FROM sekai_namespace_ownership ownership
        JOIN sekai_tenants tenant ON tenant.id = ownership.tenant_id
        WHERE ownership.namespace IN (candidate_namespace, previous_namespace)
          AND tenant.state <> 'active'
    ) THEN
        RAISE EXCEPTION 'tenant cannot admit namespace writes' USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;
DROP TRIGGER IF EXISTS trg_tenant_object_write ON sekai_objects;
CREATE TRIGGER trg_tenant_object_write
BEFORE INSERT OR UPDATE OR DELETE ON sekai_objects
FOR EACH ROW EXECUTE FUNCTION enforce_active_tenant_object_write();

CREATE OR REPLACE FUNCTION enforce_active_tenant_link_write()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE candidate_from_id TEXT; candidate_to_id TEXT;
BEGIN
    candidate_from_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.from_id ELSE NEW.from_id END;
    candidate_to_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.to_id ELSE NEW.to_id END;
    IF EXISTS (
        SELECT 1 FROM sekai_objects object
        JOIN sekai_namespace_ownership ownership ON ownership.namespace = object.namespace
        JOIN sekai_tenants tenant ON tenant.id = ownership.tenant_id
        WHERE object.id IN (candidate_from_id, candidate_to_id) AND tenant.state <> 'active'
    ) THEN
        RAISE EXCEPTION 'tenant cannot admit namespace writes' USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;
DROP TRIGGER IF EXISTS trg_tenant_link_write ON sekai_links;
CREATE TRIGGER trg_tenant_link_write
BEFORE INSERT OR UPDATE OR DELETE ON sekai_links
FOR EACH ROW EXECUTE FUNCTION enforce_active_tenant_link_write();
