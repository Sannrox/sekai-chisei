-- Durable, bounded source-batch object synchronization.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_objects_github_source_identity
    ON sekai_objects(namespace, external_id)
    WHERE external_id LIKE 'github:%';

CREATE TABLE IF NOT EXISTS sekai_source_bindings (
    binding_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    producer_identity TEXT NOT NULL,
    source TEXT NOT NULL,
    source_instance TEXT NOT NULL,
    family TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    type_digest TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    active BOOLEAN NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    UNIQUE(namespace, source, source_instance)
);
CREATE INDEX IF NOT EXISTS idx_sekai_source_bindings_lookup
    ON sekai_source_bindings(namespace, source_instance, type_digest);

CREATE TABLE IF NOT EXISTS sekai_source_batch_transactions (
    transaction_id TEXT PRIMARY KEY,
    binding_id TEXT NOT NULL REFERENCES sekai_source_bindings(binding_id),
    namespace TEXT NOT NULL,
    producer_identity TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    batch_digest TEXT NOT NULL,
    batch_json TEXT NOT NULL,
    current_cursor TEXT NOT NULL,
    proposed_next_cursor TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('OPEN', 'COMMITTED', 'ABORTED', 'QUARANTINED')),
    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'denial', 'unavailable')),
    opened_at_ms BIGINT NOT NULL,
    closed_at_ms BIGINT,
    reason TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '',
    UNIQUE(namespace, producer_identity, idempotency_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_source_batches_one_open
    ON sekai_source_batch_transactions(binding_id) WHERE status = 'OPEN';
CREATE INDEX IF NOT EXISTS idx_sekai_source_batches_history
    ON sekai_source_batch_transactions(binding_id, opened_at_ms);

CREATE TABLE IF NOT EXISTS sekai_source_identities (
    namespace TEXT NOT NULL,
    source_id TEXT NOT NULL,
    binding_id TEXT NOT NULL REFERENCES sekai_source_bindings(binding_id),
    type_digest TEXT NOT NULL,
    type_name TEXT NOT NULL,
    object_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    tombstoned BOOLEAN NOT NULL,
    synced_object_json TEXT NOT NULL,
    lineage_json TEXT NOT NULL,
    last_transaction_id TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, source_id),
    UNIQUE(object_id)
);
CREATE OR REPLACE FUNCTION sekai_reject_generic_source_object_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM sekai_source_identities
        WHERE object_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'source-owned object is immutable outside source sync'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_sekai_source_objects_no_generic_update ON sekai_objects;
CREATE TRIGGER trg_sekai_source_objects_no_generic_update
BEFORE UPDATE ON sekai_objects
FOR EACH ROW EXECUTE FUNCTION sekai_reject_generic_source_object_mutation();
DROP TRIGGER IF EXISTS trg_sekai_source_objects_no_generic_delete ON sekai_objects;
CREATE TRIGGER trg_sekai_source_objects_no_generic_delete
BEFORE DELETE ON sekai_objects
FOR EACH ROW EXECUTE FUNCTION sekai_reject_generic_source_object_mutation();

CREATE TABLE IF NOT EXISTS sekai_source_record_results (
    transaction_id TEXT NOT NULL
        REFERENCES sekai_source_batch_transactions(transaction_id),
    source_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'denial', 'unavailable')),
    reason TEXT NOT NULL,
    lineage_json TEXT NOT NULL,
    PRIMARY KEY(transaction_id, source_id)
);

CREATE TABLE IF NOT EXISTS sekai_source_checkpoints (
    binding_id TEXT PRIMARY KEY REFERENCES sekai_source_bindings(binding_id),
    namespace TEXT NOT NULL,
    cursor TEXT NOT NULL,
    committed_batch_digest TEXT NOT NULL,
    advanced_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_source_checkpoints_namespace
    ON sekai_source_checkpoints(namespace);
