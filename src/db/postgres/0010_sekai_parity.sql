-- Dedicated reusable Sekai stores not covered by the graph parity migration.
-- Tenant, OAuth/OIDC, gateway, and Chisei decision state are deliberately
-- absent from this migration.

CREATE TABLE IF NOT EXISTS sekai_ontology_classes (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    superclasses_json TEXT NOT NULL DEFAULT '[]',
    equivalent_json TEXT NOT NULL DEFAULT '[]',
    disjoint_json TEXT NOT NULL DEFAULT '[]',
    properties_json TEXT NOT NULL DEFAULT '[]',
    mapped_kind TEXT NOT NULL DEFAULT '',
    created BIGINT NOT NULL,
    updated BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ontology_classes_mapped_kind
    ON sekai_ontology_classes(mapped_kind);

CREATE TABLE IF NOT EXISTS sekai_ontology_relations (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    range TEXT NOT NULL DEFAULT '',
    cardinality_json TEXT NOT NULL DEFAULT '{}',
    inverse TEXT NOT NULL DEFAULT '',
    transitive BIGINT NOT NULL DEFAULT 0,
    mapped_relation TEXT NOT NULL DEFAULT '',
    created BIGINT NOT NULL,
    updated BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ontology_relations_domain
    ON sekai_ontology_relations(domain);
CREATE INDEX IF NOT EXISTS idx_ontology_relations_range
    ON sekai_ontology_relations(range);

CREATE TABLE IF NOT EXISTS sekai_leases (
    namespace TEXT NOT NULL,
    lease_key TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    fencing_token TEXT NOT NULL UNIQUE,
    owner TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'released')),
    acquired_at_ms BIGINT NOT NULL,
    refreshed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    released_at_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY(namespace, lease_key)
);
CREATE TABLE IF NOT EXISTS sekai_lease_requests (
    namespace TEXT NOT NULL,
    lease_key TEXT NOT NULL,
    request_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, lease_key, request_id)
);
CREATE TABLE IF NOT EXISTS sekai_lease_audit (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    lease_key TEXT NOT NULL,
    generation BIGINT NOT NULL,
    fencing_token TEXT NOT NULL,
    actor TEXT NOT NULL,
    operation TEXT NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    previous_owner TEXT NOT NULL,
    owner TEXT NOT NULL,
    previous_expires_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    request_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_lease_audit_key
    ON sekai_lease_audit(namespace, lease_key, timestamp_ms, id);
CREATE TABLE IF NOT EXISTS sekai_guarded_object_mutations (
    lease_namespace TEXT NOT NULL,
    lease_key TEXT NOT NULL,
    request_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    target_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    response_json TEXT NOT NULL,
    generation BIGINT NOT NULL,
    actor TEXT NOT NULL,
    committed_at_ms BIGINT NOT NULL,
    PRIMARY KEY(lease_namespace, lease_key, request_id)
);

-- Deterministic ordering and referential integrity for the tables that existed
-- in the original PostgreSQL bootstrap schema.
CREATE INDEX IF NOT EXISTS idx_dataset_rows_stable
    ON sekai_dataset_rows(dataset_id, id);
CREATE INDEX IF NOT EXISTS idx_virtual_tables_dataset
    ON sekai_virtual_tables(dataset_id, id);
CREATE INDEX IF NOT EXISTS idx_action_types_updated
    ON sekai_action_types(updated, name);
