CREATE TABLE IF NOT EXISTS sekai_peer_trust_roots (
    namespace TEXT NOT NULL,
    site_identity TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, site_identity, key_id)
);
CREATE TABLE IF NOT EXISTS sekai_peer_imports (
    import_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    record_json TEXT NOT NULL,
    imported_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_peer_imports_namespace
    ON sekai_peer_imports(namespace, imported_at_ms);
CREATE TABLE IF NOT EXISTS sekai_federation_namespace_grants (
    grant_id TEXT PRIMARY KEY,
    peer_site_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    record_json TEXT NOT NULL,
    revoked BOOLEAN NOT NULL,
    granted_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_federation_namespace_grants_peer
    ON sekai_federation_namespace_grants(peer_site_id, namespace, revoked);
CREATE TABLE IF NOT EXISTS sekai_federation_snapshot_exports (
    snapshot_digest TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    record_json TEXT NOT NULL,
    exported_at_ms BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_federation_snapshot_exports_sequence
    ON sekai_federation_snapshot_exports(namespace, sequence);
CREATE TABLE IF NOT EXISTS sekai_federation_snapshot_sequences (
    namespace TEXT PRIMARY KEY,
    next_sequence BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_federation_snapshot_imports (
    import_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    peer_site_id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    record_json TEXT NOT NULL,
    imported_at_ms BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_federation_snapshot_imports_digest
    ON sekai_federation_snapshot_imports(peer_site_id, namespace, snapshot_digest);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_federation_snapshot_imports_sequence
    ON sekai_federation_snapshot_imports(peer_site_id, namespace, sequence);
CREATE TABLE IF NOT EXISTS sekai_federation_snapshot_facts (
    import_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    fact_json TEXT NOT NULL,
    PRIMARY KEY (import_id, object_id),
    FOREIGN KEY (import_id)
        REFERENCES sekai_federation_snapshot_imports(import_id)
);
