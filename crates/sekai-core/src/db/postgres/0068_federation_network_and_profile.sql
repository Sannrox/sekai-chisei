CREATE TABLE IF NOT EXISTS sekai_federation_local_site (
    site_id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    region TEXT,
    residency_data_classes_json TEXT NOT NULL,
    registered_by TEXT NOT NULL,
    registered_at_ms BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_federation_peers (
    local_site_id TEXT NOT NULL,
    peer_site_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    membership TEXT NOT NULL,
    health TEXT NOT NULL,
    joined_at_ms BIGINT NOT NULL,
    PRIMARY KEY (local_site_id, peer_site_id)
);
CREATE INDEX IF NOT EXISTS idx_sekai_federation_peers_membership
    ON sekai_federation_peers(membership, health);
CREATE TABLE IF NOT EXISTS sekai_federation_network_contracts (
    namespace TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, contract_id)
);
CREATE TABLE IF NOT EXISTS sekai_federation_network_exchanges (
    namespace TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    exchange_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, contract_id, exchange_id),
    FOREIGN KEY (namespace, contract_id)
        REFERENCES sekai_federation_network_contracts(namespace, contract_id)
);
CREATE TABLE IF NOT EXISTS sekai_federation_conflicts (
    conflict_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    status TEXT NOT NULL,
    record_json TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_federation_conflicts_object
    ON sekai_federation_conflicts(namespace, object_id);
CREATE TABLE IF NOT EXISTS sekai_federation_revocations (
    revocation_id TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    status TEXT NOT NULL,
    record_json TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_federation_revocations_subject
    ON sekai_federation_revocations(subject_kind, subject_id);
