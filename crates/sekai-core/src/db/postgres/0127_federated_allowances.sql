-- Per-tenant federated aggregate allowances (#1921, ADR 0134): an
-- append-only history per namespace and object type. Additive.
CREATE TABLE IF NOT EXISTS sekai_federated_allowances (
    namespace TEXT NOT NULL,
    object_type TEXT NOT NULL,
    seq BIGINT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, object_type, seq)
);
