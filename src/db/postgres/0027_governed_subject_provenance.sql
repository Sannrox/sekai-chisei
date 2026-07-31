CREATE TABLE IF NOT EXISTS chisei_governed_subject_provenance_exports (
    actor TEXT NOT NULL,
    export_id TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    namespace TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(actor, export_id)
);

CREATE INDEX IF NOT EXISTS idx_chisei_governed_subject_provenance_namespace
    ON chisei_governed_subject_provenance_exports(namespace, created_at_ms);
