-- Source-webhook verifying-key pins (ADR 0035) and registered source-type
-- descriptors (ADR 0060), as on SQLite (#1322).
CREATE TABLE IF NOT EXISTS sekai_source_webhook_keys (
    pin_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    source_instance TEXT NOT NULL,
    key_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    UNIQUE(namespace, source_instance, key_id)
);

CREATE TABLE IF NOT EXISTS sekai_source_type_descriptors (
    namespace TEXT NOT NULL,
    digest TEXT NOT NULL,
    source TEXT NOT NULL,
    record_kind TEXT NOT NULL,
    schema_revision TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('live', 'retired')),
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(namespace, digest),
    UNIQUE(namespace, source, record_kind, schema_revision)
);
