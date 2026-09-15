CREATE TABLE IF NOT EXISTS sekai_object_type_index_join (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    property TEXT NOT NULL,
    value_digest TEXT NOT NULL,
    source_key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (namespace, kind, property, value_digest, source_key)
);
CREATE INDEX IF NOT EXISTS sekai_object_type_index_join_lookup
    ON sekai_object_type_index_join (namespace, kind, property, value_digest);
CREATE INDEX IF NOT EXISTS sekai_object_type_index_join_member
    ON sekai_object_type_index_join (namespace, kind, source_key);
CREATE TABLE IF NOT EXISTS sekai_object_type_index_join_status (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    ready BOOLEAN NOT NULL DEFAULT FALSE,
    rebuilt_at_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace, kind)
);
