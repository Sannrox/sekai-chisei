CREATE TABLE IF NOT EXISTS sekai_object_type_datasource (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    key_column TEXT NOT NULL,
    property_mapping TEXT NOT NULL,
    hidden_column TEXT NOT NULL DEFAULT '',
    edits_only BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, kind)
);
CREATE TABLE IF NOT EXISTS sekai_object_type_index_status (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    indexed_at_ms BIGINT NOT NULL,
    last_dataset_row_id BIGINT NOT NULL DEFAULT 0,
    member_count INTEGER NOT NULL DEFAULT 0,
    stale BOOLEAN NOT NULL DEFAULT FALSE,
    quarantine_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (namespace, kind)
);
CREATE TABLE IF NOT EXISTS sekai_object_type_index_member (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_key TEXT NOT NULL,
    object_id TEXT NOT NULL,
    properties TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    hidden BOOLEAN NOT NULL DEFAULT FALSE,
    from_edit BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (namespace, kind, source_key)
);
CREATE TABLE IF NOT EXISTS sekai_object_type_index_edit (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_key TEXT NOT NULL,
    properties TEXT NOT NULL,
    hidden BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (namespace, kind, source_key)
);
