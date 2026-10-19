CREATE TABLE IF NOT EXISTS sekai_search_checkpoint (
    namespace TEXT PRIMARY KEY,
    analyzer_version TEXT NOT NULL,
    last_change_rowid BIGINT NOT NULL DEFAULT 0,
    last_generation BIGINT NOT NULL DEFAULT 0,
    dataset_catalog_digest TEXT NOT NULL DEFAULT '',
    indexed_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sekai_search_object (
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    access_marking TEXT NOT NULL DEFAULT '',
    policy_attributes TEXT NOT NULL DEFAULT '{}',
    content_digest TEXT NOT NULL,
    indexed_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, object_id)
);
CREATE TABLE IF NOT EXISTS sekai_search_object_text (
    id BIGSERIAL PRIMARY KEY,
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    property TEXT NOT NULL,
    chunk INTEGER NOT NULL DEFAULT 0,
    text TEXT NOT NULL,
    tsv tsvector NOT NULL,
    UNIQUE (namespace, object_id, property, chunk)
);
CREATE INDEX IF NOT EXISTS sekai_search_object_text_tsv
    ON sekai_search_object_text USING GIN (tsv);
CREATE TABLE IF NOT EXISTS sekai_search_dataset (
    namespace TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    name TEXT NOT NULL,
    bound_object_id TEXT NOT NULL DEFAULT '',
    bound_access_marking TEXT NOT NULL DEFAULT '',
    bound_policy_attributes TEXT NOT NULL DEFAULT '{}',
    columns TEXT NOT NULL DEFAULT '[]',
    content_digest TEXT NOT NULL,
    indexed_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, dataset_id)
);
CREATE TABLE IF NOT EXISTS sekai_search_dataset_text (
    id BIGSERIAL PRIMARY KEY,
    namespace TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    field TEXT NOT NULL,
    chunk INTEGER NOT NULL DEFAULT 0,
    classification TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    tsv tsvector NOT NULL,
    UNIQUE (namespace, dataset_id, field, chunk)
);
CREATE INDEX IF NOT EXISTS sekai_search_dataset_text_tsv
    ON sekai_search_dataset_text USING GIN (tsv);
