-- Search index for the fenced scheduled catch-up (#2250). Planes from before
-- it keep reading and writing the unsuffixed sekai_search_* tables, which
-- stay unchanged; this index is separate, so the two never write each
-- other's documents. Both follow the object-change feed and the dataset
-- catalog. The legacy tables are retired and dropped in a later release.
CREATE TABLE IF NOT EXISTS sekai_search_checkpoint_v2 (
    namespace TEXT PRIMARY KEY,
    analyzer_version TEXT NOT NULL,
    last_change_rowid BIGINT NOT NULL DEFAULT 0,
    last_generation BIGINT NOT NULL DEFAULT 0,
    dataset_catalog_digest TEXT NOT NULL DEFAULT '',
    indexed_at_ms BIGINT NOT NULL DEFAULT 0,
    -- Bumped by every fenced write: a writer whose revision moved stops.
    revision BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sekai_search_object_v2 (
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    access_marking TEXT NOT NULL DEFAULT '',
    policy_attributes TEXT NOT NULL DEFAULT '{}',
    content_digest TEXT NOT NULL,
    indexed_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, object_id)
);
CREATE TABLE IF NOT EXISTS sekai_search_object_text_v2 (
    id BIGSERIAL PRIMARY KEY,
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    property TEXT NOT NULL,
    chunk INTEGER NOT NULL DEFAULT 0,
    text TEXT NOT NULL,
    tsv tsvector NOT NULL,
    UNIQUE (namespace, object_id, property, chunk)
);
CREATE INDEX IF NOT EXISTS sekai_search_object_text_v2_tsv
    ON sekai_search_object_text_v2 USING GIN (tsv);
CREATE TABLE IF NOT EXISTS sekai_search_dataset_v2 (
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
CREATE TABLE IF NOT EXISTS sekai_search_dataset_text_v2 (
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
CREATE INDEX IF NOT EXISTS sekai_search_dataset_text_v2_tsv
    ON sekai_search_dataset_text_v2 USING GIN (tsv);

-- Start warm: seed once from the legacy index. One statement, so every
-- copy reads the same snapshot even under READ COMMITTED: an older plane
-- rebuilding concurrently cannot leave a current checkpoint beside missing
-- documents. A legacy checkpoint that is stale or mid-rebuild makes the new
-- worker catch up or rebuild that namespace. ON CONFLICT keeps a rerun
-- harmless.
WITH seed_objects AS (
    INSERT INTO sekai_search_object_v2
        (namespace, object_id, kind, access_marking, policy_attributes,
         content_digest, indexed_at_ms)
    SELECT namespace, object_id, kind, access_marking, policy_attributes,
           content_digest, indexed_at_ms
    FROM sekai_search_object
    ON CONFLICT (namespace, object_id) DO NOTHING
), seed_object_text AS (
    INSERT INTO sekai_search_object_text_v2
        (namespace, object_id, property, chunk, text, tsv)
    SELECT namespace, object_id, property, chunk, text, tsv
    FROM sekai_search_object_text
    ON CONFLICT (namespace, object_id, property, chunk) DO NOTHING
), seed_datasets AS (
    INSERT INTO sekai_search_dataset_v2
        (namespace, dataset_id, name, bound_object_id, bound_access_marking,
         bound_policy_attributes, columns, content_digest, indexed_at_ms)
    SELECT namespace, dataset_id, name, bound_object_id, bound_access_marking,
           bound_policy_attributes, columns, content_digest, indexed_at_ms
    FROM sekai_search_dataset
    ON CONFLICT (namespace, dataset_id) DO NOTHING
), seed_dataset_text AS (
    INSERT INTO sekai_search_dataset_text_v2
        (namespace, dataset_id, field, chunk, classification, text, tsv)
    SELECT namespace, dataset_id, field, chunk, classification, text, tsv
    FROM sekai_search_dataset_text
    ON CONFLICT (namespace, dataset_id, field, chunk) DO NOTHING
)
INSERT INTO sekai_search_checkpoint_v2
    (namespace, analyzer_version, last_change_rowid, last_generation,
     dataset_catalog_digest, indexed_at_ms)
SELECT namespace, analyzer_version, last_change_rowid, last_generation,
       dataset_catalog_digest, indexed_at_ms
FROM sekai_search_checkpoint
ON CONFLICT (namespace) DO NOTHING;
