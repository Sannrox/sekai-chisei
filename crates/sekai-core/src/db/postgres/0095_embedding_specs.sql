-- Stored embedding specs (#1609): what catch-up embeds per namespace, and
-- the catalog model route that embeds it.
CREATE TABLE IF NOT EXISTS sekai_embedding_specs (
    namespace TEXT NOT NULL,
    spec_id TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    properties TEXT NOT NULL,
    chunk_chars BIGINT NOT NULL,
    dimension BIGINT NOT NULL,
    batch_size BIGINT NOT NULL,
    model TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, spec_id)
);
