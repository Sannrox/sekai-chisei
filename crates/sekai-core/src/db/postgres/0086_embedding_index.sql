CREATE TABLE IF NOT EXISTS sekai_embedding_chunks (
    namespace TEXT NOT NULL,
    spec_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    chunk_index BIGINT NOT NULL,
    chunk_digest TEXT NOT NULL,
    vector BYTEA NOT NULL,
    source_digest TEXT NOT NULL,
    model TEXT NOT NULL,
    model_version TEXT NOT NULL,
    marking TEXT,
    classifications TEXT NOT NULL,
    embedded_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, spec_id, object_id, chunk_index)
);
CREATE TABLE IF NOT EXISTS sekai_embedding_checkpoints (
    namespace TEXT NOT NULL,
    spec_id TEXT NOT NULL,
    spec_digest TEXT NOT NULL,
    last_change_rowid BIGINT NOT NULL,
    last_generation BIGINT NOT NULL,
    revision BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, spec_id)
);
CREATE TABLE IF NOT EXISTS sekai_embedding_rebuilds (
    id BIGSERIAL PRIMARY KEY,
    namespace TEXT NOT NULL,
    spec_id TEXT NOT NULL,
    from_digest TEXT NOT NULL,
    to_digest TEXT NOT NULL,
    objects BIGINT NOT NULL,
    rebuilt_at_ms BIGINT NOT NULL
);
