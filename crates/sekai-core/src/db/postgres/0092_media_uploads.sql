CREATE TABLE IF NOT EXISTS sekai_media_uploads (
    upload_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    uploader TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    file_name TEXT NOT NULL,
    access_marking TEXT NOT NULL,
    received_bytes BIGINT NOT NULL,
    attempt BIGINT NOT NULL,
    object_id TEXT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_media_chunks (
    upload_id TEXT NOT NULL,
    offset_bytes BIGINT NOT NULL,
    data BYTEA NOT NULL,
    PRIMARY KEY (upload_id, offset_bytes)
);

