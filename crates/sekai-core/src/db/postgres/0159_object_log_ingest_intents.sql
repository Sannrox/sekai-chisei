-- Durable intents to ingest an admitted Action's object into the object log
-- (#2289). Recorded with the object write, ready once its receipt commits,
-- deleted once drained. `seq` orders one object's writes; a watermark keeps
-- the highest drained `seq` of each object with intents left.
CREATE TABLE IF NOT EXISTS sekai_object_log_ingest_intents (
    seq BIGSERIAL PRIMARY KEY,
    instance_id TEXT NOT NULL UNIQUE,
    object_id TEXT NOT NULL,
    object_json TEXT NOT NULL,
    ready BOOLEAN NOT NULL DEFAULT FALSE,
    from_grant BOOLEAN NOT NULL DEFAULT FALSE,
    recorded_at_ms BIGINT NOT NULL,
    claim_owner TEXT NOT NULL DEFAULT '',
    claimed_until_ms BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_object_log_ingest_intents_ready
    ON sekai_object_log_ingest_intents (ready, claimed_until_ms, seq);
CREATE INDEX IF NOT EXISTS idx_object_log_ingest_intents_object
    ON sekai_object_log_ingest_intents (object_id, seq);
CREATE TABLE IF NOT EXISTS sekai_object_log_ingest_watermarks (
    object_id TEXT PRIMARY KEY,
    seq BIGINT NOT NULL
);
