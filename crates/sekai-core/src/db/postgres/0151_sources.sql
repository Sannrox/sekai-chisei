-- Sources (ADR 0148, #2185): one governed record per integration. One
-- Source owns each (namespace, source, source_instance), so the unique key
-- keeps object identity with a single owner. Additive: an older binary
-- neither reads nor writes it.
CREATE TABLE IF NOT EXISTS sekai_sources (
    namespace TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_instance TEXT NOT NULL,
    status TEXT NOT NULL,
    revision BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, source_id),
    UNIQUE (namespace, source, source_instance)
);
