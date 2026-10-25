CREATE TABLE IF NOT EXISTS sekai_ezu_geo_feeds (
    namespace TEXT NOT NULL,
    feed_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    after_seq BIGINT NOT NULL DEFAULT 0,
    run_id TEXT NOT NULL DEFAULT '',
    run_lease_until_ms BIGINT NOT NULL DEFAULT 0,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, feed_id)
);
