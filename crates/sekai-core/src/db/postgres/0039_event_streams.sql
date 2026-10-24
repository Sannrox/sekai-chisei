CREATE TABLE IF NOT EXISTS sekai_event_stream_bindings (
    stream_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_event_stream_checkpoints (
    stream_id TEXT PRIMARY KEY,
    committed_offset BIGINT NOT NULL,
    record_json TEXT NOT NULL,
    FOREIGN KEY(stream_id) REFERENCES sekai_event_stream_bindings(stream_id)
);
CREATE TABLE IF NOT EXISTS sekai_event_stream_admitted_events (
    stream_id TEXT NOT NULL,
    event_offset BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    feed_epoch TEXT NOT NULL,
    event_digest TEXT NOT NULL,
    PRIMARY KEY(stream_id, event_offset),
    FOREIGN KEY(stream_id) REFERENCES sekai_event_stream_bindings(stream_id)
);
CREATE TABLE IF NOT EXISTS sekai_event_subscriptions (
    namespace TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(namespace, subscription_id)
);
