-- Consumer violation deliveries (#1636). Additive: a binary without this
-- table keeps working during a rolling deploy, and a rollback leaves it unused.
CREATE TABLE IF NOT EXISTS sekai_consumer_violation_deliveries (
    recipient TEXT NOT NULL,
    event_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    namespace TEXT NOT NULL,
    member_kind TEXT NOT NULL,
    member_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    acknowledged_at_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (recipient, event_id)
);
CREATE INDEX IF NOT EXISTS idx_sekai_consumer_violation_deliveries_recipient
    ON sekai_consumer_violation_deliveries (recipient, created_at_ms, event_id);
