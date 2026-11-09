-- Retention sweep for consumer violation deliveries (#2195). Every instance
-- deletes rows past the bound by created_at_ms each minute; without this
-- index each sweep scans the whole table. Additive: an older binary ignores it.
CREATE INDEX IF NOT EXISTS idx_sekai_consumer_violation_deliveries_created
    ON sekai_consumer_violation_deliveries (created_at_ms);
