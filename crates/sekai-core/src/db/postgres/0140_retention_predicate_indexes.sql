-- Retention tick predicates on object changes and content events (#2028).
CREATE INDEX IF NOT EXISTS idx_object_changes_timestamp
    ON sekai_object_changes (timestamp, id);
CREATE INDEX IF NOT EXISTS idx_content_events_created
    ON sekai_content_events (created_at_ms, id);
