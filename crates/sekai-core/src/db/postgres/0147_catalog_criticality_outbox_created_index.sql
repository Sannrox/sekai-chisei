-- Retention sweep for the catalog criticality outbox (#2196). Every instance
-- deletes superseded events past the bound by created_at_ms each minute;
-- without this index each sweep scans the whole table. Additive: an older
-- binary ignores it.
CREATE INDEX IF NOT EXISTS idx_sekai_catalog_criticality_outbox_created
    ON sekai_catalog_criticality_outbox (created_at_ms);
