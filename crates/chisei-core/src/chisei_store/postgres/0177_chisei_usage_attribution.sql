-- #3043: the ledger gains units (validated by the typed reader, which skips
-- units it does not know) and principal, resource and reporter attribution.
ALTER TABLE chisei_usage_events DROP CONSTRAINT IF EXISTS chisei_usage_events_unit_check;
ALTER TABLE chisei_usage_events ADD COLUMN IF NOT EXISTS principal_id TEXT;
ALTER TABLE chisei_usage_events ADD COLUMN IF NOT EXISTS resource_kind TEXT;
ALTER TABLE chisei_usage_events ADD COLUMN IF NOT EXISTS resource_id TEXT;
ALTER TABLE chisei_usage_events ADD COLUMN IF NOT EXISTS reported_by TEXT;
