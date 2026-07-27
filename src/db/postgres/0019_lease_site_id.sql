-- Region/site pin for generation-fenced leases (#293).
-- Default 'local' preserves single-region behavior for existing rows.
ALTER TABLE sekai_leases
    ADD COLUMN IF NOT EXISTS site_id TEXT NOT NULL DEFAULT 'local';
