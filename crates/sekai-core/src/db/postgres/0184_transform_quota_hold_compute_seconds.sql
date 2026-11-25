-- #3044 part 2b: compute seconds a transform quota hold still owns. Zero on
-- holds an older plane wrote; those have no compute reservation to settle.
ALTER TABLE sekai_transform_quota_hold
    ADD COLUMN IF NOT EXISTS reserved_compute_seconds INTEGER NOT NULL DEFAULT 0;
