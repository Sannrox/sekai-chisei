-- #3044: the budget scope a transform quota hold's refund reaches. Empty on
-- holds an older plane wrote; those refund the tenant scope only.
ALTER TABLE sekai_transform_quota_hold
    ADD COLUMN IF NOT EXISTS quota_scope TEXT NOT NULL DEFAULT '';
