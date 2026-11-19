-- An archived definition branch stops appearing as open work (#2434).
ALTER TABLE sekai_definition_branches ADD COLUMN IF NOT EXISTS archived_at_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sekai_definition_branches ADD COLUMN IF NOT EXISTS archive_reason TEXT NOT NULL DEFAULT '';
