-- Stored operation identity per object change (#1689). Older rows keep ''.
ALTER TABLE sekai_object_changes
    ADD COLUMN IF NOT EXISTS operation_id TEXT NOT NULL DEFAULT '';
