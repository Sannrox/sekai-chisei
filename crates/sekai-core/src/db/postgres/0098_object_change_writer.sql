-- Writer attribution per object change (#1690). Nullable, so rows written
-- before this migration, or by a version without it during a rolling deploy,
-- read as unattributed; the writer is never inferred.
ALTER TABLE sekai_object_changes ADD COLUMN IF NOT EXISTS writer_kind TEXT;
ALTER TABLE sekai_object_changes ADD COLUMN IF NOT EXISTS writer_ref TEXT;
ALTER TABLE sekai_object_changes ADD COLUMN IF NOT EXISTS receipt_id TEXT;
