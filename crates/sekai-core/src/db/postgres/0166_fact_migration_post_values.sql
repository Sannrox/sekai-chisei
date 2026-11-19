-- Post-migration property values next to each pre-migration snapshot, so a
-- rollback keeps properties edited after the migration (ADR 0028). NULL on
-- snapshots recorded before this column: their rollback restores whole.
ALTER TABLE sekai_fact_migration_snapshots
    ADD COLUMN IF NOT EXISTS migrated_properties_json TEXT;
