ALTER TABLE sekai_governed_transform_run
    ADD COLUMN IF NOT EXISTS markings_in TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS markings_out TEXT NOT NULL DEFAULT '';
