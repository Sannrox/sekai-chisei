ALTER TABLE sekai_transform_work
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';
