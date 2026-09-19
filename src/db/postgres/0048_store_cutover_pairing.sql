ALTER TABLE sekai_store_cutover
    ADD COLUMN IF NOT EXISTS pairing_epoch BIGINT NOT NULL DEFAULT 0;
