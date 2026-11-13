ALTER TABLE sekai_source_batch_transactions
    ADD COLUMN IF NOT EXISTS dataset_landed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sekai_source_batch_transactions
    ADD COLUMN IF NOT EXISTS dataset_row_from BIGINT;
ALTER TABLE sekai_source_batch_transactions
    ADD COLUMN IF NOT EXISTS dataset_row_to BIGINT;
