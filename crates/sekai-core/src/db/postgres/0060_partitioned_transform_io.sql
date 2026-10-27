ALTER TABLE sekai_datasets
    ADD COLUMN IF NOT EXISTS partition_keys TEXT NOT NULL DEFAULT '[]';

ALTER TABLE sekai_dataset_rows
    ADD COLUMN IF NOT EXISTS partition_key TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_dataset_rows_partition
    ON sekai_dataset_rows (dataset_id, partition_key);

ALTER TABLE sekai_transform_run_input
    ADD COLUMN IF NOT EXISTS partition_key TEXT NOT NULL DEFAULT '';

ALTER TABLE sekai_governed_transform_run
    ADD COLUMN IF NOT EXISTS input_partitions TEXT NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS output_partitions TEXT NOT NULL DEFAULT '[]';

ALTER TABLE sekai_governed_transform_checkpoint
    ADD COLUMN IF NOT EXISTS input_partition_digests TEXT NOT NULL DEFAULT '{}';
