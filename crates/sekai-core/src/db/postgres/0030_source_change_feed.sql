-- Generation-fenced ordered source change feeds.
ALTER TABLE sekai_source_batch_transactions
    ADD COLUMN contract_version TEXT NOT NULL DEFAULT 'sekai.source-batch/v1',
    ADD COLUMN delivery_mode TEXT,
    ADD COLUMN sync_generation BIGINT,
    ADD COLUMN feed_epoch TEXT,
    ADD COLUMN offset_start BIGINT,
    ADD COLUMN offset_end BIGINT,
    ADD COLUMN snapshot_complete BOOLEAN;

ALTER TABLE sekai_source_checkpoints
    ADD COLUMN contract_version TEXT NOT NULL DEFAULT 'sekai.source-batch/v1',
    ADD COLUMN delivery_mode TEXT,
    ADD COLUMN sync_generation BIGINT,
    ADD COLUMN feed_epoch TEXT,
    ADD COLUMN committed_offset BIGINT;

ALTER TABLE sekai_source_record_results
    ADD COLUMN source_sequence BIGINT;

CREATE TABLE sekai_source_sync_generations (
    binding_id TEXT NOT NULL REFERENCES sekai_source_bindings(binding_id),
    sync_generation BIGINT NOT NULL CHECK(sync_generation > 0),
    status TEXT NOT NULL CHECK(
        status IN ('SNAPSHOTTING', 'ACTIVE', 'RECOVERY_REQUIRED', 'SUPERSEDED')
    ),
    delivery_mode TEXT NOT NULL CHECK(delivery_mode IN ('snapshot', 'change_feed')),
    feed_epoch TEXT,
    committed_offset BIGINT,
    reason TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY(binding_id, sync_generation),
    CHECK(committed_offset IS NULL OR committed_offset >= 0)
);

CREATE UNIQUE INDEX idx_sekai_source_generations_one_current
    ON sekai_source_sync_generations(binding_id)
    WHERE status IN ('SNAPSHOTTING', 'ACTIVE', 'RECOVERY_REQUIRED');

CREATE INDEX idx_sekai_source_batches_generation
    ON sekai_source_batch_transactions(binding_id, sync_generation, opened_at_ms);
