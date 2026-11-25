-- #3044 part 3: the concurrency queue a held transform run waits in. Empty
-- on work an older plane wrote; only held work reads it.
ALTER TABLE sekai_transform_work
    ADD COLUMN IF NOT EXISTS queue_scope TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sekai_transform_work_queue
    ON sekai_transform_work (queue_scope, created_at_ms, run_id)
    WHERE status = 'held';
