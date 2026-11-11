-- Rebuild cursor for the embedding index (#2244): an interrupted rebuild
-- resumes where it stopped instead of re-embedding every object.
-- rebuild_revision is the checkpoint revision the cursor is valid at; a
-- write that does not carry it forward voids it, and -1 means no cursor.
-- Planes from before this migration never read or write these columns.
ALTER TABLE sekai_embedding_checkpoints
    ADD COLUMN IF NOT EXISTS rebuild_from TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rebuild_to TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rebuild_after TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rebuild_watermark BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rebuild_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rebuild_objects BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rebuild_revision BIGINT NOT NULL DEFAULT -1;
