-- Source sync notes (ADR 0163, #3014): the bounded notes a runtime reported
-- on the bucket it finished last, as JSON stamped with that finish time.
-- Additive and defaulted, so a plane without the column keeps writing the
-- row; a later finish by such a plane leaves the stamp behind and the notes
-- read as none.
ALTER TABLE sekai_sources
    ADD COLUMN IF NOT EXISTS sync_last_notes_json TEXT NOT NULL DEFAULT '';
