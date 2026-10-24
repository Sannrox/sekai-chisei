-- Hop-projection evaluate fence (#967). The stamped generation is the
-- admission receipt; evaluate skips join/member COUNT when it matches.
ALTER TABLE sekai_object_type_index_join_status
    ADD COLUMN IF NOT EXISTS generation TEXT NOT NULL DEFAULT '';
