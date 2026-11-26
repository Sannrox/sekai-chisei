-- Source capture slots and measured notes (#3083, ADR 0170, ADR 0163):
-- the replication slot names a runtime recorded before it may create
-- them, a set the plane only adds to, and the notes an older plane cannot
-- decode, such as a slot's retained log, kept apart from
-- sync_last_notes_json so such a plane still reads the row. Additive and
-- defaulted, so a plane without the columns keeps writing the row.
ALTER TABLE sekai_sources
    ADD COLUMN IF NOT EXISTS sync_created_slots_json TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS sync_measured_notes_json TEXT NOT NULL DEFAULT '';
