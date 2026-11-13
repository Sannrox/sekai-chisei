ALTER TABLE sekai_object_type_datasource
    ADD COLUMN IF NOT EXISTS conflict_rule TEXT NOT NULL DEFAULT '';
ALTER TABLE sekai_object_type_datasource
    ADD COLUMN IF NOT EXISTS source_timestamp_property TEXT NOT NULL DEFAULT '';
ALTER TABLE sekai_object_type_index_edit
    ADD COLUMN IF NOT EXISTS action_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sekai_object_type_index_edit
    ADD COLUMN IF NOT EXISTS edited_at_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sekai_object_type_index_edit
    ADD COLUMN IF NOT EXISTS property_edited_at_ms TEXT NOT NULL DEFAULT '{}';
