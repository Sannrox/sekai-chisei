CREATE INDEX IF NOT EXISTS sekai_object_type_index_join_value
    ON sekai_object_type_index_join (namespace, kind, property, value);
