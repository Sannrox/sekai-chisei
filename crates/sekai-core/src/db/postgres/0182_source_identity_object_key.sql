-- Object key of a source record (#3013): the key of the stored object the
-- record came from, for connectors over keyed object storage. NULL for rows
-- whose record carried none, including every row landed before this column.
-- The column and its index use the "C" collation, so a range read over keys
-- follows UTF-8 byte order, the order object storage lists keys in, whatever
-- the database's default collation is.
ALTER TABLE sekai_source_identities
    ADD COLUMN IF NOT EXISTS object_key TEXT COLLATE "C";
CREATE INDEX IF NOT EXISTS idx_sekai_source_identities_object_key
    ON sekai_source_identities(namespace, binding_id, object_key COLLATE "C");
