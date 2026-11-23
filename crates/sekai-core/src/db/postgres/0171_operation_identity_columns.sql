-- Operation identity of the call that opened a source batch and of the merge
-- that published a definition proposal (#3087). Nullable; entries written
-- before this migration keep no identity.
ALTER TABLE sekai_source_batch_transactions ADD COLUMN IF NOT EXISTS operation_id TEXT;
ALTER TABLE sekai_definition_proposals ADD COLUMN IF NOT EXISTS operation_id TEXT;
