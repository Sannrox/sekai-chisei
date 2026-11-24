-- Keyed newest-first lookup of a source batch row (#3259). Partial, so only
-- `srcds:` rows pay for the expression; queries repeat the predicate.
CREATE INDEX IF NOT EXISTS idx_dataset_rows_source_key
    ON sekai_dataset_rows (dataset_id, ((data::jsonb)->>'source_id'), id)
    WHERE dataset_id LIKE 'srcds:%';
CREATE INDEX IF NOT EXISTS idx_dataset_version_rows_source_key
    ON sekai_dataset_version_rows (dataset_id, version_id, ((data::jsonb)->>'source_id'), row_id)
    WHERE dataset_id LIKE 'srcds:%';
