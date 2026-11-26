-- Series reads (#3472, ADR 0171) scan one series of a samples dataset by
-- time. Partial, so only rows with a series id pay for the entry.
-- `sekai_jsonb_object` (0032) is NULL for malformed JSON and the timestamp is
-- NULL unless it is an integer, so no row of any dataset fails to index;
-- queries repeat both expressions exactly.
CREATE INDEX IF NOT EXISTS idx_dataset_rows_series
    ON sekai_dataset_rows (
        dataset_id,
        (sekai_jsonb_object(data)->>'series_id'),
        (CASE WHEN sekai_jsonb_object(data)->>'timestamp' ~ '^-?[0-9]{1,18}$'
           THEN (sekai_jsonb_object(data)->>'timestamp')::bigint END),
        id
    )
    WHERE (sekai_jsonb_object(data)->>'series_id') IS NOT NULL;
