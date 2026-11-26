-- Dataset versions record changes (ADR 0172, #3475). A `copy` version keeps
-- its full row copy in sekai_dataset_version_rows; a `span` version's content
-- is every span live at its seq. This release reads both layouts and still
-- writes `copy`.
ALTER TABLE sekai_dataset_versions ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'snapshot';
ALTER TABLE sekai_dataset_versions ADD COLUMN IF NOT EXISTS layout TEXT NOT NULL DEFAULT 'copy';
CREATE TABLE IF NOT EXISTS sekai_dataset_row_spans (
    dataset_id TEXT NOT NULL,
    row_id BIGINT NOT NULL,
    from_seq BIGINT NOT NULL,
    to_seq BIGINT,
    data TEXT NOT NULL,
    partition_key TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (dataset_id, row_id, from_seq)
);
CREATE INDEX IF NOT EXISTS idx_dataset_row_spans_from
    ON sekai_dataset_row_spans (dataset_id, from_seq);
CREATE INDEX IF NOT EXISTS idx_dataset_row_spans_source_key
    ON sekai_dataset_row_spans (dataset_id, ((data::jsonb)->>'source_id'), row_id)
    WHERE dataset_id LIKE 'srcds:%';
-- The rows of every version, whichever layout holds them. Readers filter by
-- dataset_id and version_id; both branches take the filter.
CREATE OR REPLACE VIEW sekai_dataset_version_content AS
SELECT dataset_id, version_id, row_id, data, partition_key
FROM sekai_dataset_version_rows
UNION ALL
SELECT v.dataset_id, v.version_id, s.row_id, s.data, s.partition_key
FROM sekai_dataset_versions v
JOIN sekai_dataset_row_spans s
  ON s.dataset_id = v.dataset_id
 AND s.from_seq <= v.seq
 AND (s.to_seq IS NULL OR s.to_seq > v.seq)
WHERE v.layout = 'span' AND v.purged = 0;
