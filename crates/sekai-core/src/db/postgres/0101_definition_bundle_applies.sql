-- Durable, resumable apply records of definition change bundles (#1693).
-- One per proposal; every write is a compare-and-swap on revision.
CREATE TABLE IF NOT EXISTS sekai_definition_bundle_applies (
    namespace TEXT NOT NULL,
    proposal_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    revision BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, proposal_id)
);
