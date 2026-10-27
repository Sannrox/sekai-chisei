CREATE TABLE IF NOT EXISTS sekai_streaming_transform_apply (
    run_id TEXT NOT NULL,
    checkpoint TEXT NOT NULL,
    claim_generation BIGINT NOT NULL,
    transform_version TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (run_id, checkpoint)
);
