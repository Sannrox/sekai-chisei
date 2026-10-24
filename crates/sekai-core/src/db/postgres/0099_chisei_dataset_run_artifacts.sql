-- The released artifact an eval dataset run evaluates (#1677), bound once.
-- Kept apart from the run's spec_json so readers of that format are
-- unchanged across a rolling deploy.
CREATE TABLE IF NOT EXISTS chisei_dataset_run_artifacts (
    namespace TEXT NOT NULL,
    run_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    PRIMARY KEY (namespace, run_id)
);
