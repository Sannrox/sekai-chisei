CREATE TABLE IF NOT EXISTS chisei_dataset_runs (
    namespace TEXT NOT NULL,
    run_id TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    lease_holder TEXT NOT NULL DEFAULT '',
    lease_until_ms BIGINT NOT NULL DEFAULT 0,
    uncertain_micros BIGINT NOT NULL DEFAULT 0,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, run_id)
);

CREATE TABLE IF NOT EXISTS chisei_dataset_run_cases (
    namespace TEXT NOT NULL,
    run_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    cost_micros BIGINT NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, run_id, case_id)
);
