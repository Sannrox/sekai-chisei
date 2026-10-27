CREATE TABLE IF NOT EXISTS sekai_dataset_health_checks (
    dataset_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    max_age_ms BIGINT NOT NULL DEFAULT 0,
    min_rows INTEGER NOT NULL DEFAULT 0,
    max_rows INTEGER NOT NULL DEFAULT 0,
    columns TEXT NOT NULL DEFAULT '[]',
    predicate TEXT NOT NULL DEFAULT '[]',
    blocking INTEGER NOT NULL DEFAULT 0,
    every_ms BIGINT NOT NULL DEFAULT 0,
    tenant TEXT NOT NULL DEFAULT '',
    space TEXT NOT NULL DEFAULT '',
    last_run_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (dataset_id, check_id)
);
CREATE TABLE IF NOT EXISTS sekai_dataset_health_results (
    dataset_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    passed INTEGER NOT NULL,
    detail TEXT NOT NULL,
    judged_at_ms BIGINT NOT NULL,
    quarantined INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (dataset_id, version_id, check_id)
);
CREATE TABLE IF NOT EXISTS sekai_dataset_health_state (
    dataset_id TEXT PRIMARY KEY,
    last_healthy_version_id TEXT NOT NULL DEFAULT '',
    quarantined INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sekai_dataset_alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    space TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    state TEXT NOT NULL,
    emitted_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sekai_dataset_alerts_dataset
    ON sekai_dataset_alerts(dataset_id, emitted_at_ms);
