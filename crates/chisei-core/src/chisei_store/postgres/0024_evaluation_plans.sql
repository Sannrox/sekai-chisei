CREATE TABLE IF NOT EXISTS chisei_evaluator_definitions (
    definition_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    evaluator_id TEXT NOT NULL,
    version TEXT NOT NULL,
    implementation_digest TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    UNIQUE(namespace, evaluator_id, version)
);
CREATE INDEX IF NOT EXISTS idx_chisei_evaluator_definitions_namespace
    ON chisei_evaluator_definitions(namespace, evaluator_id, version);

CREATE TABLE IF NOT EXISTS chisei_evaluator_availability (
    definition_id TEXT PRIMARY KEY REFERENCES chisei_evaluator_definitions(definition_id),
    state TEXT NOT NULL,
    body_json TEXT NOT NULL,
    changed_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS chisei_evaluator_availability_events (
    definition_id TEXT NOT NULL REFERENCES chisei_evaluator_definitions(definition_id),
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    changed_at_ms BIGINT NOT NULL,
    PRIMARY KEY(definition_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_chisei_evaluator_availability_events_time
    ON chisei_evaluator_availability_events(definition_id, changed_at_ms);

CREATE TABLE IF NOT EXISTS chisei_evaluation_plans (
    plan_version_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    version TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    UNIQUE(namespace, plan_id, version)
);
CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_plans_namespace
    ON chisei_evaluation_plans(namespace, plan_id, version);
