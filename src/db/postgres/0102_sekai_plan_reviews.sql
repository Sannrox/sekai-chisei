-- One review per simulated plan (#1678). Additive: a binary without this
-- table keeps working during a rolling deploy, and a rollback leaves it
-- unused.
CREATE TABLE IF NOT EXISTS sekai_plan_reviews (
    namespace TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    decision TEXT NOT NULL DEFAULT '',
    body_json TEXT NOT NULL,
    submitted_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, plan_id)
);
