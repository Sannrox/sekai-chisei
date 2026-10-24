-- Execution progress of an approved plan (#1679), one row per plan. The
-- revision fences concurrent executors. Additive: a binary without this
-- table keeps working during a rolling deploy, and a rollback leaves it
-- unused.
CREATE TABLE IF NOT EXISTS sekai_plan_executions (
    namespace TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, plan_id)
);
