-- Intents, proposed plans and their simulations (#1675). Additive: a
-- binary without these tables keeps working during a rolling deploy, and a
-- rollback leaves them unused.
CREATE TABLE IF NOT EXISTS sekai_plan_intents (
    namespace TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, intent_id)
);
CREATE TABLE IF NOT EXISTS sekai_plans (
    namespace TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, plan_id)
);
CREATE TABLE IF NOT EXISTS sekai_plan_simulations (
    namespace TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    simulation_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    simulated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, plan_id, simulation_id)
);
