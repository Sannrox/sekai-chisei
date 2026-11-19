CREATE TABLE IF NOT EXISTS sekai_model_stages (
    namespace TEXT NOT NULL,
    model_name TEXT NOT NULL,
    stage TEXT NOT NULL,
    evaluation_suite_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, model_name, stage)
);
