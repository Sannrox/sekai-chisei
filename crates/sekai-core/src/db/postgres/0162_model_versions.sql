CREATE TABLE IF NOT EXISTS sekai_model_versions (
    version_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    model_name TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sekai_model_versions_name
    ON sekai_model_versions (namespace, model_name, version_id);
