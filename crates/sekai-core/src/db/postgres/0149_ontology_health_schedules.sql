-- Ontology health schedules (#2192): one per namespace, a member of the
-- transform schedule graph. Additive: an older binary neither reads nor
-- writes it, and keeps recording on demand into the same snapshot table.
CREATE TABLE IF NOT EXISTS sekai_ontology_health_schedules (
    namespace TEXT PRIMARY KEY,
    window_ms BIGINT NOT NULL,
    retention_ms BIGINT NOT NULL,
    threshold BIGINT NOT NULL,
    recorded_by TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    last_window_start_ms BIGINT NOT NULL,
    last_error TEXT NOT NULL
);
