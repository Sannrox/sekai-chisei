-- Ontology health snapshots, one per namespace and window, and the threshold
-- events written with them (#1694).

CREATE TABLE IF NOT EXISTS sekai_ontology_health_snapshots (
    namespace TEXT NOT NULL,
    window_start_ms BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    PRIMARY KEY (namespace, window_start_ms)
);

CREATE TABLE IF NOT EXISTS sekai_ontology_health_events (
    namespace TEXT NOT NULL,
    window_start_ms BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    PRIMARY KEY (namespace, window_start_ms)
);
