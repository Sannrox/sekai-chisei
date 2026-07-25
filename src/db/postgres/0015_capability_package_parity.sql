-- Capability-package lifecycle persistence for the reusable shared graph.
-- Manifest versions and lifecycle events are retained after uninstall.
-- Identity providers, decision engines, proxies, and runtime activation are absent.

CREATE TABLE IF NOT EXISTS sekai_capability_package_versions (
    namespace TEXT NOT NULL,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, package_name, package_version)
);

CREATE TABLE IF NOT EXISTS sekai_capability_package_installations (
    namespace TEXT NOT NULL,
    package_name TEXT NOT NULL,
    current_version TEXT NOT NULL,
    previous_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active', 'disabled')),
    installed_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    installed_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, package_name)
);

CREATE TABLE IF NOT EXISTS sekai_capability_package_events (
    sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace TEXT NOT NULL,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    evidence TEXT NOT NULL,
    result_json TEXT NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    UNIQUE(namespace, actor, request_id)
);
CREATE INDEX IF NOT EXISTS idx_capability_package_events_lookup
    ON sekai_capability_package_events(namespace, package_name, sequence);
