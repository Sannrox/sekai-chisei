CREATE TABLE IF NOT EXISTS sekai_client_packages (
    namespace TEXT NOT NULL,
    package_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, package_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS sekai_client_packages_live_identity
ON sekai_client_packages (
    namespace,
    ((record_json::jsonb) ->> 'language'),
    ((record_json::jsonb) ->> 'package_name')
)
WHERE ((record_json::jsonb) ->> 'superseded_by') = '';
