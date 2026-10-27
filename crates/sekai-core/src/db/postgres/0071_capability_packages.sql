CREATE TABLE IF NOT EXISTS sekai_capability_packages (
    namespace TEXT NOT NULL,
    certification_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, certification_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS sekai_capability_packages_live_identity
ON sekai_capability_packages (
    namespace,
    ((record_json::jsonb) ->> 'package_id')
)
WHERE ((record_json::jsonb) ->> 'superseded_by') = ''
  AND ((record_json::jsonb) ->> 'revocation') = '';
