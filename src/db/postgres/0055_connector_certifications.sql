-- Connector certifications (ADR 0055), as on SQLite (#1481). At most one
-- live (not superseded, not revoked) certification per connector and namespace.
CREATE TABLE IF NOT EXISTS sekai_connector_certifications (
    namespace TEXT NOT NULL,
    certification_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY(namespace, certification_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS sekai_connector_certifications_live_identity
ON sekai_connector_certifications(namespace, ((record_json::jsonb) ->> 'connector_id'))
WHERE (record_json::jsonb) ->> 'superseded_by' = ''
  AND (record_json::jsonb) ->> 'revocation' = '';
