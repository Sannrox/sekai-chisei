-- Partial expression index for reclaiming expired reserved authorizations.
CREATE INDEX IF NOT EXISTS idx_chisei_ext_auth_reclaim
ON chisei_external_action_authorizations (
    ((record_json::jsonb #>> '{decision,expires_at_ms}')::bigint)
)
WHERE COALESCE((record_json::jsonb ->> 'budget_reserved')::boolean, false)
   OR COALESCE((record_json::jsonb ->> 'blast_radius_reserved')::boolean, false);
