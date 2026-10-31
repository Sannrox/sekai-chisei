-- Security remediations and mitigations (#1669): one plan per exposure and
-- catalogue contents, and one applied control per plan entry, unique at
-- commit. New kinds, so no existing row can conflict.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_objects_security_remediation_identity
    ON sekai_objects(namespace, external_id)
    WHERE kind IN ('security_remediation', 'security_mitigation')
      AND external_id <> '';
