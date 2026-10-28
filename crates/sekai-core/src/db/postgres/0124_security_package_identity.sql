-- Security package identities (#1923) are primary-key analogs: a finding per
-- problem signature, an occurrence per source occurrence id, and an exposure
-- per finding and deployed target are unique at commit, not by plan-time
-- find-then-insert. Hypotheses and other kinds are not covered.
DO $$
BEGIN
    IF EXISTS (
        SELECT namespace, external_id
        FROM sekai_objects
        WHERE kind IN ('security_finding', 'security_finding_occurrence', 'security_exposure')
          AND external_id <> ''
        GROUP BY namespace, external_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'duplicate security package identities block uniqueness migration',
            HINT = 'back up the database and resolve duplicate (namespace, external_id) security rows before retrying; no graph rows were changed';
    END IF;
END;
$$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_objects_security_identity
    ON sekai_objects(namespace, external_id)
    WHERE kind IN ('security_finding', 'security_finding_occurrence', 'security_exposure')
      AND external_id <> '';
