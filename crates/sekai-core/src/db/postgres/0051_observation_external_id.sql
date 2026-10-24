-- Observation identity is a primary-key analog: unique at commit, not a
-- plan-time find-then-insert. Empty external_id stays allowed on other kinds.
DO $$
BEGIN
    IF EXISTS (
        SELECT namespace, external_id
        FROM sekai_objects
        WHERE kind = 'feedback_observation' AND external_id <> ''
        GROUP BY namespace, external_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'duplicate observation external identities block uniqueness migration',
            HINT = 'back up the database and resolve duplicate (namespace, external_id) observation rows before retrying; no graph rows were changed';
    END IF;
END;
$$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_objects_observation_external_id
    ON sekai_objects(namespace, external_id)
    WHERE kind = 'feedback_observation' AND external_id <> '';
