CREATE TABLE IF NOT EXISTS sekai_namespace_object_generation (
    namespace TEXT PRIMARY KEY,
    generation BIGINT NOT NULL
);

CREATE OR REPLACE FUNCTION sekai_bump_namespace_object_generation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO sekai_namespace_object_generation (namespace, generation)
    VALUES (
        CASE WHEN TG_OP = 'DELETE' THEN OLD.namespace ELSE NEW.namespace END,
        1
    )
    ON CONFLICT (namespace) DO UPDATE
        SET generation = sekai_namespace_object_generation.generation + 1;
    IF TG_OP = 'UPDATE' AND OLD.namespace IS DISTINCT FROM NEW.namespace THEN
        INSERT INTO sekai_namespace_object_generation (namespace, generation)
        VALUES (OLD.namespace, 1)
        ON CONFLICT (namespace) DO UPDATE
            SET generation = sekai_namespace_object_generation.generation + 1;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_sekai_objects_namespace_generation ON sekai_objects;
CREATE TRIGGER trg_sekai_objects_namespace_generation
AFTER INSERT OR UPDATE OR DELETE ON sekai_objects
FOR EACH ROW EXECUTE FUNCTION sekai_bump_namespace_object_generation();

INSERT INTO sekai_namespace_object_generation (namespace, generation)
SELECT namespace, COUNT(*)::bigint
FROM sekai_objects
GROUP BY namespace
ON CONFLICT (namespace) DO NOTHING;
