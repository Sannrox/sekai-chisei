-- Bounded runtime-scoped pressure metadata for typed action effects.
--
-- PostgreSQL jsonb rejects JSON strings containing \u0000. Store the
-- compatibility decision at write/migration time so pressure reads never
-- scan or parse the complete namespace history just to detect legacy rows.

ALTER TABLE sekai_action_effects
    ADD COLUMN IF NOT EXISTS pressure_runtime TEXT NOT NULL DEFAULT 'default';

ALTER TABLE sekai_action_effects
    ADD COLUMN IF NOT EXISTS pressure_jsonb_compatible BOOLEAN NOT NULL DEFAULT TRUE;

-- Backfill legacy rows once. Invalid JSONB (including JSON strings containing
-- \u0000) is fail-closed and remains visible to pressure reads through the
-- indexed compatibility flag.
DO $pressure_metadata$
DECLARE
    effect_row RECORD;
    payload JSONB;
    effect_body JSONB;
    runtime TEXT;
BEGIN
    FOR effect_row IN
        SELECT effect_id, payload_json, body_json
        FROM sekai_action_effects
    LOOP
        BEGIN
            payload := effect_row.payload_json::jsonb;
            effect_body := effect_row.body_json::jsonb;
            IF jsonb_typeof(payload -> 'runtime') = 'string'
               AND btrim(
                   payload ->> 'runtime',
                   ' ' || chr(9) || chr(10) || chr(11) || chr(12) || chr(13)
               ) <> ''
            THEN
                runtime := payload ->> 'runtime';
            ELSE
                runtime := 'default';
            END IF;
            UPDATE sekai_action_effects
            SET payload_json = payload::text,
                body_json = jsonb_set(
                    effect_body,
                    '{payload_json}',
                    to_jsonb(payload::text)
                )::text,
                pressure_runtime = runtime,
                pressure_jsonb_compatible = TRUE
            WHERE effect_id = effect_row.effect_id;
        EXCEPTION WHEN others THEN
            UPDATE sekai_action_effects
            SET pressure_runtime = 'invalid',
                pressure_jsonb_compatible = FALSE
            WHERE effect_id = effect_row.effect_id;
        END;
    END LOOP;
END
$pressure_metadata$;

-- Keep metadata correct while pre-migration replicas are still allowed to
-- write the old column set. The trigger owns the derived values even when an
-- older writer omits both pressure columns.
CREATE OR REPLACE FUNCTION sekai_action_effects_pressure_metadata()
RETURNS trigger
LANGUAGE plpgsql
AS $pressure_trigger$
DECLARE
    payload JSONB;
    effect_body JSONB;
    runtime TEXT;
BEGIN
    BEGIN
        payload := NEW.payload_json::jsonb;
        effect_body := NEW.body_json::jsonb;
        IF jsonb_typeof(payload -> 'runtime') = 'string'
           AND btrim(
               payload ->> 'runtime',
               ' ' || chr(9) || chr(10) || chr(11) || chr(12) || chr(13)
           ) <> ''
        THEN
            runtime := payload ->> 'runtime';
        ELSE
            runtime := 'default';
        END IF;
        -- JSONB's canonical text form removes duplicate object keys while
        -- preserving its last-value semantics. Keep the denormalized body in
        -- lockstep so a later lifecycle write cannot reintroduce raw keys.
        NEW.payload_json := payload::text;
        NEW.body_json := jsonb_set(
            effect_body,
            '{payload_json}',
            to_jsonb(payload::text)
        )::text;
        NEW.pressure_runtime := runtime;
        NEW.pressure_jsonb_compatible := TRUE;
    EXCEPTION WHEN others THEN
        NEW.pressure_runtime := 'invalid';
        NEW.pressure_jsonb_compatible := FALSE;
    END;
    RETURN NEW;
END
$pressure_trigger$;

DROP TRIGGER IF EXISTS trg_action_effects_pressure_metadata ON sekai_action_effects;
CREATE TRIGGER trg_action_effects_pressure_metadata
    BEFORE INSERT OR UPDATE ON sekai_action_effects
    FOR EACH ROW
    EXECUTE FUNCTION sekai_action_effects_pressure_metadata();

-- Narrow runtime-scoped pressure polls before evaluating aggregate state. The
-- prefix keeps the index key bounded for arbitrary runtime identifiers; the
-- read query performs an exact recheck after the prefix match.
CREATE INDEX IF NOT EXISTS idx_action_effects_pressure_runtime_prefix
    ON sekai_action_effects(
        namespace,
        kind,
        left(pressure_runtime, 128),
        created_at_ms
    );

CREATE INDEX IF NOT EXISTS idx_action_effects_pressure_compatibility
    ON sekai_action_effects(namespace, kind, pressure_jsonb_compatible);
