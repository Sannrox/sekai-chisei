ALTER TABLE chisei_portfolio_observations
    ADD COLUMN IF NOT EXISTS prompt_variant TEXT NOT NULL DEFAULT 'legacy@1';

DO $$
DECLARE primary_key_name TEXT;
BEGIN
    SELECT constraint_name INTO primary_key_name
    FROM information_schema.table_constraints
    WHERE table_schema = current_schema()
      AND table_name = 'chisei_portfolio_observations'
      AND constraint_type = 'PRIMARY KEY';
    IF primary_key_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE chisei_portfolio_observations DROP CONSTRAINT %I', primary_key_name);
    END IF;
END $$;

ALTER TABLE chisei_portfolio_observations
    ADD PRIMARY KEY (namespace, task_class, model, prompt_variant);

ALTER TABLE chisei_portfolio_routes
    ADD COLUMN IF NOT EXISTS current_prompt_variant TEXT NOT NULL DEFAULT 'legacy@1';
ALTER TABLE chisei_portfolio_routes
    ADD COLUMN IF NOT EXISTS pending_prompt_variant TEXT NOT NULL DEFAULT '';
