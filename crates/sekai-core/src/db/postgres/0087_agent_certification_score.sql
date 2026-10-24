ALTER TABLE sekai_agent_definition_certifications
    ADD COLUMN IF NOT EXISTS mean_score_milli BIGINT;
