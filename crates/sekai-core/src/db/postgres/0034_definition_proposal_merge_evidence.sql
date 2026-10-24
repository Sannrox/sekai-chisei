ALTER TABLE sekai_definition_proposals
    ADD COLUMN IF NOT EXISTS receipt_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sekai_definition_proposals
    ADD COLUMN IF NOT EXISTS close_reason_code TEXT NOT NULL DEFAULT '';
