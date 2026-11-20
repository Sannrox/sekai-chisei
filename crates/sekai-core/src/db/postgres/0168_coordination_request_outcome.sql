-- Original try_admit_work_unit outcome on the request dedup row so a replay
-- returns that result after the unit leaves pending (#2745). NULL admitted
-- is a row written before this column: replay uses current unit status.
ALTER TABLE sekai_coordination_requests
    ADD COLUMN IF NOT EXISTS admitted INTEGER;
ALTER TABLE sekai_coordination_requests
    ADD COLUMN IF NOT EXISTS queue_position INTEGER;
ALTER TABLE sekai_coordination_requests
    ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';
ALTER TABLE sekai_coordination_requests
    ADD COLUMN IF NOT EXISTS lease_owner TEXT NOT NULL DEFAULT '';
