-- #3044 (ADR 0168 part 1c): the quota mode of an assignment, per limit row.
-- An older plane never reads it and enforces.
ALTER TABLE chisei_budget_limits ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'enforce';
