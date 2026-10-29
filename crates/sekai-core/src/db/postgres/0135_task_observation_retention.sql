-- Policy-driven retention of task observations on PostgreSQL (#1984,
-- ADR 0141), as on SQLite: a policy may name a data class, and an expired
-- observation of a component that still has retained ones is redacted in
-- place and marked so it is never archived twice. Additive: older binaries
-- neither read nor write these columns.
ALTER TABLE sekai_task_observations
    ADD COLUMN IF NOT EXISTS data_class TEXT NOT NULL DEFAULT 'unclassified',
    ADD COLUMN IF NOT EXISTS retention_tombstone BOOLEAN NOT NULL DEFAULT FALSE;
