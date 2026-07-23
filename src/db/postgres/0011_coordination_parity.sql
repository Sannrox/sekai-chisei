-- Coordination is deliberately reusable Sekai state. This migration adds
-- integrity and lock-friendly indexes without activating the PostgreSQL
-- runtime backend or adding tenant/Chisei concepts.

ALTER TABLE sekai_contention_scopes
    DROP CONSTRAINT IF EXISTS sekai_contention_scopes_positive_concurrency;
ALTER TABLE sekai_contention_scopes
    ADD CONSTRAINT sekai_contention_scopes_positive_concurrency
    CHECK (max_concurrency >= 1) NOT VALID;

ALTER TABLE sekai_reservations
    DROP CONSTRAINT IF EXISTS sekai_reservations_status_check;
ALTER TABLE sekai_reservations
    ADD CONSTRAINT sekai_reservations_status_check
    CHECK (status IN ('active', 'released')) NOT VALID;

CREATE INDEX IF NOT EXISTS idx_work_units_pending_fifo
    ON sekai_work_units(created_at, id)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_reservations_active_scope
    ON sekai_reservations(scope_id, expires_at, work_unit_id)
    WHERE status = 'active' AND released_at = 0;
CREATE INDEX IF NOT EXISTS idx_coordination_requests_work_unit
    ON sekai_coordination_requests(work_unit_id, created_at)
    WHERE work_unit_id <> '';
