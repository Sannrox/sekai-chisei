-- The budget idempotency key a reservation's current charge was made under,
-- so a refund finds the period it was charged in (#1902). Rows written
-- before this column keep '' and refund at their reservation time.
ALTER TABLE chisei_operation_reservations
    ADD COLUMN IF NOT EXISTS charge_key TEXT NOT NULL DEFAULT '';
