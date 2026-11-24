-- Export recovery seeks open receipts by lease expiry instead of scanning
-- every retained receipt (#2865). Partial, so closed receipts cost nothing;
-- the recovery query repeats `closed = 0`.
CREATE INDEX IF NOT EXISTS idx_sekai_export_receipts_recoverable
    ON sekai_export_receipts (lease_until_ms)
    WHERE closed = 0;
