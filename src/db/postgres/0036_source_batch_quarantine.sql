-- Retain schema-incompatible source batches as inspectable quarantine
-- results without advancing the checkpoint.
ALTER TABLE sekai_source_batch_transactions
    DROP CONSTRAINT IF EXISTS sekai_source_batch_transactions_status_check;
ALTER TABLE sekai_source_batch_transactions
    ADD CONSTRAINT sekai_source_batch_transactions_status_check
    CHECK (status IN ('OPEN', 'COMMITTED', 'ABORTED', 'QUARANTINED'));
