-- Transform run receipts pin the dataset version each input was read at
-- (#1794). Additive: older binaries ignore the column, and older rows read
-- as no pins.
ALTER TABLE sekai_governed_transform_run
    ADD COLUMN IF NOT EXISTS input_versions TEXT NOT NULL DEFAULT '{}';
