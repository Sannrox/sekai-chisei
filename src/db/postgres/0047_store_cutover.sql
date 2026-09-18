CREATE TABLE IF NOT EXISTS sekai_store_cutover (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    generation BIGINT NOT NULL,
    fence_raised INTEGER NOT NULL,
    raised_at_ms BIGINT NOT NULL
);
