-- Highest egress log sequence of each gateway Chisei has committed (#3096).
CREATE TABLE IF NOT EXISTS sekai_gateway_log_cursors (
    gateway TEXT PRIMARY KEY,
    seq BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
