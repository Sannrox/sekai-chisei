-- Change-wake cursors of site agent instances (#1952, ADR 0137): the object
-- mutation sequence each change token has read up to, and the change id at
-- that sequence. Additive.
CREATE TABLE IF NOT EXISTS sekai_agent_wake_cursor (
    instance_id TEXT NOT NULL,
    token TEXT NOT NULL,
    after_seq BIGINT NOT NULL,
    change_id TEXT NOT NULL,
    PRIMARY KEY (instance_id, token)
);
