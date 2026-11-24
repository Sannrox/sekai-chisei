-- Agent-turn transcripts (#3045): what a turn did, appended by its worker
-- under the live claim. Separate from sekai_agent_turn, so acknowledging a
-- turn never rewrites its transcript. Additive.
CREATE TABLE IF NOT EXISTS sekai_agent_turn_transcript (
    turn_id TEXT PRIMARY KEY,
    usage_reported BOOLEAN NOT NULL DEFAULT FALSE,
    model_route TEXT NOT NULL DEFAULT '',
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    prompt_reference TEXT NOT NULL DEFAULT '',
    prompt_marking TEXT NOT NULL DEFAULT '',
    prompt_text TEXT,
    erased_at_ms BIGINT NOT NULL DEFAULT 0,
    updated_at_ms BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_agent_turn_step (
    turn_id TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    step_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    action_instance_id TEXT NOT NULL DEFAULT '',
    recorded_at_ms BIGINT NOT NULL,
    PRIMARY KEY (turn_id, sequence),
    UNIQUE (turn_id, step_id)
);
