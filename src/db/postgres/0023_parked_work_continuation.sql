-- Governed, generation-fenced continuation for parked runtime work.

CREATE TABLE IF NOT EXISTS sekai_action_work_parks (
    park_id TEXT PRIMARY KEY,
    effect_id TEXT NOT NULL REFERENCES sekai_action_effects(effect_id),
    park_generation BIGINT NOT NULL,
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    UNIQUE(effect_id, park_generation),
    UNIQUE(effect_id, request_id)
);

CREATE TABLE IF NOT EXISTS sekai_parked_resolution_inputs (
    resolution_input_id TEXT PRIMARY KEY,
    effect_id TEXT NOT NULL REFERENCES sekai_action_effects(effect_id),
    park_generation BIGINT NOT NULL,
    body_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sekai_parked_resolution_actions (
    resolution_action_id TEXT PRIMARY KEY,
    effect_id TEXT NOT NULL REFERENCES sekai_action_effects(effect_id),
    park_generation BIGINT NOT NULL,
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    body_json TEXT NOT NULL,
    UNIQUE(effect_id, request_id)
);

CREATE TABLE IF NOT EXISTS sekai_action_work_continuations (
    resolution_id TEXT PRIMARY KEY,
    effect_id TEXT NOT NULL REFERENCES sekai_action_effects(effect_id),
    park_generation BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    UNIQUE(effect_id, park_generation)
);

CREATE TABLE IF NOT EXISTS sekai_action_claim_events (
    effect_id TEXT NOT NULL REFERENCES sekai_action_effects(effect_id),
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    PRIMARY KEY(effect_id, request_id)
);
