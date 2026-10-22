CREATE TABLE IF NOT EXISTS chisei_policy_shadow (
    namespace TEXT PRIMARY KEY,
    shadow_id TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    candidate_version TEXT NOT NULL,
    active_version TEXT NOT NULL,
    min_evaluations BIGINT NOT NULL,
    min_match_rate_bps BIGINT NOT NULL,
    started_by TEXT NOT NULL,
    started_at_ms BIGINT NOT NULL,
    evaluated BIGINT NOT NULL DEFAULT 0,
    unchanged BIGINT NOT NULL DEFAULT 0,
    re_routed BIGINT NOT NULL DEFAULT 0,
    would_deny BIGINT NOT NULL DEFAULT 0,
    would_allow BIGINT NOT NULL DEFAULT 0,
    activation_claimed_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS chisei_policy_shadow_by_run
    ON chisei_policy_shadow (shadow_id);
CREATE TABLE IF NOT EXISTS chisei_policy_shadow_sample (
    id BIGSERIAL PRIMARY KEY,
    shadow_id TEXT NOT NULL,
    delta TEXT NOT NULL,
    preferred_runtime TEXT NOT NULL,
    preferred_model TEXT NOT NULL,
    active TEXT NOT NULL,
    candidate TEXT NOT NULL,
    observed_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS chisei_policy_shadow_sample_by_class
    ON chisei_policy_shadow_sample (shadow_id, delta);
