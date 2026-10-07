-- Chisei half of version 1, plus the shared decision ledger (#1240 / #1243).
CREATE TABLE IF NOT EXISTS sekai_decisions (
    id TEXT PRIMARY KEY, timestamp BIGINT NOT NULL, actor TEXT NOT NULL,
    action TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '{}',
    target_id TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT '',
    seq BIGINT, prev_hash TEXT, entry_hash TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_seq ON sekai_decisions(seq);
CREATE INDEX IF NOT EXISTS idx_decisions_target ON sekai_decisions(target_id, timestamp);
CREATE TABLE IF NOT EXISTS sekai_ledger_anchors (
    seq BIGINT PRIMARY KEY, entry_hash TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '', created BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS chisei_eval_suites (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, cases_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_eval_runs (
    id TEXT PRIMARY KEY, suite_id TEXT NOT NULL, config_ref TEXT NOT NULL,
    results_json TEXT NOT NULL, timestamp BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chisei_eval_runs_suite ON chisei_eval_runs(suite_id, timestamp);
CREATE TABLE IF NOT EXISTS chisei_eval_iterations (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, suite_id TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '', changed_file TEXT NOT NULL, diff_hash TEXT NOT NULL,
    parent_iteration_id TEXT NOT NULL, baseline_run_id TEXT NOT NULL,
    candidate_run_id TEXT NOT NULL, delta DOUBLE PRECISION NOT NULL,
    regressed BIGINT NOT NULL, created BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chisei_eval_iterations_suite
    ON chisei_eval_iterations(suite_id, created);
CREATE INDEX IF NOT EXISTS idx_chisei_eval_iterations_file
    ON chisei_eval_iterations(changed_file, created);
CREATE TABLE IF NOT EXISTS chisei_evolve_tasks (id TEXT PRIMARY KEY, task_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chisei_sample_observations (
    request_id TEXT PRIMARY KEY, namespace TEXT NOT NULL DEFAULT '', spec TEXT NOT NULL DEFAULT '',
    resolved_model TEXT NOT NULL DEFAULT '', output_content TEXT NOT NULL DEFAULT '',
    sample_reason TEXT NOT NULL DEFAULT '', input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0, stop_reason TEXT NOT NULL DEFAULT '',
    timestamp BIGINT NOT NULL, scored BIGINT NOT NULL DEFAULT 0, attempts BIGINT NOT NULL DEFAULT 0,
    task_class TEXT NOT NULL DEFAULT '', cost_usd_micros BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_chisei_sample_observations_scored
    ON chisei_sample_observations(scored, timestamp);

CREATE TABLE IF NOT EXISTS chisei_budget_limits (
    scope_id TEXT NOT NULL, metric TEXT NOT NULL DEFAULT 'tokens',
    parent_scope_id TEXT NOT NULL DEFAULT '', max_amount BIGINT NOT NULL,
    period_type TEXT NOT NULL, PRIMARY KEY (scope_id, metric)
);
CREATE TABLE IF NOT EXISTS chisei_budget_usage (
    scope_id TEXT NOT NULL, metric TEXT NOT NULL DEFAULT 'tokens', period_start BIGINT NOT NULL,
    amount_used BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (scope_id, metric, period_start)
);
CREATE TABLE IF NOT EXISTS chisei_portfolio_observations (
    namespace TEXT NOT NULL, task_class TEXT NOT NULL, model TEXT NOT NULL,
    prompt_variant TEXT NOT NULL DEFAULT 'legacy@1',
    quality_score DOUBLE PRECISION NOT NULL, cost_usd_micros BIGINT NOT NULL,
    sample_count BIGINT NOT NULL, updated_at BIGINT NOT NULL,
    PRIMARY KEY (namespace, task_class, model, prompt_variant)
);
CREATE INDEX IF NOT EXISTS idx_chisei_portfolio_frontier
    ON chisei_portfolio_observations(namespace, task_class, cost_usd_micros);
CREATE TABLE IF NOT EXISTS chisei_portfolio_objectives (
    namespace TEXT PRIMARY KEY, mode TEXT NOT NULL, budget_usd_micros BIGINT NOT NULL,
    quality_bar DOUBLE PRECISION NOT NULL, min_samples BIGINT NOT NULL, updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_portfolio_routes (
    namespace TEXT NOT NULL, task_class TEXT NOT NULL, current_model TEXT NOT NULL,
    current_prompt_variant TEXT NOT NULL DEFAULT 'legacy@1',
    pending_model TEXT NOT NULL DEFAULT '', pending_count BIGINT NOT NULL DEFAULT 0,
    pending_prompt_variant TEXT NOT NULL DEFAULT '',
    shifted_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
    PRIMARY KEY (namespace, task_class)
);
