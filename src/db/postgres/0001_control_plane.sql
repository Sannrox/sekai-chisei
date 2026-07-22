CREATE TABLE IF NOT EXISTS sekai_objects (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '', external_id TEXT NOT NULL DEFAULT '',
    properties TEXT NOT NULL DEFAULT '{}', created BIGINT NOT NULL, updated BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_objects_kind ON sekai_objects(kind);
CREATE INDEX IF NOT EXISTS idx_objects_external_id ON sekai_objects(external_id);

CREATE TABLE IF NOT EXISTS sekai_links (
    id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT NOT NULL,
    relation TEXT NOT NULL, created BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_links_from ON sekai_links(from_id, relation);
CREATE INDEX IF NOT EXISTS idx_links_to ON sekai_links(to_id, relation);

CREATE TABLE IF NOT EXISTS sekai_object_sets (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
    filter TEXT NOT NULL, owner_principal TEXT NOT NULL, created BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_object_sets_owner_name
    ON sekai_object_sets(owner_principal, name);

CREATE TABLE IF NOT EXISTS sekai_principal_credentials (
    id TEXT PRIMARY KEY, principal TEXT NOT NULL, token_hash TEXT NOT NULL,
    status TEXT NOT NULL, created BIGINT NOT NULL, rotated_at BIGINT NOT NULL DEFAULT 0,
    revoked_at BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_principal_credentials_token_hash
    ON sekai_principal_credentials(token_hash);
CREATE INDEX IF NOT EXISTS idx_sekai_principal_credentials_principal
    ON sekai_principal_credentials(principal);

CREATE TABLE IF NOT EXISTS sekai_grants (
    id TEXT PRIMARY KEY, object_id TEXT NOT NULL, principal TEXT NOT NULL,
    role TEXT NOT NULL, created BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_grants_object ON sekai_grants(object_id);

CREATE TABLE IF NOT EXISTS sekai_decisions (
    id TEXT PRIMARY KEY, timestamp BIGINT NOT NULL, actor TEXT NOT NULL,
    action TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '{}',
    target_id TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT '',
    seq BIGINT, prev_hash TEXT, entry_hash TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_seq ON sekai_decisions(seq);
CREATE INDEX IF NOT EXISTS idx_decisions_target ON sekai_decisions(target_id, timestamp);
CREATE TABLE IF NOT EXISTS sekai_object_changes (
    id TEXT PRIMARY KEY, object_id TEXT NOT NULL, field TEXT NOT NULL,
    old_value TEXT NOT NULL DEFAULT '', new_value TEXT NOT NULL DEFAULT '',
    changed_by TEXT NOT NULL DEFAULT '', timestamp BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changes_object ON sekai_object_changes(object_id);
CREATE TABLE IF NOT EXISTS sekai_ledger_anchors (
    seq BIGINT PRIMARY KEY, entry_hash TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '', created BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_attestations (
    id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, policy_kind TEXT NOT NULL,
    policy_scope TEXT NOT NULL DEFAULT '', policy_version TEXT NOT NULL,
    policy_snapshot TEXT NOT NULL, inputs TEXT NOT NULL DEFAULT '{}',
    decision TEXT NOT NULL, content_hash TEXT NOT NULL, created BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attestations_decision ON sekai_attestations(decision_id);
CREATE INDEX IF NOT EXISTS idx_attestations_scope ON sekai_attestations(policy_scope, created);

CREATE TABLE IF NOT EXISTS sekai_task_observations (
    request_id TEXT NOT NULL, namespace TEXT NOT NULL, component_id TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, timestamp BIGINT NOT NULL,
    packages_json TEXT NOT NULL DEFAULT '[]', context_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (request_id, component_id)
);
CREATE INDEX IF NOT EXISTS idx_task_observations_component_time
    ON sekai_task_observations(component_id, timestamp, request_id);
CREATE INDEX IF NOT EXISTS idx_task_observations_namespace_time
    ON sekai_task_observations(namespace, timestamp, request_id);
CREATE TABLE IF NOT EXISTS sekai_task_observation_baselines (
    component_id TEXT PRIMARY KEY, namespace TEXT NOT NULL, task_total BIGINT NOT NULL,
    task_succeeded BIGINT NOT NULL, consecutive_failures BIGINT NOT NULL, created BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sekai_object_types (
    kind TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '',
    properties_json TEXT NOT NULL DEFAULT '[]', implements_json TEXT NOT NULL DEFAULT '[]',
    created BIGINT NOT NULL, updated BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_interfaces (
    name TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '',
    properties_json TEXT NOT NULL DEFAULT '[]', created BIGINT NOT NULL, updated BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_action_types (
    name TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '',
    target_kind TEXT NOT NULL DEFAULT '', body_json TEXT NOT NULL,
    created BIGINT NOT NULL, updated BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sekai_contention_scopes (
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, parent_scope_id TEXT NOT NULL DEFAULT '',
    max_concurrency BIGINT NOT NULL, admission_policy TEXT NOT NULL DEFAULT 'fifo',
    heartbeat_ttl_seconds BIGINT NOT NULL DEFAULT 300, timeout_seconds BIGINT NOT NULL DEFAULT 0,
    owner_principal TEXT NOT NULL DEFAULT '', created BIGINT NOT NULL, updated BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_coordination_scopes_parent ON sekai_contention_scopes(parent_scope_id);
CREATE TABLE IF NOT EXISTS sekai_work_units (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, actor TEXT NOT NULL,
    target_object_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
    requested_spec TEXT NOT NULL DEFAULT '', scope_id TEXT NOT NULL,
    priority BIGINT NOT NULL DEFAULT 0, timeout_seconds BIGINT NOT NULL DEFAULT 0,
    heartbeat_ttl_seconds BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL,
    admitted_at BIGINT NOT NULL DEFAULT 0, started_at BIGINT NOT NULL DEFAULT 0,
    finished_at BIGINT NOT NULL DEFAULT 0, last_heartbeat_at BIGINT NOT NULL DEFAULT 0,
    failure_reason TEXT NOT NULL DEFAULT '', cancel_reason TEXT NOT NULL DEFAULT '',
    owner_principal TEXT NOT NULL DEFAULT '', creator_principal TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL DEFAULT '', updated_at BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_work_units_scope_status_created
    ON sekai_work_units(scope_id, status, created_at, id);
CREATE INDEX IF NOT EXISTS idx_work_units_target_created ON sekai_work_units(target_object_id, created_at);
CREATE INDEX IF NOT EXISTS idx_work_units_owner_created ON sekai_work_units(owner_principal, created_at);
CREATE INDEX IF NOT EXISTS idx_work_units_creator_created ON sekai_work_units(creator_principal, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_work_units_idempotency
    ON sekai_work_units(idempotency_key) WHERE idempotency_key != '';
CREATE TABLE IF NOT EXISTS sekai_reservations (
    id TEXT PRIMARY KEY, work_unit_id TEXT NOT NULL, scope_id TEXT NOT NULL,
    status TEXT NOT NULL, lease_owner TEXT NOT NULL DEFAULT '', leased_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL, released_at BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reservations_scope_status_leased
    ON sekai_reservations(scope_id, status, leased_at);
CREATE INDEX IF NOT EXISTS idx_reservations_work_unit_status
    ON sekai_reservations(work_unit_id, status);
CREATE INDEX IF NOT EXISTS idx_reservations_expiry_status
    ON sekai_reservations(expires_at, status);
CREATE TABLE IF NOT EXISTS sekai_run_events (
    id TEXT PRIMARY KEY, work_unit_id TEXT NOT NULL, event_type TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '', evidence_json TEXT NOT NULL DEFAULT '{}', created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_run_events_work_unit_created ON sekai_run_events(work_unit_id, created_at);
CREATE INDEX IF NOT EXISTS idx_run_events_type_created ON sekai_run_events(event_type, created_at);
CREATE TABLE IF NOT EXISTS sekai_reconciliations (
    id TEXT PRIMARY KEY, work_unit_id TEXT NOT NULL DEFAULT '', reservation_id TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL, action TEXT NOT NULL, created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reconciliations_work_unit_created
    ON sekai_reconciliations(work_unit_id, created_at);
CREATE INDEX IF NOT EXISTS idx_reconciliations_reservation_created
    ON sekai_reconciliations(reservation_id, created_at);
CREATE TABLE IF NOT EXISTS sekai_coordination_requests (
    request_id TEXT NOT NULL, operation TEXT NOT NULL, principal TEXT NOT NULL DEFAULT '',
    scope_id TEXT NOT NULL DEFAULT '', work_unit_id TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL, PRIMARY KEY (request_id, operation)
);

CREATE TABLE IF NOT EXISTS sekai_datasets (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, columns TEXT NOT NULL,
    object_id TEXT NOT NULL DEFAULT '', created BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_dataset_rows (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, dataset_id TEXT NOT NULL, data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dataset_rows ON sekai_dataset_rows(dataset_id);
CREATE TABLE IF NOT EXISTS sekai_virtual_tables (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, dataset_id TEXT NOT NULL,
    filters TEXT NOT NULL DEFAULT '[]', columns TEXT NOT NULL DEFAULT '[]', created BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_functions (
    name TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '', params TEXT NOT NULL DEFAULT '[]',
    pipeline TEXT NOT NULL DEFAULT '[]', created BIGINT NOT NULL
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
CREATE TABLE IF NOT EXISTS chisei_evolve_enhancements (
    request_id TEXT PRIMARY KEY, original_spec TEXT NOT NULL
);
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
