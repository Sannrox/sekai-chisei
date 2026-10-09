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

CREATE TABLE IF NOT EXISTS sekai_principal_credentials (
    id TEXT PRIMARY KEY, principal TEXT NOT NULL, token_hash TEXT NOT NULL,
    status TEXT NOT NULL, created BIGINT NOT NULL, rotated_at BIGINT NOT NULL DEFAULT 0,
    revoked_at BIGINT NOT NULL DEFAULT 0, tenant_id TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_principal_credentials_token_hash
    ON sekai_principal_credentials(token_hash);
CREATE INDEX IF NOT EXISTS idx_sekai_principal_credentials_principal
    ON sekai_principal_credentials(principal);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_principal_credentials_active_tenant
    ON sekai_principal_credentials(tenant_id, principal)
    WHERE tenant_id <> '' AND status = 'active';

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

-- Per-store receipt table: Combined Split writes plane-local admission
-- receipts onto the Sekai destination. Ownership stays Chisei so leftover
-- populated rows still refuse as missed relocation. Fresh Sekai-only skips
-- v16 (Chisei-owned), so this CREATE lives in the Sekai half of v1.
CREATE TABLE IF NOT EXISTS chisei_operation_receipts (
    operation_id TEXT PRIMARY KEY,
    request_id TEXT,
    lookup_request_id TEXT,
    initiating_actor TEXT,
    caller_scope TEXT,
    alias_retired BIGINT NOT NULL DEFAULT 0,
    namespace TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chisei_operation_receipts_namespace
    ON chisei_operation_receipts(namespace, updated_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_request
    ON chisei_operation_receipts(request_id) WHERE request_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_lookup
    ON chisei_operation_receipts(caller_scope, lookup_request_id)
    WHERE lookup_request_id IS NOT NULL AND alias_retired = 0;
