-- Chisei decision/execution durable tables missing from earlier control-plane
-- migrations: operation receipts, gateway aliases, budget idempotency events,
-- learning (kioku), and external-action governance.
-- Tenant, OIDC, and OAuth surfaces remain absent.

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

CREATE TABLE IF NOT EXISTS chisei_gateway_request_aliases (
    caller_scope TEXT NOT NULL,
    request_alias TEXT NOT NULL,
    request_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    reserved_at BIGINT NOT NULL,
    dispatch_started BIGINT NOT NULL DEFAULT 0,
    dispatch_token TEXT,
    PRIMARY KEY (caller_scope, request_alias)
);

CREATE TABLE IF NOT EXISTS chisei_budget_usage_events (
    idempotency_key TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    amount BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS chisei_budget_attributions (
    source_scope_id TEXT NOT NULL,
    applied_scope_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    period_start BIGINT NOT NULL,
    amount_used BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (source_scope_id, applied_scope_id, metric, period_start)
);

CREATE TABLE IF NOT EXISTS chisei_kioku_memories (
    id TEXT NOT NULL,
    version BIGINT NOT NULL,
    namespace TEXT NOT NULL,
    state TEXT NOT NULL,
    classification TEXT NOT NULL,
    expires_at_ms BIGINT,
    memory_json TEXT NOT NULL,
    PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS idx_kioku_memory_retrieval
    ON chisei_kioku_memories(namespace, state, expires_at_ms);

CREATE TABLE IF NOT EXISTS chisei_kioku_evidence_links (
    memory_id TEXT NOT NULL,
    memory_version BIGINT NOT NULL,
    operation_id TEXT NOT NULL,
    stance TEXT NOT NULL,
    link_json TEXT NOT NULL,
    PRIMARY KEY (memory_id, memory_version, operation_id),
    FOREIGN KEY (memory_id, memory_version)
        REFERENCES chisei_kioku_memories(id, version)
);
CREATE INDEX IF NOT EXISTS idx_kioku_evidence_operation
    ON chisei_kioku_evidence_links(operation_id);

CREATE TABLE IF NOT EXISTS chisei_kioku_lifecycle_events (
    id BIGSERIAL PRIMARY KEY,
    memory_id TEXT NOT NULL,
    memory_version BIGINT NOT NULL,
    action TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    recorded_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kioku_lifecycle_memory
    ON chisei_kioku_lifecycle_events(memory_id, memory_version, id);

CREATE TABLE IF NOT EXISTS chisei_kioku_outcomes (
    memory_id TEXT NOT NULL,
    memory_version BIGINT NOT NULL,
    operation_id TEXT NOT NULL,
    memory_applied BIGINT NOT NULL,
    outcome_metric TEXT NOT NULL,
    outcome_value DOUBLE PRECISION NOT NULL,
    passed BIGINT NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    PRIMARY KEY (memory_id, memory_version, operation_id),
    FOREIGN KEY (memory_id, memory_version)
        REFERENCES chisei_kioku_memories(id, version)
);
CREATE INDEX IF NOT EXISTS idx_kioku_outcome_comparison
    ON chisei_kioku_outcomes(memory_id, memory_version, memory_applied);

CREATE TABLE IF NOT EXISTS chisei_external_action_reservations (
    actor TEXT NOT NULL,
    namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    mutations BIGINT NOT NULL,
    deletes BIGINT NOT NULL,
    PRIMARY KEY (actor, namespace, operation_id)
);

CREATE TABLE IF NOT EXISTS chisei_external_action_authorizations (
    actor TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    authorization_id TEXT NOT NULL UNIQUE,
    record_json TEXT,
    claimed_at_ms BIGINT NOT NULL,
    PRIMARY KEY (actor, operation_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS chisei_external_action_releases (
    authorization_id TEXT PRIMARY KEY,
    released_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS chisei_external_action_blast_claims (
    authorization_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    mutations BIGINT NOT NULL,
    deletes BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS chisei_external_action_permits (
    permit_id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL UNIQUE,
    issuance_idempotency_key TEXT NOT NULL,
    permit_json TEXT NOT NULL,
    issued_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS chisei_external_action_redemptions (
    permit_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    redemption_json TEXT NOT NULL,
    redeemed_at_ms BIGINT NOT NULL,
    invocation_ordinal BIGINT NOT NULL,
    redemption_id TEXT,
    evidence_due_at_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (permit_id, idempotency_key),
    UNIQUE (permit_id, execution_id),
    UNIQUE (permit_id, invocation_ordinal)
);

CREATE TABLE IF NOT EXISTS chisei_external_action_revocations (
    revocation_handle TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    revoked_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS chisei_external_action_kill_switches (
    scope_kind TEXT NOT NULL,
    scope_value TEXT NOT NULL,
    reason TEXT NOT NULL,
    enabled_at_ms BIGINT NOT NULL,
    PRIMARY KEY (scope_kind, scope_value)
);

CREATE TABLE IF NOT EXISTS chisei_external_action_delegated_permits (
    permit_id TEXT PRIMARY KEY,
    parent_permit_id TEXT NOT NULL,
    permit_json TEXT NOT NULL,
    issued_at_ms BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_external_action_one_child_per_parent
    ON chisei_external_action_delegated_permits(parent_permit_id);

CREATE TABLE IF NOT EXISTS chisei_external_permit_policies (
    scope TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
