-- Tenant-free action policy, approval, and blast-radius persistence.
CREATE TABLE IF NOT EXISTS sekai_action_policies (
    scope TEXT PRIMARY KEY,
    properties_json TEXT NOT NULL,
    created BIGINT NOT NULL,
    updated BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sekai_action_approvals (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    properties_json TEXT NOT NULL,
    created BIGINT NOT NULL,
    updated BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_approvals_status_order
    ON sekai_action_approvals(status, created DESC, id);

CREATE TABLE IF NOT EXISTS sekai_action_blast_radius (
    work_unit TEXT PRIMARY KEY,
    mutations BIGINT NOT NULL CHECK (mutations >= 0),
    deletes BIGINT NOT NULL CHECK (deletes >= 0),
    updated BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sekai_action_governance_audit (
    audit_seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    operation TEXT NOT NULL,
    target_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    outcome TEXT NOT NULL,
    created BIGINT NOT NULL
);
