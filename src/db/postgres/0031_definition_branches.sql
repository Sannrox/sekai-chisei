CREATE TABLE IF NOT EXISTS sekai_definition_members (
    namespace TEXT NOT NULL,
    member_digest TEXT NOT NULL,
    member_kind TEXT NOT NULL,
    member_id TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    body_json TEXT NOT NULL,
    PRIMARY KEY(namespace, member_digest)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_definition_member_identity_content
    ON sekai_definition_members(namespace, member_kind, member_id, member_digest);

CREATE TABLE IF NOT EXISTS sekai_definition_revisions (
    namespace TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    parent_revision_digest TEXT NOT NULL,
    published BOOLEAN NOT NULL,
    body_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, revision_digest)
);
CREATE INDEX IF NOT EXISTS idx_definition_revision_parent
    ON sekai_definition_revisions(namespace, parent_revision_digest);

CREATE TABLE IF NOT EXISTS sekai_definition_branches (
    namespace TEXT NOT NULL,
    branch_id TEXT NOT NULL,
    base_revision_digest TEXT NOT NULL,
    head_revision_digest TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, branch_id)
);
CREATE INDEX IF NOT EXISTS idx_definition_branch_head
    ON sekai_definition_branches(namespace, head_revision_digest);

CREATE TABLE IF NOT EXISTS sekai_definition_requests (
    namespace TEXT NOT NULL,
    actor TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, actor, idempotency_key)
);

CREATE TABLE IF NOT EXISTS sekai_definition_branch_audit (
    event_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    branch_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    previous_head_digest TEXT NOT NULL,
    result_head_digest TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_definition_branch_audit_history
    ON sekai_definition_branch_audit(namespace, branch_id, created_at_ms, event_id);
