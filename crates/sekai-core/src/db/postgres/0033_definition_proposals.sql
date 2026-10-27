CREATE TABLE IF NOT EXISTS sekai_definition_published_heads (
    namespace TEXT PRIMARY KEY,
    revision_digest TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
INSERT INTO sekai_definition_published_heads (namespace, revision_digest, updated_at_ms)
SELECT DISTINCT ON (namespace) namespace, revision_digest, created_at_ms
FROM sekai_definition_revisions
WHERE published
ORDER BY namespace, created_at_ms DESC, revision_digest DESC
ON CONFLICT (namespace) DO NOTHING;

CREATE TABLE IF NOT EXISTS sekai_definition_proposals (
    namespace TEXT NOT NULL,
    proposal_id TEXT NOT NULL,
    branch_id TEXT NOT NULL,
    proposal_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY(namespace, proposal_id)
);
CREATE INDEX IF NOT EXISTS idx_definition_proposal_branch
    ON sekai_definition_proposals(namespace, branch_id, created_at_ms, proposal_id);
