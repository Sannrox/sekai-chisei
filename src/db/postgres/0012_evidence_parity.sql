-- Reusable evidence, attestation, and handoff state. These tables do not
-- activate PostgreSQL as a complete runtime backend.
CREATE TABLE IF NOT EXISTS sekai_evidence_producers (
 producer_identity TEXT PRIMARY KEY, config_version BIGINT NOT NULL CHECK (config_version > 0),
 capability_json TEXT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE, updated_at_ms BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS sekai_evidence_producer_history (
 producer_identity TEXT NOT NULL, config_version BIGINT NOT NULL, capability_json TEXT NOT NULL,
 recorded_at_ms BIGINT NOT NULL, PRIMARY KEY (producer_identity, config_version));
CREATE TABLE IF NOT EXISTS sekai_evidence_schemas (
 schema_id TEXT NOT NULL, schema_version TEXT NOT NULL, evidence_type TEXT NOT NULL,
 definition_json TEXT NOT NULL, registered_at_ms BIGINT NOT NULL, PRIMARY KEY (schema_id, schema_version));
CREATE TABLE IF NOT EXISTS sekai_evidence_submissions (
 id TEXT PRIMARY KEY, producer_identity TEXT NOT NULL, source_type TEXT NOT NULL,
 source_instance TEXT NOT NULL, source_record_id TEXT NOT NULL, source_version TEXT NOT NULL,
 source_sequence BIGINT NOT NULL, namespace TEXT NOT NULL, target_external_id TEXT NOT NULL,
 target_kind TEXT NOT NULL, evidence_type TEXT NOT NULL, schema_id TEXT NOT NULL,
 schema_version TEXT NOT NULL, idempotency_key TEXT NOT NULL, content_digest TEXT NOT NULL,
 classification TEXT NOT NULL CHECK (classification IN ('public','internal','confidential','restricted')),
 intent TEXT NOT NULL CHECK (intent IN ('upsert','retract','mark_stale')), lifecycle_state TEXT NOT NULL,
 rejection_code TEXT, rejection_summary TEXT, observed_at_ms BIGINT NOT NULL,
 collected_at_ms BIGINT NOT NULL, expires_at_ms BIGINT, received_at_ms BIGINT NOT NULL,
 updated_at_ms BIGINT NOT NULL, envelope_json TEXT);
CREATE INDEX IF NOT EXISTS idx_pg_evidence_submission_source
 ON sekai_evidence_submissions(source_type, source_instance, source_record_id, source_sequence);
CREATE INDEX IF NOT EXISTS idx_pg_evidence_submission_filters
 ON sekai_evidence_submissions(namespace, lifecycle_state, evidence_type, received_at_ms DESC);
CREATE TABLE IF NOT EXISTS sekai_evidence_idempotency (
 producer_identity TEXT NOT NULL, idempotency_key TEXT NOT NULL, envelope_digest TEXT NOT NULL,
 submission_id TEXT NOT NULL REFERENCES sekai_evidence_submissions(id) ON DELETE CASCADE,
 PRIMARY KEY (producer_identity, idempotency_key));
CREATE INDEX IF NOT EXISTS idx_pg_evidence_idempotency_submission
 ON sekai_evidence_idempotency(submission_id);
CREATE TABLE IF NOT EXISTS sekai_evidence_source_identity (
 source_type TEXT NOT NULL, source_instance TEXT NOT NULL, source_record_id TEXT NOT NULL,
 source_sequence BIGINT NOT NULL, source_version TEXT NOT NULL, content_digest TEXT NOT NULL,
 submission_id TEXT NOT NULL REFERENCES sekai_evidence_submissions(id) ON DELETE CASCADE,
 PRIMARY KEY (source_type, source_instance, source_record_id, source_sequence),
 UNIQUE (source_type, source_instance, source_record_id, source_version));
CREATE TABLE IF NOT EXISTS sekai_evidence_lifecycle_history (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 submission_id TEXT NOT NULL REFERENCES sekai_evidence_submissions(id) ON DELETE CASCADE,
 lifecycle_state TEXT NOT NULL, reason_code TEXT, recorded_at_ms BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_pg_evidence_lifecycle_submission
 ON sekai_evidence_lifecycle_history(submission_id, id);
CREATE TABLE IF NOT EXISTS sekai_evidence_projections (
 submission_id TEXT PRIMARY KEY REFERENCES sekai_evidence_submissions(id) ON DELETE CASCADE,
 evidence_object_id TEXT NOT NULL, target_object_id TEXT NOT NULL, projection_version TEXT NOT NULL,
 source_sequence BIGINT NOT NULL, projected_at_ms BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS sekai_evidence_observations (
 submission_id TEXT PRIMARY KEY REFERENCES sekai_evidence_submissions(id) ON DELETE CASCADE,
 evidence_object_id TEXT NOT NULL, signal TEXT NOT NULL, confidence_bps BIGINT NOT NULL,
 observed_at_ms BIGINT NOT NULL, projection_version TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sekai_evidence_relationship_projections (
 submission_id TEXT NOT NULL REFERENCES sekai_evidence_submissions(id) ON DELETE CASCADE,
 related_submission_id TEXT NOT NULL, source_relation TEXT NOT NULL,
 PRIMARY KEY (submission_id, related_submission_id, source_relation));
CREATE TABLE IF NOT EXISTS sekai_evidence_operation_links (
 submission_id TEXT PRIMARY KEY REFERENCES sekai_evidence_submissions(id) ON DELETE CASCADE,
 operation_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sekai_attestations (
 id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, policy_kind TEXT NOT NULL,
 policy_scope TEXT NOT NULL DEFAULT '', policy_version TEXT NOT NULL, policy_snapshot TEXT NOT NULL,
 inputs TEXT NOT NULL DEFAULT '{}', decision TEXT NOT NULL, content_hash TEXT NOT NULL, created BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_pg_attestations_decision ON sekai_attestations(decision_id);
CREATE INDEX IF NOT EXISTS idx_pg_attestations_scope ON sekai_attestations(policy_scope, created DESC);
CREATE TABLE IF NOT EXISTS sekai_handoffs (
 id TEXT PRIMARY KEY, namespace TEXT NOT NULL, intended_principal TEXT NOT NULL,
 creator_principal TEXT NOT NULL, request_id TEXT NOT NULL, request_digest TEXT NOT NULL,
 manifest_json TEXT NOT NULL, supersedes_manifest_id TEXT NOT NULL, created_at_ms BIGINT NOT NULL,
 expires_at_ms BIGINT NOT NULL, revoked_at_ms BIGINT, UNIQUE(creator_principal, request_id));
CREATE INDEX IF NOT EXISTS idx_pg_handoffs_receiver
 ON sekai_handoffs(namespace, intended_principal, created_at_ms DESC);
CREATE TABLE IF NOT EXISTS sekai_handoff_events (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 manifest_id TEXT NOT NULL REFERENCES sekai_handoffs(id) ON DELETE CASCADE,
 event_type TEXT NOT NULL, actor TEXT NOT NULL, request_id TEXT NOT NULL, reason TEXT NOT NULL,
 recorded_at_ms BIGINT NOT NULL, UNIQUE(manifest_id, event_type, actor, request_id));
CREATE TABLE IF NOT EXISTS sekai_external_action_execution_evidence (
 submission_id TEXT PRIMARY KEY REFERENCES sekai_evidence_submissions(id) ON DELETE CASCADE,
 permit_id TEXT NOT NULL, redemption_id TEXT NOT NULL, execution_id TEXT NOT NULL,
 producer_identity TEXT NOT NULL, lifecycle_state TEXT NOT NULL, source_sequence BIGINT NOT NULL,
 content_digest TEXT NOT NULL, evidence_json TEXT NOT NULL, observed_at_ms BIGINT NOT NULL,
 projection_status TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_pg_external_execution_evidence
 ON sekai_external_action_execution_evidence(execution_id, source_sequence);
