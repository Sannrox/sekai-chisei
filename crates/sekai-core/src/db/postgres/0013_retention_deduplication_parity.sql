-- Reusable retention, archive, scoped-content, and reconciliation state.
-- This migration does not activate PostgreSQL as a complete runtime backend.
CREATE TABLE IF NOT EXISTS sekai_retention_policies (
 dataset TEXT NOT NULL, namespace TEXT NOT NULL DEFAULT '',
 data_class TEXT NOT NULL DEFAULT '', retention_days INTEGER NOT NULL CHECK (retention_days > 0),
 updated BIGINT NOT NULL, PRIMARY KEY(dataset,namespace,data_class));

CREATE TABLE IF NOT EXISTS sekai_lifecycle_idempotency (
 scope TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 request_digest TEXT NOT NULL, result_kind TEXT NOT NULL, result_id TEXT NOT NULL,
 created_at_ms BIGINT NOT NULL, PRIMARY KEY(scope,operation,idempotency_key));

CREATE TABLE IF NOT EXISTS sekai_content_blobs (
 id TEXT PRIMARY KEY, namespace TEXT NOT NULL, classification TEXT NOT NULL,
 encryption_key_id TEXT NOT NULL, residency TEXT NOT NULL, scoped_digest TEXT NOT NULL,
 content BYTEA, content_size BIGINT NOT NULL, created_at_ms BIGINT NOT NULL,
 erased_at_ms BIGINT,
 UNIQUE(namespace,classification,encryption_key_id,residency,scoped_digest));
CREATE TABLE IF NOT EXISTS sekai_content_references (
 reference_id TEXT PRIMARY KEY, blob_id TEXT NOT NULL REFERENCES sekai_content_blobs(id),
 namespace TEXT NOT NULL, actor TEXT NOT NULL, operation_id TEXT NOT NULL,
 causal_identity TEXT NOT NULL, retention_until_ms BIGINT,
 retention_hold BOOLEAN NOT NULL, legal_hold BOOLEAN NOT NULL, archived BOOLEAN NOT NULL,
 receipt_required BOOLEAN NOT NULL, attestation_required BOOLEAN NOT NULL,
 preserve_tombstone BOOLEAN NOT NULL, created_at_ms BIGINT NOT NULL,
 released_at_ms BIGINT, release_reason TEXT);
CREATE INDEX IF NOT EXISTS idx_pg_content_references_blob
 ON sekai_content_references(blob_id);
CREATE TABLE IF NOT EXISTS sekai_content_events (
 id TEXT PRIMARY KEY, event_kind TEXT NOT NULL,
 blob_id TEXT NOT NULL REFERENCES sekai_content_blobs(id), reference_id TEXT,
 actor TEXT NOT NULL, reason TEXT NOT NULL, created_at_ms BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS sekai_reconciliation_cases (
 id TEXT PRIMARY KEY, namespace TEXT NOT NULL, kind TEXT NOT NULL,
 external_identity TEXT NOT NULL, created_at_ms BIGINT NOT NULL,
 UNIQUE(namespace,kind,external_identity));
CREATE TABLE IF NOT EXISTS sekai_reconciliation_candidates (
 case_id TEXT NOT NULL REFERENCES sekai_reconciliation_cases(id),
 object_id TEXT NOT NULL, source TEXT NOT NULL, precedence INTEGER NOT NULL,
 authoritative BOOLEAN NOT NULL, PRIMARY KEY(case_id,object_id));
CREATE TABLE IF NOT EXISTS sekai_reconciliation_decisions (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES sekai_reconciliation_cases(id),
 action TEXT NOT NULL CHECK(action IN ('merge','alias','split','suppress','conflict')),
 subjects_json TEXT NOT NULL, canonical_object_id TEXT, actor TEXT NOT NULL,
 reason TEXT NOT NULL, request_digest TEXT NOT NULL, reverses_decision_id TEXT UNIQUE,
 created_at_ms BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_pg_reconciliation_history
 ON sekai_reconciliation_decisions(case_id,created_at_ms,id);

CREATE TABLE IF NOT EXISTS sekai_archive_batches (
 id TEXT PRIMARY KEY, cutoff_ms BIGINT NOT NULL, content_hash TEXT NOT NULL,
 record_count BIGINT NOT NULL, created_at_ms BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS sekai_archive_records (
 dataset TEXT NOT NULL, source_key TEXT NOT NULL, payload TEXT NOT NULL,
 payload_hash TEXT NOT NULL, archived_at_ms BIGINT NOT NULL,
 PRIMARY KEY(dataset,source_key));
CREATE TABLE IF NOT EXISTS sekai_archive_batch_records (
 batch_id TEXT NOT NULL REFERENCES sekai_archive_batches(id),
 dataset TEXT NOT NULL, source_key TEXT NOT NULL,
 PRIMARY KEY(batch_id,dataset,source_key),
 FOREIGN KEY(dataset,source_key) REFERENCES sekai_archive_records(dataset,source_key));
CREATE TABLE IF NOT EXISTS sekai_archive_redactions (
 id TEXT PRIMARY KEY, dataset TEXT NOT NULL, source_key TEXT NOT NULL,
 old_payload_hash TEXT NOT NULL, new_payload_hash TEXT NOT NULL,
 subject_hash TEXT NOT NULL, redacted_at_ms BIGINT NOT NULL,
 FOREIGN KEY(dataset,source_key) REFERENCES sekai_archive_records(dataset,source_key));
