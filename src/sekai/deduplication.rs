//! Canonical retry identity, policy-scoped immutable content, and reversible
//! object reconciliation.
//!
//! Content equality is deliberately narrower than causal identity. Blobs may
//! be shared only inside an identical [`ContentScope`], while every actor,
//! operation, observation, receipt, and evidence occurrence keeps its own
//! stable reference. Reconciliation is an append-only overlay; original graph
//! objects are never rewritten or removed by this module.

use crate::db::sekai::{SekaiDb, row_to_object};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const DIGEST_DOMAIN: &[u8] = b"sekai-scoped-content/v1";
const MAX_IDEMPOTENCY_ALIASES: i64 = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentScope {
    pub namespace: String,
    pub classification: String,
    pub encryption_key_id: String,
    pub residency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentReferenceRequest {
    pub reference_id: String,
    pub actor: String,
    pub operation_id: String,
    pub causal_identity: String,
    pub idempotency_key: String,
    pub retention_until_ms: Option<i64>,
    pub retention_hold: bool,
    pub legal_hold: bool,
    pub archived: bool,
    pub receipt_required: bool,
    pub attestation_required: bool,
    pub preserve_tombstone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentReference {
    pub reference_id: String,
    pub blob_id: String,
    pub scope: ContentScope,
    pub scoped_digest: String,
    pub actor: String,
    pub operation_id: String,
    pub causal_identity: String,
    pub retention_until_ms: Option<i64>,
    pub retention_hold: bool,
    pub legal_hold: bool,
    pub archived: bool,
    pub receipt_required: bool,
    pub attestation_required: bool,
    pub preserve_tombstone: bool,
    pub created_at_ms: i64,
    pub released_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentObligations {
    pub retention_until_ms: Option<i64>,
    pub retention_hold: bool,
    pub legal_hold: bool,
    pub archived: bool,
    pub receipt_required: bool,
    pub attestation_required: bool,
    pub preserve_tombstone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentAdmission {
    pub reference: ContentReference,
    pub stored_new_blob: bool,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GarbageCollectionResult {
    pub payloads_erased: u64,
    pub tombstones_preserved: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationAction {
    Merge,
    Alias,
    Split,
    Suppress,
    Conflict,
}

impl ReconciliationAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Alias => "alias",
            Self::Split => "split",
            Self::Suppress => "suppress",
            Self::Conflict => "conflict",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "merge" => Ok(Self::Merge),
            "alias" => Ok(Self::Alias),
            "split" => Ok(Self::Split),
            "suppress" => Ok(Self::Suppress),
            "conflict" => Ok(Self::Conflict),
            _ => Err(format!("unknown reconciliation action {value:?}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationCandidate {
    pub object_id: String,
    pub source: String,
    pub precedence: i32,
    pub authoritative: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationRequest {
    pub namespace: String,
    pub kind: String,
    pub external_identity: String,
    pub candidates: Vec<ReconciliationCandidate>,
    pub action: ReconciliationAction,
    pub subjects: Vec<String>,
    pub canonical_object_id: Option<String>,
    pub actor: String,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationDecision {
    pub id: String,
    pub case_id: String,
    pub action: ReconciliationAction,
    pub subjects: Vec<String>,
    pub canonical_object_id: Option<String>,
    pub actor: String,
    pub reason: String,
    pub reverses_decision_id: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationOutcome {
    pub decision: ReconciliationDecision,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationDisposition {
    Independent,
    MergedInto(String),
    AliasOf(String),
    Suppressed,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationState {
    pub case_id: String,
    pub objects: BTreeMap<String, ReconciliationDisposition>,
}

impl SekaiDb {
    pub(crate) fn migrate_deduplication(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_idempotency (
                scope TEXT NOT NULL,
                operation TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                result_kind TEXT NOT NULL,
                result_id TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                PRIMARY KEY (scope, operation, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS idx_sekai_idempotency_result
                ON sekai_idempotency(scope, operation, result_kind, result_id);
            CREATE TABLE IF NOT EXISTS sekai_content_blobs (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                classification TEXT NOT NULL,
                encryption_key_id TEXT NOT NULL,
                residency TEXT NOT NULL,
                scoped_digest TEXT NOT NULL,
                content BLOB,
                content_size INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                erased_at_ms INTEGER,
                UNIQUE(namespace, classification, encryption_key_id, residency, scoped_digest)
            );
            CREATE TABLE IF NOT EXISTS sekai_content_references (
                reference_id TEXT PRIMARY KEY,
                blob_id TEXT NOT NULL,
                namespace TEXT NOT NULL,
                actor TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                causal_identity TEXT NOT NULL,
                retention_until_ms INTEGER,
                retention_hold INTEGER NOT NULL,
                legal_hold INTEGER NOT NULL,
                archived INTEGER NOT NULL,
                receipt_required INTEGER NOT NULL,
                attestation_required INTEGER NOT NULL,
                preserve_tombstone INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                released_at_ms INTEGER,
                release_reason TEXT,
                FOREIGN KEY(blob_id) REFERENCES sekai_content_blobs(id)
            );
            CREATE INDEX IF NOT EXISTS idx_sekai_content_references_blob
                ON sekai_content_references(blob_id);
            CREATE TABLE IF NOT EXISTS sekai_content_events (
                id TEXT PRIMARY KEY,
                event_kind TEXT NOT NULL,
                blob_id TEXT NOT NULL,
                reference_id TEXT,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sekai_reconciliation_cases (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                kind TEXT NOT NULL,
                external_identity TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                UNIQUE(namespace, kind, external_identity)
            );
            CREATE TABLE IF NOT EXISTS sekai_reconciliation_candidates (
                case_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                source TEXT NOT NULL,
                precedence INTEGER NOT NULL,
                authoritative INTEGER NOT NULL,
                PRIMARY KEY(case_id, object_id)
            );
            CREATE TABLE IF NOT EXISTS sekai_reconciliation_decisions (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                action TEXT NOT NULL,
                subjects_json TEXT NOT NULL,
                canonical_object_id TEXT,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                reverses_decision_id TEXT,
                created_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sekai_reconciliation_history
                ON sekai_reconciliation_decisions(case_id, created_at_ms);",
        )
        .map_err(|error| error.to_string())
    }

    pub fn put_scoped_content(
        &self,
        scope: &ContentScope,
        request: &ContentReferenceRequest,
        content: &[u8],
        now_ms: i64,
    ) -> Result<ContentAdmission, String> {
        validate_scope(scope)?;
        validate_reference_request(request)?;
        let scoped_digest = scoped_content_digest(scope, content)?;
        let semantic_digest = canonical_digest(&serde_json::json!({
            "scope": scope,
            "reference_id": request.reference_id,
            "actor": request.actor,
            "operation_id": request.operation_id,
            "causal_identity": request.causal_identity,
            "retention_until_ms": request.retention_until_ms,
            "retention_hold": request.retention_hold,
            "legal_hold": request.legal_hold,
            "archived": request.archived,
            "receipt_required": request.receipt_required,
            "attestation_required": request.attestation_required,
            "preserve_tombstone": request.preserve_tombstone,
            "scoped_digest": scoped_digest,
        }))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(result_id) = check_idempotency(
            &tx,
            &scope.namespace,
            "content.put",
            &request.idempotency_key,
            &semantic_digest,
        )? {
            let reference = load_content_reference(&tx, &result_id)?
                .ok_or_else(|| "idempotency record references missing content".to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(ContentAdmission {
                reference,
                stored_new_blob: false,
                deduplicated: true,
            });
        }

        if let Some(existing) = load_content_reference(&tx, &request.reference_id)? {
            if reference_semantic_digest(&existing)? != semantic_digest {
                return Err("content reference identity was reused for a different request".into());
            }
            insert_idempotency(
                &tx,
                &scope.namespace,
                "content.put",
                &request.idempotency_key,
                &semantic_digest,
                "content_reference",
                &request.reference_id,
                now_ms,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(ContentAdmission {
                reference: existing,
                stored_new_blob: false,
                deduplicated: true,
            });
        }

        let existing_blob = tx
            .query_row(
                "SELECT id, content FROM sekai_content_blobs
                 WHERE namespace=?1 AND classification=?2 AND encryption_key_id=?3
                   AND residency=?4 AND scoped_digest=?5",
                params![
                    scope.namespace,
                    scope.classification,
                    scope.encryption_key_id,
                    scope.residency,
                    scoped_digest
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let (blob_id, stored_new_blob) = match existing_blob {
            Some((_id, None)) => {
                return Err(
                    "content digest is retained as an erasure tombstone in this scope".into(),
                );
            }
            Some((id, Some(stored))) if stored == content => (id, false),
            Some(_) => return Err("scoped content digest collision".into()),
            None => {
                let id = format!("blob-{}", Uuid::new_v4().simple());
                tx.execute(
                    "INSERT INTO sekai_content_blobs
                     (id, namespace, classification, encryption_key_id, residency, scoped_digest,
                      content, content_size, created_at_ms, erased_at_ms)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL)",
                    params![
                        id,
                        scope.namespace,
                        scope.classification,
                        scope.encryption_key_id,
                        scope.residency,
                        scoped_digest,
                        content,
                        content.len() as i64,
                        now_ms,
                    ],
                )
                .map_err(|error| error.to_string())?;
                (id, true)
            }
        };
        tx.execute(
            "INSERT INTO sekai_content_references
             (reference_id, blob_id, namespace, actor, operation_id, causal_identity,
              retention_until_ms, retention_hold, legal_hold, archived, receipt_required,
              attestation_required, preserve_tombstone, created_at_ms, released_at_ms, release_reason)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,NULL,NULL)",
            params![
                request.reference_id,
                blob_id,
                scope.namespace,
                request.actor,
                request.operation_id,
                request.causal_identity,
                request.retention_until_ms,
                request.retention_hold,
                request.legal_hold,
                request.archived,
                request.receipt_required,
                request.attestation_required,
                request.preserve_tombstone,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_content_events
             (id,event_kind,blob_id,reference_id,actor,reason,created_at_ms)
             VALUES (?1,'reference_created',?2,?3,?4,'content admitted',?5)",
            params![
                format!("content-event-{}", Uuid::new_v4().simple()),
                blob_id,
                request.reference_id,
                request.actor,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        insert_idempotency(
            &tx,
            &scope.namespace,
            "content.put",
            &request.idempotency_key,
            &semantic_digest,
            "content_reference",
            &request.reference_id,
            now_ms,
        )?;
        let reference = load_content_reference(&tx, &request.reference_id)?
            .ok_or_else(|| "inserted content reference disappeared".to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(ContentAdmission {
            reference,
            stored_new_blob,
            deduplicated: false,
        })
    }

    /// Read content only through a live reference in the caller's exact scope.
    /// Wrong-scope and unknown references intentionally have identical results.
    pub fn read_scoped_content(
        &self,
        scope: &ContentScope,
        reference_id: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        validate_scope(scope)?;
        let conn = self.conn();
        conn.query_row(
            "SELECT b.content FROM sekai_content_references r
             JOIN sekai_content_blobs b ON b.id=r.blob_id
             WHERE r.reference_id=?1 AND r.released_at_ms IS NULL
               AND b.namespace=?2 AND b.classification=?3 AND b.encryption_key_id=?4
               AND b.residency=?5",
            params![
                reference_id,
                scope.namespace,
                scope.classification,
                scope.encryption_key_id,
                scope.residency
            ],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()
        .map(|value| value.flatten())
        .map_err(|error| error.to_string())
    }

    pub fn release_content_reference(
        &self,
        scope: &ContentScope,
        reference_id: &str,
        actor: &str,
        reason: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        validate_scope(scope)?;
        for (name, value) in [
            ("reference_id", reference_id),
            ("actor", actor),
            ("reason", reason),
            ("idempotency_key", idempotency_key),
        ] {
            require_value(name, value)?;
        }
        let digest = canonical_digest(&serde_json::json!({
            "scope": scope,
            "reference_id": reference_id,
            "actor": actor,
            "reason": reason,
        }))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if check_idempotency(
            &tx,
            &scope.namespace,
            "content.release",
            idempotency_key,
            &digest,
        )?
        .is_some()
        {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(true);
        }
        let reference = load_content_reference(&tx, reference_id)?
            .filter(|reference| reference.scope == *scope)
            .ok_or_else(|| "content reference not found".to_string())?;
        let deduplicated = reference.released_at_ms.is_some();
        if !deduplicated {
            tx.execute(
                "UPDATE sekai_content_references
                 SET released_at_ms=?1, release_reason=?2 WHERE reference_id=?3",
                params![now_ms, reason, reference_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_content_events
                 (id,event_kind,blob_id,reference_id,actor,reason,created_at_ms)
                 VALUES (?1,'reference_released',?2,?3,?4,?5,?6)",
                params![
                    format!("content-event-{}", Uuid::new_v4().simple()),
                    reference.blob_id,
                    reference_id,
                    actor,
                    reason,
                    now_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        insert_idempotency(
            &tx,
            &scope.namespace,
            "content.release",
            idempotency_key,
            &digest,
            "content_reference",
            reference_id,
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(deduplicated)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_content_obligations(
        &self,
        scope: &ContentScope,
        reference_id: &str,
        obligations: &ContentObligations,
        actor: &str,
        reason: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        validate_scope(scope)?;
        for (name, value) in [
            ("reference_id", reference_id),
            ("actor", actor),
            ("reason", reason),
            ("idempotency_key", idempotency_key),
        ] {
            require_value(name, value)?;
        }
        let digest = canonical_digest(&serde_json::json!({
            "scope": scope,
            "reference_id": reference_id,
            "obligations": obligations,
            "actor": actor,
            "reason": reason,
        }))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if check_idempotency(
            &tx,
            &scope.namespace,
            "content.obligations",
            idempotency_key,
            &digest,
        )?
        .is_some()
        {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(true);
        }
        let reference = load_content_reference(&tx, reference_id)?
            .filter(|reference| reference.scope == *scope)
            .ok_or_else(|| "content reference not found".to_string())?;
        let payload_erased = tx
            .query_row(
                "SELECT content IS NULL FROM sekai_content_blobs WHERE id=?1",
                [&reference.blob_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| error.to_string())?;
        let requires_content = obligations.retention_hold
            || obligations.legal_hold
            || obligations.archived
            || obligations.receipt_required
            || obligations.attestation_required
            || obligations
                .retention_until_ms
                .is_some_and(|retention| retention > now_ms);
        if payload_erased && requires_content {
            return Err("cannot add a content-retaining obligation after payload erasure".into());
        }
        let unchanged = reference.retention_until_ms == obligations.retention_until_ms
            && reference.retention_hold == obligations.retention_hold
            && reference.legal_hold == obligations.legal_hold
            && reference.archived == obligations.archived
            && reference.receipt_required == obligations.receipt_required
            && reference.attestation_required == obligations.attestation_required
            && reference.preserve_tombstone == obligations.preserve_tombstone;
        if !unchanged {
            tx.execute(
                "UPDATE sekai_content_references SET retention_until_ms=?1,retention_hold=?2,
                 legal_hold=?3,archived=?4,receipt_required=?5,attestation_required=?6,
                 preserve_tombstone=?7 WHERE reference_id=?8",
                params![
                    obligations.retention_until_ms,
                    obligations.retention_hold,
                    obligations.legal_hold,
                    obligations.archived,
                    obligations.receipt_required,
                    obligations.attestation_required,
                    obligations.preserve_tombstone,
                    reference_id,
                ],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_content_events
                 (id,event_kind,blob_id,reference_id,actor,reason,created_at_ms)
                 VALUES (?1,'obligations_updated',?2,?3,?4,?5,?6)",
                params![
                    format!("content-event-{}", Uuid::new_v4().simple()),
                    reference.blob_id,
                    reference_id,
                    actor,
                    reason,
                    now_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        insert_idempotency(
            &tx,
            &scope.namespace,
            "content.obligations",
            idempotency_key,
            &digest,
            "content_reference",
            reference_id,
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(unchanged)
    }

    pub fn collect_scoped_content_garbage(
        &self,
        scope: &ContentScope,
        actor: &str,
        now_ms: i64,
    ) -> Result<GarbageCollectionResult, String> {
        validate_scope(scope)?;
        require_value("actor", actor)?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let blob_ids = {
            let mut statement = tx
                .prepare(
                    "SELECT b.id FROM sekai_content_blobs b
                     WHERE b.namespace=?1 AND b.classification=?2 AND b.encryption_key_id=?3
                       AND b.residency=?4 AND b.content IS NOT NULL
                       AND NOT EXISTS (
                         SELECT 1 FROM sekai_content_references r WHERE r.blob_id=b.id AND (
                           r.released_at_ms IS NULL OR r.retention_hold=1 OR r.legal_hold=1 OR r.archived=1
                           OR r.receipt_required=1 OR r.attestation_required=1
                           OR COALESCE(r.retention_until_ms,0)>?5
                         )
                       ) ORDER BY b.id",
                )
                .map_err(|error| error.to_string())?;
            statement
                .query_map(
                    params![
                        scope.namespace,
                        scope.classification,
                        scope.encryption_key_id,
                        scope.residency,
                        now_ms
                    ],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        let mut result = GarbageCollectionResult::default();
        for blob_id in blob_ids {
            tx.execute(
                "UPDATE sekai_content_blobs SET content=NULL, erased_at_ms=?1 WHERE id=?2",
                params![now_ms, blob_id],
            )
            .map_err(|error| error.to_string())?;
            result.payloads_erased += 1;
            let tombstones = tx
                .query_row(
                    "SELECT COUNT(*) FROM sekai_content_references
                     WHERE blob_id=?1 AND preserve_tombstone=1",
                    [&blob_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|error| error.to_string())?;
            result.tombstones_preserved += tombstones as u64;
            tx.execute(
                "INSERT INTO sekai_content_events
                 (id,event_kind,blob_id,reference_id,actor,reason,created_at_ms)
                 VALUES (?1,'payload_erased',?2,NULL,?3,'no retaining reference',?4)",
                params![
                    format!("content-event-{}", Uuid::new_v4().simple()),
                    blob_id,
                    actor,
                    now_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn reconcile_objects(
        &self,
        request: &ReconciliationRequest,
        now_ms: i64,
    ) -> Result<ReconciliationOutcome, String> {
        validate_reconciliation_request(request)?;
        let request_digest = reconciliation_request_digest(request)?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(result_id) = check_idempotency(
            &tx,
            &request.namespace,
            "object.reconcile",
            &request.idempotency_key,
            &request_digest,
        )? {
            let decision = load_reconciliation_decision(&tx, &result_id)?.ok_or_else(|| {
                "idempotency record references missing reconciliation".to_string()
            })?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(ReconciliationOutcome {
                decision,
                deduplicated: true,
            });
        }
        validate_candidate_objects(&tx, request)?;
        let case_id = ensure_reconciliation_case(&tx, request, now_ms)?;
        persist_candidates(&tx, &case_id, &request.candidates)?;
        validate_authority(
            &tx,
            &case_id,
            request.action,
            request.canonical_object_id.as_deref(),
        )?;
        let decision_id = format!("reconciliation-{}", Uuid::new_v4().simple());
        let subjects_json = serde_json::to_string(&normalized_subjects(&request.subjects))
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_reconciliation_decisions
             (id,case_id,action,subjects_json,canonical_object_id,actor,reason,
              request_digest,reverses_decision_id,created_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL,?9)",
            params![
                decision_id,
                case_id,
                request.action.as_str(),
                subjects_json,
                request.canonical_object_id,
                request.actor,
                request.reason,
                request_digest,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        insert_idempotency(
            &tx,
            &request.namespace,
            "object.reconcile",
            &request.idempotency_key,
            &request_digest,
            "reconciliation_decision",
            &decision_id,
            now_ms,
        )?;
        let decision = load_reconciliation_decision(&tx, &decision_id)?
            .ok_or_else(|| "inserted reconciliation disappeared".to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(ReconciliationOutcome {
            decision,
            deduplicated: false,
        })
    }

    pub fn reverse_reconciliation(
        &self,
        decision_id: &str,
        actor: &str,
        reason: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ReconciliationOutcome, String> {
        for (name, value) in [
            ("decision_id", decision_id),
            ("actor", actor),
            ("reason", reason),
            ("idempotency_key", idempotency_key),
        ] {
            require_value(name, value)?;
        }
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let original = load_reconciliation_decision(&tx, decision_id)?
            .ok_or_else(|| "reconciliation decision not found".to_string())?;
        if original.reverses_decision_id.is_some() {
            return Err("reversal decisions cannot themselves be reversed".into());
        }
        let namespace = tx
            .query_row(
                "SELECT namespace FROM sekai_reconciliation_cases WHERE id=?1",
                [&original.case_id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?;
        let digest = canonical_digest(&serde_json::json!({
            "decision_id": decision_id,
            "actor": actor,
            "reason": reason,
        }))?;
        if let Some(result_id) = check_idempotency(
            &tx,
            &namespace,
            "object.reconcile.reverse",
            idempotency_key,
            &digest,
        )? {
            let decision = load_reconciliation_decision(&tx, &result_id)?
                .ok_or_else(|| "idempotency record references missing reversal".to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(ReconciliationOutcome {
                decision,
                deduplicated: true,
            });
        }
        let already_reversed = tx
            .query_row(
                "SELECT id FROM sekai_reconciliation_decisions
                 WHERE reverses_decision_id=?1 LIMIT 1",
                [decision_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if already_reversed.is_some() {
            return Err("reconciliation decision is already reversed".into());
        }
        let reversal_id = format!("reconciliation-{}", Uuid::new_v4().simple());
        tx.execute(
            "INSERT INTO sekai_reconciliation_decisions
             (id,case_id,action,subjects_json,canonical_object_id,actor,reason,
              request_digest,reverses_decision_id,created_at_ms)
             VALUES (?1,?2,'split','[]',NULL,?3,?4,?5,?6,?7)",
            params![
                reversal_id,
                original.case_id,
                actor,
                reason,
                digest,
                decision_id,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        insert_idempotency(
            &tx,
            &namespace,
            "object.reconcile.reverse",
            idempotency_key,
            &digest,
            "reconciliation_decision",
            &reversal_id,
            now_ms,
        )?;
        let decision = load_reconciliation_decision(&tx, &reversal_id)?
            .ok_or_else(|| "inserted reconciliation reversal disappeared".to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(ReconciliationOutcome {
            decision,
            deduplicated: false,
        })
    }

    pub fn reconciliation_state(&self, case_id: &str) -> Result<ReconciliationState, String> {
        require_value("case_id", case_id)?;
        let conn = self.conn();
        let objects = {
            let mut statement = conn
                .prepare(
                    "SELECT object_id FROM sekai_reconciliation_candidates
                     WHERE case_id=?1 ORDER BY object_id",
                )
                .map_err(|error| error.to_string())?;
            statement
                .query_map([case_id], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        if objects.is_empty() {
            return Err("reconciliation case not found".into());
        }
        let decisions = list_reconciliation_decisions(&conn, case_id)?;
        let reversed = decisions
            .iter()
            .filter_map(|decision| decision.reverses_decision_id.clone())
            .collect::<BTreeSet<_>>();
        let mut state = objects
            .into_iter()
            .map(|id| (id, ReconciliationDisposition::Independent))
            .collect::<BTreeMap<_, _>>();
        for decision in decisions {
            if decision.reverses_decision_id.is_some() || reversed.contains(&decision.id) {
                continue;
            }
            match decision.action {
                ReconciliationAction::Merge | ReconciliationAction::Alias => {
                    let canonical = decision.canonical_object_id.as_ref().ok_or_else(|| {
                        "stored reconciliation lacks canonical object".to_string()
                    })?;
                    for subject in decision.subjects {
                        if &subject == canonical {
                            state.insert(subject, ReconciliationDisposition::Independent);
                        } else if decision.action == ReconciliationAction::Merge {
                            state.insert(
                                subject,
                                ReconciliationDisposition::MergedInto(canonical.clone()),
                            );
                        } else {
                            state.insert(
                                subject,
                                ReconciliationDisposition::AliasOf(canonical.clone()),
                            );
                        }
                    }
                }
                ReconciliationAction::Split => {
                    for subject in decision.subjects {
                        state.insert(subject, ReconciliationDisposition::Independent);
                    }
                }
                ReconciliationAction::Suppress => {
                    for subject in decision.subjects {
                        state.insert(subject, ReconciliationDisposition::Suppressed);
                    }
                }
                ReconciliationAction::Conflict => {
                    for subject in decision.subjects {
                        state.insert(subject, ReconciliationDisposition::Conflict);
                    }
                }
            }
        }
        Ok(ReconciliationState {
            case_id: case_id.to_string(),
            objects: state,
        })
    }

    pub fn reconciliation_history(
        &self,
        case_id: &str,
    ) -> Result<Vec<ReconciliationDecision>, String> {
        require_value("case_id", case_id)?;
        let conn = self.conn();
        list_reconciliation_decisions(&conn, case_id)
    }
}

pub fn canonical_digest(value: &serde_json::Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn scoped_content_digest(scope: &ContentScope, content: &[u8]) -> Result<String, String> {
    validate_scope(scope)?;
    let mut digest = Sha256::new();
    digest.update(DIGEST_DOMAIN);
    for value in [
        scope.namespace.as_bytes(),
        scope.classification.as_bytes(),
        scope.encryption_key_id.as_bytes(),
        scope.residency.as_bytes(),
        content,
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_scope(scope: &ContentScope) -> Result<(), String> {
    for (name, value) in [
        ("namespace", scope.namespace.as_str()),
        ("classification", scope.classification.as_str()),
        ("encryption_key_id", scope.encryption_key_id.as_str()),
        ("residency", scope.residency.as_str()),
    ] {
        require_value(name, value)?;
    }
    Ok(())
}

fn validate_reference_request(request: &ContentReferenceRequest) -> Result<(), String> {
    for (name, value) in [
        ("reference_id", request.reference_id.as_str()),
        ("actor", request.actor.as_str()),
        ("operation_id", request.operation_id.as_str()),
        ("causal_identity", request.causal_identity.as_str()),
        ("idempotency_key", request.idempotency_key.as_str()),
    ] {
        require_value(name, value)?;
    }
    Ok(())
}

fn require_value(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn check_idempotency(
    tx: &Transaction<'_>,
    scope: &str,
    operation: &str,
    key: &str,
    request_digest: &str,
) -> Result<Option<String>, String> {
    let existing = tx
        .query_row(
            "SELECT request_digest,result_id FROM sekai_idempotency
             WHERE scope=?1 AND operation=?2 AND idempotency_key=?3",
            params![scope, operation, key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    match existing {
        Some((stored, result_id)) if stored == request_digest => Ok(Some(result_id)),
        Some(_) => {
            Err("idempotency key was reused with a different canonical request digest".into())
        }
        None => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_idempotency(
    tx: &Transaction<'_>,
    scope: &str,
    operation: &str,
    key: &str,
    request_digest: &str,
    result_kind: &str,
    result_id: &str,
    now_ms: i64,
) -> Result<(), String> {
    let aliases = tx
        .query_row(
            "SELECT COUNT(*) FROM sekai_idempotency
             WHERE scope=?1 AND operation=?2 AND result_kind=?3 AND result_id=?4",
            params![scope, operation, result_kind, result_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| error.to_string())?;
    if aliases >= MAX_IDEMPOTENCY_ALIASES {
        return Err("idempotency alias capacity exceeded".into());
    }
    tx.execute(
        "INSERT INTO sekai_idempotency
         (scope,operation,idempotency_key,request_digest,result_kind,result_id,created_at_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            scope,
            operation,
            key,
            request_digest,
            result_kind,
            result_id,
            now_ms
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn load_content_reference(
    tx: &Transaction<'_>,
    reference_id: &str,
) -> Result<Option<ContentReference>, String> {
    tx.query_row(
        "SELECT r.reference_id,r.blob_id,b.namespace,b.classification,b.encryption_key_id,
                b.residency,b.scoped_digest,r.actor,r.operation_id,r.causal_identity,
                r.retention_until_ms,r.retention_hold,r.legal_hold,r.archived,r.receipt_required,
                r.attestation_required,r.preserve_tombstone,r.created_at_ms,r.released_at_ms
         FROM sekai_content_references r JOIN sekai_content_blobs b ON b.id=r.blob_id
         WHERE r.reference_id=?1",
        [reference_id],
        |row| {
            Ok(ContentReference {
                reference_id: row.get(0)?,
                blob_id: row.get(1)?,
                scope: ContentScope {
                    namespace: row.get(2)?,
                    classification: row.get(3)?,
                    encryption_key_id: row.get(4)?,
                    residency: row.get(5)?,
                },
                scoped_digest: row.get(6)?,
                actor: row.get(7)?,
                operation_id: row.get(8)?,
                causal_identity: row.get(9)?,
                retention_until_ms: row.get(10)?,
                retention_hold: row.get(11)?,
                legal_hold: row.get(12)?,
                archived: row.get(13)?,
                receipt_required: row.get(14)?,
                attestation_required: row.get(15)?,
                preserve_tombstone: row.get(16)?,
                created_at_ms: row.get(17)?,
                released_at_ms: row.get(18)?,
            })
        },
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn reference_semantic_digest(reference: &ContentReference) -> Result<String, String> {
    canonical_digest(&serde_json::json!({
        "scope": reference.scope,
        "reference_id": reference.reference_id,
        "actor": reference.actor,
        "operation_id": reference.operation_id,
        "causal_identity": reference.causal_identity,
        "retention_until_ms": reference.retention_until_ms,
        "retention_hold": reference.retention_hold,
        "legal_hold": reference.legal_hold,
        "archived": reference.archived,
        "receipt_required": reference.receipt_required,
        "attestation_required": reference.attestation_required,
        "preserve_tombstone": reference.preserve_tombstone,
        "scoped_digest": reference.scoped_digest,
    }))
}

fn validate_reconciliation_request(request: &ReconciliationRequest) -> Result<(), String> {
    for (name, value) in [
        ("namespace", request.namespace.as_str()),
        ("kind", request.kind.as_str()),
        ("external_identity", request.external_identity.as_str()),
        ("actor", request.actor.as_str()),
        ("reason", request.reason.as_str()),
        ("idempotency_key", request.idempotency_key.as_str()),
    ] {
        require_value(name, value)?;
    }
    if request.candidates.len() < 2 {
        return Err("reconciliation requires at least two candidates".into());
    }
    let candidate_ids = request
        .candidates
        .iter()
        .map(|candidate| candidate.object_id.as_str())
        .collect::<BTreeSet<_>>();
    if candidate_ids.len() != request.candidates.len() {
        return Err("reconciliation candidates must be unique".into());
    }
    for candidate in &request.candidates {
        require_value("candidate.object_id", &candidate.object_id)?;
        require_value("candidate.source", &candidate.source)?;
    }
    let subjects = normalized_subjects(&request.subjects);
    if subjects.is_empty()
        || subjects
            .iter()
            .any(|id| !candidate_ids.contains(id.as_str()))
    {
        return Err("reconciliation subjects must be non-empty candidates".into());
    }
    match request.action {
        ReconciliationAction::Merge | ReconciliationAction::Alias => {
            let canonical = request
                .canonical_object_id
                .as_deref()
                .ok_or_else(|| "merge and alias require a canonical object".to_string())?;
            if !candidate_ids.contains(canonical) || !subjects.iter().any(|id| id == canonical) {
                return Err("canonical object must be an affected candidate".into());
            }
        }
        _ if request.canonical_object_id.is_some() => {
            return Err("only merge and alias accept a canonical object".into());
        }
        _ => {}
    }
    Ok(())
}

fn validate_candidate_objects(
    tx: &Transaction<'_>,
    request: &ReconciliationRequest,
) -> Result<(), String> {
    for candidate in &request.candidates {
        let object = tx
            .query_row(
                "SELECT id,kind,name,namespace,external_id,properties,created,updated
                 FROM sekai_objects WHERE id=?1",
                [&candidate.object_id],
                row_to_object,
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("candidate object {:?} not found", candidate.object_id))?;
        if object.namespace != request.namespace || object.kind != request.kind {
            return Err(
                "reconciliation candidates must share the requested namespace and kind".into(),
            );
        }
    }
    Ok(())
}

fn validate_authority(
    tx: &Transaction<'_>,
    case_id: &str,
    action: ReconciliationAction,
    canonical_object_id: Option<&str>,
) -> Result<(), String> {
    if !matches!(
        action,
        ReconciliationAction::Merge | ReconciliationAction::Alias
    ) {
        return Ok(());
    }
    let authoritative = {
        let mut statement = tx
            .prepare(
                "SELECT object_id,precedence FROM sekai_reconciliation_candidates
                 WHERE case_id=?1 AND authoritative=1 ORDER BY object_id",
            )
            .map_err(|error| error.to_string())?;
        statement
            .query_map([case_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    if authoritative.is_empty() {
        return Ok(());
    }
    let highest = authoritative
        .iter()
        .map(|(_, precedence)| *precedence)
        .max()
        .unwrap_or_default();
    let winners = authoritative
        .iter()
        .filter(|(_, precedence)| *precedence == highest)
        .collect::<Vec<_>>();
    if winners.len() != 1 || canonical_object_id != Some(winners[0].0.as_str()) {
        return Err(
            "conflicting authoritative mappings require an explicit conflict decision".into(),
        );
    }
    Ok(())
}

fn normalized_subjects(subjects: &[String]) -> Vec<String> {
    subjects
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn reconciliation_request_digest(request: &ReconciliationRequest) -> Result<String, String> {
    let mut canonical = request.clone();
    canonical.idempotency_key.clear();
    canonical.candidates.sort_by(|left, right| {
        (
            &left.object_id,
            &left.source,
            left.precedence,
            left.authoritative,
        )
            .cmp(&(
                &right.object_id,
                &right.source,
                right.precedence,
                right.authoritative,
            ))
    });
    canonical.subjects = normalized_subjects(&canonical.subjects);
    canonical_digest(&serde_json::to_value(canonical).map_err(|error| error.to_string())?)
}

fn ensure_reconciliation_case(
    tx: &Transaction<'_>,
    request: &ReconciliationRequest,
    now_ms: i64,
) -> Result<String, String> {
    if let Some(id) = tx
        .query_row(
            "SELECT id FROM sekai_reconciliation_cases
             WHERE namespace=?1 AND kind=?2 AND external_identity=?3",
            params![request.namespace, request.kind, request.external_identity],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
    {
        return Ok(id);
    }
    let id = format!("reconciliation-case-{}", Uuid::new_v4().simple());
    tx.execute(
        "INSERT INTO sekai_reconciliation_cases
         (id,namespace,kind,external_identity,created_at_ms) VALUES (?1,?2,?3,?4,?5)",
        params![
            id,
            request.namespace,
            request.kind,
            request.external_identity,
            now_ms
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(id)
}

fn persist_candidates(
    tx: &Transaction<'_>,
    case_id: &str,
    candidates: &[ReconciliationCandidate],
) -> Result<(), String> {
    for candidate in candidates {
        let existing = tx
            .query_row(
                "SELECT source,precedence,authoritative FROM sekai_reconciliation_candidates
                 WHERE case_id=?1 AND object_id=?2",
                params![case_id, candidate.object_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i32>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        match existing {
            Some((source, precedence, authoritative))
                if source == candidate.source
                    && precedence == candidate.precedence
                    && authoritative == candidate.authoritative => {}
            Some(_) => return Err("reconciliation candidate provenance is immutable".into()),
            None => {
                tx.execute(
                    "INSERT INTO sekai_reconciliation_candidates
                     (case_id,object_id,source,precedence,authoritative) VALUES (?1,?2,?3,?4,?5)",
                    params![
                        case_id,
                        candidate.object_id,
                        candidate.source,
                        candidate.precedence,
                        candidate.authoritative
                    ],
                )
                .map_err(|error| error.to_string())?;
            }
        }
    }
    Ok(())
}

fn load_reconciliation_decision(
    tx: &Transaction<'_>,
    id: &str,
) -> Result<Option<ReconciliationDecision>, String> {
    tx.query_row(
        "SELECT id,case_id,action,subjects_json,canonical_object_id,actor,reason,
                reverses_decision_id,created_at_ms
         FROM sekai_reconciliation_decisions WHERE id=?1",
        [id],
        row_to_reconciliation_decision,
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn row_to_reconciliation_decision(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ReconciliationDecision> {
    let action: String = row.get(2)?;
    let subjects: String = row.get(3)?;
    Ok(ReconciliationDecision {
        id: row.get(0)?,
        case_id: row.get(1)?,
        action: ReconciliationAction::parse(&action).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, error.into())
        })?,
        subjects: serde_json::from_str(&subjects).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, error.into())
        })?,
        canonical_object_id: row.get(4)?,
        actor: row.get(5)?,
        reason: row.get(6)?,
        reverses_decision_id: row.get(7)?,
        created_at_ms: row.get(8)?,
    })
}

fn list_reconciliation_decisions(
    conn: &rusqlite::Connection,
    case_id: &str,
) -> Result<Vec<ReconciliationDecision>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id,case_id,action,subjects_json,canonical_object_id,actor,reason,
                    reverses_decision_id,created_at_ms
             FROM sekai_reconciliation_decisions
             WHERE case_id=?1 ORDER BY rowid",
        )
        .map_err(|error| error.to_string())?;
    statement
        .query_map([case_id], row_to_reconciliation_decision)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use std::collections::HashMap;
    use std::sync::{Arc, Barrier};

    fn scope(namespace: &str, classification: &str) -> ContentScope {
        ContentScope {
            namespace: namespace.into(),
            classification: classification.into(),
            encryption_key_id: "key-v1".into(),
            residency: "eu".into(),
        }
    }

    fn reference(id: &str, operation: &str) -> ContentReferenceRequest {
        ContentReferenceRequest {
            reference_id: id.into(),
            actor: "adapter".into(),
            operation_id: operation.into(),
            causal_identity: format!("occurrence:{id}"),
            idempotency_key: format!("delivery:{id}"),
            retention_until_ms: None,
            retention_hold: false,
            legal_hold: false,
            archived: false,
            receipt_required: false,
            attestation_required: false,
            preserve_tombstone: true,
        }
    }

    fn object(id: &str, external_id: &str) -> Object {
        Object {
            id: id.into(),
            kind: "artifact".into(),
            name: id.into(),
            namespace: "team-a".into(),
            external_id: external_id.into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        }
    }

    fn candidates() -> Vec<ReconciliationCandidate> {
        vec![
            ReconciliationCandidate {
                object_id: "one".into(),
                source: "primary".into(),
                precedence: 100,
                authoritative: true,
            },
            ReconciliationCandidate {
                object_id: "two".into(),
                source: "secondary".into(),
                precedence: 10,
                authoritative: false,
            },
        ]
    }

    fn reconciliation(action: ReconciliationAction, key: &str) -> ReconciliationRequest {
        ReconciliationRequest {
            namespace: "team-a".into(),
            kind: "artifact".into(),
            external_identity: "vendor:item-7".into(),
            candidates: candidates(),
            action,
            subjects: vec!["one".into(), "two".into()],
            canonical_object_id: matches!(
                action,
                ReconciliationAction::Merge | ReconciliationAction::Alias
            )
            .then(|| "one".into()),
            actor: "reconciler".into(),
            reason: "authoritative mapping".into(),
            idempotency_key: key.into(),
        }
    }

    #[test]
    fn scoped_digests_and_authorized_references_do_not_leak_equality() {
        let db = SekaiDb::new(":memory:").unwrap();
        let public = scope("team-a", "public");
        let restricted = scope("team-a", "restricted");
        let other_namespace = scope("team-b", "public");
        let content = b"identical evidence";
        let first = db
            .put_scoped_content(&public, &reference("ref-a", "op-a"), content, 1)
            .unwrap();
        let second = db
            .put_scoped_content(&public, &reference("ref-b", "op-b"), content, 2)
            .unwrap();
        let restricted_admission = db
            .put_scoped_content(
                &restricted,
                &reference("ref-restricted", "op-c"),
                content,
                3,
            )
            .unwrap();
        assert_eq!(first.reference.blob_id, second.reference.blob_id);
        assert_ne!(
            first.reference.blob_id,
            restricted_admission.reference.blob_id
        );
        assert_ne!(
            first.reference.scoped_digest,
            restricted_admission.reference.scoped_digest
        );
        assert_eq!(
            db.read_scoped_content(&public, "ref-a").unwrap(),
            Some(content.to_vec())
        );
        assert_eq!(db.read_scoped_content(&restricted, "ref-a").unwrap(), None);
        assert_eq!(
            db.read_scoped_content(&other_namespace, "ref-a").unwrap(),
            None
        );
    }

    #[test]
    fn retry_conflicts_and_distinct_occurrences_are_preserved() {
        let db = SekaiDb::new(":memory:").unwrap();
        let scope = scope("team-a", "internal");
        let request = reference("event-1", "operation-1");
        let first = db
            .put_scoped_content(&scope, &request, b"same payload", 1)
            .unwrap();
        let replay = db
            .put_scoped_content(&scope, &request, b"same payload", 2)
            .unwrap();
        assert_eq!(first.reference.reference_id, replay.reference.reference_id);
        assert!(replay.deduplicated);

        let conflict = db
            .put_scoped_content(&scope, &request, b"changed payload", 3)
            .unwrap_err();
        assert!(conflict.contains("different canonical request digest"));

        let second = db
            .put_scoped_content(
                &scope,
                &reference("event-2", "operation-2"),
                b"same payload",
                4,
            )
            .unwrap();
        assert_ne!(first.reference.reference_id, second.reference.reference_id);
        assert_eq!(first.reference.blob_id, second.reference.blob_id);
    }

    #[test]
    fn transaction_failure_rolls_back_blob_reference_and_retry_identity() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.conn()
            .execute_batch(
                "CREATE TRIGGER fail_content_reference BEFORE INSERT ON sekai_content_references
                 BEGIN SELECT RAISE(ABORT, 'simulated crash'); END;",
            )
            .unwrap();
        assert!(
            db.put_scoped_content(
                &scope("team-a", "internal"),
                &reference("crash-ref", "crash-op"),
                b"payload",
                1,
            )
            .is_err()
        );
        let conn = db.conn();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM sekai_content_blobs", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM sekai_idempotency", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        conn.execute_batch("DROP TRIGGER fail_content_reference")
            .unwrap();
        drop(conn);
        db.put_scoped_content(
            &scope("team-a", "internal"),
            &reference("crash-ref", "crash-op"),
            b"payload",
            2,
        )
        .unwrap();
    }

    #[test]
    fn concurrent_replicas_return_one_reference_and_one_blob() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shared.db");
        let replicas = [
            SekaiDb::new(path.to_str().unwrap()).unwrap(),
            SekaiDb::new(path.to_str().unwrap()).unwrap(),
        ];
        let barrier = Arc::new(Barrier::new(2));
        let handles = replicas
            .into_iter()
            .map(|db| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    db.put_scoped_content(
                        &scope("team-a", "internal"),
                        &reference("race-ref", "race-op"),
                        b"payload",
                        1,
                    )
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results[0].reference.blob_id, results[1].reference.blob_id);
        assert!(results.iter().any(|result| result.deduplicated));
        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        assert_eq!(
            db.conn()
                .query_row("SELECT COUNT(*) FROM sekai_content_blobs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn garbage_collection_honors_every_retention_obligation_and_tombstones() {
        let db = SekaiDb::new(":memory:").unwrap();
        let scope = scope("team-a", "restricted");
        let mut requests = vec![reference("plain", "op-plain")];
        for (id, configure) in [
            ("retained", 0_u8),
            ("retention-hold", 1),
            ("legal-hold", 2),
            ("archived", 3),
            ("receipt", 4),
            ("attestation", 5),
        ] {
            let mut request = reference(id, &format!("op-{id}"));
            match configure {
                0 => request.retention_until_ms = Some(100),
                1 => request.retention_hold = true,
                2 => request.legal_hold = true,
                3 => request.archived = true,
                4 => request.receipt_required = true,
                5 => request.attestation_required = true,
                _ => unreachable!(),
            }
            requests.push(request);
        }
        for (index, request) in requests.iter().enumerate() {
            db.put_scoped_content(
                &scope,
                request,
                format!("payload-{index}").as_bytes(),
                index as i64,
            )
            .unwrap();
            db.release_content_reference(
                &scope,
                &request.reference_id,
                "root",
                "subject erasure",
                &format!("release-{}", request.reference_id),
                10,
            )
            .unwrap();
        }
        let first_collection = db
            .collect_scoped_content_garbage(&scope, "collector", 50)
            .unwrap();
        assert_eq!(first_collection.payloads_erased, 1);
        assert_eq!(first_collection.tombstones_preserved, 1);
        for request in requests.iter().skip(1) {
            db.set_content_obligations(
                &scope,
                &request.reference_id,
                &ContentObligations {
                    preserve_tombstone: true,
                    ..ContentObligations::default()
                },
                "retention-admin",
                "obligation released",
                &format!("obligations-{}", request.reference_id),
                150,
            )
            .unwrap();
        }
        let collected = db
            .collect_scoped_content_garbage(&scope, "collector", 150)
            .unwrap();
        assert_eq!(collected.payloads_erased, 6);
        assert_eq!(collected.tombstones_preserved, 6);
        assert_eq!(db.read_scoped_content(&scope, "legal-hold").unwrap(), None);
        assert_eq!(
            db.conn()
                .query_row(
                    "SELECT COUNT(*) FROM sekai_content_references WHERE preserve_tombstone=1",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            7
        );
        assert!(
            db.set_content_obligations(
                &scope,
                "plain",
                &ContentObligations {
                    legal_hold: true,
                    ..ContentObligations::default()
                },
                "retention-admin",
                "late hold",
                "late-hold",
                151,
            )
            .unwrap_err()
            .contains("after payload erasure")
        );
    }

    #[test]
    fn reconciliation_is_audited_reversible_and_preserves_originals() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&object("one", "source-a:7")).unwrap();
        db.create_object(&object("two", "source-b:7")).unwrap();
        let merged = db
            .reconcile_objects(&reconciliation(ReconciliationAction::Merge, "merge-1"), 10)
            .unwrap();
        let replay = db
            .reconcile_objects(&reconciliation(ReconciliationAction::Merge, "merge-1"), 11)
            .unwrap();
        assert!(replay.deduplicated);
        assert_eq!(merged.decision.id, replay.decision.id);
        assert_eq!(
            db.reconciliation_state(&merged.decision.case_id)
                .unwrap()
                .objects["two"],
            ReconciliationDisposition::MergedInto("one".into())
        );
        let reversal = db
            .reverse_reconciliation(
                &merged.decision.id,
                "reviewer",
                "false merge",
                "reverse-1",
                12,
            )
            .unwrap();
        assert_eq!(
            reversal.decision.reverses_decision_id.as_deref(),
            Some(merged.decision.id.as_str())
        );
        let state = db.reconciliation_state(&merged.decision.case_id).unwrap();
        assert_eq!(state.objects["one"], ReconciliationDisposition::Independent);
        assert_eq!(state.objects["two"], ReconciliationDisposition::Independent);
        assert!(db.get_object("one").unwrap().is_some());
        assert!(db.get_object("two").unwrap().is_some());
        assert_eq!(
            db.reconciliation_history(&merged.decision.case_id)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn reconciliation_supports_alias_split_suppression_and_conflict() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&object("one", "source-a:7")).unwrap();
        db.create_object(&object("two", "source-b:7")).unwrap();
        let alias = db
            .reconcile_objects(&reconciliation(ReconciliationAction::Alias, "alias"), 1)
            .unwrap();
        assert_eq!(
            db.reconciliation_state(&alias.decision.case_id)
                .unwrap()
                .objects["two"],
            ReconciliationDisposition::AliasOf("one".into())
        );
        for (action, key, expected) in [
            (
                ReconciliationAction::Split,
                "split",
                ReconciliationDisposition::Independent,
            ),
            (
                ReconciliationAction::Suppress,
                "suppress",
                ReconciliationDisposition::Suppressed,
            ),
            (
                ReconciliationAction::Conflict,
                "conflict",
                ReconciliationDisposition::Conflict,
            ),
        ] {
            db.reconcile_objects(&reconciliation(action, key), 2)
                .unwrap();
            assert_eq!(
                db.reconciliation_state(&alias.decision.case_id)
                    .unwrap()
                    .objects["two"],
                expected
            );
        }
    }

    #[test]
    fn conflicting_authoritative_sources_cannot_be_silently_merged() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&object("one", "source-a:7")).unwrap();
        db.create_object(&object("two", "source-b:7")).unwrap();
        db.create_object(&object("three", "source-c:7")).unwrap();
        db.create_object(&object("four", "source-d:7")).unwrap();
        let mut request = reconciliation(ReconciliationAction::Merge, "merge");
        request.candidates[1].authoritative = true;
        request.candidates[1].precedence = 100;
        assert!(
            db.reconcile_objects(&request, 1)
                .unwrap_err()
                .contains("explicit conflict")
        );
        request.action = ReconciliationAction::Conflict;
        request.canonical_object_id = None;
        request.idempotency_key = "conflict".into();
        db.reconcile_objects(&request, 2).unwrap();

        let partial = ReconciliationRequest {
            candidates: vec![
                ReconciliationCandidate {
                    object_id: "three".into(),
                    source: "tertiary".into(),
                    precedence: 5,
                    authoritative: false,
                },
                ReconciliationCandidate {
                    object_id: "four".into(),
                    source: "quaternary".into(),
                    precedence: 4,
                    authoritative: false,
                },
            ],
            action: ReconciliationAction::Merge,
            subjects: vec!["three".into(), "four".into()],
            canonical_object_id: Some("three".into()),
            idempotency_key: "partial-merge".into(),
            ..request
        };
        assert!(
            db.reconcile_objects(&partial, 3)
                .unwrap_err()
                .contains("explicit conflict")
        );
    }

    #[test]
    fn reconciliation_replays_database_append_order_despite_clock_skew() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&object("one", "source-a:7")).unwrap();
        db.create_object(&object("two", "source-b:7")).unwrap();
        let merged = db
            .reconcile_objects(&reconciliation(ReconciliationAction::Merge, "merge"), 100)
            .unwrap();
        db.reconcile_objects(&reconciliation(ReconciliationAction::Split, "split"), 50)
            .unwrap();
        assert_eq!(
            db.reconciliation_state(&merged.decision.case_id)
                .unwrap()
                .objects["two"],
            ReconciliationDisposition::Independent
        );
        let history = db.reconciliation_history(&merged.decision.case_id).unwrap();
        assert_eq!(history[0].action, ReconciliationAction::Merge);
        assert_eq!(history[1].action, ReconciliationAction::Split);
    }

    #[test]
    fn migration_upgrades_an_existing_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE legacy_marker(value TEXT); INSERT INTO legacy_marker VALUES ('kept');")
                .unwrap();
        }
        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        let conn = db.conn();
        assert_eq!(
            conn.query_row("SELECT value FROM legacy_marker", [], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "kept"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sekai_content_blobs'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }
}
