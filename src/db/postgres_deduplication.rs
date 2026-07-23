use crate::db::postgres::PostgresDb;
use crate::sekai::deduplication::{
    ContentAdmission, ContentObligations, ContentReference, ContentReferenceRequest, ContentScope,
    GarbageCollectionResult, MAX_IDEMPOTENCY_ALIASES, ReconciliationAction,
    ReconciliationCandidate, ReconciliationDecision, ReconciliationDisposition,
    ReconciliationOutcome, ReconciliationRequest, ReconciliationState, canonical_digest,
    reconciliation_request_digest, scoped_content_digest, validate_reconciliation_request,
    validate_reference_request, validate_scope,
};
use postgres::{GenericClient, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

impl PostgresDb {
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
        let digest = reference_request_digest(scope, request, &scoped_digest)?;
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        subject_erasure_barrier(&mut tx)?;
        lifecycle_lock(&mut tx, &scope.namespace)?;
        if let Some(id) = check_idempotency(
            &mut tx,
            &scope.namespace,
            "content.put",
            &request.idempotency_key,
            &digest,
        )? {
            let reference = load_reference(&mut tx, &id)?
                .ok_or_else(|| "idempotency record references missing content".to_string())?;
            tx.commit().map_err(err)?;
            return Ok(ContentAdmission {
                reference,
                stored_new_blob: false,
                deduplicated: true,
            });
        }
        if let Some(existing) = load_reference(&mut tx, &request.reference_id)? {
            if reference_digest(&existing)? != digest {
                return Err("content reference identity was reused for a different request".into());
            }
            insert_idempotency(
                &mut tx,
                &scope.namespace,
                "content.put",
                &request.idempotency_key,
                &digest,
                "content_reference",
                &request.reference_id,
                now_ms,
            )?;
            tx.commit().map_err(err)?;
            return Ok(ContentAdmission {
                reference: existing,
                stored_new_blob: false,
                deduplicated: true,
            });
        }
        let existing = tx
            .query_opt(
                "SELECT id,content FROM sekai_content_blobs
                 WHERE namespace=$1 AND classification=$2 AND encryption_key_id=$3
                   AND residency=$4 AND scoped_digest=$5 FOR UPDATE",
                &[
                    &scope.namespace,
                    &scope.classification,
                    &scope.encryption_key_id,
                    &scope.residency,
                    &scoped_digest,
                ],
            )
            .map_err(err)?;
        let (blob_id, stored_new_blob) = match existing {
            Some(row) => {
                let id: String = row.get(0);
                let stored: Option<Vec<u8>> = row.get(1);
                match stored {
                    None => {
                        return Err(
                            "content digest is retained as an erasure tombstone in this scope"
                                .into(),
                        );
                    }
                    Some(stored) if stored == content => (id, false),
                    Some(_) => return Err("scoped content digest collision".into()),
                }
            }
            None => {
                let id = format!("blob-{}", Uuid::new_v4().simple());
                tx.execute(
                    "INSERT INTO sekai_content_blobs
                     (id,namespace,classification,encryption_key_id,residency,scoped_digest,
                      content,content_size,created_at_ms)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                    &[
                        &id,
                        &scope.namespace,
                        &scope.classification,
                        &scope.encryption_key_id,
                        &scope.residency,
                        &scoped_digest,
                        &content,
                        &(content.len() as i64),
                        &now_ms,
                    ],
                )
                .map_err(err)?;
                (id, true)
            }
        };
        tx.execute(
            "INSERT INTO sekai_content_references
             (reference_id,blob_id,namespace,actor,operation_id,causal_identity,
              retention_until_ms,retention_hold,legal_hold,archived,receipt_required,
              attestation_required,preserve_tombstone,created_at_ms)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            &[
                &request.reference_id,
                &blob_id,
                &scope.namespace,
                &request.actor,
                &request.operation_id,
                &request.causal_identity,
                &request.retention_until_ms,
                &request.retention_hold,
                &request.legal_hold,
                &request.archived,
                &request.receipt_required,
                &request.attestation_required,
                &request.preserve_tombstone,
                &now_ms,
            ],
        )
        .map_err(err)?;
        content_event(
            &mut tx,
            "reference_created",
            &blob_id,
            Some(&request.reference_id),
            &request.actor,
            "content admitted",
            now_ms,
        )?;
        insert_idempotency(
            &mut tx,
            &scope.namespace,
            "content.put",
            &request.idempotency_key,
            &digest,
            "content_reference",
            &request.reference_id,
            now_ms,
        )?;
        let reference = load_reference(&mut tx, &request.reference_id)?
            .ok_or_else(|| "inserted content reference disappeared".to_string())?;
        tx.commit().map_err(err)?;
        Ok(ContentAdmission {
            reference,
            stored_new_blob,
            deduplicated: false,
        })
    }

    pub fn read_scoped_content(
        &self,
        scope: &ContentScope,
        reference_id: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        validate_scope(scope)?;
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT b.content FROM sekai_content_references r
                 JOIN sekai_content_blobs b ON b.id=r.blob_id
                 WHERE r.reference_id=$1 AND r.released_at_ms IS NULL
                   AND b.namespace=$2 AND b.classification=$3
                   AND b.encryption_key_id=$4 AND b.residency=$5",
                &[
                    &reference_id,
                    &scope.namespace,
                    &scope.classification,
                    &scope.encryption_key_id,
                    &scope.residency,
                ],
            )
            .map(|row| row.and_then(|row| row.get::<_, Option<Vec<u8>>>(0)))
            .map_err(err)
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
        require(&[
            ("reference_id", reference_id),
            ("actor", actor),
            ("reason", reason),
            ("idempotency_key", idempotency_key),
        ])?;
        let digest = canonical_digest(&serde_json::json!({
            "scope": scope, "reference_id": reference_id, "actor": actor, "reason": reason
        }))?;
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        subject_erasure_barrier(&mut tx)?;
        lifecycle_lock(&mut tx, &scope.namespace)?;
        if check_idempotency(
            &mut tx,
            &scope.namespace,
            "content.release",
            idempotency_key,
            &digest,
        )?
        .is_some()
        {
            tx.commit().map_err(err)?;
            return Ok(true);
        }
        let reference = load_reference(&mut tx, reference_id)?
            .filter(|value| value.scope == *scope)
            .ok_or_else(|| "content reference not found".to_string())?;
        let deduplicated = reference.released_at_ms.is_some();
        if !deduplicated {
            tx.execute(
                "UPDATE sekai_content_references
                 SET released_at_ms=$1,release_reason=$2 WHERE reference_id=$3",
                &[&now_ms, &reason, &reference_id],
            )
            .map_err(err)?;
            content_event(
                &mut tx,
                "reference_released",
                &reference.blob_id,
                Some(reference_id),
                actor,
                reason,
                now_ms,
            )?;
        }
        insert_idempotency(
            &mut tx,
            &scope.namespace,
            "content.release",
            idempotency_key,
            &digest,
            "content_reference",
            reference_id,
            now_ms,
        )?;
        tx.commit().map_err(err)?;
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
        require(&[
            ("reference_id", reference_id),
            ("actor", actor),
            ("reason", reason),
            ("idempotency_key", idempotency_key),
        ])?;
        let digest = canonical_digest(&serde_json::json!({
            "scope": scope, "reference_id": reference_id, "obligations": obligations,
            "actor": actor, "reason": reason
        }))?;
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        subject_erasure_barrier(&mut tx)?;
        lifecycle_lock(&mut tx, &scope.namespace)?;
        if check_idempotency(
            &mut tx,
            &scope.namespace,
            "content.obligations",
            idempotency_key,
            &digest,
        )?
        .is_some()
        {
            tx.commit().map_err(err)?;
            return Ok(true);
        }
        let reference = load_reference(&mut tx, reference_id)?
            .filter(|value| value.scope == *scope)
            .ok_or_else(|| "content reference not found".to_string())?;
        let payload_erased: bool = tx
            .query_one(
                "SELECT content IS NULL FROM sekai_content_blobs WHERE id=$1 FOR UPDATE",
                &[&reference.blob_id],
            )
            .map_err(err)?
            .get(0);
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
                "UPDATE sekai_content_references SET retention_until_ms=$1,retention_hold=$2,
                 legal_hold=$3,archived=$4,receipt_required=$5,attestation_required=$6,
                 preserve_tombstone=$7 WHERE reference_id=$8",
                &[
                    &obligations.retention_until_ms,
                    &obligations.retention_hold,
                    &obligations.legal_hold,
                    &obligations.archived,
                    &obligations.receipt_required,
                    &obligations.attestation_required,
                    &obligations.preserve_tombstone,
                    &reference_id,
                ],
            )
            .map_err(err)?;
            content_event(
                &mut tx,
                "obligations_updated",
                &reference.blob_id,
                Some(reference_id),
                actor,
                reason,
                now_ms,
            )?;
        }
        insert_idempotency(
            &mut tx,
            &scope.namespace,
            "content.obligations",
            idempotency_key,
            &digest,
            "content_reference",
            reference_id,
            now_ms,
        )?;
        tx.commit().map_err(err)?;
        Ok(unchanged)
    }

    pub fn collect_scoped_content_garbage(
        &self,
        scope: &ContentScope,
        actor: &str,
        now_ms: i64,
    ) -> Result<GarbageCollectionResult, String> {
        validate_scope(scope)?;
        require(&[("actor", actor)])?;
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        subject_erasure_barrier(&mut tx)?;
        lifecycle_lock(&mut tx, &scope.namespace)?;
        let rows = tx
            .query(
                "SELECT b.id FROM sekai_content_blobs b
                 WHERE b.namespace=$1 AND b.classification=$2 AND b.encryption_key_id=$3
                   AND b.residency=$4 AND b.content IS NOT NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM sekai_content_references r WHERE r.blob_id=b.id AND (
                       r.released_at_ms IS NULL OR r.retention_hold OR r.legal_hold OR r.archived
                       OR r.receipt_required OR r.attestation_required
                       OR COALESCE(r.retention_until_ms,0)>$5))
                 ORDER BY b.id FOR UPDATE OF b",
                &[
                    &scope.namespace,
                    &scope.classification,
                    &scope.encryption_key_id,
                    &scope.residency,
                    &now_ms,
                ],
            )
            .map_err(err)?;
        let mut result = GarbageCollectionResult::default();
        for row in rows {
            let blob_id: String = row.get(0);
            let changed = tx
                .execute(
                    "UPDATE sekai_content_blobs SET content=NULL,erased_at_ms=$1
                     WHERE id=$2 AND content IS NOT NULL",
                    &[&now_ms, &blob_id],
                )
                .map_err(err)?;
            if changed == 0 {
                continue;
            }
            result.payloads_erased += 1;
            let count: i64 = tx
                .query_one(
                    "SELECT COUNT(*) FROM sekai_content_references
                     WHERE blob_id=$1 AND preserve_tombstone",
                    &[&blob_id],
                )
                .map_err(err)?
                .get(0);
            result.tombstones_preserved += count as u64;
            content_event(
                &mut tx,
                "payload_erased",
                &blob_id,
                None,
                actor,
                "no retaining reference",
                now_ms,
            )?;
        }
        tx.commit().map_err(err)?;
        Ok(result)
    }

    pub fn reconcile_objects(
        &self,
        request: &ReconciliationRequest,
        now_ms: i64,
    ) -> Result<ReconciliationOutcome, String> {
        validate_reconciliation_request(request)?;
        let digest = reconciliation_request_digest(request)?;
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        subject_erasure_barrier(&mut tx)?;
        lifecycle_lock(&mut tx, &request.namespace)?;
        if let Some(id) = check_idempotency(
            &mut tx,
            &request.namespace,
            "object.reconcile",
            &request.idempotency_key,
            &digest,
        )? {
            let decision = load_decision(&mut tx, &id)?.ok_or_else(|| {
                "idempotency record references missing reconciliation".to_string()
            })?;
            tx.commit().map_err(err)?;
            return Ok(ReconciliationOutcome {
                decision,
                deduplicated: true,
            });
        }
        validate_candidates(&mut tx, request)?;
        let case_id = ensure_case(&mut tx, request, now_ms)?;
        persist_candidates(&mut tx, &case_id, &request.candidates)?;
        validate_authority(
            &mut tx,
            &case_id,
            request.action,
            request.canonical_object_id.as_deref(),
        )?;
        let id = format!("reconciliation-{}", Uuid::new_v4().simple());
        let subjects = normalized_subjects(&request.subjects);
        let subjects_json = serde_json::to_string(&subjects).map_err(err)?;
        tx.execute(
            "INSERT INTO sekai_reconciliation_decisions
             (id,case_id,action,subjects_json,canonical_object_id,actor,reason,
              request_digest,created_at_ms)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &id,
                &case_id,
                &request.action.as_str(),
                &subjects_json,
                &request.canonical_object_id,
                &request.actor,
                &request.reason,
                &digest,
                &now_ms,
            ],
        )
        .map_err(err)?;
        insert_idempotency(
            &mut tx,
            &request.namespace,
            "object.reconcile",
            &request.idempotency_key,
            &digest,
            "reconciliation_decision",
            &id,
            now_ms,
        )?;
        let decision = load_decision(&mut tx, &id)?
            .ok_or_else(|| "inserted reconciliation disappeared".to_string())?;
        tx.commit().map_err(err)?;
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
        require(&[
            ("decision_id", decision_id),
            ("actor", actor),
            ("reason", reason),
            ("idempotency_key", idempotency_key),
        ])?;
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(err)?;
        subject_erasure_barrier(&mut tx)?;
        let original = load_decision(&mut tx, decision_id)?
            .ok_or_else(|| "reconciliation decision not found".to_string())?;
        if original.reverses_decision_id.is_some() {
            return Err("reversal decisions cannot themselves be reversed".into());
        }
        let namespace: String = tx
            .query_one(
                "SELECT namespace FROM sekai_reconciliation_cases WHERE id=$1",
                &[&original.case_id],
            )
            .map_err(err)?
            .get(0);
        lifecycle_lock(&mut tx, &namespace)?;
        let digest = canonical_digest(&serde_json::json!({
            "decision_id": decision_id, "actor": actor, "reason": reason
        }))?;
        if let Some(id) = check_idempotency(
            &mut tx,
            &namespace,
            "object.reconcile.reverse",
            idempotency_key,
            &digest,
        )? {
            let decision = load_decision(&mut tx, &id)?
                .ok_or_else(|| "idempotency record references missing reversal".to_string())?;
            tx.commit().map_err(err)?;
            return Ok(ReconciliationOutcome {
                decision,
                deduplicated: true,
            });
        }
        if tx
            .query_opt(
                "SELECT id FROM sekai_reconciliation_decisions
                 WHERE reverses_decision_id=$1",
                &[&decision_id],
            )
            .map_err(err)?
            .is_some()
        {
            return Err("reconciliation decision is already reversed".into());
        }
        let id = format!("reconciliation-{}", Uuid::new_v4().simple());
        tx.execute(
            "INSERT INTO sekai_reconciliation_decisions
             (id,case_id,action,subjects_json,canonical_object_id,actor,reason,
              request_digest,reverses_decision_id,created_at_ms)
             VALUES($1,$2,'split','[]',NULL,$3,$4,$5,$6,$7)",
            &[
                &id,
                &original.case_id,
                &actor,
                &reason,
                &digest,
                &decision_id,
                &now_ms,
            ],
        )
        .map_err(err)?;
        insert_idempotency(
            &mut tx,
            &namespace,
            "object.reconcile.reverse",
            idempotency_key,
            &digest,
            "reconciliation_decision",
            &id,
            now_ms,
        )?;
        let decision = load_decision(&mut tx, &id)?
            .ok_or_else(|| "inserted reconciliation reversal disappeared".to_string())?;
        tx.commit().map_err(err)?;
        Ok(ReconciliationOutcome {
            decision,
            deduplicated: false,
        })
    }

    pub fn reconciliation_state(&self, case_id: &str) -> Result<ReconciliationState, String> {
        require(&[("case_id", case_id)])?;
        let mut connection = self.connection()?;
        let rows = connection
            .query(
                "SELECT object_id FROM sekai_reconciliation_candidates
                 WHERE case_id=$1 ORDER BY object_id",
                &[&case_id],
            )
            .map_err(err)?;
        if rows.is_empty() {
            return Err("reconciliation case not found".into());
        }
        let decisions = list_decisions(&mut *connection, case_id)?;
        state_from(rows.into_iter().map(|row| row.get(0)), case_id, decisions)
    }

    pub fn reconciliation_history(
        &self,
        case_id: &str,
    ) -> Result<Vec<ReconciliationDecision>, String> {
        require(&[("case_id", case_id)])?;
        let mut connection = self.connection()?;
        list_decisions(&mut *connection, case_id)
    }
}

fn lifecycle_lock(tx: &mut Transaction<'_>, scope: &str) -> Result<(), String> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 251))",
        &[&scope],
    )
    .map(|_| ())
    .map_err(err)
}

fn subject_erasure_barrier(tx: &mut Transaction<'_>) -> Result<(), String> {
    tx.query_one("SELECT pg_advisory_xact_lock_shared(251,251)", &[])
        .map(|_| ())
        .map_err(err)
}

fn reference_request_digest(
    scope: &ContentScope,
    request: &ContentReferenceRequest,
    scoped_digest: &str,
) -> Result<String, String> {
    canonical_digest(&serde_json::json!({
        "scope": scope, "reference_id": request.reference_id, "actor": request.actor,
        "operation_id": request.operation_id, "causal_identity": request.causal_identity,
        "retention_until_ms": request.retention_until_ms, "retention_hold": request.retention_hold,
        "legal_hold": request.legal_hold, "archived": request.archived,
        "receipt_required": request.receipt_required,
        "attestation_required": request.attestation_required,
        "preserve_tombstone": request.preserve_tombstone, "scoped_digest": scoped_digest
    }))
}

fn reference_digest(reference: &ContentReference) -> Result<String, String> {
    canonical_digest(&serde_json::json!({
        "scope": reference.scope, "reference_id": reference.reference_id,
        "actor": reference.actor, "operation_id": reference.operation_id,
        "causal_identity": reference.causal_identity,
        "retention_until_ms": reference.retention_until_ms,
        "retention_hold": reference.retention_hold, "legal_hold": reference.legal_hold,
        "archived": reference.archived, "receipt_required": reference.receipt_required,
        "attestation_required": reference.attestation_required,
        "preserve_tombstone": reference.preserve_tombstone,
        "scoped_digest": reference.scoped_digest
    }))
}

fn load_reference(
    client: &mut impl GenericClient,
    id: &str,
) -> Result<Option<ContentReference>, String> {
    client
        .query_opt(
            "SELECT r.reference_id,r.blob_id,b.namespace,b.classification,b.encryption_key_id,
             b.residency,b.scoped_digest,r.actor,r.operation_id,r.causal_identity,
             r.retention_until_ms,r.retention_hold,r.legal_hold,r.archived,r.receipt_required,
             r.attestation_required,r.preserve_tombstone,r.created_at_ms,r.released_at_ms
             FROM sekai_content_references r JOIN sekai_content_blobs b ON b.id=r.blob_id
             WHERE r.reference_id=$1",
            &[&id],
        )
        .map(|row| row.map(row_reference))
        .map_err(err)
}

fn row_reference(row: Row) -> ContentReference {
    ContentReference {
        reference_id: row.get(0),
        blob_id: row.get(1),
        scope: ContentScope {
            namespace: row.get(2),
            classification: row.get(3),
            encryption_key_id: row.get(4),
            residency: row.get(5),
        },
        scoped_digest: row.get(6),
        actor: row.get(7),
        operation_id: row.get(8),
        causal_identity: row.get(9),
        retention_until_ms: row.get(10),
        retention_hold: row.get(11),
        legal_hold: row.get(12),
        archived: row.get(13),
        receipt_required: row.get(14),
        attestation_required: row.get(15),
        preserve_tombstone: row.get(16),
        created_at_ms: row.get(17),
        released_at_ms: row.get(18),
    }
}

fn check_idempotency(
    client: &mut impl GenericClient,
    scope: &str,
    operation: &str,
    key: &str,
    digest: &str,
) -> Result<Option<String>, String> {
    let row = client
        .query_opt(
            "SELECT request_digest,result_id FROM sekai_lifecycle_idempotency
             WHERE scope=$1 AND operation=$2 AND idempotency_key=$3",
            &[&scope, &operation, &key],
        )
        .map_err(err)?;
    match row {
        None => Ok(None),
        Some(row) if row.get::<_, String>(0) == digest => Ok(Some(row.get(1))),
        Some(_) => Err("idempotency key was reused with a different request".into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_idempotency(
    client: &mut impl GenericClient,
    scope: &str,
    operation: &str,
    key: &str,
    digest: &str,
    result_kind: &str,
    result_id: &str,
    now_ms: i64,
) -> Result<(), String> {
    let aliases: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM sekai_lifecycle_idempotency
             WHERE scope=$1 AND operation=$2 AND result_kind=$3 AND result_id=$4",
            &[&scope, &operation, &result_kind, &result_id],
        )
        .map_err(err)?
        .get(0);
    if aliases >= MAX_IDEMPOTENCY_ALIASES {
        return Err("idempotency alias capacity exceeded".into());
    }
    client
        .execute(
            "INSERT INTO sekai_lifecycle_idempotency
             (scope,operation,idempotency_key,request_digest,result_kind,result_id,created_at_ms)
             VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[
                &scope,
                &operation,
                &key,
                &digest,
                &result_kind,
                &result_id,
                &now_ms,
            ],
        )
        .map(|_| ())
        .map_err(err)
}

fn content_event(
    client: &mut impl GenericClient,
    kind: &str,
    blob_id: &str,
    reference_id: Option<&str>,
    actor: &str,
    reason: &str,
    now_ms: i64,
) -> Result<(), String> {
    client
        .execute(
            "INSERT INTO sekai_content_events
             (id,event_kind,blob_id,reference_id,actor,reason,created_at_ms)
             VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[
                &format!("content-event-{}", Uuid::new_v4().simple()),
                &kind,
                &blob_id,
                &reference_id,
                &actor,
                &reason,
                &now_ms,
            ],
        )
        .map(|_| ())
        .map_err(err)
}

fn validate_candidates(
    client: &mut impl GenericClient,
    request: &ReconciliationRequest,
) -> Result<(), String> {
    for candidate in &request.candidates {
        let row = client
            .query_opt(
                "SELECT namespace,kind,external_id FROM sekai_objects WHERE id=$1",
                &[&candidate.object_id],
            )
            .map_err(err)?
            .ok_or_else(|| format!("candidate object {} not found", candidate.object_id))?;
        if row.get::<_, String>(0) != request.namespace || row.get::<_, String>(1) != request.kind {
            return Err(
                "reconciliation candidates must share the requested namespace and kind".into(),
            );
        }
    }
    Ok(())
}

fn ensure_case(
    client: &mut impl GenericClient,
    request: &ReconciliationRequest,
    now_ms: i64,
) -> Result<String, String> {
    if let Some(row) = client
        .query_opt(
            "SELECT id FROM sekai_reconciliation_cases
             WHERE namespace=$1 AND kind=$2 AND external_identity=$3",
            &[
                &request.namespace,
                &request.kind,
                &request.external_identity,
            ],
        )
        .map_err(err)?
    {
        return Ok(row.get(0));
    }
    let id = format!("reconciliation-case-{}", Uuid::new_v4().simple());
    client
        .execute(
            "INSERT INTO sekai_reconciliation_cases
             (id,namespace,kind,external_identity,created_at_ms) VALUES($1,$2,$3,$4,$5)",
            &[
                &id,
                &request.namespace,
                &request.kind,
                &request.external_identity,
                &now_ms,
            ],
        )
        .map_err(err)?;
    Ok(id)
}

fn persist_candidates(
    client: &mut impl GenericClient,
    case_id: &str,
    candidates: &[ReconciliationCandidate],
) -> Result<(), String> {
    for candidate in candidates {
        let changed = client
            .execute(
                "INSERT INTO sekai_reconciliation_candidates
                 (case_id,object_id,source,precedence,authoritative)
                 VALUES($1,$2,$3,$4,$5)
                 ON CONFLICT(case_id,object_id) DO UPDATE SET
                   source=EXCLUDED.source,precedence=EXCLUDED.precedence,
                   authoritative=EXCLUDED.authoritative
                 WHERE sekai_reconciliation_candidates.source=EXCLUDED.source
                   AND sekai_reconciliation_candidates.precedence=EXCLUDED.precedence
                   AND sekai_reconciliation_candidates.authoritative=EXCLUDED.authoritative",
                &[
                    &case_id,
                    &candidate.object_id,
                    &candidate.source,
                    &candidate.precedence,
                    &candidate.authoritative,
                ],
            )
            .map_err(err)?;
        if changed == 0 {
            return Err("reconciliation candidate metadata cannot be changed".into());
        }
    }
    Ok(())
}

fn validate_authority(
    client: &mut impl GenericClient,
    case_id: &str,
    action: ReconciliationAction,
    canonical: Option<&str>,
) -> Result<(), String> {
    if !matches!(
        action,
        ReconciliationAction::Merge | ReconciliationAction::Alias
    ) {
        return Ok(());
    }
    let canonical = canonical.ok_or_else(|| "canonical_object_id is required".to_string())?;
    let authoritative = client
        .query(
            "SELECT object_id,precedence,authoritative
             FROM sekai_reconciliation_candidates
             WHERE case_id=$1 AND authoritative ORDER BY object_id",
            &[&case_id],
        )
        .map_err(err)?;
    if authoritative.is_empty() {
        return Ok(());
    }
    let highest = authoritative
        .iter()
        .map(|row| row.get::<_, i32>(1))
        .max()
        .unwrap_or_default();
    let winners = authoritative
        .iter()
        .filter(|row| row.get::<_, i32>(1) == highest)
        .collect::<Vec<_>>();
    if winners.len() != 1 || winners[0].get::<_, String>(0) != canonical {
        return Err(
            "conflicting authoritative mappings require an explicit conflict decision".into(),
        );
    }
    Ok(())
}

fn normalized_subjects(subjects: &[String]) -> Vec<String> {
    let mut subjects = subjects.to_vec();
    subjects.sort();
    subjects.dedup();
    subjects
}

fn load_decision(
    client: &mut impl GenericClient,
    id: &str,
) -> Result<Option<ReconciliationDecision>, String> {
    client
        .query_opt(
            "SELECT id,case_id,action,subjects_json,canonical_object_id,actor,reason,
             reverses_decision_id,created_at_ms
             FROM sekai_reconciliation_decisions WHERE id=$1",
            &[&id],
        )
        .map_err(err)?
        .map(row_decision)
        .transpose()
}

fn list_decisions(
    client: &mut impl GenericClient,
    case_id: &str,
) -> Result<Vec<ReconciliationDecision>, String> {
    client
        .query(
            "SELECT id,case_id,action,subjects_json,canonical_object_id,actor,reason,
             reverses_decision_id,created_at_ms
             FROM sekai_reconciliation_decisions WHERE case_id=$1
             ORDER BY created_at_ms,id",
            &[&case_id],
        )
        .map_err(err)?
        .into_iter()
        .map(row_decision)
        .collect()
}

fn row_decision(row: Row) -> Result<ReconciliationDecision, String> {
    Ok(ReconciliationDecision {
        id: row.get(0),
        case_id: row.get(1),
        action: ReconciliationAction::parse(row.get::<_, String>(2).as_str())?,
        subjects: serde_json::from_str(row.get::<_, String>(3).as_str()).map_err(err)?,
        canonical_object_id: row.get(4),
        actor: row.get(5),
        reason: row.get(6),
        reverses_decision_id: row.get(7),
        created_at_ms: row.get(8),
    })
}

fn state_from(
    objects: impl Iterator<Item = String>,
    case_id: &str,
    decisions: Vec<ReconciliationDecision>,
) -> Result<ReconciliationState, String> {
    let reversed = decisions
        .iter()
        .filter_map(|decision| decision.reverses_decision_id.clone())
        .collect::<BTreeSet<_>>();
    let mut state = objects
        .map(|id| (id, ReconciliationDisposition::Independent))
        .collect::<BTreeMap<_, _>>();
    for decision in decisions {
        if decision.reverses_decision_id.is_some() || reversed.contains(&decision.id) {
            continue;
        }
        match decision.action {
            ReconciliationAction::Merge | ReconciliationAction::Alias => {
                let canonical = decision
                    .canonical_object_id
                    .ok_or_else(|| "stored reconciliation lacks canonical object".to_string())?;
                for subject in decision.subjects {
                    let disposition = if subject == canonical {
                        ReconciliationDisposition::Independent
                    } else if decision.action == ReconciliationAction::Merge {
                        ReconciliationDisposition::MergedInto(canonical.clone())
                    } else {
                        ReconciliationDisposition::AliasOf(canonical.clone())
                    };
                    state.insert(subject, disposition);
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
        case_id: case_id.into(),
        objects: state,
    })
}

fn require(values: &[(&str, &str)]) -> Result<(), String> {
    for (name, value) in values {
        if value.trim().is_empty() {
            return Err(format!("{name} is required"));
        }
    }
    Ok(())
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
