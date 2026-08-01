//! PostgreSQL persistence for governed Kioku institutional memory.

use crate::chisei::kioku::{
    HumanMemoryReview, HumanReviewAction, KIOKU_EVIDENCE_REASSESSMENT_METHOD, KiokuCandidateCursor,
    KiokuEvidenceLink, KiokuMemory, MemoryEvidenceStance, MemoryLifecycleEvent,
    MemoryLifecycleState, MemoryValidation,
};
use crate::db::postgres::PostgresDb;
use crate::sekai::evidence::{EvidenceClassification, EvidenceLifecycleState};

impl PostgresDb {
    pub fn insert_kioku_memory(
        &self,
        memory: &KiokuMemory,
        evidence: &[KiokuEvidenceLink],
    ) -> Result<(), String> {
        memory
            .validate_contract()
            .map_err(|errors| errors.join("; "))?;
        if memory.state != MemoryLifecycleState::Candidate || memory.reviewed_at_ms.is_some() {
            return Err("new memories must be unreviewed candidates".into());
        }
        if evidence.is_empty() {
            return Err("at least one evidence link is required".into());
        }
        if !evidence
            .iter()
            .any(|link| link.stance == MemoryEvidenceStance::Supporting)
        {
            return Err("at least one supporting evidence link is required".into());
        }
        for link in evidence {
            link.validate(memory)?;
        }

        let memory_json = serde_json::to_string(memory).map_err(|error| error.to_string())?;
        let version = i64::from(memory.version);
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO chisei_kioku_memories
             (id, version, namespace, state, classification, expires_at_ms, memory_json)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &memory.id,
                &version,
                &memory.namespace,
                &memory.state.as_str(),
                &memory.classification.as_str(),
                &memory.expires_at_ms,
                &memory_json,
            ],
        )
        .map_err(|error| error.to_string())?;
        for link in evidence {
            let link_json = serde_json::to_string(link).map_err(|error| error.to_string())?;
            let stance = match link.stance {
                MemoryEvidenceStance::Supporting => "supporting",
                MemoryEvidenceStance::Contradicting => "contradicting",
            };
            let memory_version = i64::from(link.memory_version);
            tx.execute(
                "INSERT INTO chisei_kioku_evidence_links
                 (memory_id, memory_version, operation_id, stance, link_json)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &link.memory_id,
                    &memory_version,
                    &link.operation_id,
                    &stance,
                    &link_json,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        insert_lifecycle_event(
            &mut tx,
            &MemoryLifecycleEvent {
                memory_id: memory.id.clone(),
                memory_version: memory.version,
                action: if memory.derivation_method
                    == crate::chisei::kioku::KIOKU_EVIDENCE_REASSESSMENT_METHOD
                {
                    "evidence_reassessed".into()
                } else {
                    "created".into()
                },
                from_state: None,
                to_state: memory.state.as_str().into(),
                actor: if memory.reassessment_actor.is_empty() {
                    memory.producer_identity.clone()
                } else {
                    memory.reassessment_actor.clone()
                },
                reason: if memory.reassessment_key.is_empty() {
                    memory.derivation_method.clone()
                } else {
                    format!(
                        "{} key={} basis={}",
                        memory.derivation_method,
                        memory.reassessment_key,
                        memory.evidence_basis_digest
                    )
                },
                recorded_at_ms: memory.created_at_ms,
            },
        )?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String> {
        let version = i64::from(version);
        let memory_json = self
            .connection()?
            .query_opt(
                "SELECT memory_json FROM chisei_kioku_memories WHERE id = $1 AND version = $2",
                &[&id, &version],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0));
        memory_json
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn list_kioku_candidates(
        &self,
        namespace: &str,
        operation_class: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KiokuMemory>, String> {
        if namespace.trim().is_empty() {
            return Err("candidate namespace is required".into());
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rows = self
            .connection()?
            .query(
                "SELECT memory_json FROM chisei_kioku_memories
                 WHERE namespace = $1 AND state = 'candidate'
                 ORDER BY version DESC, id DESC",
                &[&namespace.trim()],
            )
            .map_err(|error| error.to_string())?;
        let operation_class = operation_class
            .map(str::trim)
            .filter(|value| !value.is_empty());
        rows.into_iter()
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .filter_map(|memory: Result<KiokuMemory, String>| match memory {
                Ok(memory)
                    if operation_class.is_none_or(|class| {
                        memory
                            .operation_classes
                            .iter()
                            .any(|candidate| candidate == class)
                    }) =>
                {
                    Some(Ok(memory))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .take(limit)
            .collect()
    }

    pub fn list_kioku_candidate_page(
        &self,
        namespace: &str,
        limit: usize,
        cursor: Option<&KiokuCandidateCursor>,
    ) -> Result<Vec<KiokuMemory>, String> {
        if namespace.trim().is_empty() {
            return Err("candidate namespace is required".into());
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| "candidate page limit is too large")?;
        let cursor_id = cursor.map(|cursor| cursor.id.clone());
        let cursor_version = cursor.map(|cursor| i64::from(cursor.version));
        let rows = self
            .connection()?
            .query(
                "SELECT memory_json FROM chisei_kioku_memories
                 WHERE namespace = $1 AND state = 'candidate'
                   AND ($2::text IS NULL OR id < $2 OR (id=$2 AND version < $3))
                 ORDER BY id DESC, version DESC LIMIT $4",
                &[&namespace.trim(), &cursor_id, &cursor_version, &limit],
            )
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .collect()
    }

    pub fn list_kioku_evidence(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<KiokuEvidenceLink>, String> {
        let version = i64::from(version);
        let rows = self
            .connection()?
            .query(
                "SELECT link_json FROM chisei_kioku_evidence_links
                 WHERE memory_id = $1 AND memory_version = $2 ORDER BY operation_id",
                &[&id, &version],
            )
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .collect()
    }

    pub fn validate_kioku_candidate(
        &self,
        id: &str,
        version: u32,
    ) -> Result<MemoryValidation, String> {
        let Some(memory) = self.get_kioku_memory(id, version)? else {
            return Err(format!("memory {id} version {version} not found"));
        };
        let evidence = self.list_kioku_evidence(id, version)?;
        let mut errors = memory.validate_contract().err().unwrap_or_default();
        if memory.state != MemoryLifecycleState::Candidate {
            errors.push("only candidate memories can be validated for review".into());
        }
        let (supporting_evidence, contradicting_evidence, expected_confidence) =
            if memory.evidence_basis.is_empty() {
                let supporting = evidence
                    .iter()
                    .filter(|link| link.stance == MemoryEvidenceStance::Supporting)
                    .count();
                if supporting == 0 {
                    errors.push("candidate requires supporting evidence".into());
                }
                if evidence.len() != memory.sample_size as usize {
                    errors.push(format!(
                        "sample_size {} does not match {} evidence links",
                        memory.sample_size,
                        evidence.len()
                    ));
                }
                let expected = if evidence.is_empty() {
                    0
                } else {
                    ((supporting as u64 * 10_000) / evidence.len() as u64) as u16
                };
                (
                    supporting,
                    evidence.len().saturating_sub(supporting),
                    expected,
                )
            } else {
                let supporting = memory
                    .evidence_basis
                    .iter()
                    .filter(|basis| basis.stance == MemoryEvidenceStance::Supporting)
                    .count();
                let contradicting = memory
                    .evidence_basis
                    .iter()
                    .filter(|basis| basis.stance == MemoryEvidenceStance::Contradicting)
                    .count();
                let usable = memory
                    .evidence_basis
                    .iter()
                    .filter(|basis| basis.lifecycle_state.is_usable())
                    .collect::<Vec<_>>();
                let usable_supporting = usable
                    .iter()
                    .filter(|basis| basis.stance == MemoryEvidenceStance::Supporting)
                    .count();
                if usable_supporting == 0
                    && memory.derivation_method != KIOKU_EVIDENCE_REASSESSMENT_METHOD
                {
                    errors.push("candidate requires usable supporting evidence".into());
                }
                if memory.evidence_basis.len() != memory.sample_size as usize {
                    errors.push(format!(
                        "sample_size {} does not match {} evidence basis entries",
                        memory.sample_size,
                        memory.evidence_basis.len()
                    ));
                }
                let expected = if usable.is_empty() {
                    0
                } else {
                    ((usable_supporting as u64 * 10_000) / usable.len() as u64) as u16
                };
                for basis in &memory.evidence_basis {
                    if let Err(error) = basis.validate() {
                        errors.push(error);
                    }
                }
                (supporting, contradicting, expected)
            };
        let mut operations = std::collections::HashSet::new();
        let mut metrics = std::collections::HashSet::new();
        for link in &evidence {
            if let Err(error) = link.validate(&memory) {
                errors.push(error);
            }
            if !operations.insert(link.operation_id.as_str()) {
                errors.push(format!(
                    "duplicate evidence operation {}",
                    link.operation_id
                ));
            }
            metrics.insert(link.outcome_metric.trim());
        }
        if metrics.len() != 1 {
            errors.push("candidate evidence must share one outcome metric".into());
        }
        if (memory.derivation_method == "verified_binary_outcomes/v1"
            || memory.derivation_method == KIOKU_EVIDENCE_REASSESSMENT_METHOD)
            && (!evidence.is_empty() || !memory.evidence_basis.is_empty())
            && memory.confidence_bps != expected_confidence
        {
            errors.push(format!(
                "confidence_bps {} does not match deterministic evidence rate {expected_confidence}",
                memory.confidence_bps,
            ));
        }
        errors.sort();
        errors.dedup();
        Ok(MemoryValidation {
            valid: errors.is_empty(),
            errors,
            supporting_evidence,
            contradicting_evidence,
        })
    }

    pub fn review_kioku_candidate(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String> {
        if review.reviewer.trim().is_empty() || review.rationale.trim().is_empty() {
            return Err("reviewer and rationale are required".into());
        }
        let validation = self.validate_kioku_candidate(id, version)?;
        if review.action == HumanReviewAction::Promote && !validation.valid {
            return Err(format!(
                "candidate validation failed: {}",
                validation.errors.join("; ")
            ));
        }
        let mut memory = self
            .get_kioku_memory(id, version)?
            .ok_or_else(|| format!("memory {id} version {version} not found"))?;
        if memory.state != MemoryLifecycleState::Candidate {
            return Err("memory is no longer awaiting review".into());
        }
        if review.action == HumanReviewAction::Promote
            && (memory
                .expires_at_ms
                .is_some_and(|expires| expires <= review.reviewed_at_ms)
                || memory
                    .retention_until_ms
                    .is_some_and(|retention| retention <= review.reviewed_at_ms))
        {
            return Err("candidate expiry or retention deadline has elapsed".into());
        }
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if review.action == HumanReviewAction::Promote {
            for basis in &memory.evidence_basis {
                if basis.source_submission_id.is_empty() {
                    continue;
                }
                authorize_kioku_evidence_tx(
                    &mut tx,
                    &crate::chisei::kioku::KiokuEvidenceAuthorizationRequest {
                        source_submission_id: basis.source_submission_id.clone(),
                        namespace: memory.namespace.clone(),
                        memory_classification: memory.classification,
                        evidence_digest: basis.evidence_digest.clone(),
                        lifecycle_state: basis.lifecycle_state,
                        observed_at_ms: basis.observed_at_ms,
                        actor: review.reviewer.trim().into(),
                        now_ms: review.reviewed_at_ms,
                    },
                )?;
            }
        }
        let next_state = match review.action {
            HumanReviewAction::Promote => MemoryLifecycleState::Active,
            HumanReviewAction::Reject => MemoryLifecycleState::Rejected,
        };
        let superseded = if review.action == HumanReviewAction::Promote {
            memory
                .supersedes
                .as_ref()
                .map(|reference| {
                    let reference_version = i64::from(reference.version);
                    let prior_json: String = tx
                        .query_opt(
                            "SELECT memory_json FROM chisei_kioku_memories
                             WHERE id=$1 AND version=$2",
                            &[&reference.memory_id, &reference_version],
                        )
                        .map_err(|error| error.to_string())?
                        .map(|row| row.get(0))
                        .ok_or_else(|| "superseded memory version not found".to_string())?;
                    let mut prior: KiokuMemory =
                        serde_json::from_str(&prior_json).map_err(|error| error.to_string())?;
                    if prior.state != MemoryLifecycleState::Active {
                        return Err(String::from("superseded memory is not active"));
                    }
                    if prior.namespace != memory.namespace
                        || (prior.id == memory.id && prior.version >= memory.version)
                    {
                        return Err(String::from("invalid memory supersession lineage"));
                    }
                    prior.state = MemoryLifecycleState::Superseded;
                    let json = serde_json::to_string(&prior).map_err(|error| error.to_string())?;
                    Ok((prior, json))
                })
                .transpose()?
        } else {
            None
        };
        memory.state = next_state;
        memory.reviewed_at_ms = Some(review.reviewed_at_ms);
        let memory_json = serde_json::to_string(&memory).map_err(|error| error.to_string())?;
        let version_i64 = i64::from(version);

        let updated = tx
            .execute(
                "UPDATE chisei_kioku_memories
                 SET state = $1, memory_json = $2
                 WHERE id = $3 AND version = $4 AND state = 'candidate'",
                &[&next_state.as_str(), &memory_json, &id, &version_i64],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("memory changed during review".into());
        }
        if let Some((prior, prior_json)) = superseded {
            let prior_version = i64::from(prior.version);
            let updated = tx
                .execute(
                    "UPDATE chisei_kioku_memories
                     SET state = 'superseded', memory_json = $1
                     WHERE id = $2 AND version = $3 AND state = 'active'",
                    &[&prior_json, &prior.id, &prior_version],
                )
                .map_err(|error| error.to_string())?;
            if updated != 1 {
                return Err("superseded memory changed during review".into());
            }
            insert_lifecycle_event(
                &mut tx,
                &MemoryLifecycleEvent {
                    memory_id: prior.id,
                    memory_version: prior.version,
                    action: "superseded".into(),
                    from_state: Some(MemoryLifecycleState::Active.as_str().into()),
                    to_state: MemoryLifecycleState::Superseded.as_str().into(),
                    actor: review.reviewer.trim().into(),
                    reason: format!("superseded by {id}@{version}: {}", review.rationale.trim()),
                    recorded_at_ms: review.reviewed_at_ms,
                },
            )?;
        }
        insert_lifecycle_event(
            &mut tx,
            &MemoryLifecycleEvent {
                memory_id: id.into(),
                memory_version: version,
                action: match review.action {
                    HumanReviewAction::Promote => "promoted",
                    HumanReviewAction::Reject => "rejected",
                }
                .into(),
                from_state: Some(MemoryLifecycleState::Candidate.as_str().into()),
                to_state: next_state.as_str().into(),
                actor: review.reviewer.trim().into(),
                reason: review.rationale.trim().into(),
                recorded_at_ms: review.reviewed_at_ms,
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(memory)
    }

    pub fn list_kioku_lifecycle_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<MemoryLifecycleEvent>, String> {
        let version = i64::from(version);
        let rows = self
            .connection()?
            .query(
                "SELECT memory_id, memory_version, action, from_state, to_state, actor, reason,
                        recorded_at_ms
                 FROM chisei_kioku_lifecycle_events
                 WHERE memory_id = $1 AND memory_version = $2 ORDER BY id",
                &[&id, &version],
            )
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|row| {
                Ok(MemoryLifecycleEvent {
                    memory_id: row.get(0),
                    memory_version: row.get::<_, i64>(1) as u32,
                    action: row.get(2),
                    from_state: row.get(3),
                    to_state: row.get(4),
                    actor: row.get(5),
                    reason: row.get(6),
                    recorded_at_ms: row.get(7),
                })
            })
            .collect()
    }

    pub fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        insert_lifecycle_event(&mut tx, event)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn disable_kioku_memory(
        &self,
        id: &str,
        version: u32,
        actor: &str,
        rationale: &str,
        recorded_at_ms: i64,
    ) -> Result<KiokuMemory, String> {
        if actor.trim().is_empty() || rationale.trim().is_empty() {
            return Err("disable actor and rationale are required".into());
        }
        let mut memory = self
            .get_kioku_memory(id, version)?
            .ok_or_else(|| format!("memory {id} version {version} not found"))?;
        if memory.state != MemoryLifecycleState::Active {
            return Err("only active memories can be disabled".into());
        }
        memory.state = MemoryLifecycleState::Rejected;
        let memory_json = serde_json::to_string(&memory).map_err(|error| error.to_string())?;
        let version_i64 = i64::from(version);
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let updated = tx
            .execute(
                "UPDATE chisei_kioku_memories SET state = 'rejected', memory_json = $1
                 WHERE id = $2 AND version = $3 AND state = 'active'",
                &[&memory_json, &id, &version_i64],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("memory changed while it was being disabled".into());
        }
        insert_lifecycle_event(
            &mut tx,
            &MemoryLifecycleEvent {
                memory_id: id.into(),
                memory_version: version,
                action: "disabled".into(),
                from_state: Some(MemoryLifecycleState::Active.as_str().into()),
                to_state: MemoryLifecycleState::Rejected.as_str().into(),
                actor: actor.trim().into(),
                reason: rationale.trim().into(),
                recorded_at_ms,
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(memory)
    }

    pub fn kioku_authorized_classification_ceiling(
        &self,
        namespace: &str,
        actor: &str,
    ) -> Result<EvidenceClassification, String> {
        if matches!(actor, "root" | "local") {
            return Ok(EvidenceClassification::Restricted);
        }
        let namespace_object = self
            .find_by_external_id(&format!("namespace:{namespace}"))?
            .ok_or_else(|| "memory namespace is not an authorized graph scope".to_string())?;
        let grants = self.list_grants(&namespace_object.id)?;
        if grants.is_empty() {
            return Ok(EvidenceClassification::Public);
        }
        let role = grants
            .iter()
            .find(|grant| grant.principal == actor)
            .map(|grant| &grant.role)
            .ok_or_else(|| "actor is not authorized for memory namespace".to_string())?;
        Ok(match role {
            crate::sekai::security::Role::Viewer => EvidenceClassification::Internal,
            crate::sekai::security::Role::Editor => EvidenceClassification::Confidential,
            crate::sekai::security::Role::Admin => EvidenceClassification::Restricted,
        })
    }

    pub fn authorize_kioku_evidence(
        &self,
        request: &crate::chisei::kioku::KiokuEvidenceAuthorizationRequest,
    ) -> Result<(), String> {
        if request.source_submission_id.trim().is_empty() || request.actor.trim().is_empty() {
            return Err("evidence submission and actor are required".into());
        }
        let submission = self
            .get_evidence_submission(&request.source_submission_id)?
            .ok_or_else(|| "evidence submission not found".to_string())?;
        if submission.namespace != request.namespace {
            return Err("evidence namespace does not match memory namespace".into());
        }
        if submission.content_digest != request.evidence_digest {
            return Err("evidence digest does not match the governed submission".into());
        }
        if submission.lifecycle_state != request.lifecycle_state
            || !request.lifecycle_state.is_admitted()
            || request.lifecycle_state == EvidenceLifecycleState::Quarantined
        {
            return Err("evidence lifecycle changed; reassessment must be retried".into());
        }
        if submission.observed_at_ms != request.observed_at_ms {
            return Err("evidence observation time does not match the governed submission".into());
        }
        if submission
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= request.now_ms)
        {
            return Err("evidence submission is outside its retention window".into());
        }
        if submission.classification > request.memory_classification {
            return Err("evidence classification exceeds memory classification".into());
        }
        let ceiling =
            self.kioku_authorized_classification_ceiling(&request.namespace, &request.actor)?;
        if submission.classification > ceiling {
            return Err("evidence classification exceeds actor grant".into());
        }
        if let Some(object_id) =
            self.get_evidence_projection_object_id(&request.source_submission_id)?
        {
            let grants = self.list_grants(&object_id)?;
            if !grants.is_empty()
                && !matches!(request.actor.as_str(), "root" | "local")
                && !grants.iter().any(|grant| grant.principal == request.actor)
            {
                return Err("actor is not authorized to read evidence projection".into());
            }
        } else {
            return Err("evidence submission has no authorized projection".into());
        }
        Ok(())
    }
}

fn insert_lifecycle_event(
    tx: &mut postgres::Transaction<'_>,
    event: &MemoryLifecycleEvent,
) -> Result<(), String> {
    let memory_version = i64::from(event.memory_version);
    tx.execute(
        "INSERT INTO chisei_kioku_lifecycle_events
         (memory_id, memory_version, action, from_state, to_state, actor, reason, recorded_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &[
            &event.memory_id,
            &memory_version,
            &event.action,
            &event.from_state,
            &event.to_state,
            &event.actor,
            &event.reason,
            &event.recorded_at_ms,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn authorize_kioku_evidence_tx(
    tx: &mut postgres::Transaction<'_>,
    request: &crate::chisei::kioku::KiokuEvidenceAuthorizationRequest,
) -> Result<(), String> {
    if request.source_submission_id.trim().is_empty() || request.actor.trim().is_empty() {
        return Err("evidence submission and actor are required".into());
    }
    let row = tx
        .query_opt(
            "SELECT namespace, content_digest, classification, lifecycle_state,
                    observed_at_ms, expires_at_ms
             FROM sekai_evidence_submissions WHERE id=$1 FOR SHARE",
            &[&request.source_submission_id],
        )
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "evidence submission not found".to_string())?;
    let namespace: String = row.get(0);
    let digest: String = row.get(1);
    let classification_name: String = row.get(2);
    let lifecycle_name: String = row.get(3);
    let observed_at_ms: i64 = row.get(4);
    let expires_at_ms: Option<i64> = row.get(5);
    if namespace != request.namespace {
        return Err("evidence namespace does not match memory namespace".into());
    }
    if digest != request.evidence_digest {
        return Err("evidence digest does not match the governed submission".into());
    }
    let classification = match classification_name.as_str() {
        "public" => EvidenceClassification::Public,
        "internal" => EvidenceClassification::Internal,
        "confidential" => EvidenceClassification::Confidential,
        "restricted" => EvidenceClassification::Restricted,
        value => return Err(format!("unknown evidence classification {value}")),
    };
    let lifecycle = EvidenceLifecycleState::parse(&lifecycle_name)
        .ok_or_else(|| format!("unknown evidence lifecycle state {lifecycle_name}"))?;
    if lifecycle != request.lifecycle_state
        || !request.lifecycle_state.is_admitted()
        || request.lifecycle_state == EvidenceLifecycleState::Quarantined
    {
        return Err("evidence lifecycle changed; reassessment must be retried".into());
    }
    if observed_at_ms != request.observed_at_ms {
        return Err("evidence observation time does not match the governed submission".into());
    }
    if expires_at_ms.is_some_and(|expires_at| expires_at <= request.now_ms) {
        return Err("evidence submission is outside its retention window".into());
    }
    if classification > request.memory_classification {
        return Err("evidence classification exceeds memory classification".into());
    }
    let privileged = matches!(request.actor.as_str(), "root" | "local");
    if !privileged {
        let namespace_external_id = format!("namespace:{}", request.namespace);
        let namespace_id: Option<String> = tx
            .query_opt(
                "SELECT id FROM sekai_objects WHERE external_id=$1",
                &[&namespace_external_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        let Some(namespace_id) = namespace_id else {
            return Err("memory namespace is not an authorized graph scope".into());
        };
        let grants = tx
            .query(
                "SELECT principal, role FROM sekai_grants
             WHERE object_id=$1 FOR SHARE",
                &[&namespace_id],
            )
            .map_err(|error| error.to_string())?;
        let authorized_ceiling = if grants.is_empty() {
            EvidenceClassification::Public
        } else {
            let role = grants
                .iter()
                .find(|row| row.get::<_, String>(0) == request.actor)
                .map(|row| row.get::<_, String>(1));
            match role.as_deref() {
                Some("viewer") => EvidenceClassification::Internal,
                Some("editor") => EvidenceClassification::Confidential,
                Some("admin") => EvidenceClassification::Restricted,
                Some(_) => return Err("unknown namespace grant role".into()),
                None => return Err("actor is not authorized for memory namespace".into()),
            }
        };
        if classification > authorized_ceiling {
            return Err("evidence classification exceeds actor grant".into());
        }
    }
    let projection_id: Option<String> = tx
        .query_opt(
            "SELECT evidence_object_id FROM sekai_evidence_projections
             WHERE submission_id=$1 FOR SHARE",
            &[&request.source_submission_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    let Some(projection_id) = projection_id else {
        return Err("evidence submission has no authorized projection".into());
    };
    if !privileged {
        let grants = tx
            .query(
                "SELECT principal FROM sekai_grants WHERE object_id=$1 FOR SHARE",
                &[&projection_id],
            )
            .map_err(|error| error.to_string())?;
        if !grants.is_empty()
            && !grants
                .iter()
                .any(|row| row.get::<_, String>(0) == request.actor)
        {
            return Err("actor is not authorized to read evidence projection".into());
        }
    }
    Ok(())
}
