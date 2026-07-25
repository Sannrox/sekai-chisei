//! PostgreSQL persistence for governed Kioku institutional memory.

use crate::chisei::kioku::{
    HumanMemoryReview, HumanReviewAction, KiokuEvidenceLink, KiokuMemory, MemoryEvidenceStance,
    MemoryLifecycleEvent, MemoryLifecycleState, MemoryValidation,
};
use crate::db::postgres::PostgresDb;

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
                action: "created".into(),
                from_state: None,
                to_state: memory.state.as_str().into(),
                actor: memory.producer_identity.clone(),
                reason: memory.derivation_method.clone(),
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
        let supporting_evidence = evidence
            .iter()
            .filter(|link| link.stance == MemoryEvidenceStance::Supporting)
            .count();
        let contradicting_evidence = evidence.len().saturating_sub(supporting_evidence);
        if supporting_evidence == 0 {
            errors.push("candidate requires supporting evidence".into());
        }
        if evidence.len() != memory.sample_size as usize {
            errors.push(format!(
                "sample_size {} does not match {} evidence links",
                memory.sample_size,
                evidence.len()
            ));
        }
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
        if memory.derivation_method == "verified_binary_outcomes/v1" && !evidence.is_empty() {
            let expected = ((supporting_evidence as u64 * 10_000) / evidence.len() as u64) as u16;
            if memory.confidence_bps != expected {
                errors.push(format!(
                    "confidence_bps {} does not match verified outcome rate {expected}",
                    memory.confidence_bps
                ));
            }
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
        let next_state = match review.action {
            HumanReviewAction::Promote => MemoryLifecycleState::Active,
            HumanReviewAction::Reject => MemoryLifecycleState::Rejected,
        };
        let superseded = if review.action == HumanReviewAction::Promote {
            memory
                .supersedes
                .as_ref()
                .map(|reference| {
                    let mut prior = self
                        .get_kioku_memory(&reference.memory_id, reference.version)?
                        .ok_or_else(|| "superseded memory version not found".to_string())?;
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

        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
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
