//! Admission lifecycle for externally reported canonical receipt events.

use super::*;

pub(super) fn record_reported_memory_outcomes(
    db: &RuntimeDb,
    receipt: &OperationReceipt,
    actor: &str,
    now_ms: i64,
    require_trusted_outcome: bool,
    outcome_event_id: Option<&str>,
    validate_only: bool,
) -> Result<Vec<crate::chisei::kioku::MemoryImpactEvaluation>, String> {
    let request_id = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .and_then(|event| event.attributes.get("request_id"))
        .map(String::as_str)
        .map(str::trim)
        .filter(|request_id| !request_id.is_empty())
        .ok_or_else(|| "Kioku receipt lacks a non-empty request_id".to_string())?;
    let selected_outcome_metric = outcome_event_id
        .map(|event_id| {
            receipt
                .events
                .iter()
                .find(|event| event.event_id == event_id)
                .and_then(|event| event.attributes.get("outcome_metric"))
                .map(|metric| metric.trim().to_string())
                .ok_or_else(|| format!("Kioku outcome event {event_id} has no outcome metric"))
        })
        .transpose()?;
    let mut outcomes = HashMap::new();
    for outcome in receipt.events.iter().filter(|event| {
        matches!(
            event.kind,
            ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
        ) && ["outcome_metric", "outcome_value", "passed"]
            .iter()
            .all(|attribute| event.attributes.contains_key(*attribute))
            && (!require_trusted_outcome
                || event
                    .attributes
                    .get(KIOKU_TRUSTED_OUTCOME_ATTRIBUTE)
                    .is_some_and(|value| value == "true"))
    }) {
        let outcome_metric = outcome.attributes["outcome_metric"].trim().to_string();
        let outcome_value = outcome.attributes["outcome_value"]
            .parse::<f64>()
            .map_err(|_| "Kioku outcome value must be finite".to_string())?;
        if !outcome_value.is_finite() {
            return Err("Kioku outcome value must be finite".into());
        }
        let passed = outcome.attributes["passed"]
            .parse::<bool>()
            .map_err(|_| "Kioku outcome passed flag must be boolean".to_string())?;
        if outcomes
            .insert(outcome_metric.clone(), (outcome_value, passed))
            .is_some_and(|previous| previous != (outcome_value, passed))
        {
            return Err(format!(
                "conflicting Kioku outcomes for metric {outcome_metric}"
            ));
        }
    }
    if outcomes.is_empty() {
        return Ok(Vec::new());
    }
    let attempt_recorded_at_ms = receipt
        .events
        .iter()
        .filter(|event| event.kind == ReceiptEventKind::AttemptStarted)
        .map(|event| event.timestamp_ms)
        .min();
    let mut assignments = db
        .list_kioku_outcome_assignments(&receipt.operation_id)?
        .into_iter()
        .map(|assignment| {
            (
                (assignment.memory_id, assignment.memory_version),
                assignment.memory_applied,
            )
        })
        .collect::<HashMap<_, _>>();
    let assignment_reason = format!("pipeline operation {}", receipt.operation_id);
    let legacy_assignment_reason = format!("pipeline request {request_id}");
    let mut pending_lifecycle_events = Vec::new();
    for ((memory_id, memory_version), memory_applied) in assignments.clone() {
        let Some(memory) = db.get_kioku_memory(&memory_id, memory_version)? else {
            assignments.remove(&(memory_id, memory_version));
            continue;
        };
        if receipt.namespace != memory.namespace
            || !memory
                .operation_classes
                .iter()
                .any(|class| class == &receipt.operation_class)
        {
            return Err(format!(
                "memory {memory_id}@{memory_version} does not match receipt scope"
            ));
        }
        let lifecycle = db.list_kioku_lifecycle_events(&memory_id, memory_version)?;
        let assignment_action = if memory_applied {
            "injected"
        } else {
            "held_out"
        };
        let assignment_recorded_at_ms = lifecycle
            .iter()
            .filter(|event| event.action == assignment_action && event.reason == assignment_reason)
            .map(|event| event.recorded_at_ms)
            .max()
            .or_else(|| {
                lifecycle
                    .iter()
                    .filter(|event| {
                        event.action == assignment_action
                            && event.reason == legacy_assignment_reason
                    })
                    .map(|event| event.recorded_at_ms)
                    .max()
            });
        let Some(assignment_recorded_at_ms) = assignment_recorded_at_ms else {
            assignments.remove(&(memory_id, memory_version));
            continue;
        };
        let eligibility_recorded_at_ms = if memory_applied {
            assignment_recorded_at_ms
        } else {
            attempt_recorded_at_ms
                .ok_or_else(|| "Kioku receipt lacks an attempt-start event".to_string())?
        };
        let active_at_eligibility = lifecycle
            .into_iter()
            .filter(|event| event.recorded_at_ms <= eligibility_recorded_at_ms)
            .filter(|event| event.from_state.as_deref() != Some(event.to_state.as_str()))
            .max_by_key(|event| event.recorded_at_ms)
            .is_some_and(|event| event.to_state == "active");
        if !active_at_eligibility
            || memory.created_at_ms > eligibility_recorded_at_ms
            || memory
                .expires_at_ms
                .is_some_and(|expires| expires <= eligibility_recorded_at_ms)
            || memory
                .retention_until_ms
                .is_some_and(|retention| retention <= eligibility_recorded_at_ms)
        {
            pending_lifecycle_events.push(crate::chisei::kioku::MemoryLifecycleEvent {
                memory_id: memory_id.clone(),
                memory_version,
                action: "assignment_invalidated".into(),
                from_state: Some(memory.state.as_str().into()),
                to_state: memory.state.as_str().into(),
                actor: actor.into(),
                reason: format!("pipeline operation {}", receipt.operation_id),
                recorded_at_ms: now_ms,
            });
            assignments.remove(&(memory_id, memory_version));
        }
    }
    let governed_memories = receipt
        .events
        .iter()
        .filter(|event| event.kind == ReceiptEventKind::ContextGoverned)
        .flat_map(|event| {
            event
                .references
                .iter()
                .map(move |reference| (event.timestamp_ms, reference))
        })
        .filter(|(_, reference)| reference.kind == "kioku_memory" && !reference.omitted)
        .collect::<Vec<_>>();
    if assignments.is_empty() && governed_memories.is_empty() {
        return Err("Kioku outcome matches no eligible memory assignment".into());
    }
    let attempt_recorded_at_ms = attempt_recorded_at_ms
        .ok_or_else(|| "Kioku receipt lacks an attempt-start event".to_string())?;
    for (context_recorded_at_ms, reference) in governed_memories {
        if context_recorded_at_ms > attempt_recorded_at_ms {
            return Err("Kioku context was recorded after execution started".into());
        }
        let Some(pinned) = reference.reference.strip_prefix("memory:") else {
            return Err(format!(
                "memory reference {} has no memory prefix",
                reference.reference
            ));
        };
        let Some((memory_id, version)) = pinned.rsplit_once('@') else {
            return Err(format!(
                "memory reference {} does not pin a version",
                reference.reference
            ));
        };
        let version = version.parse::<u32>().map_err(|_| {
            format!(
                "memory reference {} has an invalid version",
                reference.reference
            )
        })?;
        let key = (memory_id.to_string(), version);
        if assignments.get(&key) == Some(&false) {
            return Err(format!(
                "memory {memory_id}@{version} is both held out and present in the receipt"
            ));
        }
        if assignments.get(&key) == Some(&true) {
            continue;
        }
        let memory = db
            .get_kioku_memory(memory_id, version)?
            .ok_or_else(|| format!("memory {memory_id}@{version} not found"))?;
        if receipt.namespace != memory.namespace
            || !memory
                .operation_classes
                .iter()
                .any(|class| class == &receipt.operation_class)
        {
            return Err(format!(
                "memory {memory_id}@{version} does not match receipt scope"
            ));
        }
        let active_at_context = db
            .list_kioku_lifecycle_events(memory_id, version)?
            .into_iter()
            .filter(|event| event.recorded_at_ms <= context_recorded_at_ms)
            .filter(|event| event.from_state.as_deref() != Some(event.to_state.as_str()))
            .max_by_key(|event| event.recorded_at_ms)
            .is_some_and(|event| event.to_state == "active");
        let active_at_attempt = db
            .list_kioku_lifecycle_events(memory_id, version)?
            .into_iter()
            .filter(|event| event.recorded_at_ms <= attempt_recorded_at_ms)
            .filter(|event| event.from_state.as_deref() != Some(event.to_state.as_str()))
            .max_by_key(|event| event.recorded_at_ms)
            .is_some_and(|event| event.to_state == "active");
        if !active_at_context
            || !active_at_attempt
            || memory.created_at_ms > context_recorded_at_ms
            || memory
                .expires_at_ms
                .is_some_and(|expires| expires <= context_recorded_at_ms)
            || memory
                .retention_until_ms
                .is_some_and(|retention| retention <= context_recorded_at_ms)
            || memory
                .expires_at_ms
                .is_some_and(|expires| expires <= attempt_recorded_at_ms)
            || memory
                .retention_until_ms
                .is_some_and(|retention| retention <= attempt_recorded_at_ms)
        {
            return Err(format!(
                "memory {memory_id}@{version} was not active when execution started"
            ));
        }
        let authorized_ceiling = db
            .kioku_authorized_classification_ceiling(&memory.namespace, &receipt.initiating_actor)
            .map_err(|_| {
                format!("initiating actor is not authorized for memory {memory_id}@{version}")
            })?;
        if memory.classification > authorized_ceiling {
            return Err(format!(
                "memory {memory_id}@{version} exceeds initiating actor authorization"
            ));
        }
        if reference.content_hash.as_deref()
            != Some(crate::chisei::kioku::memory_claim_digest(&memory).as_str())
        {
            return Err(format!(
                "memory {memory_id}@{version} digest does not match"
            ));
        }
        pending_lifecycle_events.push(crate::chisei::kioku::MemoryLifecycleEvent {
            memory_id: memory_id.into(),
            memory_version: version,
            action: "injected".into(),
            from_state: Some("active".into()),
            to_state: "active".into(),
            actor: receipt.initiating_actor.clone(),
            reason: format!("pipeline operation {}", receipt.operation_id),
            recorded_at_ms: context_recorded_at_ms,
        });
        assignments.insert(key, true);
    }
    let mut assignment_metrics = HashMap::new();
    let mut known_metrics = HashSet::new();
    for (memory_id, memory_version) in assignments.keys() {
        let evidence = db.list_kioku_evidence(memory_id, *memory_version)?;
        let outcome_metric = evidence
            .first()
            .map(|link| link.outcome_metric.trim())
            .filter(|metric| !metric.is_empty())
            .ok_or_else(|| format!("memory {memory_id}@{memory_version} has no outcome metric"))?;
        if !evidence
            .iter()
            .all(|link| link.outcome_metric.trim() == outcome_metric)
        {
            return Err(format!(
                "memory {memory_id}@{memory_version} has conflicting outcome metrics"
            ));
        }
        known_metrics.insert(outcome_metric.to_string());
        assignment_metrics.insert(
            (memory_id.clone(), *memory_version),
            outcome_metric.to_string(),
        );
    }
    if let Some(unmatched_metric) = outcomes
        .keys()
        .find(|metric| !known_metrics.contains(*metric))
    {
        return Err(format!(
            "Kioku outcome metric {unmatched_metric} matches no assigned memory"
        ));
    }
    if let Some(selected_outcome_metric) = selected_outcome_metric {
        outcomes.retain(|metric, _| metric == &selected_outcome_metric);
    }
    if validate_only {
        return Ok(Vec::new());
    }
    for event in pending_lifecycle_events {
        db.record_kioku_lifecycle_event(&event)?;
    }
    let mut evaluations = Vec::new();
    for ((memory_id, memory_version), memory_applied) in assignments {
        let outcome_metric = &assignment_metrics[&(memory_id.clone(), memory_version)];
        let Some(&(outcome_value, passed)) = outcomes.get(outcome_metric) else {
            continue;
        };
        let recorded =
            db.record_kioku_outcome(&crate::chisei::kioku::MemoryOutcomeObservation {
                memory_id: memory_id.clone(),
                memory_version,
                operation_id: receipt.operation_id.clone(),
                request_id: request_id.into(),
                memory_applied,
                outcome_metric: outcome_metric.clone(),
                outcome_value,
                passed,
                recorded_at_ms: now_ms,
            })?;
        if recorded
            && let Some(evaluation) = db.evaluate_kioku_impact_if_ready(
                &memory_id,
                memory_version,
                KIOKU_MIN_SAMPLES_PER_ARM,
                KIOKU_REGRESSION_THRESHOLD,
                actor,
                now_ms,
            )?
        {
            evaluations.push(evaluation);
        }
    }
    Ok(evaluations)
}

pub(super) struct ReportedOperationEventLifecycle<'a> {
    service: &'a ChiseiServiceImpl,
}

impl<'a> ReportedOperationEventLifecycle<'a> {
    pub(super) fn new(service: &'a ChiseiServiceImpl) -> Self {
        Self { service }
    }

    pub(super) async fn admit(
        &self,
        req: Request<ReportOperationEventRequest>,
    ) -> Result<Response<ReportOperationEventResponse>, Status> {
        report_operation_event(self.service, req).await
    }
}

async fn report_operation_event(
    service: &ChiseiServiceImpl,
    req: Request<ReportOperationEventRequest>,
) -> Result<Response<ReportOperationEventResponse>, Status> {
    let actor = authenticated_actor(&req);
    let request_auth_source = auth_source(&req);
    let configured_gateway = service
        .config
        .gateway_receipt_principals
        .iter()
        .any(|principal| principal == &actor);
    let trusted_outcome_reporter = (request_auth_source.as_deref() == Some("token")
        && (configured_gateway || matches!(actor.as_str(), "chisei-gateway" | "root")))
        || (service.config.insecure
            && request_auth_source.as_deref() == Some("local")
            && actor == "chisei-gateway");
    if !receipt_mutation_transport_allowed(&req, &service.config) {
        return Err(Status::permission_denied(
            "operation event reporting requires authenticated transport",
        ));
    }
    let mut request = req.into_inner();
    if request.operation_id.trim().is_empty() {
        return Err(Status::invalid_argument("operation_id required"));
    }
    let receipt = service
        .db
        .get_operation_receipt(&request.operation_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("operation receipt not found"))?;
    if matches!(
        receipt.operation_class.as_str(),
        evaluation_execution_domain::EXECUTION_OPERATION_CLASS
    ) {
        return Err(Status::permission_denied(
            "evaluation authority receipts accept only internal events",
        ));
    }
    let receipt_was_complete = receipt.completeness().complete;
    let kind = ReceiptEventKind::parse(&request.kind)
        .ok_or(Status::invalid_argument("unsupported operation event kind"))?;
    if !reportable_receipt_kind(kind) {
        return Err(Status::invalid_argument(
            "event kind is not reportable through this API",
        ));
    }
    let receipt_has_kioku_context = !service
        .db
        .list_kioku_outcome_assignments(&receipt.operation_id)
        .map_err(Status::internal)?
        .is_empty()
        || receipt.events.iter().any(|event| {
            event.kind == ReceiptEventKind::ContextGoverned
                && event
                    .references
                    .iter()
                    .any(|reference| reference.kind == "kioku_memory" && !reference.omitted)
        });
    let supplies_kioku_outcome = ["outcome_metric", "outcome_value"]
        .iter()
        .any(|attribute| request.attributes.contains_key(*attribute));
    let complete_kioku_outcome = ["outcome_metric", "outcome_value", "passed"]
        .iter()
        .all(|attribute| request.attributes.contains_key(*attribute));
    if kind == ReceiptEventKind::OutcomeRecorded
        && receipt_has_kioku_context
        && supplies_kioku_outcome
        && !complete_kioku_outcome
    {
        return Err(Status::invalid_argument(
            "Kioku outcomes require outcome_metric, outcome_value, and passed",
        ));
    }
    if kind == ReceiptEventKind::OutcomeRecorded
        && receipt_has_kioku_context
        && complete_kioku_outcome
    {
        let outcome_metric = request.attributes["outcome_metric"].trim().to_string();
        if outcome_metric.is_empty() {
            return Err(Status::invalid_argument(
                "Kioku outcome_metric must not be empty",
            ));
        }
        request
            .attributes
            .insert("outcome_metric".into(), outcome_metric);
        let outcome_value = request.attributes["outcome_value"]
            .parse::<f64>()
            .map_err(|_| Status::invalid_argument("Kioku outcome_value must be finite"))?;
        if !outcome_value.is_finite() {
            return Err(Status::invalid_argument(
                "Kioku outcome_value must be finite",
            ));
        }
        request.attributes["passed"]
            .parse::<bool>()
            .map_err(|_| Status::invalid_argument("Kioku passed must be boolean"))?;
    }
    if kind == ReceiptEventKind::OutcomeRecorded
        && receipt_has_kioku_context
        && supplies_kioku_outcome
        && !trusted_outcome_reporter
    {
        return Err(Status::permission_denied(
            "Kioku outcome reporting requires a trusted gateway principal",
        ));
    }
    let stored_kind = if let Some(existing_kind) = receipt
        .events
        .iter()
        .find(|event| event.event_id == request.event_id)
        .map(|event| event.kind)
    {
        existing_kind
    } else if kind == ReceiptEventKind::OutcomeRecorded
        && receipt_was_complete
        && receipt_has_kioku_context
        && complete_kioku_outcome
        && trusted_outcome_reporter
    {
        ReceiptEventKind::MemoryOutcomeRecorded
    } else {
        kind
    };
    let trusted_kioku_outcome = kind == ReceiptEventKind::OutcomeRecorded
        && receipt_has_kioku_context
        && complete_kioku_outcome
        && trusted_outcome_reporter;
    let namespace_writer =
        require_namespace_write_access(&service.db, &actor, &receipt.namespace).is_ok();
    if actor != receipt.initiating_actor
        && actor != "root"
        && !namespace_writer
        && !trusted_kioku_outcome
    {
        return Err(Status::permission_denied(
            "operation event reporter lacks namespace write authority",
        ));
    }
    if request.parent_event_id.trim().is_empty() {
        return Err(Status::invalid_argument("parent_event_id required"));
    }
    let parent = receipt
        .events
        .iter()
        .find(|event| event.event_id == request.parent_event_id)
        .ok_or(Status::failed_precondition("causal parent not found"))?;
    let now = chrono::Utc::now().timestamp_millis();
    let timestamp_ms = if request.timestamp_ms <= 0 {
        now
    } else if request.timestamp_ms > now {
        return Err(Status::invalid_argument(
            "event timestamp must not be in the future",
        ));
    } else if request.timestamp_ms < parent.timestamp_ms {
        return Err(Status::invalid_argument(
            "event timestamp must not precede its causal parent",
        ));
    } else {
        request.timestamp_ms
    };
    if request.attributes.len() > 64 {
        return Err(Status::invalid_argument(
            "at most 64 attributes are allowed",
        ));
    }
    let sensitive_attribute = request.attributes.keys().find(|key| {
        let key = key.to_ascii_lowercase().replace('-', "_");
        let compact_key = key.replace('_', "");
        [
            "authorization",
            "api_key",
            "credential",
            "cookie",
            "secret",
            "password",
            "passwd",
            "passphrase",
            "private_key",
            "token",
        ]
        .iter()
        .any(|sensitive| {
            let compact_sensitive = sensitive.replace('_', "");
            key == *sensitive
                || key.ends_with(&format!("_{sensitive}"))
                || compact_key == compact_sensitive
                || compact_key.ends_with(&compact_sensitive)
        })
    });
    if let Some(key) = sensitive_attribute {
        return Err(Status::invalid_argument(format!(
            "sensitive attribute {key:?} is not allowed"
        )));
    }
    if request
        .attributes
        .iter()
        .any(|(key, value)| key.len() > 128 || value.len() > 4096)
    {
        return Err(Status::invalid_argument("attribute exceeds size limit"));
    }
    if request.references.len() > 32 {
        return Err(Status::invalid_argument(
            "at most 32 references are allowed",
        ));
    }
    let references = request
        .references
        .into_iter()
        .map(|reference| {
            if reference.kind.trim().is_empty() || reference.reference.trim().is_empty() {
                return Err(Status::invalid_argument(
                    "reference kind and reference are required",
                ));
            }
            if reference.omitted && reference.omission_reason.trim().is_empty() {
                return Err(Status::invalid_argument(
                    "omitted reference requires omission_reason",
                ));
            }
            if !reference.content_hash.is_empty()
                && (reference.content_hash.len() != 64
                    || !reference
                        .content_hash
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err(Status::invalid_argument(
                    "content_hash must be a 64-character hexadecimal digest",
                ));
            }
            Ok(GovernedReference {
                kind: reference.kind,
                reference: reference.reference,
                content_hash: (!reference.content_hash.is_empty())
                    .then_some(reference.content_hash),
                disclosed_fields: reference.disclosed_fields,
                omitted: reference.omitted,
                omission_reason: (!reference.omission_reason.is_empty())
                    .then_some(reference.omission_reason),
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let reported_event_prefix = format!("report:{}:", request.operation_id);
    let event_id = if request.event_id.trim().is_empty() {
        format!("{reported_event_prefix}{}", uuid::Uuid::new_v4())
    } else if request.event_id.starts_with(&reported_event_prefix) {
        request.event_id
    } else {
        return Err(Status::invalid_argument(format!(
            "reported event_id must start with {reported_event_prefix:?}"
        )));
    };
    let mut attributes = request.attributes.into_iter().collect::<BTreeMap<_, _>>();
    attributes.remove(KIOKU_TRUSTED_OUTCOME_ATTRIBUTE);
    if matches!(
        stored_kind,
        ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
    ) && trusted_outcome_reporter
        && complete_kioku_outcome
    {
        attributes.insert(KIOKU_TRUSTED_OUTCOME_ATTRIBUTE.into(), "true".into());
    }
    let event = OperationReceiptEvent {
        event_id: event_id.clone(),
        operation_id: request.operation_id.clone(),
        parent_event_id: Some(request.parent_event_id),
        timestamp_ms,
        kind: stored_kind,
        surface: stored_kind.surface(),
        actor: actor.clone(),
        references,
        attributes,
    };
    let mut prospective_receipt = receipt.clone();
    let prospective_event_recorded = !prospective_receipt
        .events
        .iter()
        .any(|existing| existing.event_id == event.event_id);
    if prospective_event_recorded {
        prospective_receipt
            .uncovered_surfaces
            .retain(|entry| entry.surface != event.surface);
        if event.kind == ReceiptEventKind::OutcomeRecorded {
            prospective_receipt.completed_at_ms = Some(event.timestamp_ms);
        }
        prospective_receipt.events.push(event.clone());
    }
    let prospective_completeness = prospective_receipt.completeness();
    let should_preflight_attribution = prospective_event_recorded
        && receipt_has_kioku_context
        && prospective_completeness.complete
        && ((!receipt_was_complete)
            || (trusted_outcome_reporter
                && complete_kioku_outcome
                && matches!(
                    stored_kind,
                    ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
                )));
    if should_preflight_attribution {
        reported_operation_event_lifecycle::record_reported_memory_outcomes(
            &service.db,
            &prospective_receipt,
            &actor,
            now,
            true,
            (stored_kind == ReceiptEventKind::MemoryOutcomeRecorded).then_some(event_id.as_str()),
            true,
        )
        .map_err(|error| {
            Status::failed_precondition(format!("Kioku outcome attribution invalid: {error}"))
        })?;
    }
    let (receipt, recorded) = service
        .db
        .append_operation_receipt_event(&request.operation_id, event)
        .map_err(|error| {
            if error.contains("not found") {
                Status::not_found(error)
            } else if error.contains("already exists") {
                Status::already_exists(error)
            } else {
                Status::failed_precondition(error)
            }
        })?;
    let completeness = receipt.completeness();
    let should_attribute = receipt_has_kioku_context
        && completeness.complete
        && ((recorded && !receipt_was_complete)
            || (trusted_outcome_reporter
                && complete_kioku_outcome
                && matches!(
                    stored_kind,
                    ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
                )));
    if should_attribute
        && let Err(error) = reported_operation_event_lifecycle::record_reported_memory_outcomes(
            &service.db,
            &receipt,
            &actor,
            now,
            true,
            (stored_kind == ReceiptEventKind::MemoryOutcomeRecorded).then_some(event_id.as_str()),
            false,
        )
    {
        let _ = service.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now,
            actor: "chisei.kioku".into(),
            action: "kioku.outcome_attribution".into(),
            reason: error,
            evidence: std::collections::HashMap::from([
                ("operation_id".into(), receipt.operation_id.clone()),
                ("receipt_event_id".into(), event_id.clone()),
            ]),
            target_id: receipt.operation_id.clone(),
            outcome: "failed".into(),
        });
    }
    Ok(Response::new(ReportOperationEventResponse {
        event_id,
        recorded,
        complete: completeness.complete,
        missing_surfaces: completeness
            .missing_surfaces
            .into_iter()
            .map(|surface| surface.as_str().to_string())
            .collect(),
    }))
}
