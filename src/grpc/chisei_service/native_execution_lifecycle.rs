//! Native plan execution behind one private interface.
//!
//! The gRPC adapter authenticates the caller and translates protocol messages.
//! This module owns the ordered execute lifecycle: lookup-first short-circuit,
//! live evaluation regression gate, residency/privacy/egress rechecks, provider
//! streaming, evolve/scoring bookkeeping, and terminal receipt completion.

use super::*;

/// Result of the post-authz lookup-first attempt on ExecutePlanStream.
#[derive(Debug)]
pub(super) enum ExecuteLookupFirst {
    /// Full structured answer; caller must return without a provider call.
    Hit {
        response: PlannedChatResponse,
        capability: String,
        provenance: BTreeMap<String, String>,
    },
    /// Fail closed to the model path; record `lookup_refusal` on the receipt.
    ModelPath { lookup_refusal: Option<String> },
}

impl ChiseiServiceImpl {
    pub(super) async fn execute_planned_stream(
        &self,
        actor: String,
        context: Option<crate::enterprise::AuthenticatedContext>,
        requested_plan: ExecutionPlan,
    ) -> Result<<Self as ChiseiService>::ExecutePlanStreamStream, Status> {
        let plan = {
            let mut plans = self
                .planned_executions
                .lock()
                .expect("planned executions poisoned");
            prune_cached_plans(&mut plans);
            let cached = plans
                .get(&requested_plan.plan_id)
                .ok_or(Status::not_found("execution plan not found"))?;
            if cached.plan.planning_actor != actor
                || cached.enterprise_authority != enterprise_execution_authority(context.as_ref())
            {
                return Err(Status::permission_denied(
                    "execution plan belongs to a different planning principal",
                ));
            }
            cached.plan.clone()
        };
        if !plan.executable {
            return Err(Status::failed_precondition(
                "execution plan is not executable",
            ));
        }
        let input = plan
            .input
            .clone()
            .ok_or(Status::invalid_argument("plan input required"))?;
        require_execution_namespace_access_with_context(
            &self.db,
            &self.config,
            &actor,
            context.as_ref(),
            &input.namespace,
        )?;
        {
            let mut plans = self
                .planned_executions
                .lock()
                .expect("planned executions poisoned");
            plans
                .remove(&requested_plan.plan_id)
                .ok_or(Status::not_found("execution plan not found"))?;
        }
        let namespace_hint = input.namespace.trim().to_string();
        let attempt_started_at_ms = chrono::Utc::now().timestamp_millis();

        if let Some(signal) = self
            .eval
            .namespace_regression_signal(&namespace_hint)
            .filter(|signal| signal.regressed)
        {
            record_failed_operation_on(
                &self.db,
                &plan,
                &actor,
                "evaluation_regressed_after_planning",
            )
            .map_err(Status::internal)?;
            return Err(Status::failed_precondition(signal.reason));
        }

        // Lookup-first short-circuit for stream execute (#281 S2). This is
        // deliberately after namespace authorization and plan ownership
        // checks and the live evaluation-regression gate, but before provider
        // selection, residency, egress, or model payload preparation. A
        // complete structured hit must not enter the provider-routing path at
        // all.
        let lookup_refusal = match evaluate_execute_lookup_first(&self.db, &input, &actor) {
            ExecuteLookupFirst::Hit {
                response,
                capability,
                provenance,
            } => {
                self.invalidate_ineligible_execution_memory_holdouts(
                    &plan.plan_id,
                    &actor,
                    &plan.memory_holdouts,
                )?;
                self.record_execution_memory_injections(
                    &plan.plan_id,
                    &actor,
                    &plan.memory_references,
                )?;
                if let Err(error) = self.record_evolve_task(
                    &input.request_id,
                    &namespace_hint,
                    &plan.enriched_spec,
                    "done",
                    0,
                ) {
                    record_failed_operation_on(
                        &self.db,
                        &plan,
                        &actor,
                        "execution_bookkeeping_failed",
                    )
                    .map_err(Status::internal)?;
                    return Err(Status::internal(error));
                }
                let completed_at_ms = chrono::Utc::now().timestamp_millis();
                record_completed_lookup_operation_on(
                    &self.db,
                    &plan,
                    &actor,
                    &response,
                    attempt_started_at_ms,
                    completed_at_ms,
                    &capability,
                    &provenance,
                )
                .map_err(Status::internal)?;
                let content = response.content.clone();
                let stream = async_stream::stream! {
                    yield Ok(ExecutePlanStreamEvent {
                        content_delta: content,
                        response: Some(response),
                        done: true,
                        executed_at: completed_at_ms / 1000,
                    });
                };
                return Ok(Box::pin(stream));
            }
            ExecuteLookupFirst::ModelPath { lookup_refusal } => lookup_refusal,
        };

        let provider = crate::llm::provider_name(&plan.resolved_model).to_string();
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let data_class = self.data_class(effective_policy.as_ref());
        if let Err(error) = self.policy.enforce_residency(
            &input.namespace,
            &provider,
            &plan.resolved_model,
            data_class.as_str(),
        ) {
            record_failed_operation_on(&self.db, &plan, &actor, "residency_denied")
                .map_err(Status::internal)?;
            return Err(Status::permission_denied(error));
        }
        self.enforce_execution_provider_privacy(&plan, &input, &actor, &provider, data_class)?;
        if crate::chisei::egress::is_external_provider(&provider)
            && plan.egress_decisions.is_empty()
        {
            record_failed_operation_on(&self.db, &plan, &actor, "egress_evidence_missing")
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "external execution plan missing egress decisions",
            ));
        }
        let normalized_user_id = if input.user_id.is_empty() {
            "default".to_string()
        } else {
            input.user_id.clone()
        };
        self.enforce_execution_payload_privacy(&plan, &input, &actor, &provider, data_class)?;
        self.record_egress_audit(
            "execute_context",
            &input.request_id,
            &provider,
            &plan.resolved_model,
            &plan.egress_decisions,
        );
        let llm_req = ProviderExecutionRequest {
            model: plan.resolved_model.clone(),
            system: plan.prepared_system.clone(),
            messages: plan.prepared_messages.clone(),
            tools: plan.tools.clone(),
            max_tokens: plan.max_tokens,
            user_id: Some(normalized_user_id),
        };
        self.invalidate_ineligible_execution_memory_holdouts(
            &plan.plan_id,
            &actor,
            &plan.memory_holdouts,
        )?;
        self.record_execution_memory_injections(&plan.plan_id, &actor, &plan.memory_references)?;

        let cacheable_message_count =
            native_cacheable_message_count(&input, &plan.prepared_messages);
        let chat_stream = match execute_native_chat_request_stream(
            &self.config,
            self.budget.clone(),
            self.db.as_ref(),
            context.as_ref(),
            llm_req,
            cacheable_message_count,
        )
        .await
        {
            Ok(stream) => stream,
            Err(status) => {
                record_failed_operation_on(&self.db, &plan, &actor, "model_stream_start_failed")
                    .map_err(Status::internal)?;
                return Err(status);
            }
        };
        let db = self.db.clone();
        let evolve_history = self.evolve_history.clone();
        let request_id = input.request_id.clone();
        let enriched_spec = plan.enriched_spec.clone();
        let resolved_model = plan.resolved_model.clone();
        let sampled = plan.sampled;
        let sample_rate = plan.sample_rate;
        let sample_reason = plan.sample_reason.clone();
        let scoring_enabled = self.config.scoring_enabled;
        let receipt_plan = plan.clone();
        // `plan.task_class` holds the *privacy* class here (see `plan_from_input`); the routing/
        // cost-tier class the caller supplied is on the original `input`.
        let task_class = crate::chisei::scoring::normalize_task_class(&input.task_class);

        let stream = async_stream::stream! {
            let mut content = String::new();
            let mut tool_calls = Vec::new();
            let mut input_tokens = 0;
            let mut output_tokens = 0;
            let mut cache_read_input_tokens = 0;
            let mut cache_creation_input_tokens = 0;
            let mut stop_reason = String::new();
            let mut finished = false;

            futures_util::pin_mut!(chat_stream);
            while let Some(next) = chat_stream.next().await {
                let chunk = match next {
                    Ok(chunk) => chunk,
                    Err(err) => {
                        if let Err(receipt_error) = record_failed_operation_on(
                            &db,
                            &receipt_plan,
                            &actor,
                            "model_stream_failed",
                        ) {
                            yield Err(Status::internal(receipt_error));
                            return;
                        }
                        yield Err(err);
                        return;
                    }
                };
                if !chunk.content.is_empty() {
                    content = chunk.content.clone();
                } else if !chunk.content_delta.is_empty() {
                    content.push_str(&chunk.content_delta);
                }
                if !chunk.tool_calls.is_empty() {
                    tool_calls = chunk.tool_calls.clone();
                }
                if chunk.input_tokens > 0 {
                    input_tokens = chunk.input_tokens;
                }
                if chunk.output_tokens > 0 {
                    output_tokens = chunk.output_tokens;
                }
                if chunk.cache_read_input_tokens > 0 {
                    cache_read_input_tokens = chunk.cache_read_input_tokens;
                }
                if chunk.cache_creation_input_tokens > 0 {
                    cache_creation_input_tokens = chunk.cache_creation_input_tokens;
                }
                if !chunk.stop_reason.is_empty() {
                    stop_reason = chunk.stop_reason.clone();
                }
                if chunk.done && !finished {
                    finished = true;
                    let response = PlannedChatResponse {
                        content: content.clone(),
                        tool_calls: tool_calls
                            .iter()
                            .map(|tc| ToolCall {
                                id: tc.id.clone(),
                                name: tc.name.clone(),
                                args_json: tc.args_json.clone(),
                            })
                            .collect(),
                        input_tokens,
                        output_tokens,
                        stop_reason: stop_reason.clone(),
                        provider: provider.clone(),
                        cache_read_input_tokens,
                        cache_creation_input_tokens,
                    };
                    let execution = FinishStreamedExecution {
                        db: db.as_ref(),
                        evolve_history: &evolve_history,
                        request_id: &request_id,
                        namespace: &namespace_hint,
                        enriched_spec: &enriched_spec,
                        resolved_model: &resolved_model,
                        sampled,
                        sample_rate,
                        sample_reason: &sample_reason,
                        scoring_enabled,
                        task_class: &task_class,
                        response: &response,
                    };
                    if let Err(error) = finish_streamed_execution(&execution) {
                        if let Err(receipt_error) = record_failed_operation_on(
                            &db,
                            &receipt_plan,
                            &actor,
                            "stream_bookkeeping_failed",
                        ) {
                            yield Err(Status::internal(receipt_error));
                            return;
                        }
                        yield Err(Status::internal(error));
                        return;
                    }
                    let completed_at_ms = chrono::Utc::now().timestamp_millis();
                    let answer_path = lookup_refusal
                        .as_ref()
                        .map(|_| crate::chisei::lookup_first::ANSWER_PATH_MODEL);
                    if let Err(error) = record_completed_operation_on_with_path(
                        db.as_ref(),
                        &receipt_plan,
                        &actor,
                        &response,
                        attempt_started_at_ms,
                        completed_at_ms,
                        answer_path,
                        lookup_refusal.as_deref(),
                    ) {
                        yield Err(Status::internal(error));
                        return;
                    }
                    yield Ok(ExecutePlanStreamEvent {
                        content_delta: chunk.content_delta,
                        response: Some(response),
                        done: true,
                        executed_at: completed_at_ms / 1000,
                    });
                } else {
                    yield Ok(ExecutePlanStreamEvent {
                        content_delta: chunk.content_delta,
                        response: None,
                        done: false,
                        executed_at: 0,
                    });
                }
            }
            if !finished {
                let response = PlannedChatResponse {
                    content,
                    tool_calls: tool_calls
                        .into_iter()
                        .map(|tc| ToolCall {
                            id: tc.id,
                            name: tc.name,
                            args_json: tc.args_json,
                        })
                        .collect(),
                    input_tokens,
                    output_tokens,
                    stop_reason,
                    provider,
                    cache_read_input_tokens,
                    cache_creation_input_tokens,
                };
                let execution = FinishStreamedExecution {
                    db: db.as_ref(),
                    evolve_history: &evolve_history,
                    request_id: &request_id,
                    namespace: &namespace_hint,
                    enriched_spec: &enriched_spec,
                    resolved_model: &resolved_model,
                    sampled,
                    sample_rate,
                    sample_reason: &sample_reason,
                    scoring_enabled,
                    task_class: &task_class,
                    response: &response,
                };
                if let Err(error) = finish_streamed_execution(&execution) {
                    if let Err(receipt_error) = record_failed_operation_on(
                        &db,
                        &receipt_plan,
                        &actor,
                        "stream_bookkeeping_failed",
                    ) {
                        yield Err(Status::internal(receipt_error));
                        return;
                    }
                    yield Err(Status::internal(error));
                    return;
                }
                let completed_at_ms = chrono::Utc::now().timestamp_millis();
                let answer_path = lookup_refusal
                    .as_ref()
                    .map(|_| crate::chisei::lookup_first::ANSWER_PATH_MODEL);
                if let Err(error) = record_completed_operation_on_with_path(
                    &db,
                    &receipt_plan,
                    &actor,
                    &response,
                    attempt_started_at_ms,
                    completed_at_ms,
                    answer_path,
                    lookup_refusal.as_deref(),
                ) {
                    yield Err(Status::internal(error));
                    return;
                }
                yield Ok(ExecutePlanStreamEvent {
                    content_delta: String::new(),
                    response: Some(response),
                    done: true,
                    executed_at: completed_at_ms / 1000,
                });
            }
        };
        Ok(Box::pin(stream))
    }

    pub(super) fn record_execution_memory_injections(
        &self,
        operation_id: &str,
        actor: &str,
        references: &[MemoryContextReference],
    ) -> Result<(), Status> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        for reference in references {
            let memory = self
                .db
                .get_kioku_memory(&reference.memory_id, reference.memory_version)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("planned memory version not found"))?;
            if !memory_lifecycle_allows_execution(
                memory.state,
                memory.expires_at_ms,
                memory.retention_until_ms,
                now_ms,
            ) {
                return Err(Status::failed_precondition(
                    "planned memory version is no longer active",
                ));
            }
            let authorized_ceiling = self
                .db
                .kioku_authorized_classification_ceiling(&memory.namespace, actor)
                .map_err(|_| {
                    Status::permission_denied(
                        "executing actor is not authorized for planned memory",
                    )
                })?;
            if memory.classification > authorized_ceiling {
                return Err(Status::permission_denied(
                    "planned memory classification exceeds executing actor grant",
                ));
            }
            if crate::chisei::kioku::memory_claim_digest(&memory) != reference.content_digest {
                return Err(Status::failed_precondition(
                    "planned memory digest no longer matches the cached reference",
                ));
            }
        }
        for reference in references {
            self.db
                .record_kioku_lifecycle_event(&crate::chisei::kioku::MemoryLifecycleEvent {
                    memory_id: reference.memory_id.clone(),
                    memory_version: reference.memory_version,
                    action: "injected".into(),
                    from_state: Some("active".into()),
                    to_state: "active".into(),
                    actor: actor.into(),
                    reason: format!("pipeline operation {operation_id}"),
                    recorded_at_ms: now_ms,
                })
                .map_err(Status::internal)?;
        }
        Ok(())
    }

    pub(super) fn invalidate_ineligible_execution_memory_holdouts(
        &self,
        operation_id: &str,
        actor: &str,
        references: &[MemoryHoldoutReference],
    ) -> Result<(), Status> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        for reference in references {
            let Some(memory) = self
                .db
                .get_kioku_memory(&reference.memory_id, reference.memory_version)
                .map_err(Status::internal)?
            else {
                continue;
            };
            let authorized = self
                .db
                .kioku_authorized_classification_ceiling(&memory.namespace, actor)
                .is_ok_and(|ceiling| memory.classification <= ceiling);
            let eligible = memory_lifecycle_allows_execution(
                memory.state,
                memory.expires_at_ms,
                memory.retention_until_ms,
                now_ms,
            ) && authorized
                && memory.classification.as_str() == reference.classification
                && crate::chisei::kioku::memory_claim_digest(&memory) == reference.content_digest;
            if !eligible {
                self.db
                    .record_kioku_lifecycle_event(&crate::chisei::kioku::MemoryLifecycleEvent {
                        memory_id: reference.memory_id.clone(),
                        memory_version: reference.memory_version,
                        action: "holdout_invalidated".into(),
                        from_state: Some(memory.state.as_str().into()),
                        to_state: memory.state.as_str().into(),
                        actor: actor.into(),
                        reason: format!("pipeline operation {operation_id}"),
                        recorded_at_ms: now_ms,
                    })
                    .map_err(Status::internal)?;
            }
        }
        Ok(())
    }

    pub(super) fn enforce_execution_provider_privacy(
        &self,
        plan: &ExecutionPlan,
        input: &ExecutionInput,
        actor: &str,
        provider: &str,
        data_class: DataClass,
    ) -> Result<(), Status> {
        let task_class = TaskClass::parse(&plan.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        if safe_only && !crate::chisei::privacy::provider_safe_to_send(provider, &safe_providers) {
            self.record_privacy_audit(
                "blocked",
                &input.request_id,
                provider,
                data_class,
                task_class,
                "cached_plan_unsafe_provider",
            );
            record_failed_operation_on(&self.db, plan, actor, "provider_became_unsafe")
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                crate::chisei::privacy::gate_reason(data_class, task_class, provider),
            ));
        }
        Ok(())
    }

    pub(super) fn enforce_execution_payload_privacy(
        &self,
        plan: &ExecutionPlan,
        input: &ExecutionInput,
        actor: &str,
        provider: &str,
        data_class: DataClass,
    ) -> Result<(), Status> {
        let payload =
            payload_for_leak_check(&plan.prepared_system, &plan.prepared_messages, &plan.tools);
        let leak_findings =
            self.leak_findings_for_payload(&input.namespace, provider, data_class, &payload);
        if leak_findings
            .iter()
            .any(|finding| finding.action == LeakAction::Block)
        {
            self.record_leak_audit(
                "execute_leak_check",
                &input.request_id,
                provider,
                &leak_findings,
            );
            record_failed_operation_on(
                &self.db,
                plan,
                actor,
                "privacy_leak_detected_after_planning",
            )
            .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "privacy leak checker blocked outbound payload",
            ));
        }
        Ok(())
    }
}

/// Complete an operation that was fully answered by structured lookup (#281).
/// Records `answer_path=lookup_hit`, zero provider tokens, and no billable model call.
#[allow(clippy::too_many_arguments)]
pub(super) fn record_completed_lookup_operation_on(
    db: &RuntimeDb,
    plan: &ExecutionPlan,
    actor: &str,
    response: &PlannedChatResponse,
    attempt_started_at_ms: i64,
    completed_at_ms: i64,
    capability: &str,
    provenance: &BTreeMap<String, String>,
) -> Result<(), String> {
    db.update_operation_receipt(&plan.plan_id, |receipt| {
        if receipt.completed_at_ms.is_some() {
            return Err("operation receipt already has a terminal outcome".into());
        }
        let canonical_egress_id = format!("{}:egress", receipt.operation_id);
        let parent = if receipt.events.iter().any(|event| {
            event.event_id == canonical_egress_id && event.kind == ReceiptEventKind::EgressDecided
        }) {
            "egress"
        } else {
            "budget"
        };
        let mut artifact_attrs = BTreeMap::from([
            ("artifact_type".into(), "structured_lookup".into()),
            ("content_hash".into(), planned_response_hash(response)),
            ("content_stored".into(), "false".into()),
            (
                crate::chisei::lookup_first::ANSWER_PATH_ATTR.into(),
                crate::chisei::lookup_first::ANSWER_PATH_LOOKUP_HIT.into(),
            ),
            ("capability".into(), capability.into()),
            (
                "provider".into(),
                crate::chisei::lookup_first::LOOKUP_PROVIDER.into(),
            ),
            ("input_tokens".into(), "0".into()),
            ("output_tokens".into(), "0".into()),
        ]);
        for (key, value) in provenance {
            artifact_attrs.insert(format!("provenance_{key}"), value.clone());
        }
        receipt.events.extend([
            receipt_event(
                &receipt.operation_id,
                "attempt-1",
                Some(parent),
                attempt_started_at_ms,
                ReceiptEventKind::AttemptStarted,
                actor,
                BTreeMap::from([("attempt".into(), "1".into())]),
            ),
            receipt_event(
                &receipt.operation_id,
                "artifact-1",
                Some("attempt-1"),
                completed_at_ms,
                ReceiptEventKind::ArtifactProduced,
                "chisei.lookup_first",
                artifact_attrs,
            ),
            receipt_event(
                &receipt.operation_id,
                "verification",
                Some("artifact-1"),
                completed_at_ms,
                ReceiptEventKind::VerificationRecorded,
                "chisei.execution",
                BTreeMap::from([("status".into(), "not_requested".into())]),
            ),
            receipt_event(
                &receipt.operation_id,
                "outcome",
                Some("verification"),
                completed_at_ms,
                ReceiptEventKind::OutcomeRecorded,
                actor,
                BTreeMap::from([
                    ("status".into(), "succeeded".into()),
                    (
                        "completion_reason".into(),
                        crate::chisei::lookup_first::LOOKUP_HIT_STOP_REASON.into(),
                    ),
                    (
                        crate::chisei::lookup_first::ANSWER_PATH_ATTR.into(),
                        crate::chisei::lookup_first::ANSWER_PATH_LOOKUP_HIT.into(),
                    ),
                    ("provider_tokens".into(), "0".into()),
                    (
                        "latency_ms".into(),
                        completed_at_ms
                            .saturating_sub(receipt.started_at_ms)
                            .to_string(),
                    ),
                ]),
            ),
        ]);
        receipt.completed_at_ms = Some(completed_at_ms);
        // ModelCall remains uncovered by design: zero provider tokens, no adapter call.
        receipt.uncovered_surfaces = vec![UncoveredSurface {
            surface: ReceiptSurface::ModelCall,
            reason: "answered by structured lookup without a provider model call".into(),
        }];
        Ok(())
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record_completed_operation_on_with_path(
    db: &RuntimeDb,
    plan: &ExecutionPlan,
    actor: &str,
    response: &PlannedChatResponse,
    attempt_started_at_ms: i64,
    completed_at_ms: i64,
    answer_path: Option<&str>,
    lookup_refusal: Option<&str>,
) -> Result<(), String> {
    let cost_usd_micros = crate::cost_estimate::pricing_from_env()
        .ok()
        .and_then(|pricing| native_execution_cost(plan, response, &pricing));
    db.update_operation_receipt(&plan.plan_id, |receipt| {
        if receipt.completed_at_ms.is_some() {
            return Err("operation receipt already has a terminal outcome".into());
        }
        let canonical_egress_id = format!("{}:egress", receipt.operation_id);
        let parent = if receipt.events.iter().any(|event| {
            event.event_id == canonical_egress_id && event.kind == ReceiptEventKind::EgressDecided
        }) {
            "egress"
        } else {
            "budget"
        };
        receipt.events.extend([
            receipt_event(
                &receipt.operation_id,
                "attempt-1",
                Some(parent),
                attempt_started_at_ms,
                ReceiptEventKind::AttemptStarted,
                actor,
                BTreeMap::from([("attempt".into(), "1".into())]),
            ),
            receipt_event(
                &receipt.operation_id,
                "model-call-1",
                Some("attempt-1"),
                completed_at_ms,
                ReceiptEventKind::ModelCalled,
                "chisei.llm",
                {
                    let mut attributes = BTreeMap::from([
                        ("provider".into(), response.provider.clone()),
                        ("model".into(), plan.resolved_model.clone()),
                        ("input_tokens".into(), response.input_tokens.to_string()),
                        ("output_tokens".into(), response.output_tokens.to_string()),
                    ]);
                    if let Some(cost_usd_micros) = cost_usd_micros {
                        attributes.insert("cost_usd_micros".into(), cost_usd_micros.to_string());
                    }
                    if let Some(path) = answer_path {
                        attributes.insert(
                            crate::chisei::lookup_first::ANSWER_PATH_ATTR.into(),
                            path.into(),
                        );
                    }
                    if let Some(reason) = lookup_refusal {
                        attributes.insert(
                            crate::chisei::lookup_first::LOOKUP_REFUSAL_ATTR.into(),
                            reason.into(),
                        );
                    }
                    attributes
                },
            ),
            receipt_event(
                &receipt.operation_id,
                "artifact-1",
                Some("model-call-1"),
                completed_at_ms,
                ReceiptEventKind::ArtifactProduced,
                "chisei.llm",
                BTreeMap::from([
                    ("artifact_type".into(), "model_response".into()),
                    ("content_hash".into(), planned_response_hash(response)),
                    ("content_stored".into(), "false".into()),
                ]),
            ),
            receipt_event(
                &receipt.operation_id,
                "verification",
                Some("artifact-1"),
                completed_at_ms,
                ReceiptEventKind::VerificationRecorded,
                "chisei.execution",
                BTreeMap::from([("status".into(), "not_requested".into())]),
            ),
            receipt_event(
                &receipt.operation_id,
                "outcome",
                Some("verification"),
                completed_at_ms,
                ReceiptEventKind::OutcomeRecorded,
                actor,
                {
                    let mut attributes = BTreeMap::from([
                        ("status".into(), "succeeded".into()),
                        ("completion_reason".into(), response.stop_reason.clone()),
                        (
                            "latency_ms".into(),
                            completed_at_ms
                                .saturating_sub(receipt.started_at_ms)
                                .to_string(),
                        ),
                    ]);
                    if let Some(path) = answer_path {
                        attributes.insert(
                            crate::chisei::lookup_first::ANSWER_PATH_ATTR.into(),
                            path.into(),
                        );
                    }
                    if let Some(reason) = lookup_refusal {
                        attributes.insert(
                            crate::chisei::lookup_first::LOOKUP_REFUSAL_ATTR.into(),
                            reason.into(),
                        );
                    }
                    attributes
                },
            ),
        ]);
        receipt.completed_at_ms = Some(completed_at_ms);
        receipt.uncovered_surfaces.clear();
        Ok(())
    })?;
    Ok(())
}

/// After namespace authz, try allow-listed structured lookup before provider routing.
pub(super) fn evaluate_execute_lookup_first(
    db: &RuntimeDb,
    input: &ExecutionInput,
    actor: &str,
) -> ExecuteLookupFirst {
    if !crate::chisei::lookup_first::is_lookup_first_capability(&input.task_type) {
        return ExecuteLookupFirst::ModelPath {
            lookup_refusal: None,
        };
    }
    match crate::chisei::lookup_first::try_lookup_first(
        &input.task_type,
        &input.namespace,
        actor,
        &input.spec,
        db,
    ) {
        Ok(crate::chisei::lookup_first::LookupDecision::Hit {
            answer_json,
            capability,
            provenance,
        }) => {
            crate::chisei::lookup_first::record_lookup_hit();
            ExecuteLookupFirst::Hit {
                response: PlannedChatResponse {
                    content: answer_json,
                    tool_calls: Vec::new(),
                    input_tokens: 0,
                    output_tokens: 0,
                    stop_reason: crate::chisei::lookup_first::LOOKUP_HIT_STOP_REASON.into(),
                    provider: crate::chisei::lookup_first::LOOKUP_PROVIDER.into(),
                    cache_read_input_tokens: 0,
                    cache_creation_input_tokens: 0,
                },
                capability,
                provenance,
            }
        }
        Ok(crate::chisei::lookup_first::LookupDecision::Refusal { reason, .. }) => {
            crate::chisei::lookup_first::record_model_path(true);
            ExecuteLookupFirst::ModelPath {
                lookup_refusal: Some(reason),
            }
        }
        Ok(crate::chisei::lookup_first::LookupDecision::NotEligible) => {
            ExecuteLookupFirst::ModelPath {
                lookup_refusal: None,
            }
        }
        Err(error) => {
            crate::chisei::lookup_first::record_model_path(true);
            ExecuteLookupFirst::ModelPath {
                lookup_refusal: Some(format!("storage_error:{error}")),
            }
        }
    }
}

pub(super) fn native_execution_cost(
    plan: &ExecutionPlan,
    response: &PlannedChatResponse,
    pricing: &HashMap<String, crate::pricing::ModelPricing>,
) -> Option<i64> {
    let (priced_model, rates) =
        crate::pricing::lookup_pricing_entry(pricing, &plan.resolved_model)?;
    crate::cost_estimate::cost_usd_micros(
        priced_model,
        rates,
        i64::from(response.input_tokens),
        i64::from(response.output_tokens),
        i64::from(response.cache_read_input_tokens),
        i64::from(response.cache_creation_input_tokens),
    )
}

pub(super) fn record_failed_operation_on(
    db: &RuntimeDb,
    plan: &ExecutionPlan,
    actor: &str,
    completion_reason: &str,
) -> Result<(), String> {
    if db.get_operation_receipt(&plan.plan_id)?.is_none() {
        return Ok(());
    }
    let completed_at_ms = chrono::Utc::now().timestamp_millis();
    db.update_operation_receipt(&plan.plan_id, |receipt| {
        if receipt.completed_at_ms.is_some() {
            return Ok(());
        }
        let canonical_egress_id = format!("{}:egress", receipt.operation_id);
        let parent = if receipt.events.iter().any(|event| {
            event.event_id == canonical_egress_id && event.kind == ReceiptEventKind::EgressDecided
        }) {
            "egress"
        } else {
            "budget"
        };
        receipt.events.push(receipt_event(
            &receipt.operation_id,
            "outcome",
            Some(parent),
            completed_at_ms,
            ReceiptEventKind::OutcomeRecorded,
            actor,
            BTreeMap::from([
                ("status".into(), "denied".into()),
                ("completion_reason".into(), completion_reason.into()),
                (
                    "latency_ms".into(),
                    completed_at_ms
                        .saturating_sub(receipt.started_at_ms)
                        .to_string(),
                ),
            ]),
        ));
        receipt.completed_at_ms = Some(completed_at_ms);
        receipt.uncovered_surfaces.clear();
        Ok(())
    })?;
    Ok(())
}

pub(super) struct FinishStreamedExecution<'a> {
    db: &'a RuntimeDb,
    evolve_history: &'a Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    request_id: &'a str,
    namespace: &'a str,
    enriched_spec: &'a str,
    resolved_model: &'a str,
    sampled: bool,
    sample_rate: f64,
    sample_reason: &'a str,
    scoring_enabled: bool,
    task_class: &'a str,
    response: &'a PlannedChatResponse,
}

pub(super) fn finish_streamed_execution(execution: &FinishStreamedExecution) -> Result<(), String> {
    record_evolve_task_on(
        execution.db,
        execution.evolve_history,
        EvolveTaskRecord {
            request_id: execution.request_id,
            namespace: execution.namespace,
            spec: execution.enriched_spec,
            status: "done",
            tokens_used: execution.response.input_tokens + execution.response.output_tokens,
        },
    )?;
    if execution.sampled {
        let mut evidence = HashMap::new();
        evidence.insert("model".to_string(), execution.resolved_model.to_string());
        evidence.insert(
            "input_tokens".to_string(),
            execution.response.input_tokens.to_string(),
        );
        evidence.insert(
            "output_tokens".to_string(),
            execution.response.output_tokens.to_string(),
        );
        evidence.insert(
            "stop_reason".to_string(),
            execution.response.stop_reason.clone(),
        );
        evidence.insert("sample_rate".to_string(), execution.sample_rate.to_string());
        let _ = execution
            .db
            .record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                actor: "chisei.sampling".into(),
                action: "sample_observed".into(),
                reason: execution.sample_reason.to_string(),
                evidence,
                target_id: execution.request_id.to_string(),
                outcome: "observed".into(),
            });
        if execution.scoring_enabled {
            let _ =
                execution
                    .db
                    .put_sample_observation(&crate::chisei::scoring::SampleObservation {
                        request_id: execution.request_id.to_string(),
                        namespace: execution.namespace.to_string(),
                        spec: execution.enriched_spec.to_string(),
                        resolved_model: execution.resolved_model.to_string(),
                        output_content: execution.response.content.clone(),
                        sample_reason: execution.sample_reason.to_string(),
                        input_tokens: execution.response.input_tokens,
                        output_tokens: execution.response.output_tokens,
                        stop_reason: execution.response.stop_reason.clone(),
                        timestamp: chrono::Utc::now().timestamp_millis(),
                        scored: false,
                        task_class: execution.task_class.to_string(),
                        cost_usd_micros: 0,
                    });
        }
    }
    Ok(())
}

pub(super) fn native_cacheable_message_count(
    input: &ExecutionInput,
    prepared: &[ChatMessage],
) -> usize {
    let has_dynamic_spec = !input.spec.is_empty() || prepared.len() > input.messages.len();
    if has_dynamic_spec
        && prepared
            .first()
            .is_some_and(|message| message.content.starts_with("[Task spec]\n"))
    {
        0
    } else if has_dynamic_spec {
        input.messages.len().min(prepared.len())
    } else {
        prepared.len().saturating_sub(1)
    }
}
