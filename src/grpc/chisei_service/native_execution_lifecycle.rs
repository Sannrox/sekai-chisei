//! Native plan execution behind one private interface.
//!
//! The gRPC adapter authenticates the caller and translates protocol messages.
//! This module owns the ordered execute lifecycle: lookup-first short-circuit,
//! live evaluation regression gate, residency/privacy/egress rechecks, provider
//! streaming, evolve/scoring bookkeeping, and terminal receipt completion.

use super::*;

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
}
