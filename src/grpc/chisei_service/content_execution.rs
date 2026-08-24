//! Parallel bounded-content planning and execution.
//!
//! This module intentionally does not reuse `ChatMessage`: old servers must
//! reject the new RPC instead of silently executing a text-only projection.

use super::native_execution_lifecycle::{
    FinishStreamedExecution, finish_streamed_execution, record_completed_operation_on_with_path,
    record_failed_operation_on,
};
use super::*;
use crate::content::{
    self, ContentCapabilities as DomainCapabilities, ContentDescriptor as DomainDescriptor,
    ContentKind as DomainKind, ContentMessage as DomainMessage,
    ContentProvenance as DomainProvenance, DisclosureState as DomainDisclosure,
    ResolvedContentPart as DomainResolvedPart, ResolvedPayload as DomainPayload,
};
use crate::grpc::provider_execution::{
    ProviderContentExecutionRequest, execute_native_content_request_stream,
};

impl ChiseiServiceImpl {
    pub(super) async fn plan_content_from_input(
        &self,
        input: ContentExecutionInputV1,
        actor: &str,
    ) -> Result<ContentExecutionPlanV1, Status> {
        if input.disclosure_authority != content::DISCLOSURE_AUTHORITY {
            return Err(Status::failed_precondition(
                "recognized Chisei disclosure authority is required",
            ));
        }
        let mut execution_input = input
            .execution
            .ok_or_else(|| Status::invalid_argument("content execution input required"))?;
        if !execution_input.messages.is_empty() {
            return Err(Status::invalid_argument(
                "content execution must not use text ChatMessage fields",
            ));
        }
        validate_content_messages(&input.content_messages)?;
        let requested = input
            .requested_capabilities
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("content capabilities required"))?;
        validate_requested_capabilities(requested, &input.content_messages)?;

        execution_input.messages.clear();
        let mut execution = self.plan_from_input(execution_input, actor).await?;
        let content_messages =
            match self.authorize_content_disclosures(&mut execution, input.content_messages) {
                Ok(messages) => messages,
                Err(status) => {
                    record_failed_operation_on(
                        &self.db,
                        &execution,
                        actor,
                        "content_disclosure_denied",
                    )
                    .map_err(Status::internal)?;
                    return Err(status);
                }
            };
        let resolved_capabilities =
            match resolve_content_capabilities(&execution, requested, &content_messages) {
                Ok(capabilities) => capabilities,
                Err(status) => {
                    record_failed_operation_on(
                        &self.db,
                        &execution,
                        actor,
                        "content_capability_denied",
                    )
                    .map_err(Status::internal)?;
                    return Err(status);
                }
            };
        let descriptors = content_messages
            .iter()
            .flat_map(|message| &message.parts)
            .map(descriptor_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ContentExecutionPlanV1 {
            execution: Some(execution),
            content_messages,
            resolved_capabilities: Some(resolved_capabilities),
            descriptor_digest: content::descriptor_digest(&descriptors),
        })
    }

    fn authorize_content_disclosures(
        &self,
        execution: &mut ExecutionPlan,
        mut messages: Vec<ContentMessageV1>,
    ) -> Result<Vec<ContentMessageV1>, Status> {
        let input = execution
            .input
            .as_ref()
            .ok_or_else(|| Status::data_loss("content execution input missing"))?;
        let provider = crate::llm::provider_name(&execution.resolved_model).to_string();
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let data_class = self.data_class(effective_policy.as_ref());
        self.policy
            .enforce_residency(
                &input.namespace,
                &provider,
                &execution.resolved_model,
                data_class.as_str(),
            )
            .map_err(Status::permission_denied)?;

        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let provider_is_safe =
            crate::chisei::privacy::provider_safe_to_send(&provider, &safe_providers);
        let task_class = TaskClass::parse(&execution.task_class);
        if !crate::chisei::privacy::external_allowed(data_class, task_class) && !provider_is_safe {
            return Err(Status::failed_precondition(
                crate::chisei::privacy::gate_reason(data_class, task_class, &provider),
            ));
        }
        let mut included = Vec::new();
        let mut redacted = Vec::new();
        for descriptor in messages.iter_mut().flat_map(|message| &mut message.parts) {
            match descriptor.disclosure_state {
                1 if content_part_disclosure_allowed(
                    descriptor.kind,
                    provider_is_safe,
                    data_class,
                    task_class,
                ) =>
                {
                    descriptor.disclosure_reason.clear();
                    included.push(descriptor.part_id.clone());
                }
                1 => {
                    descriptor.disclosure_state = 2;
                    descriptor.disclosure_reason =
                        "Chisei policy cannot verify this content for provider disclosure".into();
                    redacted.push(descriptor.part_id.clone());
                }
                2 => {
                    descriptor.disclosure_reason = "caller requested redaction".into();
                    redacted.push(descriptor.part_id.clone());
                }
                3 => {
                    descriptor.disclosure_reason = "caller omitted content".into();
                    redacted.push(descriptor.part_id.clone());
                }
                _ => {
                    return Err(Status::invalid_argument(
                        "content disclosure state is unknown",
                    ));
                }
            }
        }
        validate_authorized_content_messages(&messages)?;
        if included.is_empty() {
            return Err(Status::permission_denied(
                "Chisei policy did not authorize any content for disclosure",
            ));
        }
        execution.egress_decisions.push(EgressDecision {
            provider: provider.clone(),
            external: crate::chisei::egress::is_external_provider(&provider),
            included,
            redacted,
            reasons: vec![content::DISCLOSURE_AUTHORITY.into()],
        });
        Ok(messages)
    }

    pub(super) fn cache_content_plan(
        &self,
        plan: ContentExecutionPlanV1,
        enterprise_authority: Option<String>,
    ) -> Result<(), Status> {
        let plan_id = plan
            .execution
            .as_ref()
            .map(|execution| execution.plan_id.as_str())
            .filter(|plan_id| !plan_id.is_empty())
            .ok_or_else(|| Status::invalid_argument("content execution plan id required"))?
            .to_string();
        let mut plans = self
            .planned_content_executions
            .lock()
            .expect("planned content executions poisoned");
        prune_content_plans(&mut plans);
        plans.insert(
            plan_id.clone(),
            CachedContentExecutionPlan {
                plan,
                enterprise_authority,
            },
        );
        while plans.len() > MAX_CACHED_EXECUTION_PLANS {
            let Some(oldest) = plans
                .iter()
                .filter(|(candidate, _)| candidate.as_str() != plan_id)
                .min_by(|left, right| {
                    content_plan_created_at(&left.1.plan)
                        .cmp(&content_plan_created_at(&right.1.plan))
                        .then_with(|| left.0.cmp(right.0))
                })
                .map(|(candidate, _)| candidate.clone())
            else {
                break;
            };
            plans.remove(&oldest);
        }
        Ok(())
    }

    pub(super) async fn execute_content_planned_stream(
        &self,
        actor: String,
        context: Option<crate::enterprise::AuthenticatedContext>,
        requested_plan: ContentExecutionPlanV1,
        resolved_parts: Vec<ResolvedContentPartV1>,
    ) -> Result<<Self as ChiseiService>::ExecuteContentPlanStreamStream, Status> {
        let requested_plan_id = requested_plan
            .execution
            .as_ref()
            .map(|execution| execution.plan_id.as_str())
            .filter(|plan_id| !plan_id.is_empty())
            .ok_or_else(|| Status::invalid_argument("content execution plan required"))?;
        let cached = {
            let mut plans = self
                .planned_content_executions
                .lock()
                .expect("planned content executions poisoned");
            prune_content_plans(&mut plans);
            let cached = plans
                .get(requested_plan_id)
                .ok_or_else(|| Status::not_found("content execution plan not found"))?;
            let execution = cached
                .plan
                .execution
                .as_ref()
                .ok_or_else(|| Status::data_loss("cached content execution plan is invalid"))?;
            if execution.planning_actor != actor
                || cached.enterprise_authority != enterprise_execution_authority(context.as_ref())
            {
                return Err(Status::permission_denied(
                    "content execution plan belongs to a different planning principal",
                ));
            }
            cached.clone()
        };
        let plan = cached.plan;
        let execution = plan
            .execution
            .clone()
            .ok_or_else(|| Status::data_loss("cached content execution plan is invalid"))?;
        if !execution.executable {
            return Err(Status::failed_precondition(
                "content execution plan is not executable",
            ));
        }
        let input = execution
            .input
            .clone()
            .ok_or_else(|| Status::data_loss("content execution input missing"))?;
        require_execution_namespace_access_with_context(
            &self.db,
            &self.config,
            &actor,
            context.as_ref(),
            &input.namespace,
        )?;
        let domain_messages = resolve_content_messages(&plan, resolved_parts)?;

        let namespace = input.namespace.trim().to_string();
        if let Some(signal) = self
            .eval
            .namespace_regression_signal(&namespace)
            .filter(|signal| signal.regressed)
        {
            record_failed_operation_on(
                &self.db,
                &execution,
                &actor,
                "evaluation_regressed_after_planning",
            )
            .map_err(Status::internal)?;
            return Err(Status::failed_precondition(signal.reason));
        }
        let provider = crate::llm::provider_name(&execution.resolved_model).to_string();
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let data_class = self.data_class(effective_policy.as_ref());
        if let Err(error) = self.policy.enforce_residency(
            &input.namespace,
            &provider,
            &execution.resolved_model,
            data_class.as_str(),
        ) {
            record_failed_operation_on(&self.db, &execution, &actor, "residency_denied")
                .map_err(Status::internal)?;
            return Err(Status::permission_denied(error));
        }
        self.enforce_execution_provider_privacy(&execution, &input, &actor, &provider, data_class)?;
        if !has_content_disclosure_evidence(&execution, &plan.content_messages, &provider) {
            record_failed_operation_on(&self.db, &execution, &actor, "egress_evidence_missing")
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "content execution plan missing disclosure evidence",
            ));
        }
        self.enforce_execution_payload_privacy(&execution, &input, &actor, &provider, data_class)?;
        let resolved_text = domain_messages
            .iter()
            .flat_map(|message| &message.parts)
            .filter_map(|part| match &part.payload {
                DomainPayload::Text(text) => Some(text.as_str()),
                DomainPayload::Bytes(_) => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let leak_findings =
            self.leak_findings_for_payload(&input.namespace, &provider, data_class, &resolved_text);
        if !leak_findings.is_empty() {
            self.record_leak_audit(
                "content_leak_check",
                &input.request_id,
                &provider,
                &leak_findings,
            );
            record_failed_operation_on(&self.db, &execution, &actor, "content_leak_check_denied")
                .map_err(Status::internal)?;
            return Err(Status::permission_denied(
                "privacy policy requires content redaction or blocking",
            ));
        }
        self.record_egress_audit(
            "execute_content",
            &input.request_id,
            &provider,
            &execution.resolved_model,
            &execution.egress_decisions,
        );

        {
            let mut plans = self
                .planned_content_executions
                .lock()
                .expect("planned content executions poisoned");
            plans
                .remove(requested_plan_id)
                .ok_or_else(|| Status::not_found("content execution plan not found"))?;
        }

        self.invalidate_ineligible_execution_memory_holdouts(
            &execution.plan_id,
            &actor,
            &execution.memory_holdouts,
        )?;
        self.record_execution_memory_injections(
            &execution.plan_id,
            &actor,
            &execution.memory_references,
        )?;
        let normalized_user_id = if input.user_id.is_empty() {
            "default".to_string()
        } else {
            input.user_id.clone()
        };
        let mut system = execution.prepared_system.clone();
        if !execution.enriched_spec.trim().is_empty() {
            if !system.is_empty() {
                system.push_str("\n\n");
            }
            system.push_str("[Task spec]\n");
            system.push_str(&execution.enriched_spec);
        }
        let provider_request = ProviderContentExecutionRequest {
            model: execution.resolved_model.clone(),
            system,
            messages: domain_messages,
            tools: execution.tools.clone(),
            max_tokens: execution.max_tokens,
            user_id: Some(normalized_user_id),
        };
        let provider_stream = match execute_native_content_request_stream(
            &self.config,
            self.budget.clone(),
            self.db.as_ref(),
            context.as_ref(),
            provider_request,
        )
        .await
        {
            Ok(stream) => stream,
            Err(status) => {
                record_failed_operation_on(
                    &self.db,
                    &execution,
                    &actor,
                    "content_stream_start_failed",
                )
                .map_err(Status::internal)?;
                return Err(status);
            }
        };
        let attempt_started_at_ms = chrono::Utc::now().timestamp_millis();
        let db = self.db.clone();
        let evolve_history = self.evolve_history.clone();
        let request_id = input.request_id.clone();
        let enriched_spec = execution.enriched_spec.clone();
        let resolved_model = execution.resolved_model.clone();
        let sampled = execution.sampled;
        let sample_rate = execution.sample_rate;
        let sample_reason = execution.sample_reason.clone();
        let scoring_enabled = self.config.scoring_enabled;
        let task_class = crate::chisei::scoring::normalize_task_class(&input.task_class);
        let receipt_plan = execution.clone();
        let plan_id = execution.plan_id.clone();
        let stream = async_stream::stream! {
            let mut content = String::new();
            let mut tool_calls = Vec::new();
            let mut input_tokens = 0;
            let mut output_tokens = 0;
            let mut cache_read_input_tokens = 0;
            let mut cache_creation_input_tokens = 0;
            let mut stop_reason = String::new();
            let mut finished = false;
            futures_util::pin_mut!(provider_stream);
            while let Some(next) = provider_stream.next().await {
                let chunk = match next {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        if let Err(receipt_error) = record_failed_operation_on(
                            &db,
                            &receipt_plan,
                            &actor,
                            "content_stream_failed",
                        ) {
                            yield Err(Status::internal(receipt_error));
                            return;
                        }
                        yield Err(error);
                        return;
                    }
                };
                if !chunk.content.is_empty() {
                    content.clone_from(&chunk.content);
                } else if !chunk.content_delta.is_empty() {
                    content.push_str(&chunk.content_delta);
                }
                if !chunk.tool_calls.is_empty() {
                    tool_calls.clone_from(&chunk.tool_calls);
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
                    stop_reason.clone_from(&chunk.stop_reason);
                }
                if chunk.done && !finished {
                    finished = true;
                    let response = planned_response(
                        &content,
                        &tool_calls,
                        input_tokens,
                        output_tokens,
                        &stop_reason,
                        &provider,
                        cache_read_input_tokens,
                        cache_creation_input_tokens,
                    );
                    if let Err(error) = finish_content_execution(
                        &db,
                        &evolve_history,
                        &receipt_plan,
                        &actor,
                        &request_id,
                        &namespace,
                        &enriched_spec,
                        &resolved_model,
                        sampled,
                        sample_rate,
                        &sample_reason,
                        scoring_enabled,
                        &task_class,
                        &response,
                        attempt_started_at_ms,
                    ) {
                        yield Err(Status::internal(error));
                        return;
                    }
                    let completed_at_ms = chrono::Utc::now().timestamp_millis();
                    yield Ok(ExecuteContentPlanStreamEvent {
                        text_delta: chunk.content_delta,
                        response: Some(ContentExecutionResponseV1 {
                            output_parts: text_output_descriptors(
                                &plan_id,
                                &provider,
                                &content,
                                completed_at_ms,
                            ),
                            response: Some(response),
                        }),
                        done: true,
                        executed_at: completed_at_ms / 1000,
                    });
                } else {
                    yield Ok(ExecuteContentPlanStreamEvent {
                        text_delta: chunk.content_delta,
                        response: None,
                        done: false,
                        executed_at: 0,
                    });
                }
            }
            if !finished {
                let response = planned_response(
                    &content,
                    &tool_calls,
                    input_tokens,
                    output_tokens,
                    &stop_reason,
                    &provider,
                    cache_read_input_tokens,
                    cache_creation_input_tokens,
                );
                if let Err(error) = finish_content_execution(
                    &db,
                    &evolve_history,
                    &receipt_plan,
                    &actor,
                    &request_id,
                    &namespace,
                    &enriched_spec,
                    &resolved_model,
                    sampled,
                    sample_rate,
                    &sample_reason,
                    scoring_enabled,
                    &task_class,
                    &response,
                    attempt_started_at_ms,
                ) {
                    yield Err(Status::internal(error));
                    return;
                }
                let completed_at_ms = chrono::Utc::now().timestamp_millis();
                yield Ok(ExecuteContentPlanStreamEvent {
                    text_delta: String::new(),
                    response: Some(ContentExecutionResponseV1 {
                        output_parts: text_output_descriptors(
                            &plan_id,
                            &provider,
                            &content,
                            completed_at_ms,
                        ),
                        response: Some(response),
                    }),
                    done: true,
                    executed_at: completed_at_ms / 1000,
                });
            }
        };
        Ok(Box::pin(stream))
    }
}

fn validate_content_messages(messages: &[ContentMessageV1]) -> Result<(), Status> {
    if messages.is_empty() {
        return Err(Status::invalid_argument("content messages required"));
    }
    let mut descriptors = Vec::new();
    for message in messages {
        if !matches!(message.role.as_str(), "user" | "assistant" | "tool") {
            return Err(Status::invalid_argument(
                "content message role must be user, assistant, or tool",
            ));
        }
        for descriptor in &message.parts {
            descriptors.push(descriptor_from_proto(descriptor)?);
        }
    }
    content::validate_descriptors(&descriptors).map_err(Status::invalid_argument)?;
    if !descriptors
        .iter()
        .any(|descriptor| descriptor.disclosure_state == DomainDisclosure::Accepted)
    {
        return Err(Status::failed_precondition(
            "at least one content part must be accepted for disclosure",
        ));
    }
    Ok(())
}

fn validate_authorized_content_messages(messages: &[ContentMessageV1]) -> Result<(), Status> {
    for message in messages {
        let accepted = message
            .parts
            .iter()
            .filter(|descriptor| descriptor.disclosure_state == 1)
            .collect::<Vec<_>>();
        match message.role.as_str() {
            "user"
                if accepted.is_empty()
                    || !message.tool_call_id.is_empty()
                    || !message.tool_calls.is_empty() =>
            {
                return Err(Status::invalid_argument(
                    "user content messages require accepted parts and cannot carry tool calls",
                ));
            }
            "assistant"
                if !message.tool_call_id.is_empty()
                    || (accepted.is_empty() && message.tool_calls.is_empty()) =>
            {
                return Err(Status::invalid_argument(
                    "assistant content messages require accepted parts or tool calls",
                ));
            }
            "tool"
                if accepted.len() != 1
                    || accepted[0].kind != kind_to_proto(DomainKind::Text)
                    || !valid_content_tool_identifier(&message.tool_call_id)
                    || !message.tool_calls.is_empty() =>
            {
                return Err(Status::invalid_argument(
                    "tool content messages require one accepted text part and a call id",
                ));
            }
            _ => {}
        }
        if message.tool_calls.len() > content::MAX_CONTENT_PARTS {
            return Err(Status::invalid_argument(
                "content message tool call count exceeds the hard limit",
            ));
        }
        for call in &message.tool_calls {
            if message.role != "assistant"
                || !valid_content_tool_identifier(&call.id)
                || !valid_content_tool_identifier(&call.name)
                || call.args_json.len() > 64 * 1024
                || !serde_json::from_str::<serde_json::Value>(&call.args_json)
                    .is_ok_and(|value| value.is_object())
            {
                return Err(Status::invalid_argument(
                    "content tool calls require bounded ids, names, and JSON object arguments",
                ));
            }
        }
    }
    Ok(())
}

fn valid_content_tool_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value == value.trim()
        && !value.contains(char::is_control)
        && !value.contains(char::is_whitespace)
}

fn validate_requested_capabilities(
    capabilities: &ContentCapabilitiesV1,
    messages: &[ContentMessageV1],
) -> Result<(), Status> {
    if capabilities.contract_version != content::CONTENT_CONTRACT_VERSION {
        return Err(Status::failed_precondition(
            "unsupported content capability contract version",
        ));
    }
    let domain = capabilities_from_proto(capabilities)?;
    content::validate_capabilities(&domain).map_err(Status::invalid_argument)?;
    if !capabilities.streaming {
        return Err(Status::failed_precondition(
            "content stream capability is required",
        ));
    }
    let requested_kinds = domain.input_kinds.iter().copied().collect::<HashSet<_>>();
    let requested_media = capabilities
        .media_types
        .iter()
        .map(|value| content::normalize_media_type(value))
        .collect::<Result<HashSet<_>, _>>()
        .map_err(Status::invalid_argument)?;
    let mut part_count = 0_usize;
    let mut aggregate_bytes = 0_u64;
    for descriptor in messages.iter().flat_map(|message| &message.parts) {
        let descriptor = descriptor_from_proto(descriptor)?;
        part_count = part_count.saturating_add(1);
        aggregate_bytes = aggregate_bytes
            .checked_add(descriptor.byte_length)
            .ok_or_else(|| Status::invalid_argument("content byte length overflow"))?;
        if part_count > capabilities.max_parts as usize
            || descriptor.byte_length > capabilities.max_part_bytes
            || aggregate_bytes > capabilities.max_aggregate_bytes
        {
            return Err(Status::resource_exhausted(
                "content exceeds the requested capability limits",
            ));
        }
        if !requested_kinds.contains(&descriptor.kind)
            || !requested_media.contains(&descriptor.media_type)
        {
            return Err(Status::failed_precondition(
                "content is outside the requested capability envelope",
            ));
        }
    }
    Ok(())
}

fn resolve_content_capabilities(
    execution: &ExecutionPlan,
    requested: &ContentCapabilitiesV1,
    messages: &[ContentMessageV1],
) -> Result<ContentCapabilitiesV1, Status> {
    let registry = crate::provider_profile::provider_registry_snapshot();
    let resolved = registry
        .resolve_model(&execution.resolved_model)
        .map_err(Status::failed_precondition)?;
    let profile = registry
        .effective_profile(&resolved.provider)
        .ok_or_else(|| Status::failed_precondition("provider profile unavailable"))?;
    let provider_modalities = profile
        .capabilities
        .modalities
        .iter()
        .map(|value| value.as_str())
        .collect::<HashSet<_>>();
    let descriptors = messages
        .iter()
        .flat_map(|message| &message.parts)
        .map(descriptor_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    for descriptor in descriptors
        .iter()
        .filter(|descriptor| descriptor.disclosure_state == DomainDisclosure::Accepted)
    {
        if !provider_modalities.contains(descriptor.kind.modality()) {
            return Err(Status::failed_precondition(format!(
                "selected provider does not support {} content input",
                descriptor.kind.modality()
            )));
        }
    }
    let requested_domain = capabilities_from_proto(requested)?;
    if requested_domain
        .output_kinds
        .iter()
        .any(|kind| *kind != DomainKind::Text)
    {
        return Err(Status::failed_precondition(
            "selected provider has no owned output-media reference capability",
        ));
    }
    let mut input_kinds = descriptors
        .iter()
        .filter(|descriptor| descriptor.disclosure_state == DomainDisclosure::Accepted)
        .map(|descriptor| descriptor.kind)
        .collect::<Vec<_>>();
    input_kinds.sort_by_key(|kind| kind_to_proto(*kind));
    input_kinds.dedup();
    let mut media_types = descriptors
        .iter()
        .filter(|descriptor| descriptor.disclosure_state == DomainDisclosure::Accepted)
        .map(|descriptor| descriptor.media_type.clone())
        .collect::<Vec<_>>();
    media_types.sort();
    media_types.dedup();
    Ok(ContentCapabilitiesV1 {
        contract_version: content::CONTENT_CONTRACT_VERSION.into(),
        input_kinds: input_kinds.into_iter().map(kind_to_proto).collect(),
        output_kinds: vec![kind_to_proto(DomainKind::Text)],
        media_types,
        reference_modes: vec!["opaque".into()],
        max_parts: requested.max_parts.min(content::MAX_CONTENT_PARTS as u32),
        max_part_bytes: requested
            .max_part_bytes
            .min(content::MAX_CONTENT_PART_BYTES),
        max_aggregate_bytes: requested
            .max_aggregate_bytes
            .min(content::MAX_CONTENT_AGGREGATE_BYTES),
        streaming: true,
    })
}

fn resolve_content_messages(
    plan: &ContentExecutionPlanV1,
    resolved_parts: Vec<ResolvedContentPartV1>,
) -> Result<Vec<DomainMessage>, Status> {
    let resolved_capabilities = plan
        .resolved_capabilities
        .as_ref()
        .ok_or_else(|| Status::data_loss("resolved content capabilities missing"))?;
    let capability_domain = capabilities_from_proto(resolved_capabilities)?;
    content::validate_capabilities(&capability_domain).map_err(Status::data_loss)?;
    let capability_kinds = capability_domain
        .input_kinds
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let capability_media = capability_domain
        .media_types
        .iter()
        .map(|value| content::normalize_media_type(value))
        .collect::<Result<HashSet<_>, _>>()
        .map_err(Status::data_loss)?;
    let planned_descriptors = plan
        .content_messages
        .iter()
        .flat_map(|message| &message.parts)
        .map(descriptor_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    let actual_digest = content::descriptor_digest(&planned_descriptors);
    if actual_digest != plan.descriptor_digest {
        return Err(Status::data_loss(
            "content execution descriptor digest is invalid",
        ));
    }
    let accepted = planned_descriptors
        .iter()
        .filter(|descriptor| descriptor.disclosure_state == DomainDisclosure::Accepted)
        .map(|descriptor| (descriptor.part_id.clone(), descriptor.clone()))
        .collect::<HashMap<_, _>>();
    if resolved_parts.len() != accepted.len() {
        return Err(Status::invalid_argument(
            "resolved content must exactly cover accepted descriptors",
        ));
    }
    let mut resolved = HashMap::new();
    let mut aggregate = 0_u64;
    for value in resolved_parts {
        let part = resolved_part_from_proto(value)?;
        let planned = accepted
            .get(&part.descriptor.part_id)
            .ok_or_else(|| Status::invalid_argument("resolved content part is not in the plan"))?;
        if planned != &part.descriptor {
            return Err(Status::failed_precondition(
                "resolved content descriptor differs from the planned descriptor",
            ));
        }
        content::validate_resolved_part(&part).map_err(Status::invalid_argument)?;
        if !capability_kinds.contains(&part.descriptor.kind)
            || !capability_media.contains(&part.descriptor.media_type)
            || part.descriptor.byte_length > capability_domain.max_part_bytes
        {
            return Err(Status::failed_precondition(
                "resolved content exceeds the planned capability envelope",
            ));
        }
        aggregate = aggregate
            .checked_add(part.descriptor.byte_length)
            .ok_or_else(|| Status::invalid_argument("resolved content byte length overflow"))?;
        if resolved.len() >= capability_domain.max_parts
            || aggregate > capability_domain.max_aggregate_bytes
        {
            return Err(Status::resource_exhausted(
                "resolved content exceeds the planned capability limits",
            ));
        }
        if resolved
            .insert(part.descriptor.part_id.clone(), part)
            .is_some()
        {
            return Err(Status::invalid_argument(
                "resolved content part ids must be unique",
            ));
        }
    }
    plan.content_messages
        .iter()
        .map(|message| {
            let mut parts = Vec::new();
            for descriptor in &message.parts {
                let descriptor = descriptor_from_proto(descriptor)?;
                if descriptor.disclosure_state != DomainDisclosure::Accepted {
                    continue;
                }
                parts.push(resolved.remove(&descriptor.part_id).ok_or_else(|| {
                    Status::invalid_argument("accepted descriptor is missing resolved content")
                })?);
            }
            let tool_calls = message
                .tool_calls
                .iter()
                .map(|call| {
                    Ok(crate::llm::ToolCall {
                        id: call.id.clone(),
                        name: call.name.clone(),
                        args: serde_json::from_str(&call.args_json).map_err(|_| {
                            Status::invalid_argument("tool call args_json is invalid")
                        })?,
                    })
                })
                .collect::<Result<Vec<_>, Status>>()?;
            Ok(DomainMessage {
                role: message.role.clone(),
                parts,
                tool_call_id: message.tool_call_id.clone(),
                tool_calls,
            })
        })
        .collect()
}

fn descriptor_from_proto(descriptor: &ContentPartDescriptorV1) -> Result<DomainDescriptor, Status> {
    let provenance = descriptor
        .provenance
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("content provenance required"))?;
    let kind = kind_from_proto(descriptor.kind)?;
    let media_type =
        content::normalize_media_type(&descriptor.media_type).map_err(Status::invalid_argument)?;
    let disclosure_state = match descriptor.disclosure_state {
        1 => DomainDisclosure::Accepted,
        2 => DomainDisclosure::Redacted,
        3 => DomainDisclosure::Omitted,
        _ => {
            return Err(Status::invalid_argument(
                "content disclosure state is unknown",
            ));
        }
    };
    Ok(DomainDescriptor {
        part_id: descriptor.part_id.clone(),
        kind,
        media_type,
        byte_length: descriptor.byte_length,
        sha256_digest: descriptor.sha256_digest.clone(),
        reference: descriptor.reference.clone(),
        provenance: DomainProvenance {
            source: provenance.source.clone(),
            source_id: provenance.source_id.clone(),
            source_version: provenance.source_version.clone(),
            observed_at_ms: provenance.observed_at_ms,
        },
        disclosure_state,
        disclosure_reason: descriptor.disclosure_reason.clone(),
    })
}

fn resolved_part_from_proto(value: ResolvedContentPartV1) -> Result<DomainResolvedPart, Status> {
    let descriptor = value
        .descriptor
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("resolved content descriptor required"))
        .and_then(descriptor_from_proto)?;
    let payload = match value.payload {
        Some(resolved_content_part_v1::Payload::Text(text)) => DomainPayload::Text(text),
        Some(resolved_content_part_v1::Payload::Bytes(bytes)) => DomainPayload::Bytes(bytes),
        None => {
            return Err(Status::invalid_argument(
                "resolved content payload required",
            ));
        }
    };
    Ok(DomainResolvedPart {
        descriptor,
        payload,
    })
}

fn capabilities_from_proto(value: &ContentCapabilitiesV1) -> Result<DomainCapabilities, Status> {
    Ok(DomainCapabilities {
        input_kinds: value
            .input_kinds
            .iter()
            .map(|kind| kind_from_proto(*kind))
            .collect::<Result<Vec<_>, _>>()?,
        output_kinds: value
            .output_kinds
            .iter()
            .map(|kind| kind_from_proto(*kind))
            .collect::<Result<Vec<_>, _>>()?,
        media_types: value.media_types.clone(),
        reference_modes: value.reference_modes.clone(),
        max_parts: value.max_parts as usize,
        max_part_bytes: value.max_part_bytes,
        max_aggregate_bytes: value.max_aggregate_bytes,
        streaming: value.streaming,
    })
}

fn kind_from_proto(value: i32) -> Result<DomainKind, Status> {
    match value {
        1 => Ok(DomainKind::Text),
        2 => Ok(DomainKind::Image),
        3 => Ok(DomainKind::Audio),
        4 => Ok(DomainKind::Document),
        _ => Err(Status::invalid_argument("content kind is unknown")),
    }
}

fn kind_to_proto(value: DomainKind) -> i32 {
    match value {
        DomainKind::Text => 1,
        DomainKind::Image => 2,
        DomainKind::Audio => 3,
        DomainKind::Document => 4,
    }
}

// Binary payloads cannot use the text leak scanner, so external disclosure
// requires either an explicitly open data class or an operator-safe provider.
// Unclassified text is provisionally accepted and rechecked after resolution.
fn content_part_disclosure_allowed(
    kind: i32,
    provider_is_safe: bool,
    data_class: DataClass,
    task_class: TaskClass,
) -> bool {
    provider_is_safe
        || data_class == DataClass::Open
        || (kind == kind_to_proto(DomainKind::Text)
            && data_class == DataClass::Unclassified
            && task_class == TaskClass::Private)
}

fn has_content_disclosure_evidence(
    execution: &ExecutionPlan,
    messages: &[ContentMessageV1],
    provider: &str,
) -> bool {
    let included = messages
        .iter()
        .flat_map(|message| &message.parts)
        .filter(|descriptor| descriptor.disclosure_state == 1)
        .map(|descriptor| descriptor.part_id.as_str())
        .collect::<Vec<_>>();
    let redacted = messages
        .iter()
        .flat_map(|message| &message.parts)
        .filter(|descriptor| matches!(descriptor.disclosure_state, 2 | 3))
        .map(|descriptor| descriptor.part_id.as_str())
        .collect::<Vec<_>>();
    execution.egress_decisions.iter().any(|decision| {
        decision.provider == provider
            && decision.external == crate::chisei::egress::is_external_provider(provider)
            && decision
                .reasons
                .iter()
                .any(|reason| reason == content::DISCLOSURE_AUTHORITY)
            && decision
                .included
                .iter()
                .map(String::as_str)
                .eq(included.iter().copied())
            && decision
                .redacted
                .iter()
                .map(String::as_str)
                .eq(redacted.iter().copied())
    })
}

fn content_plan_created_at(plan: &ContentExecutionPlanV1) -> i64 {
    plan.execution
        .as_ref()
        .map(|execution| execution.created_at)
        .unwrap_or_default()
}

fn prune_content_plans(plans: &mut HashMap<String, CachedContentExecutionPlan>) {
    let cutoff = chrono::Utc::now().timestamp_millis() - MAX_CACHED_EXECUTION_PLAN_AGE_MS;
    plans.retain(|_, cached| content_plan_created_at(&cached.plan) >= cutoff);
}

#[allow(clippy::too_many_arguments)]
fn planned_response(
    content: &str,
    tool_calls: &[ToolCall],
    input_tokens: i32,
    output_tokens: i32,
    stop_reason: &str,
    provider: &str,
    cache_read_input_tokens: i32,
    cache_creation_input_tokens: i32,
) -> PlannedChatResponse {
    PlannedChatResponse {
        content: content.into(),
        tool_calls: tool_calls.to_vec(),
        input_tokens,
        output_tokens,
        stop_reason: stop_reason.into(),
        provider: provider.into(),
        cache_read_input_tokens,
        cache_creation_input_tokens,
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_content_execution(
    db: &RuntimeDb,
    evolve_history: &Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    plan: &ExecutionPlan,
    actor: &str,
    request_id: &str,
    namespace: &str,
    enriched_spec: &str,
    resolved_model: &str,
    sampled: bool,
    sample_rate: f64,
    sample_reason: &str,
    scoring_enabled: bool,
    task_class: &str,
    response: &PlannedChatResponse,
    attempt_started_at_ms: i64,
) -> Result<(), String> {
    finish_streamed_execution(&FinishStreamedExecution {
        db,
        evolve_history,
        request_id,
        namespace,
        enriched_spec,
        resolved_model,
        sampled,
        sample_rate,
        sample_reason,
        scoring_enabled,
        task_class,
        response,
    })?;
    record_completed_operation_on_with_path(
        db,
        plan,
        actor,
        response,
        attempt_started_at_ms,
        chrono::Utc::now().timestamp_millis(),
        None,
        None,
    )
}

fn text_output_descriptors(
    plan_id: &str,
    provider: &str,
    value: &str,
    observed_at_ms: i64,
) -> Vec<ContentPartDescriptorV1> {
    if value.is_empty() {
        return Vec::new();
    }
    vec![ContentPartDescriptorV1 {
        part_id: "output-text-1".into(),
        kind: kind_to_proto(DomainKind::Text),
        media_type: "text/plain".into(),
        byte_length: value.len() as u64,
        sha256_digest: format!("sha256:{:x}", sha2::Sha256::digest(value.as_bytes())),
        reference: format!("response:{plan_id}"),
        provenance: Some(ContentProvenanceV1 {
            source: "provider".into(),
            source_id: provider.into(),
            source_version: "v1".into(),
            observed_at_ms,
        }),
        disclosure_state: 1,
        disclosure_reason: String::new(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(
        part_id: &str,
        kind: i32,
        media_type: &str,
        payload: &[u8],
    ) -> ContentPartDescriptorV1 {
        ContentPartDescriptorV1 {
            part_id: part_id.into(),
            kind,
            media_type: media_type.into(),
            byte_length: payload.len() as u64,
            sha256_digest: format!("sha256:{:x}", sha2::Sha256::digest(payload)),
            reference: format!("fixture:{part_id}"),
            provenance: Some(ContentProvenanceV1 {
                source: "fixture".into(),
                source_id: "content-contract".into(),
                source_version: "v1".into(),
                observed_at_ms: 1,
            }),
            disclosure_state: 1,
            disclosure_reason: String::new(),
        }
    }

    fn capabilities() -> ContentCapabilitiesV1 {
        ContentCapabilitiesV1 {
            contract_version: content::CONTENT_CONTRACT_VERSION.into(),
            input_kinds: vec![1, 2, 3, 4],
            output_kinds: vec![1],
            media_types: vec![
                "text/plain".into(),
                "image/png".into(),
                "audio/wav".into(),
                "application/pdf".into(),
            ],
            reference_modes: vec!["opaque".into()],
            max_parts: 8,
            max_part_bytes: 1024,
            max_aggregate_bytes: 4096,
            streaming: true,
        }
    }

    #[test]
    fn mixed_descriptors_preserve_order_and_validate() {
        let message = ContentMessageV1 {
            role: "user".into(),
            parts: vec![
                descriptor("text-1", 1, "text/plain", b"text"),
                descriptor("image-1", 2, "image/png", b"png"),
                descriptor("audio-1", 3, "audio/wav", b"wav"),
                descriptor("document-1", 4, "application/pdf", b"pdf"),
            ],
            ..Default::default()
        };
        validate_content_messages(std::slice::from_ref(&message)).unwrap();
        validate_requested_capabilities(&capabilities(), std::slice::from_ref(&message)).unwrap();
        assert_eq!(
            message
                .parts
                .iter()
                .map(|part| part.part_id.as_str())
                .collect::<Vec<_>>(),
            ["text-1", "image-1", "audio-1", "document-1"]
        );
    }

    #[test]
    fn rejects_unknown_kind_credentials_and_output_media() {
        let mut message = ContentMessageV1 {
            role: "user".into(),
            parts: vec![descriptor("image-1", 2, "image/png", b"png")],
            ..Default::default()
        };
        message.parts[0].kind = 99;
        assert!(validate_content_messages(std::slice::from_ref(&message)).is_err());
        message.parts[0].kind = 2;
        message.parts[0].reference = "https://example.test/item?token=secret".into();
        assert!(validate_content_messages(std::slice::from_ref(&message)).is_err());
        message.parts[0].reference = "fixture:image-1".into();
        let mut requested = capabilities();
        requested.output_kinds = vec![2];
        assert!(
            validate_requested_capabilities(&requested, std::slice::from_ref(&message)).is_err()
        );
        let payload = vec![b'x'; 600];
        let bounded_message = ContentMessageV1 {
            role: "user".into(),
            parts: vec![
                descriptor("text-1", 1, "text/plain", &payload),
                descriptor("text-2", 1, "text/plain", &payload),
            ],
            ..Default::default()
        };
        requested = capabilities();
        requested.max_parts = 1;
        assert!(
            validate_requested_capabilities(&requested, std::slice::from_ref(&bounded_message))
                .is_err()
        );
        requested = capabilities();
        requested.max_part_bytes = 2;
        assert!(
            validate_requested_capabilities(&requested, std::slice::from_ref(&message)).is_err()
        );
        requested = capabilities();
        requested.max_aggregate_bytes = 1100;
        assert!(
            validate_requested_capabilities(&requested, std::slice::from_ref(&bounded_message))
                .is_err()
        );

        let mut empty_user = message.clone();
        empty_user.parts[0].disclosure_state = 2;
        empty_user.parts[0].disclosure_reason = "policy redacted".into();
        assert!(validate_authorized_content_messages(&[empty_user]).is_err());
        let invalid_tool = ContentMessageV1 {
            role: "tool".into(),
            parts: vec![descriptor("tool-1", 1, "text/plain", b"result")],
            ..Default::default()
        };
        assert!(validate_authorized_content_messages(&[invalid_tool]).is_err());
        let assistant_tool_call = ContentMessageV1 {
            role: "assistant".into(),
            tool_calls: vec![ToolCall {
                id: "call-1".into(),
                name: "lookup".into(),
                args_json: "{}".into(),
            }],
            ..Default::default()
        };
        validate_authorized_content_messages(&[assistant_tool_call]).unwrap();
    }

    #[test]
    fn resolved_payloads_require_exact_descriptor_and_digest() {
        let descriptor = descriptor("text-1", 1, "text/plain", b"sensitive-body");
        let descriptors = vec![descriptor_from_proto(&descriptor).unwrap()];
        let plan = ContentExecutionPlanV1 {
            execution: Some(ExecutionPlan {
                plan_id: "plan-1".into(),
                ..Default::default()
            }),
            content_messages: vec![ContentMessageV1 {
                role: "user".into(),
                parts: vec![descriptor.clone()],
                ..Default::default()
            }],
            resolved_capabilities: Some(capabilities()),
            descriptor_digest: content::descriptor_digest(&descriptors),
        };
        let bad = ResolvedContentPartV1 {
            descriptor: Some(descriptor.clone()),
            payload: Some(resolved_content_part_v1::Payload::Text("drift".into())),
        };
        assert!(resolve_content_messages(&plan, vec![bad]).is_err());
        let good = ResolvedContentPartV1 {
            descriptor: Some(descriptor),
            payload: Some(resolved_content_part_v1::Payload::Text(
                "sensitive-body".into(),
            )),
        };
        let resolved = resolve_content_messages(&plan, vec![good]).unwrap();
        assert_eq!(resolved[0].parts[0].payload.as_bytes(), b"sensitive-body");
        assert!(!format!("{:?}", resolved[0].parts[0]).contains("sensitive-body"));
    }

    #[test]
    fn disclosure_evidence_is_server_bound_and_empty_output_has_no_descriptor() {
        assert!(content_part_disclosure_allowed(
            2,
            true,
            DataClass::Sensitive,
            TaskClass::Private
        ));
        assert!(content_part_disclosure_allowed(
            2,
            false,
            DataClass::Open,
            TaskClass::Private
        ));
        assert!(content_part_disclosure_allowed(
            1,
            false,
            DataClass::Unclassified,
            TaskClass::Private
        ));
        assert!(!content_part_disclosure_allowed(
            2,
            false,
            DataClass::Unclassified,
            TaskClass::Private
        ));
        assert!(!content_part_disclosure_allowed(
            1,
            false,
            DataClass::Sensitive,
            TaskClass::TemplateOnly
        ));
        let mut redacted = descriptor("image-1", 2, "image/png", b"png");
        redacted.disclosure_state = 2;
        redacted.disclosure_reason = "policy redacted".into();
        let messages = vec![ContentMessageV1 {
            role: "user".into(),
            parts: vec![descriptor("text-1", 1, "text/plain", b"text"), redacted],
            ..Default::default()
        }];
        let mut execution = ExecutionPlan {
            resolved_model: "openai:gpt-test".into(),
            egress_decisions: vec![EgressDecision {
                provider: "openai".into(),
                external: true,
                included: vec!["text-1".into()],
                redacted: vec!["image-1".into()],
                reasons: vec![content::DISCLOSURE_AUTHORITY.into()],
            }],
            ..Default::default()
        };
        assert!(has_content_disclosure_evidence(
            &execution, &messages, "openai"
        ));
        execution.egress_decisions[0].included.clear();
        assert!(!has_content_disclosure_evidence(
            &execution, &messages, "openai"
        ));
        assert!(text_output_descriptors("plan-1", "openai", "", 1).is_empty());
    }
}
