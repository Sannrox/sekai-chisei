use super::*;

/// Finish the attempt's GenAI span from the observed usage and outcome. Only
/// counts and bounded outcome tokens are recorded, never response content.
fn record_genai_outcome(
    context: &UsageContext,
    usage: Option<&ResponseUsage>,
    observation: Option<&ResponseObservation>,
    outcome: &GatewayUsageOutcome,
) {
    let span = &context.genai_span;
    if let Some(usage) = usage {
        record_genai_usage(span, usage);
    }
    if let Some(observation) = observation {
        chisei_provider::genai::record_finish_reason(span, &observation.stop_reason);
    }
    match outcome {
        GatewayUsageOutcome::TerminalFailure(_, reason)
        | GatewayUsageOutcome::Interrupted(_, reason) => {
            chisei_provider::genai::record_error(span, reason);
        }
        GatewayUsageOutcome::Success(_)
        | GatewayUsageOutcome::Incomplete(_, _)
        | GatewayUsageOutcome::AccountingOnly(_) => {}
    }
}

fn record_genai_usage(span: &tracing::Span, usage: &ResponseUsage) {
    chisei_provider::genai::record_usage(
        span,
        usage.input_tokens.into(),
        usage.output_tokens.into(),
    );
}

pub(super) async fn record_usage_and_append(
    config: &GatewayConfig,
    runtime: &GatewayRuntime,
    identity: &GatewayIdentity,
    usage: Option<ResponseUsage>,
    response_observation: Option<ResponseObservation>,
    context: &UsageContext,
    outcome: GatewayUsageOutcome,
) {
    record_genai_outcome(
        context,
        usage.as_ref(),
        response_observation.as_ref(),
        &outcome,
    );
    let (log_status, log_outcome, log_reason) = match &outcome {
        GatewayUsageOutcome::Success(status) => (*status, "success", None),
        GatewayUsageOutcome::Incomplete(status, reason) => (*status, "incomplete", Some(reason)),
        GatewayUsageOutcome::TerminalFailure(status, reason) => (*status, "failed", Some(reason)),
        GatewayUsageOutcome::Interrupted(status, reason) => (*status, "interrupted", Some(reason)),
        GatewayUsageOutcome::AccountingOnly(status) => (*status, "accounting_only", None),
    };
    // The receipt and `llm_calls` row are built once: the egress log carries
    // them, and the Chisei and Sekai writes below use the same values.
    let terminal = match &outcome {
        GatewayUsageOutcome::Success(_) => Some(None),
        GatewayUsageOutcome::Incomplete(_, reason) => {
            Some(Some(ReceiptTerminalOutcome::Incomplete(reason)))
        }
        GatewayUsageOutcome::TerminalFailure(_, reason) if reason == "response_cancelled" => {
            Some(Some(ReceiptTerminalOutcome::Cancelled))
        }
        GatewayUsageOutcome::TerminalFailure(_, _) => Some(Some(ReceiptTerminalOutcome::Failed)),
        GatewayUsageOutcome::Interrupted(_, reason) => {
            Some(Some(ReceiptTerminalOutcome::Interrupted(reason)))
        }
        GatewayUsageOutcome::AccountingOnly(_) => None,
    };
    let elapsed_ms = Utc::now().timestamp_millis() - context.started_ms;
    let receipt = terminal.map(|terminal| {
        gateway_operation_receipt(
            config,
            identity,
            context,
            log_status,
            usage.as_ref(),
            response_observation.as_ref(),
            None,
            terminal,
        )
    });
    let row = receipt.is_some().then(|| {
        llm_calls_row(
            config,
            identity,
            context,
            log_status,
            &outcome,
            usage.as_ref(),
            elapsed_ms,
        )
    });
    log_attempt_usage(
        runtime,
        context,
        log_status,
        log_outcome,
        log_reason.map(String::as_str),
        usage.as_ref(),
        receipt.as_ref().zip(row.as_ref()),
    )
    .await;
}
/// The `llm_calls` row of a provider attempt that was not refused.
pub(super) fn llm_calls_row(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    context: &UsageContext,
    status: StatusCode,
    outcome: &GatewayUsageOutcome,
    usage: Option<&ResponseUsage>,
    elapsed_ms: i64,
) -> HashMap<String, String> {
    let mut values = HashMap::from([
        ("request_id".into(), context.request_id.clone()),
        (
            "receipt_id".into(),
            gateway_provider_receipt_id(
                &context.operation_id,
                &context.request_id,
                context.attempt,
                context.provider_ordinal,
            ),
        ),
        (
            "timestamp_ms".into(),
            Utc::now().timestamp_millis().to_string(),
        ),
        ("agent".into(), identity.agent.clone()),
        ("project".into(), identity.project.clone()),
        ("data_class".into(), context.data_class.clone()),
        ("user_id".into(), identity.user_id.clone()),
        (
            "provider".into(),
            capability_provider_id(context.provider).to_string(),
        ),
        ("status".into(), status.as_u16().to_string()),
        ("request_bytes".into(), context.request_bytes.to_string()),
        ("latency_ms".into(), elapsed_ms.max(0).to_string()),
    ]);
    insert_correlation_values(&mut values, context);
    for (key, value) in [
        ("key_id", Some(identity.key_id.as_str())),
        ("model", context.requested_model.as_deref()),
        ("resolved_model", context.resolved_model.as_deref()),
        ("profile_version", context.profile_version.as_deref()),
        (
            "pricing_snapshot_version",
            context.pricing_snapshot_version.as_deref(),
        ),
        (
            "capability_snapshot_version",
            context.capability_snapshot_version.as_deref(),
        ),
        ("work_unit_id", context.work_unit_id.as_deref()),
        ("route_bias", context.route_bias.as_deref()),
        ("policy_scope", context.policy_scope.as_deref()),
        ("policy_version", context.policy_version.as_deref()),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            values.insert(key.into(), value.into());
        }
    }
    let terminal = match outcome {
        GatewayUsageOutcome::Incomplete(_, _) => Some("incomplete"),
        GatewayUsageOutcome::TerminalFailure(_, reason) if reason == "response_cancelled" => {
            Some("cancelled")
        }
        GatewayUsageOutcome::TerminalFailure(_, _) => Some("failed"),
        GatewayUsageOutcome::Interrupted(_, _) => Some("interrupted"),
        _ => None,
    };
    if let Some(terminal) = terminal {
        values.insert("terminal_outcome".into(), terminal.into());
    }
    // The live row records pipeline sampling only for a completed call.
    if terminal.is_none()
        && let Some(observation) = &context.pipeline_observation
    {
        values.insert("pipeline_sampled".into(), observation.sampled.to_string());
        values.insert("sample_reason".into(), observation.reason.clone());
        values.insert("sample_rate".into(), observation.rate.to_string());
    }
    if let Some(usage) = usage {
        insert_normalized_usage_values(&mut values, usage);
        if let Some(cost) = estimate_cost_usd_micros(config, context, usage) {
            values.insert("cost_usd_micros".into(), cost.to_string());
            values.insert("cost_usd".into(), format_usd_micros(cost));
        }
        if usage.cache_read_input_tokens > 0
            && let Some(savings) = estimate_cache_savings_usd_micros(config, context, usage)
        {
            values.insert("cache_savings_usd_micros".into(), savings.to_string());
            values.insert("cache_savings_usd".into(), format_usd_micros(savings));
        }
    }
    values
}
pub(super) async fn record_refusal_and_append(
    config: &GatewayConfig,
    runtime: &GatewayRuntime,
    identity: &GatewayIdentity,
    context: &UsageContext,
    rejection: &GatewayRejection,
) {
    record_refusal_with_usage_and_append(
        config, runtime, identity, context, rejection, None, false,
    )
    .await;
}
pub(super) async fn record_refusal_with_usage_and_append(
    config: &GatewayConfig,
    runtime: &GatewayRuntime,
    identity: &GatewayIdentity,
    context: &UsageContext,
    rejection: &GatewayRejection,
    usage: Option<ResponseUsage>,
    model_attempted: bool,
) {
    if let Some(usage) = &usage {
        record_genai_usage(&context.genai_span, usage);
    }
    chisei_provider::genai::record_error(&context.genai_span, &rejection.error_type);
    let receipt = gateway_operation_receipt(
        config,
        identity,
        context,
        rejection.status,
        usage.as_ref(),
        None,
        Some(ReceiptRejection {
            rejection,
            model_attempted,
        }),
        None,
    );
    let values = refusal_llm_calls_row(
        config,
        identity,
        context,
        rejection,
        usage.as_ref(),
        Utc::now().timestamp_millis() - context.started_ms,
    );
    log_attempt_usage(
        runtime,
        context,
        rejection.status,
        "refused",
        Some(&rejection.error_type),
        usage.as_ref(),
        Some((&receipt, &values)),
    )
    .await;
}
/// The `llm_calls` row of a refused request or attempt.
fn refusal_llm_calls_row(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    context: &UsageContext,
    rejection: &GatewayRejection,
    usage: Option<&ResponseUsage>,
    elapsed_ms: i64,
) -> HashMap<String, String> {
    let mut values = HashMap::new();
    values.insert("request_id".to_string(), context.request_id.clone());
    values.insert(
        "receipt_id".to_string(),
        gateway_provider_receipt_id(
            &context.operation_id,
            &context.request_id,
            context.attempt,
            context.provider_ordinal,
        ),
    );
    insert_correlation_values(&mut values, context);
    values.insert(
        "timestamp_ms".to_string(),
        Utc::now().timestamp_millis().to_string(),
    );
    values.insert("agent".to_string(), identity.agent.clone());
    values.insert("project".to_string(), identity.project.clone());
    values.insert("data_class".to_string(), context.data_class.clone());
    values.insert("user_id".to_string(), identity.user_id.clone());
    if !identity.key_id.is_empty() {
        values.insert("key_id".to_string(), identity.key_id.clone());
    }
    values.insert(
        "provider".to_string(),
        capability_provider_id(context.provider).to_string(),
    );
    if let Some(model) = &context.requested_model {
        values.insert("model".to_string(), model.clone());
    }
    if let Some(model) = &context.resolved_model {
        values.insert("resolved_model".to_string(), model.clone());
    }
    if let Some(profile_version) = &context.profile_version {
        values.insert("profile_version".to_string(), profile_version.clone());
    }
    if let Some(pricing_version) = &context.pricing_snapshot_version {
        values.insert(
            "pricing_snapshot_version".to_string(),
            pricing_version.clone(),
        );
    }
    if let Some(snapshot_version) = &context.capability_snapshot_version {
        values.insert(
            "capability_snapshot_version".to_string(),
            snapshot_version.clone(),
        );
    }
    if let Some(work_unit_id) = &context.work_unit_id {
        values.insert("work_unit_id".to_string(), work_unit_id.clone());
    }
    values.insert("status".to_string(), rejection.status.as_u16().to_string());
    values.insert("error_type".to_string(), rejection.error_type.clone());
    values.insert("refusal_reason".to_string(), rejection.reason.clone());
    values.insert(
        "request_bytes".to_string(),
        context.request_bytes.to_string(),
    );
    values.insert("latency_ms".to_string(), elapsed_ms.max(0).to_string());
    if let Some(usage) = usage {
        insert_normalized_usage_values(&mut values, usage);
        if let Some(cost_usd_micros) = estimate_cost_usd_micros(config, context, usage) {
            values.insert("cost_usd_micros".to_string(), cost_usd_micros.to_string());
            values.insert("cost_usd".to_string(), format_usd_micros(cost_usd_micros));
        }
        if usage.cache_read_input_tokens > 0
            && let Some(savings) = estimate_cache_savings_usd_micros(config, context, usage)
        {
            values.insert("cache_savings_usd_micros".to_string(), savings.to_string());
            values.insert("cache_savings_usd".to_string(), format_usd_micros(savings));
        }
    }
    values
}
pub(super) fn insert_correlation_values(
    values: &mut HashMap<String, String>,
    context: &UsageContext,
) {
    values.insert("operation_id".into(), context.operation_id.clone());
    values.insert("attempt".into(), context.attempt.to_string());
    if context.cache_requested {
        values.insert("cache_requested".into(), "true".into());
    }
    if let Some(value) = &context.parent_operation_id {
        values.insert("parent_operation_id".into(), value.clone());
    }
    if let Some(value) = &context.turn_id {
        values.insert("turn_id".into(), value.clone());
    }
    if let Some(value) = &context.cycle_id {
        values.insert("cycle_id".into(), value.clone());
    }
    if let Some(value) = &context.traceparent {
        values.insert("traceparent".into(), value.clone());
    }
}
pub(super) fn gateway_receipt_event(
    operation_id: &str,
    suffix: &str,
    parent: Option<&str>,
    timestamp_ms: i64,
    kind: ReceiptEventKind,
    actor: &str,
    attributes: BTreeMap<String, String>,
) -> OperationReceiptEvent {
    OperationReceiptEvent {
        event_id: format!("{operation_id}:{suffix}"),
        operation_id: operation_id.into(),
        parent_event_id: parent.map(|parent| format!("{operation_id}:{parent}")),
        timestamp_ms,
        kind,
        surface: kind.surface(),
        actor: actor.into(),
        references: Vec::new(),
        attributes,
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn build_gateway_operation_receipt(
    identity: &GatewayIdentity,
    context: &UsageContext,
    status: StatusCode,
    usage: Option<&ResponseUsage>,
    observation: Option<&ResponseObservation>,
    rejection: Option<ReceiptRejection<'_>>,
    terminal_outcome: Option<ReceiptTerminalOutcome<'_>>,
    cost_usd_micros: Option<i64>,
    cache_savings_usd_micros: Option<i64>,
) -> OperationReceipt {
    let model_attempted = rejection
        .map(|failure| failure.model_attempted)
        .unwrap_or(true);
    let rejection = rejection.map(|failure| failure.rejection);
    let operation_id = gateway_provider_receipt_id(
        &context.operation_id,
        &context.request_id,
        context.attempt,
        context.provider_ordinal,
    );
    let completed_at_ms = Utc::now().timestamp_millis();
    let actor = identity.agent.as_str();
    let policy_version = context
        .policy_version
        .clone()
        .unwrap_or_else(|| "unavailable/v1".into());
    let rejection_type = rejection.map(|rejection| rejection.error_type.as_str());
    let policy_status = if rejection_type == Some("policy_denied") {
        "denied"
    } else if context.policy_version.is_some() {
        "resolved"
    } else {
        "not_evaluated"
    };
    let mut context_attributes = BTreeMap::from([
        ("egress_applied".into(), context.egress_applied.to_string()),
        ("raw_context_stored".into(), "false".into()),
    ]);
    if let Some(version) = &context.context_admission_policy_version {
        context_attributes.insert("context_admission_policy_version".into(), version.clone());
        context_attributes.insert(
            "context_admission_descriptor_version".into(),
            context
                .context_admission_descriptor_version
                .clone()
                .unwrap_or_default(),
        );
        context_attributes.insert(
            "context_admission_decision".into(),
            context
                .context_admission_decision
                .clone()
                .unwrap_or_default(),
        );
        context_attributes.insert(
            "context_admission_reasons".into(),
            context.context_admission_reasons.join(","),
        );
    }
    let mut context_event = gateway_receipt_event(
        &operation_id,
        "context",
        Some("intent"),
        context.started_ms,
        ReceiptEventKind::ContextGoverned,
        "chisei.gateway",
        context_attributes,
    );
    context_event.references.push(GovernedReference {
        kind: "gateway_request".into(),
        reference: format!("operation:{operation_id}:request"),
        content_hash: Some(context.request_hash.clone()),
        disclosed_fields: vec!["request_body".into()],
        omitted: true,
        omission_reason: Some("raw request content is not copied into receipts".into()),
    });
    let mut events = vec![
        gateway_receipt_event(
            &operation_id,
            "intent",
            None,
            context.started_ms,
            ReceiptEventKind::IntentRecorded,
            actor,
            BTreeMap::from([
                ("request_id".into(), context.request_id.clone()),
                ("logical_operation_id".into(), context.operation_id.clone()),
                ("attempt_id".into(), context.attempt.to_string()),
                (
                    "lookup_request_id".into(),
                    context.lookup_request_id.clone().unwrap_or_default(),
                ),
                ("caller_scope".into(), context.caller_scope.clone()),
                ("request_hash".into(), context.request_hash.clone()),
                ("request_bytes".into(), context.request_bytes.to_string()),
                ("attempt".into(), context.attempt.to_string()),
                (
                    "turn_id".into(),
                    context.turn_id.clone().unwrap_or_default(),
                ),
                (
                    "cycle_id".into(),
                    context.cycle_id.clone().unwrap_or_default(),
                ),
                (
                    "traceparent".into(),
                    context.traceparent.clone().unwrap_or_default(),
                ),
            ]),
        ),
        context_event,
        gateway_receipt_event(
            &operation_id,
            "policy",
            Some("context"),
            context.started_ms,
            ReceiptEventKind::PolicyDecided,
            "chisei.policy",
            {
                let mut attributes = BTreeMap::from([
                    ("status".into(), policy_status.into()),
                    ("policy_version".into(), policy_version.clone()),
                    (
                        "policy_scope".into(),
                        context.policy_scope.clone().unwrap_or_default(),
                    ),
                ]);
                if let Some(version) = &context.context_admission_policy_version {
                    attributes.insert("context_admission_policy_version".into(), version.clone());
                    attributes.insert(
                        "context_admission_descriptor_version".into(),
                        context
                            .context_admission_descriptor_version
                            .clone()
                            .unwrap_or_default(),
                    );
                    attributes.insert(
                        "context_admission_decision".into(),
                        context
                            .context_admission_decision
                            .clone()
                            .unwrap_or_default(),
                    );
                    attributes.insert(
                        "context_admission_reasons".into(),
                        context.context_admission_reasons.join(","),
                    );
                }
                attributes
            },
        ),
        gateway_receipt_event(
            &operation_id,
            "route",
            Some("policy"),
            context.started_ms,
            ReceiptEventKind::RouteSelected,
            "chisei.routing",
            BTreeMap::from([
                (
                    "provider".into(),
                    capability_provider_id(context.provider).to_string(),
                ),
                (
                    "requested_model".into(),
                    context.requested_model.clone().unwrap_or_default(),
                ),
                (
                    "resolved_model".into(),
                    context.resolved_model.clone().unwrap_or_default(),
                ),
                (
                    "route_override".into(),
                    context.route_override.clone().unwrap_or_default(),
                ),
                (
                    "bias_bypassed".into(),
                    context.route_override.is_some().to_string(),
                ),
                (
                    "requested_alias".into(),
                    context.requested_alias.clone().unwrap_or_default(),
                ),
                (
                    "profile_version".into(),
                    context.profile_version.clone().unwrap_or_default(),
                ),
                (
                    "capability_snapshot_version".into(),
                    context
                        .capability_snapshot_version
                        .clone()
                        .unwrap_or_default(),
                ),
                (
                    "pricing_snapshot_version".into(),
                    context.pricing_snapshot_version.clone().unwrap_or_default(),
                ),
                (
                    "governance_metadata_status".into(),
                    context
                        .governance_metadata_status
                        .clone()
                        .unwrap_or_default(),
                ),
            ]),
        ),
        gateway_receipt_event(
            &operation_id,
            "budget",
            Some("route"),
            context.started_ms,
            ReceiptEventKind::BudgetDecided,
            "chisei.budget",
            BTreeMap::from([
                (
                    "status".into(),
                    if rejection_type.is_some_and(|kind| kind.starts_with("budget_")) {
                        "denied".into()
                    } else {
                        context.budget_status.clone()
                    },
                ),
                (
                    "subject".into(),
                    context.budget_subject.clone().unwrap_or_default(),
                ),
            ]),
        ),
        gateway_receipt_event(
            &operation_id,
            "egress",
            Some("budget"),
            context.started_ms,
            ReceiptEventKind::EgressDecided,
            "chisei.egress",
            BTreeMap::from([(
                "status".into(),
                if rejection_type
                    .is_some_and(|kind| kind.contains("egress") || kind.starts_with("context_"))
                {
                    "denied"
                } else if rejection.is_some() && context.egress_applied {
                    "failed"
                } else if context.egress_applied {
                    "evaluated"
                } else {
                    "not_evaluated"
                }
                .into(),
            )]),
        ),
    ];
    let mut model_call_attributes = BTreeMap::from([(
        "usage_status".into(),
        if usage.is_some() { "known" } else { "unknown" }.into(),
    )]);
    if let Some(usage) = usage {
        model_call_attributes.insert("input_tokens".into(), usage.input_tokens.to_string());
        model_call_attributes.insert("output_tokens".into(), usage.output_tokens.to_string());
        model_call_attributes.insert("total_tokens".into(), usage.total_tokens.to_string());
        let mut normalized = HashMap::new();
        insert_normalized_usage_values(&mut normalized, usage);
        for key in [
            "uncached_input_tokens",
            "provider_total_tokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens",
            "cache_creation_5m_input_tokens",
            "cache_creation_1h_input_tokens",
        ] {
            if let Some(value) = normalized.remove(key) {
                model_call_attributes.insert(key.into(), value);
            }
        }
    }
    for (key, value) in [
        ("resolved_model", context.resolved_model.as_deref()),
        ("profile_version", context.profile_version.as_deref()),
        (
            "pricing_snapshot_version",
            context.pricing_snapshot_version.as_deref(),
        ),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            model_call_attributes.insert(key.into(), value.into());
        }
    }
    if let Some(cost_usd_micros) = cost_usd_micros {
        model_call_attributes.insert("cost_usd_micros".into(), cost_usd_micros.to_string());
    }
    if let Some(savings) = cache_savings_usd_micros {
        model_call_attributes.insert("cache_savings_usd_micros".into(), savings.to_string());
    }
    let outcome_parent = if rejection.is_some() && !model_attempted {
        "egress"
    } else {
        events.extend([
            gateway_receipt_event(
                &operation_id,
                "attempt-1",
                Some("egress"),
                context.started_ms,
                ReceiptEventKind::AttemptStarted,
                actor,
                BTreeMap::from([
                    ("attempt".into(), context.attempt.to_string()),
                    (
                        "turn_id".into(),
                        context.turn_id.clone().unwrap_or_default(),
                    ),
                    (
                        "cycle_id".into(),
                        context.cycle_id.clone().unwrap_or_default(),
                    ),
                ]),
            ),
            gateway_receipt_event(
                &operation_id,
                "model-call-1",
                Some("attempt-1"),
                completed_at_ms,
                ReceiptEventKind::ModelCalled,
                "chisei.gateway",
                model_call_attributes,
            ),
            gateway_receipt_event(
                &operation_id,
                "artifact-1",
                Some("model-call-1"),
                completed_at_ms,
                ReceiptEventKind::ArtifactProduced,
                "chisei.gateway",
                BTreeMap::from([
                    ("artifact_type".into(), "model_response".into()),
                    (
                        "observation_hash".into(),
                        observation
                            .map(|observation| {
                                format!(
                                    "{:x}",
                                    Sha256::digest(observation.output_content.as_bytes())
                                )
                            })
                            .unwrap_or_default(),
                    ),
                    ("artifact_content_absent".into(), "true".into()),
                    (
                        "omission_reason".into(),
                        "raw upstream response is not copied into receipts".into(),
                    ),
                ]),
            ),
            gateway_receipt_event(
                &operation_id,
                "verification",
                Some("artifact-1"),
                completed_at_ms,
                ReceiptEventKind::VerificationRecorded,
                "chisei.gateway",
                BTreeMap::from([("status".into(), "not_requested".into())]),
            ),
        ]);
        "verification"
    };
    events.push(gateway_receipt_event(
        &operation_id,
        "outcome",
        Some(outcome_parent),
        completed_at_ms,
        ReceiptEventKind::OutcomeRecorded,
        actor,
        BTreeMap::from([
            (
                "status".into(),
                if rejection.is_some() {
                    "denied"
                } else if let Some(terminal) = terminal_outcome {
                    terminal.status()
                } else {
                    "completed"
                }
                .into(),
            ),
            ("http_status".into(), status.as_u16().to_string()),
            (
                "completion_reason".into(),
                rejection
                    .map(|rejection| rejection.error_type.clone())
                    .or_else(|| terminal_outcome.map(|terminal| terminal.reason().to_string()))
                    .or_else(|| observation.map(|observation| observation.stop_reason.clone()))
                    .unwrap_or_else(|| "upstream_completed".into()),
            ),
            (
                "latency_ms".into(),
                completed_at_ms
                    .saturating_sub(context.started_ms)
                    .to_string(),
            ),
        ]),
    ));
    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id,
        parent_operation_id: if context.attempt > 1 {
            Some(context.operation_id.clone())
        } else {
            context
                .parent_operation_id
                .clone()
                .or_else(|| context.work_unit_id.clone())
        },
        namespace: identity.project.clone(),
        operation_class: "model_inference".into(),
        initiating_actor: actor.into(),
        schema_version: "chisei.gateway/v1".into(),
        policy_version,
        started_at_ms: context.started_ms,
        completed_at_ms: Some(completed_at_ms),
        events,
        uncovered_surfaces: Vec::<UncoveredSurface>::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    }
}
/// Builds the receipt of a provider attempt, priced from the gateway's
/// pricing table.
#[allow(clippy::too_many_arguments)]
pub(super) fn gateway_operation_receipt(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    context: &UsageContext,
    status: StatusCode,
    usage: Option<&ResponseUsage>,
    observation: Option<&ResponseObservation>,
    rejection: Option<ReceiptRejection<'_>>,
    terminal_outcome: Option<ReceiptTerminalOutcome<'_>>,
) -> OperationReceipt {
    build_gateway_operation_receipt(
        identity,
        context,
        status,
        usage,
        observation,
        rejection,
        terminal_outcome,
        usage.and_then(|usage| estimate_cost_usd_micros(config, context, usage)),
        usage.and_then(|usage| estimate_cache_savings_usd_micros(config, context, usage)),
    )
}

pub(super) async fn record_gateway_decision(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    action: &str,
    reason: &str,
    outcome: &str,
    mut evidence: HashMap<String, String>,
) {
    evidence
        .entry("user_id".to_string())
        .or_insert_with(|| identity.user_id.clone());
    evidence
        .entry("project".to_string())
        .or_insert_with(|| identity.project.clone());
    evidence
        .entry("tier".to_string())
        .or_insert_with(|| identity.tier.clone());
    if !identity.key_id.is_empty() {
        evidence
            .entry("key_id".to_string())
            .or_insert_with(|| identity.key_id.clone());
    }
    record_gateway_event(config, &identity.agent, action, reason, outcome, evidence).await;
}

pub(super) async fn record_gateway_event(
    _config: &GatewayConfig,
    actor: &str,
    action: &str,
    reason: &str,
    outcome: &str,
    evidence: HashMap<String, String>,
) -> bool {
    info!(
        actor,
        action,
        reason,
        outcome,
        evidence = ?sanitize_audit_evidence(evidence),
        "gateway event"
    );
    true
}

/// Audit evidence is a metadata-only boundary. Credentials are represented by
/// non-secret identities such as `key_id`; any accidentally named credential
/// field is dropped before it is logged.
pub(super) fn sanitize_audit_evidence(
    evidence: HashMap<String, String>,
) -> HashMap<String, String> {
    evidence
        .into_iter()
        .filter(|(key, _)| {
            let key = key.to_ascii_lowercase().replace('-', "_");
            ![
                "authorization",
                "api_key",
                "credential",
                "cookie",
                "secret",
                "password",
                "passwd",
                "passphrase",
                "private_key",
            ]
            .iter()
            .any(|sensitive| key == *sensitive || key.ends_with(&format!("_{sensitive}")))
                && key != "token"
                && !key.ends_with("_token")
        })
        .collect()
}
