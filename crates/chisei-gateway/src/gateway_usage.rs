use super::*;

pub(super) async fn record_usage_and_append(
    config: &GatewayConfig,
    runtime: &GatewayRuntime,
    identity: &GatewayIdentity,
    usage: Option<ResponseUsage>,
    response_observation: Option<ResponseObservation>,
    context: &UsageContext,
    outcome: GatewayUsageOutcome,
) {
    let Some(target) = &config.chisei_grpc_target else {
        return;
    };
    let status = match outcome {
        GatewayUsageOutcome::Success(status)
        | GatewayUsageOutcome::Incomplete(status, _)
        | GatewayUsageOutcome::TerminalFailure(status, _)
        | GatewayUsageOutcome::Interrupted(status, _)
        | GatewayUsageOutcome::AccountingOnly(status) => status,
    };
    if matches!(outcome, GatewayUsageOutcome::Success(_)) {
        record_gateway_operation_receipt(
            config,
            Some(runtime),
            identity,
            context,
            status,
            usage.as_ref(),
            response_observation.as_ref(),
            None,
            None,
        )
        .await;
    } else if let GatewayUsageOutcome::Incomplete(_, ref reason) = outcome {
        record_gateway_operation_receipt(
            config,
            Some(runtime),
            identity,
            context,
            status,
            usage.as_ref(),
            response_observation.as_ref(),
            None,
            Some(ReceiptTerminalOutcome::Incomplete(reason)),
        )
        .await;
    } else if let GatewayUsageOutcome::TerminalFailure(_, ref reason) = outcome {
        let terminal = if reason == "response_cancelled" {
            ReceiptTerminalOutcome::Cancelled
        } else {
            ReceiptTerminalOutcome::Failed
        };
        record_gateway_operation_receipt(
            config,
            Some(runtime),
            identity,
            context,
            status,
            usage.as_ref(),
            response_observation.as_ref(),
            None,
            Some(terminal),
        )
        .await;
    } else if let GatewayUsageOutcome::Interrupted(_, ref reason) = outcome {
        record_gateway_operation_receipt(
            config,
            Some(runtime),
            identity,
            context,
            status,
            usage.as_ref(),
            response_observation.as_ref(),
            None,
            Some(ReceiptTerminalOutcome::Interrupted(reason)),
        )
        .await;
    }
    let elapsed_ms = Utc::now().timestamp_millis() - context.started_ms;
    let total_tokens = usage.as_ref().map(|usage| usage.total_tokens).unwrap_or(0);
    let request_usage = RecordUsageRequest {
        user_id: identity.user_id.clone(),
        tokens_used: 1,
        subject: String::new(),
        project: identity.project.clone(),
        agent: identity.agent.clone(),
        key_id: identity.key_id.clone(),
        work_unit: context.work_unit_id.clone().unwrap_or_default(),
        metric: METRIC_REQUESTS.to_string(),
        idempotency_key: format!("gateway-usage:{}:requests", context.request_id),
        operation_receipt_json: String::new(),
        sample_observation: None,
    };
    let token_usage = (total_tokens > 0).then(|| RecordUsageRequest {
        user_id: identity.user_id.clone(),
        tokens_used: total_tokens,
        subject: String::new(),
        project: identity.project.clone(),
        agent: identity.agent.clone(),
        key_id: identity.key_id.clone(),
        work_unit: context.work_unit_id.clone().unwrap_or_default(),
        metric: String::new(),
        idempotency_key: format!("gateway-usage:{}:tokens", context.request_id),
        operation_receipt_json: String::new(),
        sample_observation: None,
    });
    match connect_sekai_with_timeout(target, Some(runtime.resilience.control_plane_timeout)).await {
        Ok(channel) => {
            spawn_gateway_recovery_replay(config.clone(), runtime.clone());
            let mut chisei = ChiseiServiceClient::new(channel.clone());
            if let Err(err) = reconcile_pending_usage_records(runtime, &mut chisei).await {
                warn!(error = %err, "chisei-gateway pending usage reconciliation failed");
            }
            if let Err(err) = chisei
                .record_usage(gateway_request(request_usage.clone()))
                .await
            {
                warn!(error = %err, "chisei-gateway request-count usage record failed");
                if !queue_pending_usage_records(runtime, [request_usage.clone()]).await {
                    error!("chisei-gateway usage recovery queue is saturated");
                }
            }
            if let Some(token_usage) = token_usage.as_ref() {
                // Empty `subject` lets the server walk the same
                // project -> agent -> work_unit chain as the preflight check
                // and deduct at every ancestor level in one call.
                if let Err(err) = chisei
                    .record_usage(gateway_request(token_usage.clone()))
                    .await
                {
                    warn!(error = %err, "chisei-gateway usage record failed");
                    if !queue_pending_usage_records(runtime, [token_usage.clone()]).await {
                        error!("chisei-gateway usage recovery queue is saturated");
                    }
                }
            }
            if matches!(outcome, GatewayUsageOutcome::AccountingOnly(_)) {
                return;
            }
            let non_success = matches!(
                outcome,
                GatewayUsageOutcome::Incomplete(_, _)
                    | GatewayUsageOutcome::TerminalFailure(_, _)
                    | GatewayUsageOutcome::Interrupted(_, _)
            );
            let pipeline_observation = if non_success {
                None
            } else {
                context.pipeline_observation.clone()
            };
            let portfolio_cost_usd_micros = usage
                .as_ref()
                .and_then(|usage| estimate_cost_usd_micros(config, context, usage))
                .unwrap_or(0);
            if !non_success {
                record_sample_observation_if_needed(
                    identity,
                    context,
                    usage,
                    portfolio_cost_usd_micros,
                    response_observation.as_ref(),
                    pipeline_observation.as_ref(),
                    &mut chisei,
                )
                .await;
            }

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
            if let Some(route_bias) = context
                .route_bias
                .as_deref()
                .filter(|bias| !bias.is_empty())
            {
                values.insert("route_bias".to_string(), route_bias.to_string());
            }
            if let Some(policy_scope) = context
                .policy_scope
                .as_deref()
                .filter(|scope| !scope.is_empty())
            {
                values.insert("policy_scope".to_string(), policy_scope.to_string());
            }
            if let Some(policy_version) = context
                .policy_version
                .as_deref()
                .filter(|version| !version.is_empty())
            {
                values.insert("policy_version".to_string(), policy_version.to_string());
            }
            if let Some(observation) = &pipeline_observation {
                values.insert(
                    "pipeline_sampled".to_string(),
                    observation.sampled.to_string(),
                );
                values.insert("sample_reason".to_string(), observation.reason.clone());
                values.insert("sample_rate".to_string(), observation.rate.to_string());
            }
            values.insert("status".to_string(), status.as_u16().to_string());
            match &outcome {
                GatewayUsageOutcome::Incomplete(_, _) => {
                    values.insert("terminal_outcome".into(), "incomplete".into());
                }
                GatewayUsageOutcome::TerminalFailure(_, reason) => {
                    values.insert(
                        "terminal_outcome".into(),
                        if reason == "response_cancelled" {
                            "cancelled"
                        } else {
                            "failed"
                        }
                        .into(),
                    );
                }
                GatewayUsageOutcome::Interrupted(_, _) => {
                    values.insert("terminal_outcome".into(), "interrupted".into());
                }
                _ => {}
            }
            values.insert(
                "request_bytes".to_string(),
                context.request_bytes.to_string(),
            );
            values.insert("latency_ms".to_string(), elapsed_ms.max(0).to_string());
            if let Some(usage) = usage {
                insert_normalized_usage_values(&mut values, &usage);
                if let Some(cost_usd_micros) = estimate_cost_usd_micros(config, context, &usage) {
                    values.insert("cost_usd_micros".to_string(), cost_usd_micros.to_string());
                    values.insert("cost_usd".to_string(), format_usd_micros(cost_usd_micros));
                }
                if usage.cache_read_input_tokens > 0
                    && let Some(savings) =
                        estimate_cache_savings_usd_micros(config, context, &usage)
                {
                    values.insert("cache_savings_usd_micros".to_string(), savings.to_string());
                    values.insert("cache_savings_usd".to_string(), format_usd_micros(savings));
                }
            }

            let mut sekai = SekaiServiceClient::new(channel);
            let append = AppendRowsRequest {
                dataset_id: "llm_calls".to_string(),
                rows: vec![Row {
                    values: values.clone(),
                }],
            };
            let append_result = append_llm_calls_rows(runtime, &mut sekai, append.clone()).await;
            if let Err(append_err) = append_result {
                warn!(error = %append_err, "chisei-gateway llm_calls append failed");
                if !append_gateway_recovery(
                    runtime,
                    GatewayRecoveryRecord::LlmRow {
                        values: values.clone(),
                    },
                )
                .await
                {
                    error!("chisei-gateway llm_calls recovery spool write failed");
                }
                return;
            }
            link_work_unit_usage(&mut sekai, identity, context, &values).await;
            record_gateway_pipeline_decision(config, identity, context, pipeline_observation).await;
        }
        Err(err) => {
            if !queue_pending_usage_records(
                runtime,
                std::iter::once(request_usage).chain(token_usage),
            )
            .await
            {
                error!(
                    "chisei-gateway usage recovery queue saturated; additional recovery refused"
                );
            }
            if !matches!(outcome, GatewayUsageOutcome::AccountingOnly(_)) {
                let mut values = gateway_recovery_llm_values(
                    config,
                    identity,
                    context,
                    status,
                    &outcome,
                    usage.as_ref(),
                    elapsed_ms,
                );
                values.insert("control_plane_error".into(), "unavailable".into());
                if !append_gateway_recovery(runtime, GatewayRecoveryRecord::LlmRow { values }).await
                {
                    error!("chisei-gateway llm_calls recovery spool write failed");
                }
            }
            warn!(error = %err, "chisei-gateway usage append skipped; Chisei unavailable");
        }
    }
}
pub(super) fn gateway_recovery_llm_values(
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
    let Some(target) = &config.chisei_grpc_target else {
        return;
    };
    record_gateway_operation_receipt(
        config,
        Some(runtime),
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
    )
    .await;
    let elapsed_ms = Utc::now().timestamp_millis() - context.started_ms;
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
        insert_normalized_usage_values(&mut values, &usage);
        if let Some(cost_usd_micros) = estimate_cost_usd_micros(config, context, &usage) {
            values.insert("cost_usd_micros".to_string(), cost_usd_micros.to_string());
            values.insert("cost_usd".to_string(), format_usd_micros(cost_usd_micros));
        }
        if usage.cache_read_input_tokens > 0
            && let Some(savings) = estimate_cache_savings_usd_micros(config, context, &usage)
        {
            values.insert("cache_savings_usd_micros".to_string(), savings.to_string());
            values.insert("cache_savings_usd".to_string(), format_usd_micros(savings));
        }
    }

    match connect_sekai_with_timeout(target, Some(configured_control_plane_timeout())).await {
        Ok(channel) => {
            spawn_gateway_recovery_replay(config.clone(), runtime.clone());
            let mut sekai = SekaiServiceClient::new(channel);
            let append = AppendRowsRequest {
                dataset_id: "llm_calls".to_string(),
                rows: vec![Row {
                    values: values.clone(),
                }],
            };
            let append_result = append_llm_calls_rows(runtime, &mut sekai, append.clone()).await;
            if let Err(append_err) = append_result {
                warn!(error = %append_err, "chisei-gateway refusal append failed");
                if !append_gateway_recovery(
                    runtime,
                    GatewayRecoveryRecord::LlmRow {
                        values: values.clone(),
                    },
                )
                .await
                {
                    error!("chisei-gateway refusal recovery spool write failed");
                }
                return;
            }
            link_work_unit_usage(&mut sekai, identity, context, &values).await;
        }
        Err(err) => {
            if !append_gateway_recovery(runtime, GatewayRecoveryRecord::LlmRow { values }).await {
                error!("chisei-gateway refusal recovery spool write failed");
            }
            warn!(error = %err, "chisei-gateway refusal append skipped; Chisei unavailable");
        }
    }
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
#[allow(clippy::too_many_arguments)]
pub(super) async fn record_gateway_operation_receipt(
    config: &GatewayConfig,
    runtime: Option<&GatewayRuntime>,
    identity: &GatewayIdentity,
    context: &UsageContext,
    status: StatusCode,
    usage: Option<&ResponseUsage>,
    observation: Option<&ResponseObservation>,
    rejection: Option<ReceiptRejection<'_>>,
    terminal_outcome: Option<ReceiptTerminalOutcome<'_>>,
) {
    let receipt = build_gateway_operation_receipt(
        identity,
        context,
        status,
        usage,
        observation,
        rejection,
        terminal_outcome,
        usage.and_then(|usage| estimate_cost_usd_micros(config, context, usage)),
        usage.and_then(|usage| estimate_cache_savings_usd_micros(config, context, usage)),
    );
    let Ok(receipt_json) = serde_json::to_string(&receipt) else {
        error!(operation_id = %receipt.operation_id, "gateway operation receipt serialization failed");
        return;
    };
    let operation_id = receipt.operation_id.clone();
    let outcome = if rejection.is_some() {
        "denied"
    } else {
        "recorded"
    };
    let persisted = persist_gateway_receipt(
        config,
        &identity.user_id,
        &identity.project,
        &identity.agent,
        &operation_id,
        &receipt_json,
    )
    .await;
    if !persisted
        && let Some(runtime) = runtime
        && !append_gateway_recovery(
            runtime,
            GatewayRecoveryRecord::Receipt {
                actor: identity.agent.clone(),
                operation_id,
                receipt_json,
                outcome: outcome.into(),
            },
        )
        .await
    {
        error!("gateway operation receipt recovery spool write failed");
    }
}
pub(super) async fn persist_gateway_receipt(
    config: &GatewayConfig,
    user_id: &str,
    project: &str,
    actor: &str,
    operation_id: &str,
    receipt_json: &str,
) -> bool {
    let Some(target) = config.chisei_grpc_target.as_deref() else {
        return false;
    };
    let Ok(channel) =
        connect_sekai_as_gateway_with_timeout(target, Some(configured_control_plane_timeout()))
            .await
    else {
        return false;
    };
    ChiseiServiceClient::new(channel)
        .record_usage(gateway_request(RecordUsageRequest {
            user_id: user_id.into(),
            tokens_used: 0,
            subject: format!("gateway-receipt:{operation_id}"),
            project: project.into(),
            agent: actor.into(),
            key_id: String::new(),
            work_unit: String::new(),
            metric: String::new(),
            idempotency_key: format!("gateway-receipt:{operation_id}"),
            operation_receipt_json: receipt_json.into(),
            sample_observation: None,
        }))
        .await
        .is_ok()
}
pub(super) async fn append_llm_calls_rows(
    runtime: &GatewayRuntime,
    sekai: &mut SekaiServiceClient<GatewayClient>,
    append: AppendRowsRequest,
) -> Result<(), tonic::Status> {
    let now_ms = Utc::now().timestamp_millis().max(0) as u64;
    if !runtime.llm_calls_schema_reconciled.load(Ordering::Acquire)
        && now_ms
            >= runtime
                .llm_calls_schema_retry_after_ms
                .load(Ordering::Acquire)
    {
        let _guard = runtime.llm_calls_schema_lock.lock().await;
        let claimed_at_ms = Utc::now().timestamp_millis().max(0) as u64;
        if !runtime.llm_calls_schema_reconciled.load(Ordering::Acquire)
            && claimed_at_ms
                >= runtime
                    .llm_calls_schema_retry_after_ms
                    .load(Ordering::Acquire)
        {
            runtime.llm_calls_schema_retry_after_ms.store(
                claimed_at_ms.saturating_add(SCHEMA_RECONCILIATION_RETRY_MS),
                Ordering::Release,
            );
            match ensure_llm_calls_dataset(sekai).await {
                Ok(true) => runtime
                    .llm_calls_schema_reconciled
                    .store(true, Ordering::Release),
                Ok(false) => {}
                Err(error) => {
                    warn!(%error, "llm_calls schema reconciliation deferred");
                }
            }
        }
    }
    match sekai.append_rows(gateway_request(append.clone())).await {
        Ok(_) => Ok(()),
        Err(error) if error.code() == tonic::Code::NotFound => {
            let _guard = runtime.llm_calls_schema_lock.lock().await;
            match sekai.append_rows(gateway_request(append.clone())).await {
                Ok(_) => return Ok(()),
                Err(error) if error.code() == tonic::Code::NotFound => {}
                Err(error) => return Err(error),
            }
            runtime
                .llm_calls_schema_reconciled
                .store(false, Ordering::Release);
            runtime.llm_calls_schema_retry_after_ms.store(
                now_ms.saturating_add(SCHEMA_RECONCILIATION_RETRY_MS),
                Ordering::Release,
            );
            let reconciled = ensure_llm_calls_dataset(sekai).await?;
            runtime
                .llm_calls_schema_reconciled
                .store(reconciled, Ordering::Release);
            sekai.append_rows(gateway_request(append)).await.map(|_| ())
        }
        Err(error) => Err(error),
    }
}
pub(super) async fn ensure_llm_calls_dataset(
    sekai: &mut SekaiServiceClient<GatewayClient>,
) -> Result<bool, tonic::Status> {
    let columns = LLM_CALLS_COLUMNS
        .iter()
        .copied()
        .map(|name| ColumnDef {
            name: name.to_string(),
            r#type: "string".to_string(),
            classification: crate::gateway_support::llm_call_column_classification(name)
                .to_string(),
        })
        .collect();

    let dataset = Dataset {
        id: "llm_calls".to_string(),
        name: "LLM calls".to_string(),
        columns,
        object_id: String::new(),
        created: Utc::now().timestamp_millis(),
    };
    match sekai
        .create_dataset(gateway_request(CreateDatasetRequest {
            dataset: Some(dataset.clone()),
        }))
        .await
    {
        Ok(_) => Ok(true),
        Err(error)
            if error.code() == tonic::Code::InvalidArgument
                && error.message().contains("UNIQUE constraint failed") =>
        {
            match sekai
                .update_dataset(gateway_request(UpdateDatasetRequest {
                    dataset: Some(dataset),
                }))
                .await
            {
                Ok(_) => Ok(true),
                Err(error) if error.code() == tonic::Code::Unimplemented => Ok(false),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}
pub(super) async fn record_sample_observation_if_needed(
    identity: &GatewayIdentity,
    context: &UsageContext,
    usage: Option<ResponseUsage>,
    cost_usd_micros: i64,
    response_observation: Option<&ResponseObservation>,
    pipeline_observation: Option<&GatewayPipelineObservation>,
    chisei: &mut ChiseiServiceClient<GatewayClient>,
) {
    let Some(pipeline_observation) = pipeline_observation else {
        return;
    };
    if !pipeline_observation.sampled {
        return;
    }
    let Some(response_observation) = response_observation else {
        return;
    };
    if response_observation.output_content.trim().is_empty() {
        return;
    }
    let usage = usage.unwrap_or_default();
    match chisei
        .record_usage(gateway_request(RecordUsageRequest {
            user_id: identity.user_id.clone(),
            tokens_used: 0,
            subject: String::new(),
            project: identity.project.clone(),
            agent: identity.agent.clone(),
            key_id: identity.key_id.clone(),
            work_unit: context.work_unit_id.clone().unwrap_or_default(),
            metric: String::new(),
            idempotency_key: format!("gateway-sample:{}", context.request_id),
            operation_receipt_json: String::new(),
            sample_observation: Some(SampleObservation {
                request_id: context.request_id.clone(),
                namespace: identity.project.clone(),
                spec: pipeline_observation.prepared_spec.clone(),
                resolved_model: context
                    .resolved_model
                    .as_ref()
                    .or(context.requested_model.as_ref())
                    .cloned()
                    .unwrap_or_default(),
                output_content: response_observation.output_content.clone(),
                sample_reason: pipeline_observation.reason.clone(),
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                stop_reason: response_observation.stop_reason.clone(),
                timestamp: Utc::now().timestamp_millis(),
                task_class: context.task_class.clone(),
                cost_usd_micros,
            }),
        }))
        .await
    {
        Ok(_) => {}
        Err(err) => warn!(error = %err, "chisei-gateway sample observation record failed"),
    }
}
pub(super) async fn record_gateway_pipeline_decision(
    config: &GatewayConfig,
    identity: &GatewayIdentity,
    context: &UsageContext,
    observation: Option<GatewayPipelineObservation>,
) {
    let Some(observation) = observation else {
        return;
    };
    if !observation.sampled {
        return;
    }
    record_gateway_decision(
        config,
        identity,
        "gateway.sampled",
        &observation.reason,
        "sampled",
        HashMap::from([
            ("request_id".to_string(), context.request_id.clone()),
            ("sample_rate".to_string(), observation.rate.to_string()),
            (
                "provider".to_string(),
                capability_provider_id(context.provider).to_string(),
            ),
        ]),
    )
    .await;
}
pub(super) async fn link_work_unit_usage(
    sekai: &mut SekaiServiceClient<GatewayClient>,
    identity: &GatewayIdentity,
    context: &UsageContext,
    values: &HashMap<String, String>,
) {
    let Some(work_unit_id) = context.work_unit_id.as_deref() else {
        return;
    };
    let work_unit_object_id = match ensure_gateway_object(
        sekai,
        format!("work_unit:{work_unit_id}"),
        format!("work-unit-{}", sanitize_gateway_id(work_unit_id)),
        "work_unit",
        work_unit_id,
        &identity.project,
        HashMap::from([
            ("gateway_managed".to_string(), "true".to_string()),
            ("source".to_string(), "gateway_header".to_string()),
        ]),
    )
    .await
    {
        Ok(id) => id,
        Err(err) => {
            warn!(error = %err, "chisei-gateway work_unit object upsert failed");
            return;
        }
    };
    let llm_call_object_id = match ensure_gateway_object(
        sekai,
        format!("llm_call:{}", context.request_id),
        format!("llm-call-{}", context.request_id),
        "llm_call",
        &context.request_id,
        &identity.project,
        llm_call_object_properties(identity, context, values),
    )
    .await
    {
        Ok(id) => id,
        Err(err) => {
            warn!(error = %err, "chisei-gateway llm_call object create failed");
            return;
        }
    };
    let link = Link {
        id: format!(
            "work-unit-{}-incurs-{}",
            sanitize_gateway_id(work_unit_id),
            context.request_id
        ),
        from_id: work_unit_object_id,
        to_id: llm_call_object_id,
        relation: "incurs_usage".to_string(),
        created: Utc::now().timestamp_millis(),
    };
    match sekai
        .create_link(gateway_request(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(link),
        }))
        .await
    {
        Ok(_) => {}
        Err(err)
            if err.code() == tonic::Code::InvalidArgument
                && err.message().contains("UNIQUE constraint failed") => {}
        Err(err) => warn!(error = %err, "chisei-gateway work_unit usage link failed"),
    }
}
pub(super) async fn ensure_gateway_object(
    sekai: &mut SekaiServiceClient<GatewayClient>,
    external_id: String,
    fallback_id: String,
    kind: &str,
    name: &str,
    namespace: &str,
    properties: HashMap<String, String>,
) -> Result<String, tonic::Status> {
    match sekai
        .find_by_external_id(gateway_request(FindByExternalIdRequest {
            external_id: external_id.clone(),
        }))
        .await
    {
        Ok(resp) => {
            if let Some(object) = resp.into_inner().object {
                return Ok(object.id);
            }
        }
        Err(err) if err.code() == tonic::Code::NotFound => {}
        Err(err) => return Err(err),
    }

    let id = fallback_id;
    match sekai
        .create_object(gateway_request(CreateObjectRequest {
            object: Some(SekaiObject {
                id: id.clone(),
                kind: kind.to_string(),
                name: name.to_string(),
                namespace: namespace.to_string(),
                external_id,
                properties,
                created: Utc::now().timestamp_millis(),
                updated: Utc::now().timestamp_millis(),
            }),
            lease_precondition: None,
        }))
        .await
    {
        Ok(_) => Ok(id),
        Err(err)
            if err.code() == tonic::Code::InvalidArgument
                && err.message().contains("UNIQUE constraint failed") =>
        {
            Ok(id)
        }
        Err(err) => Err(err),
    }
}
pub(super) fn llm_call_object_properties(
    identity: &GatewayIdentity,
    context: &UsageContext,
    values: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut properties = HashMap::from([
        ("gateway_managed".to_string(), "true".to_string()),
        ("agent".to_string(), identity.agent.clone()),
        ("project".to_string(), identity.project.clone()),
        (
            "provider".to_string(),
            capability_provider_id(context.provider).to_string(),
        ),
    ]);
    for key in [
        "model",
        "resolved_model",
        "status",
        "input_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "total_tokens",
        "provider_total_tokens",
        "cost_usd_micros",
        "cost_usd",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
        "cache_creation_5m_input_tokens",
        "cache_creation_1h_input_tokens",
        "cache_savings_usd_micros",
        "pricing_snapshot_version",
    ] {
        if let Some(value) = values.get(key).filter(|value| !value.is_empty()) {
            properties.insert(key.to_string(), value.clone());
        }
    }
    properties
}
pub(super) fn sanitize_gateway_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
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
pub(super) fn alias_reservation_error_response(error: AliasReservationError) -> Response<Body> {
    match error {
        AliasReservationError::Conflict(reason) => {
            json_error(StatusCode::CONFLICT, "request_id_conflict", &reason)
        }
        AliasReservationError::Unavailable(reason) => json_error_with_retry_safety(
            StatusCode::SERVICE_UNAVAILABLE,
            "governance_unavailable",
            &reason,
            "ambiguous",
        ),
    }
}
pub(super) async fn claim_gateway_dispatch(
    config: &GatewayConfig,
    context: &UsageContext,
    dispatch_token: &str,
) -> Result<(), AliasReservationError> {
    let Some(request_alias) = context.lookup_request_id.as_deref() else {
        return Ok(());
    };
    let target = config.chisei_grpc_target.as_deref().ok_or_else(|| {
        AliasReservationError::Unavailable(
            "opaque request aliases require the policy control plane".into(),
        )
    })?;
    let channel =
        connect_sekai_as_gateway_with_timeout(target, Some(configured_control_plane_timeout()))
            .await
            .map_err(|error| {
                AliasReservationError::Unavailable(format!(
                    "request alias dispatch claim is unavailable: {error}"
                ))
            })?;
    let mut client = ChiseiServiceClient::new(channel);
    let request = ClaimGatewayDispatchRequest {
        caller_scope: context.caller_scope.clone(),
        request_alias: request_alias.to_string(),
        request_id: context.request_id.clone(),
        operation_id: context.operation_id.clone(),
        dispatch_token: dispatch_token.to_string(),
    };
    let mut last_error = None;
    let mut claimed = None;
    for _ in 0..2 {
        match client
            .claim_gateway_dispatch(gateway_request(request.clone()))
            .await
        {
            Ok(response) => {
                claimed = Some(response.into_inner().claimed);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let claimed = claimed.ok_or_else(|| {
        AliasReservationError::Unavailable(format!(
            "request alias dispatch claim failed: {}",
            last_error.expect("dispatch claim retry records an error")
        ))
    })?;
    if !claimed {
        return Err(AliasReservationError::Conflict(
            "x-chisei-request-id already authorized another provider dispatch".into(),
        ));
    }
    Ok(())
}
pub(super) async fn record_gateway_event(
    config: &GatewayConfig,
    actor: &str,
    action: &str,
    reason: &str,
    outcome: &str,
    evidence: HashMap<String, String>,
) -> bool {
    let Some(target) = &config.chisei_grpc_target else {
        return false;
    };
    let timeout = configured_control_plane_timeout();
    let Ok(channel) = connect_sekai_as_gateway_with_timeout(target, Some(timeout)).await else {
        return false;
    };
    let mut sekai = SekaiServiceClient::new(channel.clone());
    if let Err(err) = ensure_llm_calls_dataset(&mut sekai).await
        && (err.code() != tonic::Code::InvalidArgument
            || !err.message().contains("UNIQUE constraint failed"))
    {
        error!(error = %err, "chisei-gateway audit target create failed");
        return false;
    }
    let target_id = if action == "operation.receipt.upsert" {
        evidence
            .get("operation_id")
            .cloned()
            .unwrap_or_else(|| "llm_calls".into())
    } else {
        "llm_calls".into()
    };
    if let Err(err) = sekai
        .record_decision(gateway_request(RecordDecisionRequest {
            decision: Some(Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Utc::now().timestamp_millis(),
                actor: actor.to_string(),
                action: action.to_string(),
                reason: reason.to_string(),
                evidence: sanitize_audit_evidence(evidence),
                target_id,
                outcome: outcome.to_string(),
            }),
        }))
        .await
    {
        error!(error = %err, "chisei-gateway audit decision record failed");
        return false;
    }
    true
}
/// Audit evidence is a metadata-only boundary. Credentials are intentionally
/// represented by non-secret identities such as `key_id`; any accidentally
/// named credential field is dropped before crossing the persistence boundary.
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
pub(super) fn recovery_spool_path(runtime: &GatewayRuntime) -> Option<PathBuf> {
    runtime.recovery_spool_path.clone()
}
