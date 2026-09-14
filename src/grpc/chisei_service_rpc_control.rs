use super::*;

pub(super) async fn evaluate_governed_subject(
    service: &ChiseiServiceImpl,
    req: Request<EvaluateGovernedSubjectRequest>,
) -> Result<Response<EvaluateGovernedSubjectResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let value = req
        .into_inner()
        .subject
        .ok_or_else(|| Status::invalid_argument("subject required"))?;
    let envelope = subject::GovernedSubjectEnvelope {
        version: value.version,
        namespace: value.namespace,
        request_id: value.request_id,
        subject_profile: value.subject_profile,
        subject_identity: value.subject_identity,
        content_digest: value.content_digest,
        references: value
            .references
            .into_iter()
            .map(subject_reference_from_proto)
            .collect(),
        evaluation_profile: value.evaluation_profile,
    };
    let result = governed_subject_lifecycle::GovernedSubjectLifecycle::new(
        service.db.clone(),
        service.config.clone(),
    )
    .evaluate(&actor, envelope, chrono::Utc::now().timestamp_millis())?;
    Ok(Response::new(EvaluateGovernedSubjectResponse {
        result: Some(to_proto_governed_subject_result(&result)),
    }))
}
pub(super) async fn export_governed_subject_provenance(
    service: &ChiseiServiceImpl,
    req: Request<ExportGovernedSubjectProvenanceRequest>,
) -> Result<Response<ExportGovernedSubjectProvenanceResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let request = req.into_inner();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let outcome = governed_subject_lifecycle::GovernedSubjectLifecycle::new(
        service.db.clone(),
        service.config.clone(),
    )
    .export_provenance(
        subject_provenance::ExportRequestBinding {
            actor,
            export_id: request.export_id,
            operation_id: request.operation_id,
            expected_subject_identity: request.expected_subject_identity,
            expected_subject_content_digest: request.expected_subject_content_digest,
            expected_manifest_digest: request.expected_manifest_digest,
            expected_artifact_digest: request.expected_artifact_digest,
            expected_receipt_digest: request.expected_receipt_digest,
        },
        now_ms,
    )?;
    Ok(Response::new(subject_provenance_response(
        &outcome.record,
        outcome.replayed,
        now_ms,
    )?))
}
pub(super) async fn authorize_external_action(
    service: &ChiseiServiceImpl,
    req: Request<AuthorizeExternalActionRequest>,
) -> Result<Response<AuthorizeExternalActionResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let response = service.authorize_from_authenticated(actor, req.into_inner())?;
    Ok(Response::new(response))
}
pub(super) async fn transition_external_action(
    service: &ChiseiServiceImpl,
    req: Request<TransitionExternalActionRequest>,
) -> Result<Response<TransitionExternalActionResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let response = service.transition_from_authenticated(actor, req.into_inner())?;
    Ok(Response::new(response))
}
pub(super) async fn redeem_external_action_permit(
    service: &ChiseiServiceImpl,
    req: Request<RedeemExternalActionPermitRequest>,
) -> Result<Response<RedeemExternalActionPermitResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let input = req.into_inner();
    if input.idempotency_key.trim().is_empty() || input.execution_id.trim().is_empty() {
        return Err(Status::invalid_argument(
            "idempotency_key and execution_id required",
        ));
    }
    let value = external_permit_from_proto(
        input
            .permit
            .ok_or_else(|| Status::invalid_argument("permit required"))?,
    );
    if actor != value.executor && !matches!(actor.as_str(), "root" | "local") {
        return Err(Status::permission_denied(
            "permit redemption requires the bound executor",
        ));
    }
    if let Some(redemption) = service
        .db
        .replay_redemption(&value, &input.idempotency_key, &input.execution_id)
        .map_err(Status::failed_precondition)?
    {
        return Ok(Response::new(RedeemExternalActionPermitResponse {
            redemption: Some(ExternalActionRedemption {
                version: redemption.version,
                permit_id: redemption.permit_id,
                redemption_id: redemption.redemption_id,
                executor: redemption.executor,
                redeemed_at_ms: redemption.redeemed_at_ms,
                invocation_ordinal: redemption.invocation_ordinal,
                evidence_due_at_ms: redemption.evidence_due_at_ms,
                site_id: redemption.site_id,
            }),
        }));
    }
    let context = external_host_context(
        input.executor,
        input.requesting_harness,
        input.canonical_arguments_digest,
        input.target_selectors,
        input.observed_preconditions,
        input.host_capabilities,
    );
    let key = permit_signing_key(&service.config)?.verifying_key();
    value
        .verify_trust(&service.config.permit_issuer, &service.config.permit_key_id)
        .map_err(Status::failed_precondition)?;
    let redemption = service
        .db
        .redeem_or_reconcile_permit(
            &value,
            &context,
            &key,
            &input.idempotency_key,
            &input.execution_id,
            &service.config.site_id,
            crate::chisei::external_permit::RedemptionTiming {
                invoked_at_ms: input.invoked_at_ms,
                reconciled_at_ms: chrono::Utc::now().timestamp_millis(),
            },
        )
        .map_err(Status::failed_precondition)?;
    Ok(Response::new(RedeemExternalActionPermitResponse {
        redemption: Some(ExternalActionRedemption {
            version: redemption.version,
            permit_id: redemption.permit_id,
            redemption_id: redemption.redemption_id,
            executor: redemption.executor,
            redeemed_at_ms: redemption.redeemed_at_ms,
            invocation_ordinal: redemption.invocation_ordinal,
            evidence_due_at_ms: redemption.evidence_due_at_ms,
            site_id: redemption.site_id,
        }),
    }))
}
pub(super) async fn set_external_action_policy(
    service: &ChiseiServiceImpl,
    req: Request<SetExternalActionPolicyRequest>,
) -> Result<Response<SetExternalActionPolicyResponse>, Status> {
    require_control_plane_admin(&req, "external action policy mutation")?;
    let actor = required_authenticated_actor(&req)?;
    let input = req.into_inner();
    match input.operation.as_str() {
        "set_policy" => {
            let input_policy = input
                .policy
                .ok_or_else(|| Status::invalid_argument("policy required"))?;
            let policy = permit::ExternalPermitPolicy {
                scope: input_policy.scope,
                offline_action_types: input_policy.offline_action_types,
                offline_max_duration_ms: input_policy.offline_max_duration_ms,
                offline_max_invocations: input_policy.offline_max_invocations,
                permitted_delegators: input_policy.permitted_delegators,
                max_delegation_depth: input_policy.max_delegation_depth,
            };
            service
                .db
                .set_external_permit_policy(&policy, chrono::Utc::now().timestamp_millis())
                .map_err(Status::invalid_argument)?;
            Ok(Response::new(SetExternalActionPolicyResponse {
                policy: Some(external_permit_policy_to_proto(&policy)),
                changed: true,
            }))
        }
        "kill_switch" => {
            if input.scope_value.trim().is_empty() || input.reason.trim().is_empty() {
                return Err(Status::invalid_argument("scope_value and reason required"));
            }
            let now = chrono::Utc::now().timestamp_millis();
            let changed = service
                .db
                .set_permit_kill_switch(
                    &input.scope_kind,
                    &input.scope_value,
                    input.enabled,
                    &input.reason,
                    now,
                )
                .map_err(Status::invalid_argument)?;
            service
                .db
                .record_decisions_idempotently(&[crate::sekai::audit::Decision {
                    id: format!("external-kill-{}", uuid::Uuid::new_v4().simple()),
                    timestamp: now,
                    actor,
                    action: "external_action_permit/kill_switch".into(),
                    reason: input.reason,
                    evidence: HashMap::from([
                        ("scope_kind".into(), input.scope_kind.clone()),
                        ("scope_value".into(), input.scope_value.clone()),
                    ]),
                    target_id: input.scope_value,
                    outcome: if input.enabled {
                        "enabled".into()
                    } else {
                        "disabled".into()
                    },
                }])
                .map_err(Status::internal)?;
            Ok(Response::new(SetExternalActionPolicyResponse {
                policy: None,
                changed,
            }))
        }
        _ => Err(Status::invalid_argument(
            "operation must be set_policy or kill_switch",
        )),
    }
}
pub(super) async fn decide_gateway_execution(
    service: &ChiseiServiceImpl,
    req: Request<DecideGatewayExecutionRequest>,
) -> Result<Response<DecideGatewayExecutionResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let delegated_principal = req
        .metadata()
        .get(DELEGATED_PRINCIPAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let response = service
        .decide_from_authenticated_request(actor, delegated_principal, req.into_inner())
        .await?;
    Ok(Response::new(response))
}
pub(super) async fn record_usage(
    service: &ChiseiServiceImpl,
    req: Request<RecordUsageRequest>,
) -> Result<Response<RecordUsageResponse>, Status> {
    let actor = authenticated_actor(&req);
    let trusted_accounting_principal =
        matches!(actor.as_str(), "root" | "local" | "chisei-gateway")
            || service
                .config
                .gateway_receipt_principals
                .iter()
                .any(|principal| principal == &actor);
    if !trusted_accounting_principal {
        return Err(Status::permission_denied(
            "usage recording requires an authorized accounting principal",
        ));
    }
    let r = req.into_inner();
    if r.tokens_used < 0 && !matches!(actor.as_str(), "root" | "local") {
        return Err(Status::permission_denied(
            "negative usage adjustments require control-plane administration",
        ));
    }
    let response = service.record_usage_from_authenticated(actor, r)?;
    Ok(Response::new(response))
}
pub(super) async fn set_budget_limit(
    service: &ChiseiServiceImpl,
    req: Request<SetBudgetLimitRequest>,
) -> Result<Response<SetBudgetLimitResponse>, Status> {
    require_control_plane_admin(&req, "budget mutation")?;
    let r = req.into_inner();
    let metric = budget_metric(&r.metric)?;
    let period = crate::chisei::budget::PeriodType::parse_strict(&r.period_type)
        .map_err(Status::invalid_argument)?;
    let budget_subject = budget_subject(
        &r.subject,
        &r.project,
        &r.agent,
        &r.key_id,
        &r.work_unit,
        &r.user_id,
    )?;
    service
        .budget
        .set_limit_with_metric(&budget_subject, metric, r.max_tokens, period)
        .map_err(Status::internal)?;
    Ok(Response::new(SetBudgetLimitResponse {}))
}
pub(super) async fn set_namespace_policy(
    service: &ChiseiServiceImpl,
    req: Request<SetNamespacePolicyRequest>,
) -> Result<Response<SetNamespacePolicyResponse>, Status> {
    require_control_plane_admin(&req, "namespace policy mutation")?;
    let registry = service.refresh_provider_registry_for_resolution().await?;
    let validated_registry_version = registry.state_version;
    crate::provider_profile::with_provider_registry_snapshot(registry, async {
        let r = req.into_inner();
        if r.namespace.trim().is_empty() {
            return Err(Status::invalid_argument("namespace required"));
        }
        let policy = normalize_legacy_policy_provider_pairs(policy_from_request(&r));
        validate_policy_provider_pairs(&policy).map_err(Status::invalid_argument)?;
        let context_admission_policy = if r.context_admission_policy_json.trim().is_empty() {
            service
                .policy
                .context_admission_policy(&r.namespace)
                .map_err(Status::failed_precondition)?
        } else if r.context_admission_policy_json.trim() == "null" {
            None
        } else {
            let context_policy = serde_json::from_str::<
                crate::chisei::policy::ContextAdmissionPolicy,
            >(&r.context_admission_policy_json)
            .map_err(|error| {
                Status::invalid_argument(format!("invalid context admission policy: {error}"))
            })?;
            context_policy
                .validate()
                .map_err(Status::invalid_argument)?;
            Some(context_policy)
        };
        let policy_data_class = policy.data_class.clone();
        let policy_version = policy.version();
        let current_registry = service.refresh_provider_registry_for_resolution().await?;
        if current_registry.state_version != validated_registry_version {
            return Err(Status::aborted(
                "provider registry changed while validating namespace policy",
            ));
        }
        persist_namespace_policy(
            &service.db,
            &r.namespace,
            &policy,
            context_admission_policy.as_ref(),
        )
        .map_err(Status::internal)?;
        let default_runtime = policy.default_runtime.clone();
        let default_model = policy.default_model.clone();
        service.policy.set_namespace_policy(&r.namespace, policy);
        if let Some(context_policy) = context_admission_policy {
            service
                .policy
                .set_context_admission_policy(&r.namespace, context_policy)
                .map_err(Status::invalid_argument)?;
        } else {
            service.policy.clear_context_admission_policy(&r.namespace);
        }
        let (runtime, model) = service
            .policy
            .resolve(&r.namespace, &default_runtime, &default_model)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(SetNamespacePolicyResponse {
            resolution: Some(PolicyResolution {
                runtime,
                model,
                data_class: policy_data_class,
                eval_regressed: false,
                eval_regression_reason: String::new(),
                route_bias: String::new(),
                policy_scope: r.namespace,
                policy_version,
                fallback_models: Vec::new(),
            }),
        }))
    })
    .await
}
pub(super) async fn get_effective_policy_summary(
    service: &ChiseiServiceImpl,
    req: Request<GetEffectivePolicySummaryRequest>,
) -> Result<Response<GetEffectivePolicySummaryResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let namespace = canonical_namespace(&req.get_ref().namespace)?.to_string();
    require_namespace_access(&service.db, &actor, &namespace)?;

    let routing = service.policy.effective_policy(&namespace).map_or_else(
        || EffectiveRoutingSummary {
            configured: false,
            status: "unconfigured".into(),
            ..Default::default()
        },
        |policy| EffectiveRoutingSummary {
            configured: true,
            status: "configured".into(),
            runtime: policy.default_runtime.clone(),
            model: policy.default_model.clone(),
            policy_scope: namespace.clone(),
            policy_version: policy.version(),
        },
    );

    let raw_limits = service
        .db
        .budget_limits_for_scope(&format!("project:{namespace}"))
        .map_err(Status::internal)?;
    let budget_version = content_version(&raw_limits);
    let limits = raw_limits
        .into_iter()
        .map(
            |(scope, metric, max_amount, period_type)| EffectiveBudgetLimit {
                metric,
                max_amount,
                period_type,
                policy_scope: scope,
            },
        )
        .collect::<Vec<_>>();
    let budgets = EffectiveBudgetSummary {
        configured: !limits.is_empty(),
        status: if limits.is_empty() {
            "unconfigured"
        } else {
            "configured"
        }
        .into(),
        limits,
        policy_version: budget_version,
    };

    let project_action_scope = format!("project:{namespace}");
    let action_policy = match service
        .db
        .get_action_policy(&project_action_scope)
        .map_err(Status::internal)?
    {
        some @ Some(_) => some,
        None => service
            .db
            .get_action_policy(&namespace)
            .map_err(Status::internal)?,
    };
    let actions = action_policy.map_or_else(
        || EffectiveActionPolicySummary {
            configured: false,
            status: "unconfigured".into(),
            ..Default::default()
        },
        |policy| {
            use crate::sekai::action_policy::ActionDecision;
            let canonical_properties = policy
                .to_properties()
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            let decisions = policy
                .action_overrides
                .values()
                .chain(policy.risk_overrides.values());
            let (mut allow, mut deny, mut approval) = (0, 0, 0);
            for decision in decisions {
                match decision {
                    ActionDecision::Allow => allow += 1,
                    ActionDecision::Deny => deny += 1,
                    ActionDecision::RequireApproval => approval += 1,
                }
            }
            EffectiveActionPolicySummary {
                configured: true,
                status: "configured".into(),
                allow_rule_count: allow,
                deny_rule_count: deny,
                require_approval_rule_count: approval,
                default_decision: policy.default_decision.as_str().into(),
                policy_scope: policy.scope.clone(),
                policy_version: content_version(&canonical_properties),
            }
        },
    );

    let provider = req.get_ref().provider.trim();
    let discovery = crate::chisei::model_availability::ModelDiscoveryConfig {
        openai_base_url: std::env::var("CHISEI_OPENAI_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1".into()),
        openai_api_key: service.config.openai_api_key.clone(),
        anthropic_base_url: std::env::var("CHISEI_ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com/v1".into()),
        anthropic_api_key: service.config.anthropic_api_key.clone(),
        ollama_url: service.config.ollama_url.clone(),
        native_configured: service.config.native_llm_url.is_some(),
    };
    let availability =
        crate::chisei::model_availability::refresh_model_availability(&discovery, false).await;
    let view = availability.public_models((!provider.is_empty()).then_some(provider));
    let models = view
        .models
        .into_iter()
        .map(|model| AvailableModelRecord {
            provider: model.provider,
            upstream_model: model.upstream_model,
            canonical_model: model.canonical_model,
            lifecycle: model.lifecycle,
            capabilities: model.capabilities.map(|value| AvailableModelCapabilities {
                responses: value.responses,
                streaming: value.streaming,
                tools: value.tools,
                parallel_tools: value.parallel_tools,
                structured_output: value.structured_output,
                reasoning_controls: value.reasoning_controls,
                modalities: value.modalities,
                provider_continuation: value.provider_continuation,
                reports_usage: value.reports_usage,
                partial_usage: value.partial_usage,
                context_tokens: value.context_tokens,
                output_tokens: value.output_tokens,
                built_in_tools: value.built_in_tools,
            }),
            pricing: model.pricing.map(|value| AvailableModelPricing {
                version: value.version,
                source: value.source,
                observed_at: value.observed_at,
                dimensions: value.dimensions,
            }),
        })
        .collect();

    Ok(Response::new(GetEffectivePolicySummaryResponse {
        namespace,
        routing: Some(routing),
        budgets: Some(budgets),
        actions: Some(actions),
        available_models_version: view.version,
        models,
    }))
}
