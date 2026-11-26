use super::*;
use crate::chisei_store::{ChiseiBudgetStore, ChiseiPermitStore};

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
        service.sekai_facts.clone(),
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
        service.sekai_facts.clone(),
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
    Ok(Response::new(
        service.redeem_from_authenticated(actor, req.into_inner())?,
    ))
}
/// Records the decision before the state change it covers, so a failed audit
/// write leaves the state untouched (the decision-first rule). The caller
/// leaves `id` empty; each attempt gets its own.
fn record_permit_decision(
    service: &ChiseiServiceImpl,
    mut decision: crate::sekai::audit::Decision,
) -> Result<(), Status> {
    decision.id = format!("external-permit-{}", uuid::Uuid::new_v4().simple());
    crate::sekai::audit::validate_decision(&decision)
        .map_err(|error| Status::invalid_argument(format!("cannot audit change: {error}")))?;
    service
        .db
        .record_decisions_idempotently(&[decision])
        .map_err(Status::internal)
}

pub(super) async fn set_external_action_policy(
    service: &ChiseiServiceImpl,
    req: Request<SetExternalActionPolicyRequest>,
) -> Result<Response<SetExternalActionPolicyResponse>, Status> {
    require_control_plane_admin(&req, "external action policy mutation")?;
    let actor = required_authenticated_actor(&req)?;
    let input = req.into_inner();
    let now = chrono::Utc::now().timestamp_millis();
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
            record_permit_decision(
                service,
                crate::sekai::audit::Decision {
                    id: String::new(),
                    timestamp: now,
                    actor,
                    action: "external_action_permit/set_policy".into(),
                    reason: input.reason,
                    evidence: HashMap::from([("scope".into(), policy.scope.clone())]),
                    target_id: policy.scope.clone(),
                    outcome: "set".into(),
                },
            )?;
            service
                .db
                .set_external_permit_policy(&policy, now)
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
            record_permit_decision(
                service,
                crate::sekai::audit::Decision {
                    id: String::new(),
                    timestamp: now,
                    actor,
                    action: "external_action_permit/kill_switch".into(),
                    reason: input.reason.clone(),
                    evidence: HashMap::from([
                        ("scope_kind".into(), input.scope_kind.clone()),
                        ("scope_value".into(), input.scope_value.clone()),
                    ]),
                    target_id: input.scope_value.clone(),
                    outcome: if input.enabled { "enabled" } else { "disabled" }.into(),
                },
            )?;
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
pub(super) async fn record_usage(
    service: &ChiseiServiceImpl,
    req: Request<RecordUsageRequest>,
) -> Result<Response<RecordUsageResponse>, Status> {
    let actor = authenticated_actor(&req);
    if !is_gateway_service_principal(&req, &service.config) {
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
/// Sets or clears the default limit of a scope's work units (#1862). Its own
/// RPC, so a server without work-unit defaults refuses it as unimplemented
/// instead of applying the limit to the scope itself. Authorized like
/// `SetBudgetLimit`.
pub(super) async fn set_budget_work_unit_default(
    service: &ChiseiServiceImpl,
    req: Request<SetBudgetWorkUnitDefaultRequest>,
) -> Result<Response<SetBudgetWorkUnitDefaultResponse>, Status> {
    require_control_plane_admin(&req, "budget mutation")?;
    let r = req.into_inner();
    let metric = budget_metric(&r.metric)?;
    let scope_id = budget_subject(&r.subject, &r.project, &r.agent, &r.key_id, "", &r.user_id)?;
    if r.clear {
        service.budget.clear_work_unit_default(&scope_id, metric)
    } else {
        let period = crate::chisei::budget::PeriodType::parse_strict(&r.period_type)
            .map_err(Status::invalid_argument)?;
        service
            .budget
            .set_work_unit_default(&scope_id, metric, r.max_amount, period)
    }
    .map_err(Status::internal)?;
    Ok(Response::new(SetBudgetWorkUnitDefaultResponse {}))
}
/// Usage, limit and remainder of every level the scope's admission checks.
/// Authorized like `SetBudgetLimit`: limits and spend of any scope are
/// control-plane data.
pub(super) async fn get_budget_usage(
    service: &ChiseiServiceImpl,
    req: Request<GetBudgetUsageRequest>,
) -> Result<Response<GetBudgetUsageResponse>, Status> {
    require_control_plane_admin(&req, "budget usage read")?;
    let r = req.into_inner();
    let scope_id = budget_subject(
        &r.subject,
        &r.project,
        &r.agent,
        &r.key_id,
        &r.work_unit,
        &r.user_id,
    )?;
    let levels = service
        .budget
        .usage_chain(&scope_id)
        .map_err(Status::internal)?
        .into_iter()
        .map(|level| BudgetScopeUsage {
            unlimited: level.limit.is_none(),
            from_work_unit_default: level.from_work_unit_default,
            limit: level.limit.unwrap_or_default(),
            remaining: level.remaining().unwrap_or_default(),
            scope_id: level.scope_id,
            metric: level.metric,
            period_type: level.period_type,
            period_start: level.period_start,
            used: level.used,
        })
        .collect();
    Ok(Response::new(GetBudgetUsageResponse { scope_id, levels }))
}
pub(super) async fn set_namespace_policy(
    service: &ChiseiServiceImpl,
    req: Request<SetNamespacePolicyRequest>,
) -> Result<Response<SetNamespacePolicyResponse>, Status> {
    require_control_plane_admin(&req, "namespace policy mutation")?;
    let actor = authenticated_actor(&req);
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
        // An empty field keeps the rule as stored; the write reads it from
        // the store, never from this instance's memory (#1861).
        let impact_route = match r.impact_route_policy_json.trim() {
            "" => ImpactRouteUpdate::Keep,
            "null" => ImpactRouteUpdate::Clear,
            encoded => ImpactRouteUpdate::Set(
                parse_impact_route_policy(encoded).map_err(Status::invalid_argument)?,
            ),
        };
        let policy_data_class = policy.data_class.clone();
        let policy_version = policy.version();
        let current_registry = service.refresh_provider_registry_for_resolution().await?;
        if current_registry.state_version != validated_registry_version {
            return Err(Status::aborted(
                "provider registry changed while validating namespace policy",
            ));
        }
        let shadow = super::rpc_policy_shadow::admit_policy_activation(
            service,
            &actor,
            &r.namespace,
            &policy_version,
        )?;
        persist_namespace_policy(
            service
                .sekai_facts
                .reader()
                .in_process_store()
                .map(crate::db::store::SekaiStore::runtime)
                .unwrap_or_else(|_| service.db.fact_runtime()),
            &r.namespace,
            &policy,
            context_admission_policy.as_ref(),
            &impact_route,
            &actor,
        )
        .map_err(|error| {
            if error.contains("no such table") && error.contains("sekai_objects") {
                Status::failed_precondition(
                    "namespace policy persistence requires in-process Sekai graph storage",
                )
            } else {
                Status::internal(error)
            }
        })?;
        let default_runtime = policy.default_runtime.clone();
        let default_model = policy.default_model.clone();
        service.policy.set_namespace_policy(&r.namespace, policy);
        if let Some(shadow) = shadow.as_ref() {
            super::rpc_policy_shadow::end_policy_shadow(service, &actor, shadow);
        }
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
    service.require_in_process_namespace_policy()?;
    require_namespace_access(service.sekai_facts.reader(), &actor, &namespace)?;

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
    let action_policy = match get_action_policy_from_graph(
        service.sekai_facts.reader(),
        service.db.fact_runtime(),
        &project_action_scope,
    )
    .map_err(Status::internal)?
    {
        some @ Some(_) => some,
        None => get_action_policy_from_graph(
            service.sekai_facts.reader(),
            service.db.fact_runtime(),
            &namespace,
        )
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

const MAX_APPENDED_USAGE_EVENTS: usize = 500;

/// Appends usage a service measured outside the plane (#3043, ADR 0158). The
/// tenant and the principal come from the verified tenant assertion: the
/// principal is the person the caller acts for (`act`), else the caller, and
/// the caller is recorded as `reported_by`. Every event is checked before any
/// is written; each is keyed, so a retried request records nothing twice.
pub(super) async fn append_usage_events(
    service: &ChiseiServiceImpl,
    req: Request<AppendUsageEventsRequest>,
) -> Result<Response<AppendUsageEventsResponse>, Status> {
    use crate::chisei::usage_ledger::{
        ReportedUsage, UsageResource, UsageUnit, reported_usage_event,
    };
    let context = enterprise_authenticated_context(&req)?
        .cloned()
        .ok_or_else(|| Status::permission_denied("usage append requires a tenant assertion"))?;
    let tenant_id = context
        .tenant
        .as_ref()
        .map(|tenant| tenant.tenant_id.clone())
        .filter(|tenant| !tenant.trim().is_empty())
        .ok_or_else(|| Status::permission_denied("usage append requires a tenant assertion"))?;
    let reported_by = context.principal.subject.clone();
    let principal_id = context
        .act
        .as_deref()
        .map(str::trim)
        .filter(|act| !act.is_empty())
        .unwrap_or(&reported_by)
        .to_string();
    let request = req.into_inner();
    if request.events.is_empty() || request.events.len() > MAX_APPENDED_USAGE_EVENTS {
        return Err(Status::invalid_argument(format!(
            "between 1 and {MAX_APPENDED_USAGE_EVENTS} events required"
        )));
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut events = Vec::with_capacity(request.events.len());
    for (index, event) in request.events.iter().enumerate() {
        let invalid = |reason: String| Status::invalid_argument(format!("event {index}: {reason}"));
        let unit = UsageUnit::parse(&event.unit)
            .ok_or_else(|| invalid(format!("unknown unit {:?}", event.unit)))?;
        let namespace = canonical_namespace(&event.namespace)?;
        require_enterprise_namespace(
            service.sekai_facts.reader(),
            &context,
            namespace,
            crate::enterprise::NamespaceAction::Write,
        )?;
        events.push(
            reported_usage_event(ReportedUsage {
                tenant_id: &tenant_id,
                principal_id: &principal_id,
                reported_by: &reported_by,
                namespace,
                unit,
                quantity: event.quantity,
                dedupe_key: &event.dedupe_key,
                operation_id: Some(event.operation_id.as_str()),
                resource: event.resource.as_ref().map(|resource| UsageResource {
                    kind: resource.kind.clone(),
                    id: resource.id.clone(),
                }),
                event_time_ms: now_ms,
            })
            .map_err(invalid)?,
        );
    }
    let store = service.db.runtime_arc();
    let appended = tokio::task::spawn_blocking(move || {
        events
            .into_iter()
            .map(|event| {
                crate::chisei_store::append_usage_event_in(store.as_ref(), &event).map(|recorded| {
                    AppendedUsageEvent {
                        event_id: event.event_id,
                        recorded,
                    }
                })
            })
            .collect::<Result<Vec<_>, String>>()
    })
    .await
    .map_err(|_| Status::internal("usage append task failed"))?
    .map_err(Status::internal)?;
    Ok(Response::new(AppendUsageEventsResponse {
        events: appended,
    }))
}
