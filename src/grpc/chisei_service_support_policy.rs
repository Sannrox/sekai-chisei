use super::*;

pub(super) fn prune_cached_plans(plans: &mut HashMap<String, CachedExecutionPlan>) {
    prune_expired_plans(plans);
    prune_excess_plans(plans, None);
}
pub(super) fn prune_expired_plans(plans: &mut HashMap<String, CachedExecutionPlan>) {
    let cutoff = chrono::Utc::now().timestamp_millis() - MAX_CACHED_EXECUTION_PLAN_AGE_MS;
    plans.retain(|_, cached| cached.plan.created_at >= cutoff);
}
pub(super) fn prune_excess_plans(
    plans: &mut HashMap<String, CachedExecutionPlan>,
    protected_plan_id: Option<&str>,
) {
    while plans.len() > MAX_CACHED_EXECUTION_PLANS {
        let Some(oldest_id) = plans
            .iter()
            .filter(|(plan_id, _)| protected_plan_id != Some(plan_id.as_str()))
            .min_by(|left, right| {
                left.1
                    .plan
                    .created_at
                    .cmp(&right.1.plan.created_at)
                    .then_with(|| left.0.cmp(right.0))
            })
            .map(|(plan_id, _)| plan_id.clone())
        else {
            break;
        };
        plans.remove(&oldest_id);
    }
}
pub(super) fn load_namespace_policies(db: &RuntimeDb, resolver: &PolicyResolver) {
    // Canonical `policy:` objects must win. Leftover `namespace_policy` rows
    // still exist in older stores; applying them last restored a JSON-null
    // context-admission clear (and any later canonical revision) on restart.
    for kind in ["namespace_policy", "policy"] {
        let Ok(objects) = db.list_all_objects(&ListFilter {
            kind: Some(kind.into()),
            ..Default::default()
        }) else {
            continue;
        };
        for obj in objects {
            let namespace = policy_namespace(&obj);
            if namespace.is_empty() {
                continue;
            }
            resolver.set_namespace_policy(
                &namespace,
                normalize_persisted_legacy_policy(policy_from_properties(&obj.properties)),
            );
            match context_admission_policy_from_properties(&obj.properties) {
                Ok(Some(policy)) => {
                    let _ = resolver.set_context_admission_policy(&namespace, policy);
                }
                Ok(None) => resolver.clear_context_admission_policy(&namespace),
                Err(error) => resolver.set_context_admission_error(&namespace, error),
            }
        }
    }
}
pub(super) fn policy_namespace(obj: &crate::domain::Object) -> String {
    if !obj.namespace.trim().is_empty() {
        return obj.namespace.trim().to_string();
    }
    for prefix in ["namespace_policy:", "policy:", "namespace:"] {
        if let Some(value) = obj.external_id.strip_prefix(prefix)
            && !value.trim().is_empty()
        {
            return value.trim().to_string();
        }
    }
    obj.name.trim().to_string()
}
pub(super) fn policy_from_properties(
    properties: &std::collections::HashMap<String, String>,
) -> Policy {
    Policy {
        allowed_runtimes: csv_property(properties.get("allowed_runtimes")),
        allowed_models: csv_property(properties.get("allowed_models")),
        default_runtime: properties
            .get("default_runtime")
            .cloned()
            .unwrap_or_default(),
        default_model: properties.get("default_model").cloned().unwrap_or_default(),
        data_class: properties.get("data_class").cloned().unwrap_or_default(),
    }
}
pub(super) fn context_admission_policy_from_properties(
    properties: &std::collections::HashMap<String, String>,
) -> Result<Option<crate::chisei::policy::ContextAdmissionPolicy>, String> {
    let Some(encoded) = properties
        .get("context_admission_policy_json")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if encoded == "null" {
        return Ok(None);
    }
    let policy = serde_json::from_str::<crate::chisei::policy::ContextAdmissionPolicy>(encoded)
        .map_err(|error| format!("invalid context admission policy: {error}"))?;
    policy.validate()?;
    Ok(Some(policy))
}
pub(super) fn policy_properties(
    policy: &Policy,
    context_admission_policy: Option<&crate::chisei::policy::ContextAdmissionPolicy>,
) -> std::collections::HashMap<String, String> {
    let mut properties = std::collections::HashMap::from([
        ("allowed_runtimes".into(), policy.allowed_runtimes.join(",")),
        ("allowed_models".into(), policy.allowed_models.join(",")),
        ("default_runtime".into(), policy.default_runtime.clone()),
        ("default_model".into(), policy.default_model.clone()),
        ("data_class".into(), policy.data_class.clone()),
    ]);
    if let Some(context_admission_policy) = context_admission_policy {
        properties.insert(
            "context_admission_policy_json".into(),
            serde_json::to_string(context_admission_policy).unwrap_or_default(),
        );
    }
    properties
}
pub(super) fn policy_from_request(r: &SetNamespacePolicyRequest) -> Policy {
    Policy {
        allowed_runtimes: r.allowed_runtimes.clone(),
        allowed_models: r.allowed_models.clone(),
        default_runtime: r.default_runtime.clone(),
        default_model: r.default_model.clone(),
        data_class: DataClass::parse(&r.data_class).as_str().into(),
    }
}
pub(super) fn normalize_legacy_policy_provider_pairs(mut policy: Policy) -> Policy {
    let provider_for = |model: &str| {
        let explicitly_native = model.starts_with("native/")
            || model.starts_with("native-")
            || model.starts_with("fallback:");
        let explicitly_ollama = model.starts_with("ollama/");
        crate::provider_profile::resolve_provider_id(model)
            .ok()
            .filter(|provider| {
                (*provider == "native" && explicitly_native)
                    || (*provider == "ollama" && explicitly_ollama)
            })
            .map(str::to_string)
    };
    if policy.default_runtime == "openai"
        && let Some(provider) = provider_for(&policy.default_model)
        && matches!(provider.as_str(), "ollama" | "native")
    {
        policy.default_runtime = provider;
    }
    if policy
        .allowed_runtimes
        .iter()
        .any(|runtime| runtime == "openai")
    {
        let mut providers = policy
            .allowed_models
            .iter()
            .filter_map(|model| provider_for(model))
            .filter(|provider| matches!(provider.as_str(), "ollama" | "native"))
            .collect::<Vec<_>>();
        if matches!(policy.default_runtime.as_str(), "ollama" | "native") {
            providers.push(policy.default_runtime.clone());
        }
        for provider in providers {
            if !policy.allowed_runtimes.contains(&provider) {
                policy.allowed_runtimes.push(provider);
            }
        }
    }
    policy
}
pub(super) fn normalize_persisted_legacy_policy(mut policy: Policy) -> Policy {
    let runtime_unspecified =
        policy.default_runtime.is_empty() && policy.allowed_runtimes.is_empty();
    let openai_only_allowed = !policy.allowed_runtimes.is_empty()
        && policy
            .allowed_runtimes
            .iter()
            .all(|runtime| runtime == "openai");
    let legacy_namespace = if policy.default_runtime == "openai"
        || policy.default_runtime.is_empty() && openai_only_allowed
    {
        Some("openai")
    } else if runtime_unspecified
        || matches!(policy.default_runtime.as_str(), "native" | "kiro")
        || policy
            .allowed_runtimes
            .iter()
            .any(|runtime| matches!(runtime.as_str(), "native" | "kiro"))
    {
        Some("native")
    } else {
        None
    };
    let canonicalize = |model: &mut String| {
        if let Some(namespace) = legacy_namespace
            && !model.is_empty()
            && !model.contains('/')
            && !model.eq_ignore_ascii_case("kiro")
            && model != "auto"
            && crate::provider_profile::resolve_provider_id(model).is_err()
        {
            *model = format!("{namespace}/{model}");
        }
    };
    canonicalize(&mut policy.default_model);
    for model in &mut policy.allowed_models {
        canonicalize(model);
    }
    if policy.default_runtime == "kiro" {
        policy.default_runtime = "native".into();
    }
    for runtime in &mut policy.allowed_runtimes {
        if runtime == "kiro" {
            *runtime = "native".into();
        }
    }
    policy.allowed_runtimes.sort();
    policy.allowed_runtimes.dedup();
    normalize_legacy_policy_provider_pairs(policy)
}
pub(super) fn validate_policy_provider_pairs(policy: &Policy) -> Result<(), String> {
    for model in policy
        .allowed_models
        .iter()
        .chain((!policy.default_model.is_empty()).then_some(&policy.default_model))
    {
        validate_policy_model_alias(model)?;
    }
    for runtime in policy
        .allowed_runtimes
        .iter()
        .chain((!policy.default_runtime.is_empty()).then_some(&policy.default_runtime))
    {
        if !matches!(
            runtime.as_str(),
            "openai" | "anthropic" | "ollama" | "native" | "xai" | "meta"
        ) {
            return Err(format!("unsupported policy runtime {runtime:?}"));
        }
    }
    if !policy.default_runtime.is_empty()
        && !policy.allowed_runtimes.is_empty()
        && !policy.allowed_runtimes.contains(&policy.default_runtime)
    {
        return Err(format!(
            "default runtime {:?} is not in allowed runtimes",
            policy.default_runtime
        ));
    }
    if !policy.default_model.is_empty()
        && !policy.allowed_models.is_empty()
        && !policy
            .allowed_models
            .iter()
            .any(|allowed| models_have_same_identity(allowed, &policy.default_model))
    {
        return Err(format!(
            "default model {:?} is not in allowed models",
            policy.default_model
        ));
    }
    if !policy.default_model.is_empty() && !policy.default_runtime.is_empty() {
        crate::chisei::policy::validate_resolved_route(
            &policy.default_runtime,
            &policy.default_model,
        )?;
    } else if !policy.default_model.is_empty() {
        let provider = crate::provider_resolution::resolve_model(&policy.default_model)?.provider;
        if !policy.allowed_runtimes.is_empty() && !policy.allowed_runtimes.contains(&provider) {
            return Err(format!(
                "default model provider {provider:?} is not in allowed runtimes"
            ));
        }
    }
    for model in &policy.allowed_models {
        if policy.allowed_runtimes.is_empty() {
            if let Some((runtime, _)) = model.split_once('/') {
                crate::chisei::policy::validate_resolved_route(runtime, model)?;
            } else {
                crate::provider_resolution::resolve_model(model)?;
            }
            continue;
        }
        if !policy
            .allowed_runtimes
            .iter()
            .any(|runtime| crate::chisei::policy::validate_resolved_route(runtime, model).is_ok())
        {
            return Err(format!(
                "allowed model {model:?} cannot be routed by any allowed runtime"
            ));
        }
    }
    Ok(())
}
pub(super) fn validate_policy_model_alias(model: &str) -> Result<(), String> {
    let provider = crate::provider_resolution::provider_id(model)?;
    if provider == "native"
        && !model.starts_with("native/")
        && !model.starts_with("native-")
        && !model.starts_with("fallback:")
    {
        return Err(format!(
            "native policy model {model:?} must use an advertised native alias"
        ));
    }
    Ok(())
}
pub(super) fn models_have_same_identity(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    crate::provider_resolution::models_have_same_identity(left, right)
}
pub(super) fn validate_explicit_requested_model(model: &str) -> Result<(), String> {
    if model.is_empty() || model == "auto" {
        return Ok(());
    }
    let Some((namespace, _)) = model.split_once('/') else {
        return crate::provider_resolution::resolve_model(model).map(|_| ());
    };
    match crate::provider_resolution::resolve_model(model) {
        Ok(_) => Ok(()),
        Err(error)
            if crate::provider_profile::provider_registry_snapshot()
                .profile(namespace)
                .is_some() =>
        {
            Err(error)
        }
        Err(error) => Err(error),
    }
}
pub(super) fn csv_property(value: Option<&String>) -> Vec<String> {
    value
        .map(String::as_str)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
pub(super) fn build_egress_decisions(
    records: &[crate::chisei::egress::ContextEgressRecord],
    provider: &str,
    external: bool,
) -> Vec<EgressDecision> {
    if records.is_empty() {
        return vec![EgressDecision {
            provider: provider.into(),
            external,
            included: vec![],
            redacted: vec![],
            reasons: vec!["no sekai context selected".into()],
        }];
    }
    records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let object_ref = if record
                .included_fields
                .iter()
                .any(|field| field == "identity")
            {
                record.object_ref.clone()
            } else {
                format!("object#{}", index + 1)
            };
            EgressDecision {
                provider: provider.into(),
                external,
                included: record
                    .included_fields
                    .iter()
                    .map(|field| format!("{object_ref}.{field}"))
                    .collect(),
                redacted: record
                    .redacted_fields
                    .iter()
                    .map(|field| format!("{object_ref}.{field}"))
                    .collect(),
                reasons: record.reasons.clone(),
            }
        })
        .collect()
}
pub(super) fn payload_for_leak_check(
    system: &str,
    messages: &[ChatMessage],
    tools: &[ToolDef],
) -> String {
    let mut payload = String::new();
    payload.push_str(system);
    for message in messages {
        payload.push('\n');
        payload.push_str(&message.role);
        payload.push_str(": ");
        payload.push_str(&message.content);
    }
    for tool in tools {
        payload.push('\n');
        payload.push_str(&tool.name);
        payload.push_str(": ");
        payload.push_str(&tool.description);
        payload.push('\n');
        payload.push_str(&tool.input_schema_json);
    }
    payload
}
pub(super) fn leak_findings_to_decisions(
    provider: &str,
    external: bool,
    findings: &[LeakFinding],
) -> Vec<EgressDecision> {
    findings
        .iter()
        .map(|finding| EgressDecision {
            provider: provider.into(),
            external,
            included: vec![],
            redacted: vec![],
            reasons: vec![format!(
                "leak_checker {} {} match(es)",
                finding.rule_label, finding.match_count
            )],
        })
        .collect()
}
pub(super) fn build_prepared_messages(
    input: &ExecutionInput,
    enriched_spec: &str,
) -> Vec<ChatMessage> {
    let mut messages = input.messages.clone();
    let prepared_spec = if enriched_spec.is_empty() {
        input.spec.as_str()
    } else {
        enriched_spec
    };
    if prepared_spec.is_empty() {
        return messages;
    }
    if messages.is_empty() {
        return vec![ChatMessage {
            role: "user".into(),
            content: prepared_spec.into(),
            tool_call_id: String::new(),
            tool_calls: vec![],
        }];
    }
    let task_message = ChatMessage {
        role: "user".into(),
        content: format!("[Task spec]\n{prepared_spec}"),
        tool_call_id: String::new(),
        tool_calls: vec![],
    };
    // A pending assistant tool call must remain adjacent to its tool result.
    // Such a history is not cacheable across the current governed task spec.
    if messages
        .last()
        .is_some_and(|message| !message.tool_calls.is_empty())
    {
        messages.insert(0, task_message);
    } else {
        messages.push(task_message);
    }
    messages
}
pub(super) fn subject_reference_from_proto(
    value: GovernedSubjectReference,
) -> subject::GovernedSubjectReference {
    subject::GovernedSubjectReference {
        kind: value.kind,
        reference: value.reference,
        content_digest: value.content_digest,
        observed_at_ms: value.observed_at_ms,
    }
}
pub(super) fn to_proto_governed_subject_result(
    result: &subject::GovernedSubjectResult,
) -> GovernedSubjectResult {
    GovernedSubjectResult {
        version: result.version.clone(),
        decision: result.decision.clone(),
        operation_id: result.operation_id.clone(),
        receipt_schema: result.receipt_schema.clone(),
        receipt_digest: result.receipt_digest.clone(),
        references: result
            .references
            .iter()
            .map(|reference| GovernedSubjectReference {
                kind: reference.kind.clone(),
                reference: reference.reference.clone(),
                content_digest: reference.content_digest.clone(),
                observed_at_ms: reference.observed_at_ms,
            })
            .collect(),
        fresh: result.fresh,
        failure_code: result.failure_code.clone().unwrap_or_default(),
        failure_message: result.failure_message.clone().unwrap_or_default(),
    }
}
pub(super) fn subject_provenance_envelope_to_proto(
    value: &subject_provenance::ProvenanceEnvelope,
) -> GovernedSubjectProvenanceEnvelope {
    GovernedSubjectProvenanceEnvelope {
        profile: value.profile.clone(),
        issuer: value.issuer.clone(),
        issuer_key_id: value.issuer_key_id.clone(),
        subject: value.subject.clone(),
        content_digest: value.content_digest.clone(),
        decision: value.decision.clone(),
        receipt_schema: value.receipt_schema.clone(),
        receipt_digest: value.receipt_digest.clone(),
        governed_references: value
            .governed_references
            .iter()
            .map(|reference| GovernedSubjectProvenanceReference {
                kind: reference.kind.clone(),
                id: reference.id.clone(),
                digest: reference.digest.clone(),
            })
            .collect(),
        observed_at_unix_ms: value.observed_at_unix_ms,
        expires_at_unix_ms: value.expires_at_unix_ms,
        signature: value.signature.clone(),
    }
}
pub(super) fn subject_provenance_response(
    record: &subject_provenance::ExportRecord,
    replayed: bool,
    now_ms: i64,
) -> Result<ExportGovernedSubjectProvenanceResponse, Status> {
    record
        .envelope
        .validate(now_ms)
        .map_err(Status::failed_precondition)?;
    Ok(ExportGovernedSubjectProvenanceResponse {
        envelope: Some(subject_provenance_envelope_to_proto(&record.envelope)),
        envelope_digest: record.envelope.digest().map_err(Status::data_loss)?,
        replayed,
        trust_root: Some(GovernedSubjectProvenanceTrustRoot {
            version: subject_provenance::TRUST_ROOT_VERSION,
            key_id: record.envelope.issuer_key_id.clone(),
            identity: subject_provenance::ISSUER.into(),
            public_key: record.public_key.clone(),
        }),
    })
}
