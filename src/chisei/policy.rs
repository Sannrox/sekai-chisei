use std::collections::HashMap;
use std::sync::Mutex;

use crate::chisei::epistemic_descriptor::{
    EpistemicDescriptor, EvidenceStatus, LifecycleStatus, OriginClass,
};
use crate::chisei::residency::{ResidencyDecision, ResidencyPolicy, ResidencyResolver};

pub const CONTEXT_ADMISSION_POLICY_VERSION: &str = "chisei.context-admission/v1";
const MAX_CONTEXT_ADMISSION_RULES: usize = 32;
const MAX_CONTEXT_ADMISSION_VALUES: usize = 8;
const MAX_CONTEXT_ADMISSION_SELECTOR_BYTES: usize = 128;

/// A context action is deliberately narrower than a truth judgement. It says
/// how a previously-authorized projection may be used by Chisei; it never
/// changes the source descriptor or promotes evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAdmissionAction {
    #[default]
    Include,
    Qualify,
    HoldOut,
    RequireReview,
    RequireVerification,
}

impl ContextAdmissionAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Qualify => "qualify",
            Self::HoldOut => "hold_out",
            Self::RequireReview => "require_review",
            Self::RequireVerification => "require_verification",
        }
    }
}

/// Domain-neutral operation risk used only for policy matching. A numeric risk
/// score remains the pipeline source of truth; these buckets are a
/// deterministic policy vocabulary rather than a domain-specific taxonomy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OperationRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl OperationRisk {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_score(score: f64) -> Self {
        if !score.is_finite() || score < 0.3 {
            Self::Low
        } else if score < 0.7 {
            Self::Medium
        } else if score < 0.9 {
            Self::High
        } else {
            Self::Critical
        }
    }

    /// Gateway requests do not carry a pipeline risk score. Their operation
    /// and task labels still provide a conservative, deterministic bucket for
    /// rules that intentionally match risk without needing context metadata.
    pub fn from_labels(operation_class: &str, task_class: &str) -> Self {
        let value = format!("{} {}", operation_class, task_class).to_ascii_lowercase();
        if ["critical", "destructive", "delete", "security"]
            .iter()
            .any(|label| value.contains(label))
        {
            Self::Critical
        } else if ["high", "write", "migration", "admin"]
            .iter()
            .any(|label| value.contains(label))
        {
            Self::High
        } else if ["medium", "review", "change"]
            .iter()
            .any(|label| value.contains(label))
        {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAdmissionRule {
    pub action: ContextAdmissionAction,
    #[serde(default)]
    pub origin_classes: Vec<OriginClass>,
    #[serde(default)]
    pub evidence_statuses: Vec<EvidenceStatus>,
    #[serde(default)]
    pub lifecycle_statuses: Vec<LifecycleStatus>,
    #[serde(default)]
    pub applicability: Option<String>,
    #[serde(default)]
    pub confidence_basis: Option<String>,
    #[serde(default)]
    pub min_confidence_bps: Option<u16>,
    #[serde(default)]
    pub max_confidence_bps: Option<u16>,
    #[serde(default)]
    pub operation_risk: Option<OperationRisk>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAdmissionPolicy {
    pub contract_version: String,
    #[serde(default)]
    pub default_action: ContextAdmissionAction,
    /// Unknown metadata is never silently treated as a stronger state. The
    /// safe default for a configured policy is to hold it out; operators may
    /// explicitly choose another action and that choice is versioned.
    #[serde(default = "default_unknown_context_action")]
    pub unknown_action: ContextAdmissionAction,
    #[serde(default)]
    pub rules: Vec<ContextAdmissionRule>,
}

fn default_unknown_context_action() -> ContextAdmissionAction {
    ContextAdmissionAction::HoldOut
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextAdmissionDecision {
    pub action: ContextAdmissionAction,
    pub policy_version: String,
    pub descriptor_version: String,
    pub reason_code: String,
}

impl ContextAdmissionDecision {
    pub fn admits_context(&self) -> bool {
        matches!(
            self.action,
            ContextAdmissionAction::Include
                | ContextAdmissionAction::Qualify
                | ContextAdmissionAction::RequireReview
        )
    }

    pub fn qualifies_context(&self) -> bool {
        matches!(
            self.action,
            ContextAdmissionAction::Qualify | ContextAdmissionAction::RequireReview
        )
    }

    pub fn blocks_provider(&self) -> bool {
        matches!(
            self.action,
            ContextAdmissionAction::RequireReview | ContextAdmissionAction::RequireVerification
        )
    }
}

impl ContextAdmissionPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != CONTEXT_ADMISSION_POLICY_VERSION {
            return Err(format!(
                "unsupported context admission policy version {}",
                self.contract_version
            ));
        }
        if self.rules.len() > MAX_CONTEXT_ADMISSION_RULES {
            return Err("context admission policy rule bound exceeded".into());
        }
        for rule in &self.rules {
            validate_selector_values(&rule.origin_classes, "origin_classes")?;
            validate_selector_values(&rule.evidence_statuses, "evidence_statuses")?;
            validate_selector_values(&rule.lifecycle_statuses, "lifecycle_statuses")?;
            if rule
                .applicability
                .as_deref()
                .is_some_and(|value| !valid_selector_string(value))
            {
                return Err("context admission applicability selector is invalid".into());
            }
            if rule
                .confidence_basis
                .as_deref()
                .is_some_and(|value| !valid_selector_string(value))
            {
                return Err("context admission confidence basis selector is invalid".into());
            }
            if rule.min_confidence_bps.is_some_and(|value| value > 10_000)
                || rule.max_confidence_bps.is_some_and(|value| value > 10_000)
                || matches!(
                    (rule.min_confidence_bps, rule.max_confidence_bps),
                    (Some(min), Some(max)) if min > max
                )
            {
                return Err("context admission confidence bounds are invalid".into());
            }
        }
        Ok(())
    }

    pub fn version(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        format!("{:x}", Sha256::digest(canonical))
    }

    pub fn decide(
        &self,
        descriptor: &EpistemicDescriptor,
        applicability: Option<&str>,
        operation_risk: OperationRisk,
    ) -> Result<ContextAdmissionDecision, String> {
        self.validate()?;
        descriptor.validate()?;
        let action = self
            .rules
            .iter()
            .find(|rule| rule.matches(descriptor, applicability, operation_risk))
            .map(|rule| rule.action)
            .unwrap_or_else(|| {
                if descriptor_has_unknown_dimension(descriptor) {
                    self.unknown_action
                } else {
                    self.default_action
                }
            });
        Ok(ContextAdmissionDecision {
            action,
            policy_version: self.version(),
            descriptor_version: descriptor.contract_version.clone(),
            reason_code: format!("context_admission:{}", action.as_str()),
        })
    }

    /// Apply only rules whose selectors are operation-level. This is used by
    /// the compatible gateway path, which has no authorized context reference
    /// to inspect. Descriptor-specific rules are left to native enrichment.
    pub fn operation_gate(
        &self,
        operation_risk: OperationRisk,
    ) -> Result<Option<ContextAdmissionDecision>, String> {
        self.validate()?;
        let unknown = EpistemicDescriptor::unknown();
        for rule in &self.rules {
            if !rule.has_descriptor_selectors() && rule.matches(&unknown, None, operation_risk) {
                return Ok(Some(ContextAdmissionDecision {
                    action: rule.action,
                    policy_version: self.version(),
                    descriptor_version: unknown.contract_version.clone(),
                    reason_code: format!("context_admission:{}", rule.action.as_str()),
                }));
            }
        }
        Ok(None)
    }
}

impl ContextAdmissionRule {
    fn has_descriptor_selectors(&self) -> bool {
        !self.origin_classes.is_empty()
            || !self.evidence_statuses.is_empty()
            || !self.lifecycle_statuses.is_empty()
            || self.applicability.is_some()
            || self.confidence_basis.is_some()
            || self.min_confidence_bps.is_some()
            || self.max_confidence_bps.is_some()
    }

    fn matches(
        &self,
        descriptor: &EpistemicDescriptor,
        applicability: Option<&str>,
        operation_risk: OperationRisk,
    ) -> bool {
        (self.origin_classes.is_empty() || self.origin_classes.contains(&descriptor.origin_class))
            && (self.evidence_statuses.is_empty()
                || self.evidence_statuses.contains(&descriptor.evidence_status))
            && (self.lifecycle_statuses.is_empty()
                || self
                    .lifecycle_statuses
                    .contains(&descriptor.lifecycle_status))
            && self
                .applicability
                .as_deref()
                .is_none_or(|expected| applicability == Some(expected))
            && self
                .confidence_basis
                .as_deref()
                .is_none_or(|expected| descriptor.confidence_basis.as_deref() == Some(expected))
            && self.min_confidence_bps.is_none_or(|minimum| {
                descriptor
                    .producer_confidence_bps
                    .is_some_and(|value| value >= minimum)
            })
            && self.max_confidence_bps.is_none_or(|maximum| {
                descriptor
                    .producer_confidence_bps
                    .is_some_and(|value| value <= maximum)
            })
            && self
                .operation_risk
                .is_none_or(|minimum| operation_risk >= minimum)
    }
}

fn descriptor_has_unknown_dimension(descriptor: &EpistemicDescriptor) -> bool {
    matches!(descriptor.origin_class, OriginClass::Unknown)
        || matches!(descriptor.evidence_status, EvidenceStatus::Unknown)
        || matches!(descriptor.lifecycle_status, LifecycleStatus::Unknown)
        || descriptor.producer_confidence_bps.is_none()
        || descriptor.confidence_basis.is_none()
}

fn valid_selector_string(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= MAX_CONTEXT_ADMISSION_SELECTOR_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn validate_selector_values<T>(values: &[T], name: &str) -> Result<(), String>
where
    T: Eq,
{
    if values.len() > MAX_CONTEXT_ADMISSION_VALUES {
        return Err(format!("context admission {name} bound exceeded"));
    }
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(format!("context admission {name} contains duplicates"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub allowed_runtimes: Vec<String>,
    pub allowed_models: Vec<String>,
    pub default_runtime: String,
    pub default_model: String,
    pub data_class: String,
}

impl Policy {
    /// Content hash identifying this exact policy revision. Surfaced with
    /// every resolution so a decision can be pinned to (and re-derived from)
    /// the policy version that produced it.
    pub fn version(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_vec(&(
            &self.allowed_runtimes,
            &self.allowed_models,
            &self.default_runtime,
            &self.default_model,
            &self.data_class,
        ))
        .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

pub struct PolicyResolver {
    namespace_policies: Mutex<HashMap<String, Policy>>,
    context_admission_policies: Mutex<HashMap<String, Result<ContextAdmissionPolicy, String>>>,
    residency: ResidencyResolver,
}

impl Default for PolicyResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyResolver {
    pub fn new() -> Self {
        Self {
            namespace_policies: Mutex::new(HashMap::new()),
            context_admission_policies: Mutex::new(HashMap::new()),
            residency: ResidencyResolver::new(),
        }
    }

    pub fn set_namespace_policy(&self, ns: &str, p: Policy) {
        self.namespace_policies.lock().unwrap().insert(ns.into(), p);
    }

    pub fn set_context_admission_policy(
        &self,
        namespace: &str,
        policy: ContextAdmissionPolicy,
    ) -> Result<(), String> {
        policy.validate()?;
        self.context_admission_policies
            .lock()
            .map_err(|_| "context admission policy lock poisoned".to_string())?
            .insert(namespace.trim().into(), Ok(policy));
        Ok(())
    }

    pub fn set_context_admission_error(&self, namespace: &str, error: impl Into<String>) {
        if let Ok(mut policies) = self.context_admission_policies.lock() {
            policies.insert(namespace.trim().into(), Err(error.into()));
        }
    }

    pub fn clear_context_admission_policy(&self, namespace: &str) {
        if let Ok(mut policies) = self.context_admission_policies.lock() {
            policies.remove(namespace.trim());
        }
    }

    /// Return the configured context policy or its durable configuration
    /// error. An error is intentionally not converted into an implicit allow.
    pub fn context_admission_policy(
        &self,
        namespace: &str,
    ) -> Result<Option<ContextAdmissionPolicy>, String> {
        let policies = self
            .context_admission_policies
            .lock()
            .map_err(|_| "context admission policy lock poisoned".to_string())?;
        match policies.get(namespace.trim()) {
            Some(Ok(policy)) => Ok(Some(policy.clone())),
            Some(Err(error)) => Err(error.clone()),
            None => Ok(None),
        }
    }

    pub fn set_residency_policy(
        &self,
        namespace: &str,
        policy: ResidencyPolicy,
    ) -> Result<(), String> {
        self.residency.set_namespace_policy(namespace, policy)
    }

    pub fn residency_policy(&self, namespace: &str) -> Option<ResidencyPolicy> {
        self.residency.get(namespace)
    }

    /// Fail closed when a residency policy is configured for the namespace.
    pub fn enforce_residency(
        &self,
        namespace: &str,
        provider: &str,
        model: &str,
        data_class: &str,
    ) -> Result<ResidencyDecision, String> {
        let decision = self
            .residency
            .evaluate_namespace(namespace, provider, model, data_class)?;
        if decision.allowed {
            Ok(decision)
        } else {
            Err(format!(
                "residency policy denied route: {}",
                decision.reasons.join("; ")
            ))
        }
    }

    /// Receipt attributes for a residency decision.
    pub fn residency_receipt_attributes(
        &self,
        decision: &ResidencyDecision,
    ) -> std::collections::BTreeMap<String, String> {
        // Attribute projection is pure over the decision; use a default policy
        // shell for the helper on ResidencyPolicy.
        ResidencyPolicy {
            policy_id: decision.policy_id.clone(),
            version: decision.policy_version.clone(),
            allowed_regions: Default::default(),
            provider_regions: Default::default(),
            model_regions: Default::default(),
            allowed_data_classes: Default::default(),
        }
        .receipt_attributes(decision)
    }

    pub fn effective_policy(&self, namespace: &str) -> Option<Policy> {
        self.namespace_policies
            .lock()
            .unwrap()
            .get(namespace)
            .cloned()
    }

    pub fn effective_policy_for_scopes(&self, scopes: &[String]) -> Option<(String, Policy)> {
        let policies = self.namespace_policies.lock().unwrap();
        scopes.iter().find_map(|scope| {
            policies
                .get(scope)
                .cloned()
                .map(|policy| (scope.clone(), policy))
        })
    }

    pub fn resolve(
        &self,
        namespace: &str,
        preferred_runtime: &str,
        preferred_model: &str,
    ) -> Result<(String, String), String> {
        let automatic = preferred_model == "auto";
        let preferred_model = if automatic { "" } else { preferred_model };
        // Then namespace
        let nss = self.namespace_policies.lock().unwrap();
        if let Some(p) = nss.get(namespace) {
            return self.apply_policy(p, preferred_runtime, preferred_model);
        }
        if automatic {
            let model = match preferred_runtime {
                "openai" => "gpt-5.5",
                "anthropic" => "claude-sonnet-4-20250514",
                "ollama" => "ollama/llama3.2:latest",
                "native" => "native-default",
                "" => {
                    return Err(
                        "auto model resolution requires a preferred runtime or namespace policy"
                            .into(),
                    );
                }
                runtime => {
                    return Err(format!(
                        "auto model resolution has no default for runtime {runtime:?}"
                    ));
                }
            };
            return Ok((preferred_runtime.into(), model.into()));
        }
        // No policy = allow anything
        Ok((
            if preferred_runtime.is_empty() {
                "kiro".into()
            } else {
                preferred_runtime.into()
            },
            if preferred_model.is_empty() {
                "claude-sonnet-4-20250514".into()
            } else {
                preferred_model.into()
            },
        ))
    }

    pub(crate) fn apply_policy(
        &self,
        p: &Policy,
        preferred_runtime: &str,
        preferred_model: &str,
    ) -> Result<(String, String), String> {
        let preferred_model = if preferred_model == "auto" {
            ""
        } else {
            preferred_model
        };
        let uses_preferred_model = !preferred_model.is_empty()
            && (p.allowed_models.is_empty()
                || p.allowed_models
                    .iter()
                    .any(|allowed| policy_models_equivalent(allowed, preferred_model)));
        let model = if uses_preferred_model {
            preferred_model.to_string()
        } else if !p.default_model.is_empty() {
            p.default_model.clone()
        } else {
            return Err(format!("model {:?} not allowed by policy", preferred_model));
        };
        let preferred_runtime_allowed = !preferred_runtime.is_empty()
            && (p.allowed_runtimes.is_empty()
                || p.allowed_runtimes.contains(&preferred_runtime.to_string()));
        let runtime = if !uses_preferred_model && !p.default_runtime.is_empty() {
            p.default_runtime.clone()
        } else if !uses_preferred_model {
            let provider = crate::provider_resolution::resolve_model(&model)
                .map_err(|reason| format!("default model cannot be routed: {reason}"))?
                .provider;
            if p.allowed_runtimes.is_empty() || p.allowed_runtimes.contains(&provider) {
                provider
            } else {
                return Err(format!(
                    "default model runtime {provider:?} is not allowed by policy"
                ));
            }
        } else if preferred_runtime_allowed {
            preferred_runtime.to_string()
        } else if !p.default_runtime.is_empty() {
            p.default_runtime.clone()
        } else {
            let model_namespace = model.split_once('/').map(|(namespace, _)| namespace);
            let matching_opaque_runtimes = p
                .allowed_runtimes
                .iter()
                .filter(|runtime| {
                    !is_registry_runtime(runtime)
                        && model_namespace.is_some_and(|namespace| namespace == runtime.as_str())
                })
                .collect::<Vec<_>>();
            if matching_opaque_runtimes.len() == 1 {
                matching_opaque_runtimes[0].clone()
            } else {
                let resolved = crate::provider_resolution::resolve_model(&model)
                    .map_err(|reason| format!("preferred model cannot be routed: {reason}"))?;
                if p.allowed_runtimes.is_empty() || p.allowed_runtimes.contains(&resolved.provider)
                {
                    resolved.provider
                } else {
                    return Err(format!(
                        "model runtime {:?} is not allowed by policy",
                        resolved.provider
                    ));
                }
            }
        };

        validate_resolved_route(&runtime, &model)?;

        // Residency is enforced by callers that know the operation data class
        // via `enforce_residency` after route resolution.

        Ok((runtime, model))
    }

    /// Resolve a route and enforce residency for the namespace data class.
    pub fn resolve_with_residency(
        &self,
        namespace: &str,
        preferred_runtime: &str,
        preferred_model: &str,
        data_class: &str,
    ) -> Result<(String, String, ResidencyDecision), String> {
        let (runtime, model) = self.resolve(namespace, preferred_runtime, preferred_model)?;
        let data_class = if data_class.trim().is_empty() {
            self.effective_policy(namespace)
                .map(|policy| policy.data_class)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unclassified".into())
        } else {
            data_class.to_string()
        };
        let decision = self.enforce_residency(namespace, &runtime, &model, &data_class)?;
        Ok((runtime, model, decision))
    }
}

fn is_registry_runtime(runtime: &str) -> bool {
    matches!(
        runtime,
        "openai" | "anthropic" | "ollama" | "native" | "xai" | "meta"
    )
}

pub(crate) fn validate_resolved_route(runtime: &str, model: &str) -> Result<(), String> {
    if is_registry_runtime(runtime) {
        let resolved = crate::provider_resolution::resolve_model(model)?;
        return (resolved.provider == runtime).then_some(()).ok_or_else(|| {
            format!(
                "runtime {runtime:?} does not match model provider {:?}",
                resolved.provider
            )
        });
    }
    if runtime == "kiro" {
        let resolved = crate::provider_resolution::resolve_model(model)?;
        if resolved.provider == "native" {
            return Ok(());
        }
    }
    Err(format!(
        "unsupported legacy runtime {runtime:?} for model {model:?}"
    ))
}

fn policy_models_equivalent(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    crate::provider_resolution::models_have_same_identity(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_policy_allows_all() {
        let r = PolicyResolver::new();
        let (rt, m) = r.resolve("ns", "kiro", "claude-4").unwrap();
        assert_eq!(rt, "kiro");
        assert_eq!(m, "claude-4");
    }

    #[test]
    fn test_namespace_policy_denies() {
        let r = PolicyResolver::new();
        r.set_namespace_policy(
            "prod",
            Policy {
                allowed_runtimes: vec!["anthropic".into()],
                allowed_models: vec!["claude-sonnet".into()],
                default_runtime: "anthropic".into(),
                default_model: "claude-sonnet".into(),
                data_class: String::new(),
            },
        );
        let result = r.resolve("prod", "anthropic", "gpt-4");
        // gpt-4 not in allowed → falls to default
        let (_, m) = result.unwrap();
        assert_eq!(m, "claude-sonnet");
    }

    #[test]
    fn test_namespace_only_policy() {
        let r = PolicyResolver::new();
        r.set_namespace_policy(
            "ns",
            Policy {
                allowed_runtimes: vec![],
                allowed_models: vec!["claude".into()],
                default_runtime: "anthropic".into(),
                default_model: "claude".into(),
                data_class: String::new(),
            },
        );
        let (rt, m) = r.resolve("ns", "", "").unwrap();
        assert_eq!(rt, "anthropic");
        assert_eq!(m, "claude");
    }

    #[test]
    fn auto_selects_policy_or_resolver_defaults() {
        let resolver = PolicyResolver::new();
        let (runtime, model) = resolver.resolve("missing", "anthropic", "auto").unwrap();
        assert_eq!(runtime, "anthropic");
        assert_eq!(model, "claude-sonnet-4-20250514");
        let (runtime, model) = resolver.resolve("missing", "openai", "auto").unwrap();
        assert_eq!(runtime, "openai");
        assert_eq!(model, "gpt-5.5");
        assert!(resolver.resolve("missing", "", "auto").is_err());

        let policy = Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec![],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        };
        let (runtime, model) = resolver.apply_policy(&policy, "openai", "auto").unwrap();
        assert_eq!(runtime, "openai");
        assert_eq!(model, "gpt-5.5");
    }

    #[test]
    fn effective_policy_for_scopes_prefers_first_match() {
        let r = PolicyResolver::new();
        r.set_namespace_policy(
            "project:sekai-chisei",
            Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5-mini".into(),
                data_class: String::new(),
            },
        );
        r.set_namespace_policy(
            "agent:codex-app",
            Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            },
        );

        let (scope, policy) = r
            .effective_policy_for_scopes(&["agent:codex-app".into(), "project:sekai-chisei".into()])
            .unwrap();
        assert_eq!(scope, "agent:codex-app");
        assert_eq!(policy.default_model, "gpt-5.5");
    }

    #[test]
    fn policy_version_is_stable_and_content_addressed() {
        let policy = Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: "internal".into(),
        };
        let same = policy.clone();
        let mut changed = policy.clone();
        changed.data_class = "sensitive".into();

        assert_eq!(policy.version(), same.version());
        assert_eq!(policy.version().len(), 64);
        assert_ne!(policy.version(), changed.version());
    }

    fn descriptor(origin: OriginClass, evidence: EvidenceStatus) -> EpistemicDescriptor {
        let mut descriptor = EpistemicDescriptor::unknown();
        descriptor.origin_class = origin;
        descriptor.evidence_status = evidence;
        descriptor.lifecycle_status = LifecycleStatus::Current;
        descriptor.producer_confidence_bps = Some(9_000);
        descriptor.confidence_basis = Some("producer_input".into());
        descriptor
    }

    #[test]
    fn context_admission_rules_are_deterministic_and_do_not_adjudicate_truth() {
        let policy = ContextAdmissionPolicy {
            contract_version: CONTEXT_ADMISSION_POLICY_VERSION.into(),
            default_action: ContextAdmissionAction::Include,
            unknown_action: ContextAdmissionAction::HoldOut,
            rules: vec![
                ContextAdmissionRule {
                    action: ContextAdmissionAction::Qualify,
                    origin_classes: vec![OriginClass::Hypothesis],
                    evidence_statuses: vec![],
                    lifecycle_statuses: vec![],
                    applicability: None,
                    confidence_basis: None,
                    min_confidence_bps: None,
                    max_confidence_bps: None,
                    operation_risk: Some(OperationRisk::High),
                },
                ContextAdmissionRule {
                    action: ContextAdmissionAction::HoldOut,
                    origin_classes: vec![],
                    evidence_statuses: vec![EvidenceStatus::Contested],
                    lifecycle_statuses: vec![],
                    applicability: None,
                    confidence_basis: None,
                    min_confidence_bps: None,
                    max_confidence_bps: None,
                    operation_risk: None,
                },
            ],
        };
        policy.validate().unwrap();
        let contested = policy
            .decide(
                &descriptor(OriginClass::Asserted, EvidenceStatus::Contested),
                None,
                OperationRisk::Low,
            )
            .unwrap();
        assert_eq!(contested.action, ContextAdmissionAction::HoldOut);
        let hypothesis = policy
            .decide(
                &descriptor(OriginClass::Hypothesis, EvidenceStatus::Unknown),
                None,
                OperationRisk::High,
            )
            .unwrap();
        assert_eq!(hypothesis.action, ContextAdmissionAction::Qualify);
        assert_eq!(
            hypothesis.descriptor_version,
            crate::chisei::epistemic_descriptor::EPISTEMIC_DESCRIPTOR_VERSION
        );
        let unknown = policy
            .decide(
                &EpistemicDescriptor::from_hypothesis("scenario-1", &[], 0, false),
                None,
                OperationRisk::Low,
            )
            .unwrap();
        assert_eq!(unknown.action, ContextAdmissionAction::HoldOut);
    }

    #[test]
    fn invalid_context_policy_values_fail_closed() {
        let policy = ContextAdmissionPolicy {
            contract_version: "unknown/v9".into(),
            default_action: ContextAdmissionAction::Include,
            unknown_action: ContextAdmissionAction::HoldOut,
            rules: vec![],
        };
        assert!(policy.validate().is_err());
        assert!(
            serde_json::from_str::<ContextAdmissionPolicy>(
                r#"{"contract_version":"chisei.context-admission/v1","unexpected":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn operation_gate_only_applies_operation_level_rules() {
        let policy = ContextAdmissionPolicy {
            contract_version: CONTEXT_ADMISSION_POLICY_VERSION.into(),
            default_action: ContextAdmissionAction::Include,
            unknown_action: ContextAdmissionAction::HoldOut,
            rules: vec![
                ContextAdmissionRule {
                    action: ContextAdmissionAction::RequireReview,
                    origin_classes: vec![],
                    evidence_statuses: vec![],
                    lifecycle_statuses: vec![],
                    applicability: None,
                    confidence_basis: None,
                    min_confidence_bps: None,
                    max_confidence_bps: None,
                    operation_risk: Some(OperationRisk::High),
                },
                ContextAdmissionRule {
                    action: ContextAdmissionAction::HoldOut,
                    origin_classes: vec![OriginClass::Hypothesis],
                    evidence_statuses: vec![],
                    lifecycle_statuses: vec![],
                    applicability: None,
                    confidence_basis: None,
                    min_confidence_bps: None,
                    max_confidence_bps: None,
                    operation_risk: None,
                },
            ],
        };
        let decision = policy.operation_gate(OperationRisk::High).unwrap().unwrap();
        assert_eq!(decision.action, ContextAdmissionAction::RequireReview);
        assert!(policy.operation_gate(OperationRisk::Low).unwrap().is_none());
    }

    #[test]
    fn operation_gate_does_not_reinterpret_unknown_descriptor_rules() {
        let policy = ContextAdmissionPolicy {
            contract_version: CONTEXT_ADMISSION_POLICY_VERSION.into(),
            default_action: ContextAdmissionAction::Include,
            unknown_action: ContextAdmissionAction::HoldOut,
            rules: vec![
                ContextAdmissionRule {
                    action: ContextAdmissionAction::HoldOut,
                    origin_classes: vec![OriginClass::Unknown],
                    evidence_statuses: vec![],
                    lifecycle_statuses: vec![],
                    applicability: None,
                    confidence_basis: None,
                    min_confidence_bps: None,
                    max_confidence_bps: None,
                    operation_risk: None,
                },
                ContextAdmissionRule {
                    action: ContextAdmissionAction::RequireReview,
                    origin_classes: vec![],
                    evidence_statuses: vec![],
                    lifecycle_statuses: vec![],
                    applicability: None,
                    confidence_basis: None,
                    min_confidence_bps: None,
                    max_confidence_bps: None,
                    operation_risk: Some(OperationRisk::High),
                },
            ],
        };
        let decision = policy.operation_gate(OperationRisk::High).unwrap().unwrap();
        assert_eq!(decision.action, ContextAdmissionAction::RequireReview);
    }

    #[test]
    fn policy_allowlists_accept_canonical_and_legacy_model_forms() {
        let resolver = PolicyResolver::new();
        let policy = Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5-mini".into(),
            data_class: String::new(),
        };
        let (_, model) = resolver
            .apply_policy(&policy, "openai", "openai/gpt-5.5")
            .unwrap();
        assert_eq!(model, "openai/gpt-5.5");
        assert!(!policy_models_equivalent("gpt-5.5", "native/gpt-5.5"));
    }

    #[test]
    fn model_fallback_uses_its_default_runtime() {
        let resolver = PolicyResolver::new();
        let policy = Policy {
            allowed_runtimes: vec!["openai".into(), "native".into()],
            allowed_models: vec!["native/mistral".into()],
            default_runtime: "native".into(),
            default_model: "native/mistral".into(),
            data_class: String::new(),
        };

        let (runtime, model) = resolver
            .apply_policy(&policy, "openai", "openai/gpt-5.5")
            .unwrap();
        assert_eq!(runtime, "native");
        assert_eq!(model, "native/mistral");
    }

    #[test]
    fn model_fallback_preserves_allowed_runtime_without_default() {
        let resolver = PolicyResolver::new();
        let policy = Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: String::new(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        };

        let (runtime, model) = resolver
            .apply_policy(&policy, "openai", "native/bad")
            .unwrap();
        assert_eq!(runtime, "openai");
        assert_eq!(model, "gpt-5.5");
    }

    #[test]
    fn model_fallback_derives_runtime_instead_of_preserving_mismatch() {
        let resolver = PolicyResolver::new();
        let policy = Policy {
            allowed_runtimes: vec!["openai".into(), "anthropic".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: String::new(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        };

        let (runtime, model) = resolver
            .apply_policy(&policy, "anthropic", "anthropic/claude-unknown")
            .unwrap();
        assert_eq!(runtime, "openai");
        assert_eq!(model, "gpt-5.5");
    }

    #[test]
    fn registered_preferred_model_derives_runtime_without_defaults() {
        let resolver = PolicyResolver::new();
        let policy = Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: String::new(),
            default_model: String::new(),
            data_class: String::new(),
        };

        let (runtime, model) = resolver.apply_policy(&policy, "", "gpt-5.5").unwrap();
        assert_eq!(runtime, "openai");
        assert_eq!(model, "gpt-5.5");
    }

    #[test]
    fn legacy_kiro_runtime_accepts_canonical_native_identity() {
        assert_eq!(
            validate_resolved_route("kiro", "native/native-default"),
            Ok(())
        );
        assert!(validate_resolved_route("kiro", "kiro/native-default").is_err());
        assert!(validate_resolved_route("kiro", "openai/gpt-5.5").is_err());
    }

    #[test]
    fn hosted_registry_runtimes_validate_against_their_models() {
        assert!(validate_resolved_route("xai", "xai/grok-4.5").is_ok());
        assert!(is_registry_runtime("meta"));
        assert!(validate_resolved_route("xai", "openai/gpt-5.5").is_err());
    }

    #[test]
    fn resolve_with_residency_denies_disallowed_region() {
        use crate::chisei::residency::ResidencyPolicy;
        use std::collections::{BTreeMap, BTreeSet};

        let resolver = PolicyResolver::new();
        resolver.set_namespace_policy(
            "eu-ns",
            Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: "internal".into(),
            },
        );
        resolver
            .set_residency_policy(
                "eu-ns",
                ResidencyPolicy {
                    policy_id: "eu".into(),
                    version: "1".into(),
                    allowed_regions: BTreeSet::from(["eu".into()]),
                    provider_regions: BTreeMap::from([("openai".into(), "us".into())]),
                    model_regions: BTreeMap::from([("gpt-5.5".into(), "us".into())]),
                    allowed_data_classes: BTreeSet::new(),
                },
            )
            .unwrap();
        let err = resolver
            .resolve_with_residency("eu-ns", "openai", "gpt-5.5", "internal")
            .unwrap_err();
        assert!(err.contains("residency"), "{err}");
    }

    #[test]
    fn opaque_provider_namespaces_are_rejected() {
        let resolver = PolicyResolver::new();
        let policy = Policy {
            allowed_runtimes: vec!["kiro".into()],
            allowed_models: vec!["kiro/private-model".into()],
            default_runtime: String::new(),
            default_model: String::new(),
            data_class: String::new(),
        };

        assert!(
            resolver
                .apply_policy(&policy, "", "kiro/private-model")
                .is_err()
        );

        let prefixed_runtime_policy = Policy {
            allowed_runtimes: vec!["native/team".into()],
            allowed_models: vec!["native/team/model".into()],
            ..policy
        };
        assert!(
            resolver
                .apply_policy(&prefixed_runtime_policy, "", "native/team/model")
                .is_err()
        );
        assert!(
            resolver
                .apply_policy(&prefixed_runtime_policy, "native/team", "native/team/model")
                .is_err()
        );

        let hosted_alias_policy = Policy {
            allowed_runtimes: vec!["kiro".into()],
            allowed_models: vec!["gpt-5.5".into()],
            ..prefixed_runtime_policy
        };
        assert!(
            resolver
                .apply_policy(&hosted_alias_policy, "kiro", "gpt-5.5")
                .is_err()
        );
    }
}
