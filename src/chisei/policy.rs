use std::collections::HashMap;
use std::sync::Mutex;

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
        }
    }

    pub fn set_namespace_policy(&self, ns: &str, p: Policy) {
        self.namespace_policies.lock().unwrap().insert(ns.into(), p);
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

        Ok((runtime, model))
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
