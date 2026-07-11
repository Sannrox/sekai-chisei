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
        // Then namespace
        let nss = self.namespace_policies.lock().unwrap();
        if let Some(p) = nss.get(namespace) {
            return self.apply_policy(p, preferred_runtime, preferred_model);
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
        let runtime = if !preferred_runtime.is_empty()
            && (p.allowed_runtimes.is_empty()
                || p.allowed_runtimes.contains(&preferred_runtime.to_string()))
        {
            preferred_runtime.to_string()
        } else if !p.default_runtime.is_empty() {
            p.default_runtime.clone()
        } else {
            "kiro".into()
        };

        let model = if !preferred_model.is_empty()
            && (p.allowed_models.is_empty()
                || p.allowed_models.contains(&preferred_model.to_string()))
        {
            preferred_model.to_string()
        } else if !p.default_model.is_empty() {
            p.default_model.clone()
        } else {
            return Err(format!("model {:?} not allowed by policy", preferred_model));
        };

        Ok((runtime, model))
    }
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
                allowed_runtimes: vec!["kiro".into()],
                allowed_models: vec!["claude-sonnet".into()],
                default_runtime: "kiro".into(),
                default_model: "claude-sonnet".into(),
                data_class: String::new(),
            },
        );
        let result = r.resolve("prod", "kiro", "gpt-4");
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
                default_runtime: "kiro".into(),
                default_model: "claude".into(),
                data_class: String::new(),
            },
        );
        let (rt, m) = r.resolve("ns", "", "").unwrap();
        assert_eq!(rt, "kiro");
        assert_eq!(m, "claude");
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
}
