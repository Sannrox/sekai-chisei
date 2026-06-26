use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Policy {
    pub allowed_runtimes: Vec<String>,
    pub allowed_models: Vec<String>,
    pub default_runtime: String,
    pub default_model: String,
}

pub struct PolicyResolver {
    namespace_policies: Mutex<HashMap<String, Policy>>,
    repo_policies: Mutex<HashMap<String, Policy>>, // "ns:repo" -> policy
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
            repo_policies: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_namespace_policy(&self, ns: &str, p: Policy) {
        self.namespace_policies.lock().unwrap().insert(ns.into(), p);
    }

    pub fn set_repo_policy(&self, ns: &str, repo: &str, p: Policy) {
        self.repo_policies
            .lock()
            .unwrap()
            .insert(format!("{}:{}", ns, repo), p);
    }

    pub fn effective_policy(&self, namespace: &str, repo: &str) -> Option<Policy> {
        let repo_key = format!("{}:{}", namespace, repo);
        if let Some(policy) = self.repo_policies.lock().unwrap().get(&repo_key).cloned() {
            return Some(policy);
        }
        self.namespace_policies
            .lock()
            .unwrap()
            .get(namespace)
            .cloned()
    }

    pub fn resolve(
        &self,
        namespace: &str,
        repo: &str,
        preferred_runtime: &str,
        preferred_model: &str,
    ) -> Result<(String, String), String> {
        // Check repo-level override first
        let repo_key = format!("{}:{}", namespace, repo);
        let repos = self.repo_policies.lock().unwrap();
        if let Some(p) = repos.get(&repo_key) {
            return self.apply_policy(p, preferred_runtime, preferred_model);
        }
        drop(repos);
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

    fn apply_policy(
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
        let (rt, m) = r.resolve("ns", "repo", "kiro", "claude-4").unwrap();
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
            },
        );
        let result = r.resolve("prod", "repo", "kiro", "gpt-4");
        // gpt-4 not in allowed → falls to default
        let (_, m) = result.unwrap();
        assert_eq!(m, "claude-sonnet");
    }

    #[test]
    fn test_repo_override() {
        let r = PolicyResolver::new();
        r.set_namespace_policy(
            "ns",
            Policy {
                allowed_runtimes: vec![],
                allowed_models: vec!["claude".into()],
                default_runtime: "kiro".into(),
                default_model: "claude".into(),
            },
        );
        r.set_repo_policy(
            "ns",
            "special",
            Policy {
                allowed_runtimes: vec![],
                allowed_models: vec!["gpt-4".into()],
                default_runtime: "codex".into(),
                default_model: "gpt-4".into(),
            },
        );
        let (rt, m) = r.resolve("ns", "special", "", "").unwrap();
        assert_eq!(rt, "codex");
        assert_eq!(m, "gpt-4");
    }
}
