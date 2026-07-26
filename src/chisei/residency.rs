//! Single-plane provider/model/data-class residency enforcement (#289).
//!
//! Empty allow-lists mean unrestricted (compatible default). Once configured,
//! checks fail closed before provider contact.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResidencyPolicy {
    pub policy_id: String,
    pub version: String,
    /// If non-empty, resolved provider region and model region must both be in the set
    /// (when a region tag is known). Unknown tags deny when the allow-list is non-empty.
    pub allowed_regions: BTreeSet<String>,
    /// provider id → region label (e.g. openai → us)
    pub provider_regions: BTreeMap<String, String>,
    /// model id → region label
    pub model_regions: BTreeMap<String, String>,
    /// If non-empty, operation data_class must be listed.
    pub allowed_data_classes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidencyDecision {
    pub allowed: bool,
    pub policy_id: String,
    pub policy_version: String,
    pub provider: String,
    pub model: String,
    pub data_class: String,
    pub provider_region: Option<String>,
    pub model_region: Option<String>,
    pub reasons: Vec<String>,
}

impl ResidencyPolicy {
    pub fn is_unrestricted(&self) -> bool {
        self.allowed_regions.is_empty()
            && self.allowed_data_classes.is_empty()
            && self.provider_regions.is_empty()
            && self.model_regions.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.is_unrestricted() {
            return Ok(());
        }
        if self.policy_id.trim().is_empty() || self.version.trim().is_empty() {
            return Err("residency policy id and version are required when constraints are set".into());
        }
        for region in self
            .allowed_regions
            .iter()
            .chain(self.provider_regions.values())
            .chain(self.model_regions.values())
        {
            if region.trim().is_empty() || region == "*" {
                return Err("residency regions must be explicit (no empty or *)".into());
            }
        }
        for class in &self.allowed_data_classes {
            if class.trim().is_empty() || class == "*" {
                return Err("residency data classes must be explicit (no empty or *)".into());
            }
        }
        Ok(())
    }

    pub fn evaluate(
        &self,
        provider: &str,
        model: &str,
        data_class: &str,
    ) -> Result<ResidencyDecision, String> {
        self.validate()?;
        let provider_region = self.provider_regions.get(provider).cloned();
        let model_region = self
            .model_regions
            .get(model)
            .cloned()
            .or_else(|| {
                // Prefix match: ollama/llama → provider region if model unset
                self.model_regions
                    .iter()
                    .find(|(key, _)| model.starts_with(key.as_str()))
                    .map(|(_, region)| region.clone())
            });

        let mut reasons = Vec::new();
        if !self.allowed_data_classes.is_empty()
            && !self.allowed_data_classes.contains(data_class)
        {
            reasons.push(format!(
                "data class {data_class:?} is not allowed by residency policy"
            ));
        }
        if !self.allowed_regions.is_empty() {
            match &provider_region {
                Some(region) if self.allowed_regions.contains(region) => {}
                Some(region) => reasons.push(format!(
                    "provider {provider:?} region {region:?} is outside residency allow-list"
                )),
                None if self.provider_regions.is_empty() && self.model_regions.is_empty() => {
                    // Allow-list present but no region tags configured → cannot prove residency.
                    reasons.push(format!(
                        "provider {provider:?} has no residency region tag under an active region allow-list"
                    ));
                }
                None => reasons.push(format!(
                    "provider {provider:?} has no residency region mapping"
                )),
            }
            match &model_region {
                Some(region) if self.allowed_regions.contains(region) => {}
                Some(region) => reasons.push(format!(
                    "model {model:?} region {region:?} is outside residency allow-list"
                )),
                None if !self.model_regions.is_empty() || !self.provider_regions.is_empty() => {
                    // If we already have provider region ok and model map empty for this model,
                    // inherit provider region (already checked).
                    if provider_region
                        .as_ref()
                        .is_some_and(|region| self.allowed_regions.contains(region))
                        && self.model_regions.is_empty()
                    {
                        // ok via provider
                    } else if provider_region.is_none() {
                        // already reported
                    } else if !self.model_regions.is_empty() {
                        reasons.push(format!(
                            "model {model:?} has no residency region mapping"
                        ));
                    }
                }
                None => {}
            }
        }

        Ok(ResidencyDecision {
            allowed: reasons.is_empty(),
            policy_id: self.policy_id.clone(),
            policy_version: self.version.clone(),
            provider: provider.into(),
            model: model.into(),
            data_class: data_class.into(),
            provider_region,
            model_region,
            reasons,
        })
    }

    pub fn receipt_attributes(&self, decision: &ResidencyDecision) -> BTreeMap<String, String> {
        let mut attrs = BTreeMap::from([
            (
                "residency_allowed".into(),
                if decision.allowed {
                    "true".into()
                } else {
                    "false".into()
                },
            ),
            ("residency_policy_id".into(), decision.policy_id.clone()),
            (
                "residency_policy_version".into(),
                decision.policy_version.clone(),
            ),
        ]);
        if let Some(region) = &decision.provider_region {
            attrs.insert("residency_provider_region".into(), region.clone());
        }
        if let Some(region) = &decision.model_region {
            attrs.insert("residency_model_region".into(), region.clone());
        }
        if !decision.reasons.is_empty() {
            attrs.insert("residency_denial_reasons".into(), decision.reasons.join("; "));
        }
        attrs
    }
}

#[derive(Default)]
pub struct ResidencyResolver {
    by_namespace: Mutex<BTreeMap<String, ResidencyPolicy>>,
}

impl ResidencyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_namespace_policy(&self, namespace: &str, policy: ResidencyPolicy) -> Result<(), String> {
        policy.validate()?;
        self.by_namespace
            .lock()
            .expect("residency resolver poisoned")
            .insert(namespace.into(), policy);
        Ok(())
    }

    pub fn get(&self, namespace: &str) -> Option<ResidencyPolicy> {
        self.by_namespace
            .lock()
            .expect("residency resolver poisoned")
            .get(namespace)
            .cloned()
    }

    pub fn evaluate_namespace(
        &self,
        namespace: &str,
        provider: &str,
        model: &str,
        data_class: &str,
    ) -> Result<ResidencyDecision, String> {
        match self.get(namespace) {
            Some(policy) if !policy.is_unrestricted() => policy.evaluate(provider, model, data_class),
            _ => Ok(ResidencyDecision {
                allowed: true,
                policy_id: String::new(),
                policy_version: String::new(),
                provider: provider.into(),
                model: model.into(),
                data_class: data_class.into(),
                provider_region: None,
                model_region: None,
                reasons: vec![],
            }),
        }
    }
}

/// Parse `model=region` or `provider:region` CSV/list entries.
pub fn parse_region_bindings(entries: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (key, region) = entry
            .split_once('=')
            .or_else(|| entry.split_once(':'))
            .ok_or_else(|| format!("residency binding must be key=region, got {entry:?}"))?;
        let key = key.trim();
        let region = region.trim();
        if key.is_empty() || region.is_empty() {
            return Err(format!("invalid residency binding {entry:?}"));
        }
        out.insert(key.into(), region.into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eu_policy() -> ResidencyPolicy {
        ResidencyPolicy {
            policy_id: "eu-only".into(),
            version: "1".into(),
            allowed_regions: BTreeSet::from(["eu".into()]),
            provider_regions: BTreeMap::from([
                ("openai".into(), "us".into()),
                ("azure-eu".into(), "eu".into()),
            ]),
            model_regions: BTreeMap::from([
                ("gpt-eu".into(), "eu".into()),
                ("gpt-us".into(), "us".into()),
            ]),
            allowed_data_classes: BTreeSet::from(["internal".into(), "public".into()]),
        }
    }

    #[test]
    fn unrestricted_policy_allows_any_route() {
        let decision = ResidencyPolicy::default()
            .evaluate("openai", "gpt-us", "secret")
            .unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn disallowed_provider_region_fails_closed() {
        let decision = eu_policy()
            .evaluate("openai", "gpt-us", "internal")
            .unwrap();
        assert!(!decision.allowed);
        assert!(decision.reasons.iter().any(|r| r.contains("openai")));
    }

    #[test]
    fn allowed_eu_route_proceeds() {
        let decision = eu_policy()
            .evaluate("azure-eu", "gpt-eu", "internal")
            .unwrap();
        assert!(decision.allowed, "{:?}", decision.reasons);
    }

    #[test]
    fn sensitive_data_class_denied() {
        let decision = eu_policy()
            .evaluate("azure-eu", "gpt-eu", "restricted")
            .unwrap();
        assert!(!decision.allowed);
        assert!(decision.reasons.iter().any(|r| r.contains("data class")));
    }

    #[test]
    fn resolver_default_allows_when_unset() {
        let resolver = ResidencyResolver::new();
        let decision = resolver
            .evaluate_namespace("ns", "openai", "gpt", "secret")
            .unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn wildcards_rejected() {
        let mut policy = eu_policy();
        policy.allowed_regions.insert("*".into());
        assert!(policy.validate().unwrap_err().contains("explicit"));
    }
}
