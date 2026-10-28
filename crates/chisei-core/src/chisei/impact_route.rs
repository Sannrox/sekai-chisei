//! Impact-class route rule of a namespace route policy (#1861).
//!
//! A namespace may map the impact class of a model call to the models it may
//! use. The class is never declared by the caller: it is the class of the
//! Action type whose live Action Work claim the call cites (#1910). Every
//! other call, and a class without its own entry, uses the `unclassified`
//! entry, so a missing, stale or foreign claim can never widen the route.
//!
//! The rule narrows the namespace's allowed models before model family
//! enablement and model admission run; the most restrictive layer wins. A
//! requested model the class may not use is replaced by the namespace
//! default when the class may use that, the router's usual substitution;
//! otherwise the call is refused. A namespace without the rule routes as
//! before.

use std::collections::BTreeMap;

use crate::chisei::action_impact::ImpactClass;
use crate::chisei::policy::Policy;

pub const IMPACT_ROUTE_POLICY_VERSION: &str = "chisei.impact-route/v1";
/// Prefix of every refusal, so callers can tell it from other route errors.
pub const IMPACT_ROUTE_REFUSAL: &str = "impact route denied";
const MAX_ROUTE_ENTRIES: usize = 32;
const MAX_ENTRY_BYTES: usize = 256;

/// The class a call routes as: its Action type's class, or unclassified.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RouteClass {
    Routine,
    HighImpact,
    Unclassified,
}

impl RouteClass {
    pub fn of(class: Option<ImpactClass>) -> Self {
        match class {
            Some(ImpactClass::Routine) => Self::Routine,
            Some(ImpactClass::HighImpact) => Self::HighImpact,
            None => Self::Unclassified,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::HighImpact => "high_impact",
            Self::Unclassified => "unclassified",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Self::Routine, Self::HighImpact, Self::Unclassified]
            .into_iter()
            .find(|class| class.as_str() == value)
    }
}

/// Models one class may use: a model matches an entry of `allowed_models` by
/// identity, or belongs to a family of `allowed_families` (a provider, or a
/// model-id prefix family as for family enablement).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactRoute {
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub allowed_families: Vec<String>,
}

/// The rule, stored with the namespace route policy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactRoutePolicy {
    pub contract_version: String,
    pub routes: BTreeMap<RouteClass, ImpactRoute>,
}

impl ImpactRoutePolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != IMPACT_ROUTE_POLICY_VERSION {
            return Err(format!(
                "unsupported impact route policy version {:?}",
                self.contract_version
            ));
        }
        if !self.routes.contains_key(&RouteClass::Unclassified) {
            return Err("impact route policy needs an unclassified entry".into());
        }
        for (class, route) in &self.routes {
            let class = class.as_str();
            if route.allowed_models.is_empty() && route.allowed_families.is_empty() {
                return Err(format!(
                    "impact route {class} allows no model; list models or families"
                ));
            }
            for (name, values) in [
                ("allowed_models", &route.allowed_models),
                ("allowed_families", &route.allowed_families),
            ] {
                if values.len() > MAX_ROUTE_ENTRIES {
                    return Err(format!("impact route {class} {name} bound exceeded"));
                }
                for (index, value) in values.iter().enumerate() {
                    if value.trim() != value
                        || value.is_empty()
                        || value.len() > MAX_ENTRY_BYTES
                        || value.bytes().any(|byte| byte.is_ascii_control())
                    {
                        return Err(format!("impact route {class} {name} entry is invalid"));
                    }
                    if values[..index].contains(value) {
                        return Err(format!("impact route {class} {name} contains duplicates"));
                    }
                }
            }
        }
        Ok(())
    }

    /// The rule as it applies to a call of `class`.
    pub fn routing(&self, class: Option<ImpactClass>) -> ImpactRouting {
        let class = RouteClass::of(class);
        let route = self
            .routes
            .get(&class)
            .or_else(|| self.routes.get(&RouteClass::Unclassified))
            .cloned()
            // `validate` requires the unclassified entry; without it nothing
            // is allowed.
            .unwrap_or_default();
        ImpactRouting { class, route }
    }
}

/// What the rule did to one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpactRouteOutcome {
    /// The requested model (or the namespace default) is allowed.
    Allowed,
    /// The requested model is not allowed; the namespace default replaced it.
    Substituted,
    Refused,
}

impl ImpactRouteOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Substituted => "substituted",
            Self::Refused => "refused",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Self::Allowed, Self::Substituted, Self::Refused]
            .into_iter()
            .find(|outcome| outcome.as_str() == value)
    }
}

/// The rule's entry for one call's class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactRouting {
    pub class: RouteClass,
    pub route: ImpactRoute,
}

impl ImpactRouting {
    pub fn allows(&self, model: &str) -> bool {
        let model = model.trim();
        if model.is_empty() {
            return false;
        }
        self.route.allowed_models.iter().any(|allowed| {
            chisei_provider::provider_resolution::models_have_same_identity(allowed, model)
        }) || self.route.allowed_families.iter().any(|family| {
            chisei_provider::provider_resolution::provider_id(model).as_deref()
                == Ok(family.as_str())
                || crate::chisei::model_review::model_belongs_to_family(model, family)
        })
    }

    /// Whether the router may be handed `model` under this class: a model
    /// the class allows, or a routing alias, which resolves only among
    /// allowed models (`RoutingContext::impact`) or is refused.
    fn admits_request(&self, model: &str) -> bool {
        crate::chisei::model_routing::is_routing_alias(model.trim()) || self.allows(model)
    }

    /// Refusal when a routing alias resolves to no model the class allows.
    pub fn alias_refusal(&self, alias: &str) -> String {
        self.refusal(format!(
            "routing alias {alias:?} resolves to no allowed model"
        ))
    }

    fn refusal(&self, detail: impl std::fmt::Display) -> String {
        format!(
            "{IMPACT_ROUTE_REFUSAL}: {detail} for impact class {}",
            self.class.as_str()
        )
    }

    /// The namespace policy with only the models this class may use. Routing
    /// aliases stay: they resolve among permitted candidates only. A
    /// namespace that allows any model takes the class's listed models,
    /// unless the class allows whole families, which the router's candidate
    /// filter enforces. The default is kept only when the class may use it.
    pub fn narrow(&self, policy: Option<&Policy>) -> Result<Policy, String> {
        let mut narrowed = policy.cloned().unwrap_or(Policy {
            allowed_runtimes: Vec::new(),
            allowed_models: Vec::new(),
            default_runtime: String::new(),
            default_model: String::new(),
            data_class: String::new(),
        });
        if narrowed.allowed_models.is_empty() {
            if self.route.allowed_families.is_empty() {
                narrowed.allowed_models = self.route.allowed_models.clone();
            }
        } else {
            narrowed
                .allowed_models
                .retain(|model| self.admits_request(model));
            if narrowed.allowed_models.is_empty() {
                return Err(self.refusal("no namespace model is allowed"));
            }
        }
        if !narrowed.default_model.is_empty() && !self.admits_request(&narrowed.default_model) {
            narrowed.default_model.clear();
            narrowed.default_runtime.clear();
        }
        Ok(narrowed)
    }

    /// The model preference to hand the router, from the caller's request
    /// and the namespace default. An empty result asks the router for the
    /// namespace default, which is how it substitutes a disallowed model.
    pub fn route_request<'a>(
        &self,
        requested: &'a str,
        namespace_default: &str,
    ) -> Result<(&'a str, ImpactRouteOutcome), String> {
        let requested = requested.trim();
        let wants_default = requested.is_empty() || requested == "auto";
        if !wants_default && self.admits_request(requested) {
            return Ok((requested, ImpactRouteOutcome::Allowed));
        }
        if !self.admits_request(namespace_default) {
            return Err(if wants_default {
                self.refusal("the namespace default model is not allowed")
            } else {
                self.refusal(format!(
                    "model {requested:?} and the namespace default are not allowed"
                ))
            });
        }
        Ok(if wants_default {
            (requested, ImpactRouteOutcome::Allowed)
        } else {
            ("", ImpactRouteOutcome::Substituted)
        })
    }

    /// A route override is an exact pin with no fallback: refused when the
    /// class may not use it.
    pub fn check_override(&self, route_override: &str) -> Result<(), String> {
        if self.allows(route_override) {
            Ok(())
        } else {
            Err(self.refusal(format!("route override {route_override:?} is not allowed")))
        }
    }

    /// The final gate on the model the router resolved.
    pub fn check_resolved(&self, model: &str) -> Result<(), String> {
        if self.allows(model) {
            Ok(())
        } else {
            Err(self.refusal(format!("resolved model {model:?} is not allowed")))
        }
    }

    /// The outcome for a call that resolved: allowed unless the requested
    /// model was replaced.
    pub fn outcome_for(&self, requested: &str) -> ImpactRouteOutcome {
        let requested = requested.trim();
        if requested.is_empty() || requested == "auto" || self.admits_request(requested) {
            ImpactRouteOutcome::Allowed
        } else {
            ImpactRouteOutcome::Substituted
        }
    }
}

/// Receipt and decision-record attributes of the rule: the class the call
/// routed as and the decision, or only `impact_route_applied=false` when the
/// namespace has no rule.
pub fn record_attributes(
    applied: Option<(RouteClass, ImpactRouteOutcome)>,
) -> BTreeMap<String, String> {
    match applied {
        Some((class, outcome)) => BTreeMap::from([
            ("impact_route_applied".into(), "true".into()),
            ("impact_route_class".into(), class.as_str().into()),
            ("impact_route_decision".into(), outcome.as_str().into()),
        ]),
        None => BTreeMap::from([("impact_route_applied".into(), "false".into())]),
    }
}

pub fn is_refusal(message: &str) -> bool {
    message.starts_with(IMPACT_ROUTE_REFUSAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> ImpactRoutePolicy {
        serde_json::from_value(serde_json::json!({
            "contract_version": IMPACT_ROUTE_POLICY_VERSION,
            "routes": {
                "unclassified": {"allowed_models": ["native-default"]},
                "high_impact": {"allowed_models": ["native-default", "gpt-5.5"]},
            },
        }))
        .unwrap()
    }

    fn namespace() -> Policy {
        Policy {
            allowed_runtimes: vec!["native".into(), "openai".into()],
            allowed_models: vec!["native-default".into(), "gpt-5.5".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }
    }

    #[test]
    fn rejects_unknown_classes_and_a_missing_default() {
        rule().validate().unwrap();
        let unknown = serde_json::from_value::<ImpactRoutePolicy>(serde_json::json!({
            "contract_version": IMPACT_ROUTE_POLICY_VERSION,
            "routes": {"unclassified": {"allowed_models": ["a"]}, "critical": {"allowed_models": ["b"]}},
        }));
        assert!(unknown.is_err());
        let mut no_default = rule();
        no_default.routes.remove(&RouteClass::Unclassified);
        assert!(no_default.validate().unwrap_err().contains("unclassified"));
        let mut empty = rule();
        empty
            .routes
            .insert(RouteClass::Routine, ImpactRoute::default());
        assert!(empty.validate().unwrap_err().contains("allows no model"));
    }

    #[test]
    fn a_class_without_an_entry_uses_unclassified() {
        let routing = rule().routing(Some(ImpactClass::Routine));
        assert_eq!(routing.class, RouteClass::Routine);
        assert!(routing.allows("native-default"));
        assert!(!routing.allows("gpt-5.5"));
        assert!(rule().routing(None).route == routing.route);
        assert!(
            rule()
                .routing(Some(ImpactClass::HighImpact))
                .allows("gpt-5.5")
        );
    }

    #[test]
    fn a_disallowed_request_takes_an_allowed_default_or_is_refused() {
        let routing = rule().routing(None);
        let narrowed = routing.narrow(Some(&namespace())).unwrap();
        assert_eq!(narrowed.allowed_models, vec!["native-default".to_string()]);
        assert_eq!(
            routing
                .route_request("gpt-5.5", &narrowed.default_model)
                .unwrap(),
            ("", ImpactRouteOutcome::Substituted)
        );
        assert_eq!(
            routing
                .route_request("native-default", &narrowed.default_model)
                .unwrap(),
            ("native-default", ImpactRouteOutcome::Allowed)
        );

        let mut expensive_default = namespace();
        expensive_default.default_model = "gpt-5.5".into();
        expensive_default.default_runtime = "openai".into();
        let narrowed = routing.narrow(Some(&expensive_default)).unwrap();
        assert!(narrowed.default_model.is_empty());
        let refused = routing
            .route_request("gpt-5.5", &expensive_default.default_model)
            .unwrap_err();
        assert!(is_refusal(&refused), "{refused}");
        assert!(
            routing
                .route_request("", &expensive_default.default_model)
                .is_err()
        );

        let mut disjoint = namespace();
        disjoint.allowed_models = vec!["gpt-5.5".into()];
        assert!(routing.narrow(Some(&disjoint)).is_err());
    }

    #[test]
    fn aliases_stay_for_constrained_resolution() {
        let routing = rule().routing(None);
        let mut aliased = namespace();
        aliased.allowed_models = vec!["ollama/cheap".into(), "gpt-5.5".into()];
        aliased.default_model = "ollama/cheap".into();
        let narrowed = routing.narrow(Some(&aliased)).unwrap();
        assert_eq!(narrowed.allowed_models, vec!["ollama/cheap".to_string()]);
        assert_eq!(narrowed.default_model, "ollama/cheap");
        assert_eq!(
            routing.route_request("ollama/cheap", "").unwrap(),
            ("ollama/cheap", ImpactRouteOutcome::Allowed)
        );
    }

    #[test]
    fn families_gate_the_resolved_model() {
        let rule: ImpactRoutePolicy = serde_json::from_value(serde_json::json!({
            "contract_version": IMPACT_ROUTE_POLICY_VERSION,
            "routes": {"unclassified": {"allowed_families": ["gpt-4"]}},
        }))
        .unwrap();
        let routing = rule.routing(None);
        assert!(routing.allows("gpt-4-turbo"));
        assert!(!routing.allows("gpt-5.5"));
        // A namespace allowing any model keeps that; the final gate decides.
        let open = routing.narrow(None).unwrap();
        assert!(open.allowed_models.is_empty());
        assert!(routing.check_resolved("gpt-5.5").is_err());
        assert!(routing.check_override("gpt-5.5").is_err());
    }
}
