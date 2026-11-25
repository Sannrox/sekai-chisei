//! Disclosure by allowed egress (ADR 0152 decision 7, ADR 0164).
//!
//! Reads withhold a property whose data class may not reach every route the
//! reading principal's model traffic can take. The routes come from each
//! configured gateway's published policy (`GET /_chisei/policy`), polled with
//! the same reader key as its egress log.
//!
//! - With no gateway configured the check is off ([`Disclosure::Unchecked`]).
//! - A reader mapped to gateway principals (by `sekai_principal`, default
//!   `name`) gets the classes every provider on their routes releases.
//! - A reader with no mapping, or whose mapping reaches no route, has unknown
//!   egress: it gets the classes every provider of every policy releases.
//! - A gateway whose policy has not been read, or whose last read failed,
//!   releases nothing, so the answer fails closed.
//!
//! The policies are derived state held in memory. Each instance polls on its
//! own and starts with every policy unread.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;
use tonic_health::ServingStatus;
use tonic_health::server::HealthReporter;

use super::gateway_log_reader::GatewayLogSource;

/// The only published policy format this reader accepts.
const POLICY_FORMAT: &str = "chisei.gateway-policy/v1";
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// What a read may disclose to a reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disclosure {
    /// No gateway is configured; reads behave as without this check.
    Unchecked,
    /// Only properties whose data class is in `classes` are returned.
    Limited {
        classes: BTreeSet<String>,
        reason: WithholdReason,
    },
}

/// Why a property was withheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithholdReason {
    /// A route in the reader's allowed egress may not receive the class.
    EgressNotAllowed,
    /// The reader's egress is unknown, so only classes every route releases pass.
    EgressUnknown,
}

impl WithholdReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EgressNotAllowed => "egress_not_allowed",
            Self::EgressUnknown => "egress_unknown",
        }
    }
}

impl Disclosure {
    /// Whether a property of `classification` may be returned.
    pub fn releases(&self, classification: &str) -> bool {
        match self {
            Self::Unchecked => true,
            Self::Limited { classes, .. } => classes.contains(&normalize_class(classification)),
        }
    }
}

/// A property classification as the gateway spells data classes.
fn normalize_class(value: &str) -> String {
    let value = sekai_types::object_schema::normalize_property_classification(value);
    value.to_ascii_lowercase().replace([' ', '_'], "-")
}

/// The part of a gateway's published policy disclosure needs.
#[derive(Debug, Clone, Deserialize)]
struct PublishedPolicy {
    format: String,
    principals: Vec<PublishedPrincipal>,
    egress: Vec<PublishedEgress>,
}

#[derive(Debug, Clone, Deserialize)]
struct PublishedPrincipal {
    name: String,
    #[serde(default)]
    sekai_principal: Option<String>,
    routes: Vec<PublishedRoute>,
}

#[derive(Debug, Clone, Deserialize)]
struct PublishedRoute {
    provider: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PublishedEgress {
    provider: String,
    data_classes: Vec<String>,
}

impl PublishedPolicy {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let policy: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("decode gateway policy: {error}"))?;
        if policy.format != POLICY_FORMAT {
            return Err(format!(
                "gateway policy format {:?} is not {POLICY_FORMAT}",
                policy.format
            ));
        }
        Ok(policy)
    }

    /// Classes this policy lets leave toward `provider`; none without a rule.
    fn releasable_to(&self, provider: &str) -> BTreeSet<String> {
        self.egress
            .iter()
            .filter(|rule| rule.provider == provider)
            .flat_map(|rule| rule.data_classes.iter().map(|class| normalize_class(class)))
            .collect()
    }

    /// Providers on the routes of gateway principals mapped to `reader`.
    fn mapped_providers<'a>(&'a self, reader: &str) -> impl Iterator<Item = &'a str> {
        self.principals
            .iter()
            .filter(move |principal| {
                principal
                    .sekai_principal
                    .as_deref()
                    .unwrap_or(&principal.name)
                    == reader
            })
            .flat_map(|principal| principal.routes.iter().map(|route| route.provider.as_str()))
    }

    /// Every provider this policy names, on a route or in an egress rule.
    fn all_providers(&self) -> impl Iterator<Item = &str> {
        self.principals
            .iter()
            .flat_map(|principal| principal.routes.iter().map(|route| route.provider.as_str()))
            .chain(self.egress.iter().map(|rule| rule.provider.as_str()))
    }
}

/// The latest published policy of each configured gateway.
#[derive(Debug, Default)]
pub struct EgressPolicies {
    /// Keyed by gateway name; `None` until read, and after a failed read.
    policies: RwLock<BTreeMap<String, Option<PublishedPolicy>>>,
}

impl EgressPolicies {
    /// Policies for `gateways`, all unread. No gateways turns the check off.
    pub fn new(gateways: impl IntoIterator<Item = String>) -> Arc<Self> {
        Arc::new(Self {
            policies: RwLock::new(gateways.into_iter().map(|name| (name, None)).collect()),
        })
    }

    /// Replaces `gateway`'s policy with a published view. A view that fails
    /// to parse leaves the gateway unread, so it releases nothing.
    pub fn load(&self, gateway: &str, published: &[u8]) -> Result<(), String> {
        let parsed = PublishedPolicy::parse(published);
        let error = parsed.as_ref().err().cloned();
        self.set(gateway, parsed.ok());
        error.map_or(Ok(()), Err)
    }

    fn set(&self, gateway: &str, policy: Option<PublishedPolicy>) {
        self.policies
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(gateway.to_string(), policy);
    }

    /// What a read by `readers` may disclose: the strictest answer over all
    /// of them (a request's principals and, when delegated, its actor).
    pub fn disclosure<'a>(&self, readers: impl IntoIterator<Item = &'a str>) -> Disclosure {
        let policies = self.policies.read().unwrap_or_else(PoisonError::into_inner);
        if policies.is_empty() {
            return Disclosure::Unchecked;
        }
        let read: Option<Vec<&PublishedPolicy>> = policies.values().map(Option::as_ref).collect();
        let mut classes: Option<BTreeSet<String>> = None;
        let mut reason = WithholdReason::EgressNotAllowed;
        for reader in readers {
            let (allowed, known) = match &read {
                // An unread policy releases nothing.
                None => (BTreeSet::new(), false),
                Some(read) => reader_classes(read, reader),
            };
            if !known {
                reason = WithholdReason::EgressUnknown;
            }
            classes = Some(match classes {
                None => allowed,
                Some(so_far) => so_far.intersection(&allowed).cloned().collect(),
            });
        }
        Disclosure::Limited {
            classes: classes.unwrap_or_default(),
            reason,
        }
    }
}

/// The classes releasable to one reader, and whether its egress is known.
fn reader_classes(policies: &[&PublishedPolicy], reader: &str) -> (BTreeSet<String>, bool) {
    let mapped = policies
        .iter()
        .flat_map(|policy| {
            policy
                .mapped_providers(reader)
                .map(|provider| policy.releasable_to(provider))
        })
        .collect::<Vec<_>>();
    if !mapped.is_empty() {
        return (intersect(mapped), true);
    }
    let every_route = policies
        .iter()
        .flat_map(|policy| {
            policy
                .all_providers()
                .map(|provider| policy.releasable_to(provider))
        })
        .collect::<Vec<_>>();
    (intersect(every_route), false)
}

/// Intersection of `sets`; empty when there are none, so nothing passes.
fn intersect(sets: Vec<BTreeSet<String>>) -> BTreeSet<String> {
    let mut sets = sets.into_iter();
    let first = sets.next().unwrap_or_default();
    sets.fold(first, |acc, set| acc.intersection(&set).cloned().collect())
}

/// Reads `source`'s published policy view once.
async fn read_policy(
    client: &reqwest::Client,
    source: &GatewayLogSource,
) -> Result<Vec<u8>, String> {
    let bytes = client
        .get(format!("{}/_chisei/policy", source.base_url))
        .bearer_auth(source.reader_key())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| format!("read gateway policy: {}", error.without_url()))?
        .bytes()
        .await
        .map_err(|error| format!("read gateway policy: {}", error.without_url()))?;
    Ok(bytes.to_vec())
}

/// Polls each source's published policy into `policies`. A failed read
/// clears that gateway's policy, so reads fail closed until the next good one,
/// and reports `NOT_SERVING` under `chisei.gateway_policy.<name>`.
pub fn spawn(
    sources: Vec<GatewayLogSource>,
    policies: Arc<EgressPolicies>,
    health: HealthReporter,
) {
    let client = match reqwest::Client::builder().timeout(HTTP_TIMEOUT).build() {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(%error, "gateway policy reader cannot build its HTTP client");
            return;
        }
    };
    for source in sources {
        let (client, policies, health) = (client.clone(), policies.clone(), health.clone());
        tokio::spawn(async move {
            let service = format!("chisei.gateway_policy.{}", source.name);
            loop {
                let read = read_policy(&client, &source)
                    .await
                    .and_then(|published| policies.load(&source.name, &published));
                match read {
                    Ok(()) => {
                        health
                            .set_service_status(&service, ServingStatus::Serving)
                            .await;
                    }
                    Err(error) => {
                        tracing::warn!(gateway = %source.name, %error, "gateway policy read failed; withholding until it succeeds");
                        policies.set(&source.name, None);
                        health
                            .set_service_status(&service, ServingStatus::NotServing)
                            .await;
                    }
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: serde_json::Value) -> PublishedPolicy {
        PublishedPolicy::parse(json.to_string().as_bytes()).unwrap()
    }

    /// `analyst` reaches a hosted provider that takes only public data,
    /// `local-agent` reaches only a local provider that takes everything.
    fn gateway() -> PublishedPolicy {
        policy(serde_json::json!({
            "format": POLICY_FORMAT,
            "generation": 3,
            "principals": [
                {"name": "analyst", "routes": [{"provider": "openai", "models": ["*"]}]},
                {"name": "gw-local", "sekai_principal": "local-agent",
                 "routes": [{"provider": "ollama", "models": ["*"]}]},
            ],
            "egress": [
                {"provider": "openai", "data_classes": ["public"]},
                {"provider": "ollama", "data_classes": ["public", "internal", "sensitive"]},
            ],
        }))
    }

    fn with(policies: Vec<(&str, Option<PublishedPolicy>)>) -> Arc<EgressPolicies> {
        let store = EgressPolicies::new(policies.iter().map(|(name, _)| name.to_string()));
        for (name, policy) in policies {
            store.set(name, policy);
        }
        store
    }

    fn classes(disclosure: &Disclosure) -> (Vec<&str>, Option<WithholdReason>) {
        match disclosure {
            Disclosure::Unchecked => (vec![], None),
            Disclosure::Limited { classes, reason } => {
                (classes.iter().map(String::as_str).collect(), Some(*reason))
            }
        }
    }

    #[test]
    fn no_configured_gateway_leaves_reads_unchecked() {
        assert_eq!(
            EgressPolicies::new([]).disclosure(["analyst"]),
            Disclosure::Unchecked
        );
    }

    #[test]
    fn a_mapped_reader_gets_what_its_routes_release() {
        let store = with(vec![("edge", Some(gateway()))]);
        let analyst = store.disclosure(["analyst"]);
        assert_eq!(
            classes(&analyst),
            (vec!["public"], Some(WithholdReason::EgressNotAllowed))
        );
        assert!(!analyst.releases("sensitive"));
        // Mapped through `sekai_principal`, local only.
        let local = store.disclosure(["local-agent"]);
        assert!(local.releases("sensitive") && local.releases("internal"));
        // An empty classification is `public`.
        assert!(analyst.releases(""));
    }

    #[test]
    fn the_strictest_reader_of_a_delegated_request_wins() {
        let store = with(vec![("edge", Some(gateway()))]);
        assert_eq!(
            classes(&store.disclosure(["local-agent", "analyst"])).0,
            vec!["public"]
        );
    }

    #[test]
    fn an_unread_gateway_releases_nothing_to_anyone() {
        let store = with(vec![("edge", Some(gateway())), ("other", None)]);
        assert_eq!(
            classes(&store.disclosure(["local-agent"])),
            (vec![], Some(WithholdReason::EgressUnknown))
        );
    }

    #[test]
    fn a_route_without_an_egress_rule_releases_nothing() {
        let store = with(vec![(
            "edge",
            Some(policy(serde_json::json!({
                "format": POLICY_FORMAT,
                "principals": [{"name": "analyst", "routes": [
                    {"provider": "ollama", "models": ["*"]},
                    {"provider": "anthropic", "models": ["*"]},
                ]}],
                "egress": [{"provider": "ollama", "data_classes": ["public"]}],
            }))),
        )]);
        assert!(!store.disclosure(["analyst"]).releases("public"));
    }
}
