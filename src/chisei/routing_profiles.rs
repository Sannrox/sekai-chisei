//! Namespace routing catalog over the providers the control plane already
//! resolves (#1094, Discussion #1101).
//!
//! A routing profile names one admitted provider route and its mode. Listing
//! a profile is not a grant: a plan that pins one is rechecked against live
//! policy and the provider registry, and fails closed when the pin does not
//! match the planned route.
//!
//! Customer-hosted profiles (#1171) are registered per namespace by a
//! namespace administrator. Where model traffic may go is operator-owned:
//! [`ENDPOINT_ALLOWLIST_ENV`] lists the origins a hosted profile may use, and
//! a profile whose origin leaves that list stops being listed or pinnable.
//! A profile holds only a credential reference, never a secret.

use crate::provider_profile::ProviderRegistry;

pub const ROUTING_PROFILES_CONTRACT: &str = "chisei.routing-profiles/v1";
pub const MODE_LOCAL: &str = "local";
pub const MODE_PROXIED: &str = "proxied";
pub const MODE_CUSTOMER_HOSTED: &str = "customer_hosted";
/// Runtime every customer-hosted profile speaks.
pub const HOSTED_RUNTIME: &str = "openai-compatible";
/// Operator-owned, comma-separated `https://host[:port]` origins that
/// customer-hosted profiles may use. Loopback `http` origins are admitted
/// only when listed. Unset or empty admits none.
pub const ENDPOINT_ALLOWLIST_ENV: &str = "SEKAI_ROUTING_ENDPOINT_ALLOWLIST";
/// Community credential references resolve to this operator-set variable
/// prefix followed by the reference, so a profile can never name an
/// arbitrary process secret.
pub const CREDENTIAL_ENV_PREFIX: &str = "SEKAI_ROUTING_CREDENTIAL_";
const HOSTED_PROFILE_PREFIX: &str = "hosted:";
const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_MODEL_PATTERNS: usize = 32;

/// One customer-hosted route registered by a namespace administrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedRoutingProfile {
    pub namespace: String,
    /// Full profile id, `hosted:<name>`.
    pub profile_id: String,
    /// Canonical `scheme://host[:port]` origin.
    pub endpoint_origin: String,
    pub model_patterns: Vec<String>,
    pub credential_ref: String,
    pub registered_by: String,
    pub registered_at_ms: i64,
}

impl HostedRoutingProfile {
    pub fn entry(&self) -> RoutingProfileEntry {
        RoutingProfileEntry {
            profile_id: self.profile_id.clone(),
            mode: MODE_CUSTOMER_HOSTED.into(),
            runtime: HOSTED_RUNTIME.into(),
            model_patterns: self.model_patterns.clone(),
            lifecycle: "registered".into(),
        }
    }
}

/// A registration request before validation.
#[derive(Debug, Clone, Default)]
pub struct HostedRoutingProfileInput {
    pub namespace: String,
    pub name: String,
    pub endpoint_url: String,
    pub model_patterns: Vec<String>,
    pub credential_ref: String,
}

/// The operator's endpoint allowlist, as canonical origins.
pub fn endpoint_allowlist() -> Vec<String> {
    endpoint_allowlist_from(&std::env::var(ENDPOINT_ALLOWLIST_ENV).unwrap_or_default())
}

pub fn endpoint_allowlist_from(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| canonical_origin(entry).ok())
        .collect()
}

/// `scheme://host[:port]` in lower case, for an `https` URL or a loopback
/// `http` URL with no credentials, query, or fragment. A path is allowed
/// and dropped; the default port is dropped.
pub fn canonical_origin(url: &str) -> Result<String, &'static str> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or("endpoint must be an absolute https URL")?;
    let scheme = scheme.to_ascii_lowercase();
    if url.contains(['?', '#']) {
        return Err("endpoint must not carry a query or fragment");
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err("endpoint must name a host");
    }
    if authority.contains('@') {
        return Err("endpoint must not embed credentials");
    }
    let authority = authority.to_ascii_lowercase();
    let loopback = is_loopback_url(&format!("{scheme}://{authority}"));
    let default_port = match scheme.as_str() {
        "https" => ":443",
        "http" if loopback => ":80",
        _ => return Err("endpoint must use https"),
    };
    let authority = authority
        .strip_suffix(default_port)
        .unwrap_or(&authority)
        .to_string();
    if authority.is_empty() || authority.starts_with(':') {
        return Err("endpoint must name a host");
    }
    Ok(format!("{scheme}://{authority}"))
}

/// The references of every non-empty `SEKAI_ROUTING_CREDENTIAL_<REF>`
/// variable, sorted. Only names leave this function.
pub fn resolvable_credential_refs() -> Vec<String> {
    let mut refs = std::env::vars()
        .filter(|(_, value)| !value.trim().is_empty())
        .filter_map(|(name, _)| name.strip_prefix(CREDENTIAL_ENV_PREFIX).map(str::to_string))
        .filter(|reference| valid_identifier(reference, true))
        .collect::<Vec<_>>();
    refs.sort();
    refs
}

fn valid_identifier(value: &str, upper: bool) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_digit()
                || byte == b'_'
                || if upper {
                    byte.is_ascii_uppercase()
                } else {
                    byte.is_ascii_lowercase() || byte == b'-'
                }
        })
}

/// Validates a registration against the operator allowlist and credential
/// resolution. `credential_resolves` reports whether the reference resolves
/// to a credential right now; the secret itself never passes through here.
pub fn admit_hosted_profile(
    input: HostedRoutingProfileInput,
    allowlist: &[String],
    credential_resolves: impl Fn(&str) -> bool,
    registered_by: &str,
    now_ms: i64,
) -> Result<HostedRoutingProfile, String> {
    if !valid_identifier(&input.name, false) {
        return Err(format!(
            "invalid_argument: profile name must be 1-{MAX_IDENTIFIER_BYTES} of [a-z0-9_-]"
        ));
    }
    let origin = canonical_origin(input.endpoint_url.trim())
        .map_err(|error| format!("invalid_argument: {error}"))?;
    if !allowlist.contains(&origin) {
        return Err("permission_denied: endpoint origin is not in the operator allowlist".into());
    }
    let mut patterns = input
        .model_patterns
        .iter()
        .map(|pattern| pattern.trim().to_string())
        .filter(|pattern| !pattern.is_empty())
        .collect::<Vec<_>>();
    patterns.sort();
    patterns.dedup();
    if patterns.is_empty() || patterns.len() > MAX_MODEL_PATTERNS {
        return Err(format!(
            "invalid_argument: 1-{MAX_MODEL_PATTERNS} model patterns required"
        ));
    }
    if !valid_identifier(&input.credential_ref, true) {
        return Err(format!(
            "invalid_argument: credential_ref must be 1-{MAX_IDENTIFIER_BYTES} of [A-Z0-9_]"
        ));
    }
    if !credential_resolves(&input.credential_ref) {
        return Err("failed_precondition: credential reference does not resolve".into());
    }
    Ok(HostedRoutingProfile {
        namespace: input.namespace,
        profile_id: format!("{HOSTED_PROFILE_PREFIX}{}", input.name),
        endpoint_origin: origin,
        model_patterns: patterns,
        credential_ref: input.credential_ref,
        registered_by: registered_by.into(),
        registered_at_ms: now_ms,
    })
}

/// The hosted profiles still admissible: their origin is still allowlisted.
pub fn admissible_hosted_profiles(
    profiles: Vec<HostedRoutingProfile>,
    allowlist: &[String],
) -> Vec<HostedRoutingProfile> {
    profiles
        .into_iter()
        .filter(|profile| allowlist.contains(&profile.endpoint_origin))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingProfileEntry {
    pub profile_id: String,
    pub mode: String,
    pub runtime: String,
    pub model_patterns: Vec<String>,
    pub lifecycle: String,
}

/// The stable profile id for a provider runtime.
pub fn profile_id_for_runtime(runtime: &str) -> String {
    format!("provider:{runtime}")
}

/// Profiles for every provider the registry admits right now, sorted by id.
pub fn list_routing_profiles(registry: &ProviderRegistry) -> Vec<RoutingProfileEntry> {
    let mut profiles = registry
        .profiles
        .iter()
        .filter(|profile| {
            registry
                .ensure_provider_available(&profile.provider)
                .is_ok()
        })
        .filter_map(|profile| registry.effective_profile(&profile.provider))
        .map(|profile| RoutingProfileEntry {
            profile_id: profile_id_for_runtime(&profile.provider),
            mode: mode_for_runtime(registry, &profile.provider).into(),
            runtime: profile.provider.clone(),
            model_patterns: profile.accepted_model_patterns.clone(),
            lifecycle: profile.lifecycle.clone(),
        })
        .collect::<Vec<_>>();
    profiles.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    profiles
}

/// `local` when the runtime serves from this host (a loopback endpoint, the
/// native runtime, or an agent runtime outside the provider registry);
/// `proxied` when the control plane forwards to a remote provider.
pub fn mode_for_runtime(registry: &ProviderRegistry, runtime: &str) -> &'static str {
    let Some(profile) = registry.effective_profile(runtime) else {
        return MODE_LOCAL;
    };
    if profile.provider == "native" {
        return MODE_LOCAL;
    }
    let base_url = std::env::var(&profile.endpoint.base_url_env)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or(profile.endpoint.default_base_url.clone());
    match base_url {
        Some(url) if is_loopback_url(&url) => MODE_LOCAL,
        _ => MODE_PROXIED,
    }
}

fn is_loopback_url(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Checks a plan's pin against the live catalog: the pinned profile must be
/// admitted (a provider route, or one of the namespace's admissible hosted
/// profiles) and must be the one serving the planned runtime. Planning does
/// not route to hosted profiles yet, so a hosted pin fails closed as not
/// serving the planned route.
pub fn check_pin(
    registry: &ProviderRegistry,
    hosted: &[HostedRoutingProfile],
    pinned_profile_id: &str,
    planned_runtime: &str,
) -> Result<(), &'static str> {
    let admitted = list_routing_profiles(registry)
        .into_iter()
        .any(|profile| profile.profile_id == pinned_profile_id)
        || hosted
            .iter()
            .any(|profile| profile.profile_id == pinned_profile_id);
    if !admitted {
        return Err("routing profile unavailable");
    }
    if profile_id_for_runtime(planned_runtime) != pinned_profile_id {
        return Err("routing profile does not serve the planned route");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_catalog_lists_admitted_providers_with_their_modes() {
        let registry = ProviderRegistry::built_in();
        let profiles = list_routing_profiles(&registry);
        let by_id = |id: &str| profiles.iter().find(|profile| profile.profile_id == id);
        let ollama = by_id("provider:ollama").expect("ollama profile");
        assert_eq!(ollama.runtime, "ollama");
        if std::env::var("CHISEI_OLLAMA_BASE_URL").is_err() {
            assert_eq!(ollama.mode, MODE_LOCAL);
        }
        if std::env::var("CHISEI_OPENAI_BASE_URL").is_err() {
            assert_eq!(by_id("provider:openai").expect("openai").mode, MODE_PROXIED);
        }
        assert!(
            profiles
                .windows(2)
                .all(|pair| pair[0].profile_id < pair[1].profile_id)
        );
    }

    #[test]
    fn loopback_detection_covers_hosts_ports_and_credentials() {
        for url in [
            "http://127.0.0.1:11434/v1",
            "http://localhost/v1",
            "https://user:secret@127.0.0.9:8443",
            "http://[::1]:8080",
        ] {
            assert!(is_loopback_url(url), "{url}");
        }
        for url in [
            "https://api.openai.com/v1",
            "http://localhost.example.com",
            "http://10.0.0.1:8080",
        ] {
            assert!(!is_loopback_url(url), "{url}");
        }
    }

    #[test]
    fn a_pin_must_be_admitted_and_serve_the_planned_route() {
        let registry = ProviderRegistry::built_in();
        assert!(check_pin(&registry, &[], "provider:ollama", "ollama").is_ok());
        assert_eq!(
            check_pin(&registry, &[], "provider:ollama", "openai"),
            Err("routing profile does not serve the planned route")
        );
        assert_eq!(
            check_pin(&registry, &[], "provider:unknown", "unknown"),
            Err("routing profile unavailable")
        );
    }

    fn input(endpoint_url: &str, credential_ref: &str) -> HostedRoutingProfileInput {
        HostedRoutingProfileInput {
            namespace: "sales".into(),
            name: "acme-llm".into(),
            endpoint_url: endpoint_url.into(),
            model_patterns: vec!["acme-*".into(), " acme-*".into()],
            credential_ref: credential_ref.into(),
        }
    }

    #[test]
    fn origins_are_canonical_https_or_listed_loopback() {
        assert_eq!(
            canonical_origin("HTTPS://Models.Example.com:443/v1").unwrap(),
            "https://models.example.com"
        );
        assert_eq!(
            canonical_origin("https://models.example.com:8443").unwrap(),
            "https://models.example.com:8443"
        );
        assert_eq!(
            canonical_origin("http://127.0.0.1:8080/v1").unwrap(),
            "http://127.0.0.1:8080"
        );
        for url in [
            "http://models.example.com",
            "https://user:secret@models.example.com",
            "https://models.example.com/v1?key=x",
            "models.example.com",
            "https:///v1",
            "https://:443",
            "https://:8443/v1",
        ] {
            assert!(canonical_origin(url).is_err(), "{url}");
        }
        assert_eq!(
            endpoint_allowlist_from(" https://a.example.com/ , bogus, http://localhost:9000"),
            vec!["https://a.example.com", "http://localhost:9000"]
        );
    }

    #[test]
    fn registration_requires_an_allowlisted_origin_and_a_resolving_credential() {
        let allowlist = endpoint_allowlist_from("https://models.example.com");
        let admitted = admit_hosted_profile(
            input("https://models.example.com/v1", "ACME"),
            &allowlist,
            |reference| reference == "ACME",
            "admin",
            7,
        )
        .unwrap();
        assert_eq!(admitted.profile_id, "hosted:acme-llm");
        assert_eq!(admitted.endpoint_origin, "https://models.example.com");
        assert_eq!(admitted.model_patterns, vec!["acme-*"]);
        assert_eq!(admitted.entry().mode, MODE_CUSTOMER_HOSTED);

        let egress = admit_hosted_profile(
            input("https://elsewhere.example.com", "ACME"),
            &allowlist,
            |_| true,
            "admin",
            7,
        );
        assert!(egress.unwrap_err().starts_with("permission_denied"));
        let missing = admit_hosted_profile(
            input("https://models.example.com", "MISSING"),
            &allowlist,
            |_| false,
            "admin",
            7,
        );
        assert!(missing.unwrap_err().starts_with("failed_precondition"));
        let lower = admit_hosted_profile(
            input("https://models.example.com", "acme"),
            &allowlist,
            |_| true,
            "admin",
            7,
        );
        assert!(lower.unwrap_err().starts_with("invalid_argument"));
    }

    #[test]
    fn a_hosted_pin_is_admitted_only_while_listed_and_never_serves_a_provider_route() {
        let registry = ProviderRegistry::built_in();
        let allowlist = endpoint_allowlist_from("https://models.example.com");
        let profile = admit_hosted_profile(
            input("https://models.example.com", "ACME"),
            &allowlist,
            |_| true,
            "admin",
            7,
        )
        .unwrap();
        let hosted = admissible_hosted_profiles(vec![profile.clone()], &allowlist);
        assert_eq!(
            check_pin(&registry, &hosted, "hosted:acme-llm", "openai"),
            Err("routing profile does not serve the planned route")
        );
        let revoked_egress = admissible_hosted_profiles(vec![profile], &[]);
        assert_eq!(
            check_pin(&registry, &revoked_egress, "hosted:acme-llm", "openai"),
            Err("routing profile unavailable")
        );
    }
}
