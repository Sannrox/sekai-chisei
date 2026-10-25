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

use chisei_provider::provider_profile::ProviderRegistry;

pub const ROUTING_PROFILES_CONTRACT: &str = "chisei.routing-profiles/v1";
pub const MODE_LOCAL: &str = "local";
pub const MODE_PROXIED: &str = "proxied";
pub const MODE_CUSTOMER_HOSTED: &str = "customer_hosted";
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostedRoutingProfile {
    pub namespace: String,
    /// Full profile id, `hosted:<name>`.
    pub profile_id: String,
    /// Canonical `scheme://host[:port]` origin.
    pub endpoint_origin: String,
    pub model_patterns: Vec<String>,
    pub credential_ref: String,
    /// Digest of the weights the endpoint is declared to serve (`sha256:<64 hex>`),
    /// passed to enterprise model admission. A namespace admin's claim, not evidence.
    pub artifact_digest: Option<String>,
    pub registered_by: String,
    pub registered_at_ms: i64,
    /// When set, admit this route only with current Tenkai runtime evidence (#1396).
    pub require_runtime_evidence: bool,
    pub evidence_provider: String,
    pub evidence_model: String,
    pub evidence_profile_version: String,
    pub evidence_artifact_digest: String,
    pub evidence_endpoint: String,
}

impl HostedRoutingProfile {
    /// The catalog entry. Like a provider entry, `runtime` and the model
    /// patterns are the keys a namespace policy and a plan use: runtime
    /// `hosted.<name>` and models `hosted.<name>/<pattern>` (#1189). Every
    /// hosted profile speaks the OpenAI-compatible API, which `mode` implies.
    pub fn entry(&self) -> RoutingProfileEntry {
        let runtime = hosted_runtime(self);
        RoutingProfileEntry {
            profile_id: self.profile_id.clone(),
            mode: MODE_CUSTOMER_HOSTED.into(),
            model_patterns: self
                .model_patterns
                .iter()
                .map(|pattern| format!("{runtime}/{pattern}"))
                .collect(),
            runtime,
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
    /// Optional `sha256:<64 hex>`; empty means unpinned.
    pub artifact_digest: String,
    pub require_runtime_evidence: bool,
    pub evidence_provider: String,
    pub evidence_model: String,
    pub evidence_profile_version: String,
    pub evidence_artifact_digest: String,
    pub evidence_endpoint: String,
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
    let artifact_digest = match input.artifact_digest.trim() {
        "" => None,
        digest if valid_sha256_digest(digest) => Some(digest.to_string()),
        _ => {
            return Err(
                "invalid_argument: artifact_digest must be sha256:<64 lowercase hex>".into(),
            );
        }
    };
    let evidence_endpoint = input.evidence_endpoint.trim().to_string();
    if input.require_runtime_evidence {
        let Some(digest) = artifact_digest.as_deref() else {
            return Err(
                "invalid_argument: artifact_digest is required when require_runtime_evidence is set"
                    .into(),
            );
        };
        for (label, value) in [
            ("evidence_provider", input.evidence_provider.trim()),
            ("evidence_model", input.evidence_model.trim()),
            (
                "evidence_profile_version",
                input.evidence_profile_version.trim(),
            ),
            (
                "evidence_artifact_digest",
                input.evidence_artifact_digest.trim(),
            ),
            ("evidence_endpoint", input.evidence_endpoint.trim()),
        ] {
            if value.is_empty() {
                return Err(format!(
                    "invalid_argument: {label} is required when require_runtime_evidence is set"
                ));
            }
        }
        if digest != input.evidence_artifact_digest.trim() {
            return Err(
                "invalid_argument: evidence_artifact_digest must match artifact_digest when require_runtime_evidence is set"
                    .into(),
            );
        }
        let bound_origin = canonical_origin(&evidence_endpoint)
            .map_err(|error| format!("invalid_argument: evidence_endpoint {error}"))?;
        if bound_origin != origin {
            return Err(
                "invalid_argument: evidence_endpoint must match the served endpoint origin".into(),
            );
        }
    }
    Ok(HostedRoutingProfile {
        namespace: input.namespace,
        profile_id: format!("{HOSTED_PROFILE_PREFIX}{}", input.name),
        endpoint_origin: origin,
        model_patterns: patterns,
        credential_ref: input.credential_ref,
        artifact_digest,
        registered_by: registered_by.into(),
        registered_at_ms: now_ms,
        require_runtime_evidence: input.require_runtime_evidence,
        evidence_provider: input.evidence_provider.trim().into(),
        evidence_model: input.evidence_model.trim().into(),
        evidence_profile_version: input.evidence_profile_version.trim().into(),
        evidence_artifact_digest: input.evidence_artifact_digest.trim().into(),
        evidence_endpoint,
    })
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
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

/// The stable profile id for a provider runtime. A hosted runtime
/// `hosted.<name>` is the profile `hosted:<name>`.
pub fn profile_id_for_runtime(runtime: &str) -> String {
    match runtime.strip_prefix(chisei_provider::provider_profile::HOSTED_PROVIDER_PREFIX) {
        Some(name) if chisei_provider::provider_profile::is_hosted_provider(runtime) => {
            format!("{HOSTED_PROFILE_PREFIX}{name}")
        }
        _ => format!("provider:{runtime}"),
    }
}

/// The exact runtime serving `model`: the provider name, or the full
/// `hosted.<name>` id for a customer-hosted model.
pub fn runtime_for_model(model: &str) -> String {
    match chisei_provider::provider_profile::hosted_provider_of(model) {
        Some(provider) => provider.into(),
        None => chisei_provider::llm::provider_name(model).into(),
    }
}

/// The environment variable a community credential reference names.
pub fn credential_env_name(credential_ref: &str) -> String {
    format!("{CREDENTIAL_ENV_PREFIX}{credential_ref}")
}

/// The provider runtime a hosted profile serves, `hosted.<name>`.
pub fn hosted_runtime(profile: &HostedRoutingProfile) -> String {
    let name = profile
        .profile_id
        .strip_prefix(HOSTED_PROFILE_PREFIX)
        .unwrap_or(&profile.profile_id);
    format!(
        "{}{name}",
        chisei_provider::provider_profile::HOSTED_PROVIDER_PREFIX
    )
}

/// Registry extension entries for a namespace's admissible hosted profiles.
pub fn hosted_endpoints(
    profiles: &[HostedRoutingProfile],
) -> Vec<chisei_provider::provider_profile::HostedEndpoint> {
    profiles
        .iter()
        .filter_map(|profile| {
            Some(chisei_provider::provider_profile::HostedEndpoint {
                name: profile
                    .profile_id
                    .strip_prefix(HOSTED_PROFILE_PREFIX)?
                    .to_string(),
                origin: profile.endpoint_origin.clone(),
                model_patterns: profile.model_patterns.clone(),
                artifact_digest: profile.artifact_digest.clone(),
            })
        })
        .collect()
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
    if chisei_provider::provider_profile::is_hosted_provider(runtime) {
        return MODE_CUSTOMER_HOSTED;
    }
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

pub fn is_loopback_url(url: &str) -> bool {
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
/// profiles) and must be the one serving the planned runtime.
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
            ..Default::default()
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
        let entry = admitted.entry();
        assert_eq!(entry.mode, MODE_CUSTOMER_HOSTED);
        // The listed runtime and patterns are the policy and model keys.
        assert_eq!(entry.runtime, hosted_runtime(&admitted));
        assert_eq!(entry.runtime, "hosted.acme-llm");
        assert_eq!(entry.model_patterns, vec!["hosted.acme-llm/acme-*"]);

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

    #[test]
    fn artifact_digest_is_optional_validated_and_reaches_the_hosted_endpoint() {
        let admit = |digest: &str| {
            let mut request = input("https://models.example.com/v1", "ACME_KEY");
            request.artifact_digest = digest.into();
            admit_hosted_profile(
                request,
                &["https://models.example.com".to_string()],
                |_| true,
                "admin",
                1,
            )
        };
        assert_eq!(admit("").unwrap().artifact_digest, None);
        let pinned = format!("sha256:{}", "ab".repeat(32));
        let profile = admit(&pinned).unwrap();
        assert_eq!(profile.artifact_digest.as_deref(), Some(pinned.as_str()));
        for bad in [
            "sha256:ab",
            "md5:00",
            &format!("sha256:{}", "AB".repeat(32)),
        ] {
            assert!(
                admit(bad).unwrap_err().starts_with("invalid_argument"),
                "{bad}"
            );
        }
        let endpoints = hosted_endpoints(std::slice::from_ref(&profile));
        assert_eq!(
            endpoints[0].artifact_digest.as_deref(),
            Some(pinned.as_str())
        );
    }

    fn evidence_request(
        digest: &str,
        evidence_digest: &str,
        evidence_endpoint: &str,
    ) -> HostedRoutingProfileInput {
        let mut request = input("https://models.example.com/v1", "ACME_KEY");
        request.artifact_digest = digest.into();
        request.require_runtime_evidence = true;
        request.evidence_provider = "hosted.acme".into();
        request.evidence_model = "qwen".into();
        request.evidence_profile_version = "v1".into();
        request.evidence_artifact_digest = evidence_digest.into();
        request.evidence_endpoint = evidence_endpoint.into();
        request
    }

    fn admit_evidence(
        digest: &str,
        evidence_digest: &str,
        evidence_endpoint: &str,
    ) -> Result<HostedRoutingProfile, String> {
        admit_hosted_profile(
            evidence_request(digest, evidence_digest, evidence_endpoint),
            &["https://models.example.com".to_string()],
            |_| true,
            "admin",
            1,
        )
    }

    #[test]
    fn evidence_required_profiles_bind_digest_and_served_origin() {
        let pinned = format!("sha256:{}", "ab".repeat(32));
        let other = format!("sha256:{}", "cd".repeat(32));
        let bound = admit_evidence(&pinned, &pinned, "https://models.example.com/v1").unwrap();
        assert_eq!(bound.artifact_digest.as_deref(), Some(pinned.as_str()));
        assert_eq!(bound.evidence_endpoint, "https://models.example.com/v1");
        assert_eq!(bound.endpoint_origin, "https://models.example.com");
        assert!(
            admit_evidence("", &pinned, "https://models.example.com")
                .unwrap_err()
                .contains("artifact_digest is required")
        );
        assert!(
            admit_evidence(&pinned, &other, "https://models.example.com")
                .unwrap_err()
                .contains("evidence_artifact_digest must match artifact_digest")
        );
        assert!(
            admit_evidence(&pinned, &pinned, "served://acme")
                .unwrap_err()
                .contains("evidence_endpoint")
        );
        assert!(
            admit_evidence(&pinned, &pinned, "https://elsewhere.example.com")
                .unwrap_err()
                .contains("evidence_endpoint must match the served endpoint origin")
        );
    }
}
