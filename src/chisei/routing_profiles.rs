//! Namespace routing catalog over the providers the control plane already
//! resolves (#1094, Discussion #1101).
//!
//! A routing profile names one admitted provider route and its mode. Listing
//! a profile is not a grant: a plan that pins one is rechecked against live
//! policy and the provider registry, and fails closed when the pin does not
//! match the planned route. Customer-hosted profiles are admitted separately
//! (#1171).

use crate::provider_profile::ProviderRegistry;

pub const ROUTING_PROFILES_CONTRACT: &str = "chisei.routing-profiles/v1";
pub const MODE_LOCAL: &str = "local";
pub const MODE_PROXIED: &str = "proxied";

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
/// admitted and must be the one serving the planned runtime.
pub fn check_pin(
    registry: &ProviderRegistry,
    pinned_profile_id: &str,
    planned_runtime: &str,
) -> Result<(), &'static str> {
    let admitted = list_routing_profiles(registry)
        .into_iter()
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
        assert!(check_pin(&registry, "provider:ollama", "ollama").is_ok());
        assert_eq!(
            check_pin(&registry, "provider:ollama", "openai"),
            Err("routing profile does not serve the planned route")
        );
        assert_eq!(
            check_pin(&registry, "provider:unknown", "unknown"),
            Err("routing profile unavailable")
        );
    }
}
