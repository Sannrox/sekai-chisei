use std::path::Path;

use crate::provider_profile::{
    ProviderRegistry, ResolvedProviderModel, provider_registry_snapshot,
    refresh_provider_registry_async,
};

/// Loads the provider registry snapshot used for one governed execution.
///
/// Transport owners call this boundary instead of reading registry persistence
/// or constructing built-in registries themselves. When persistence is not
/// configured, resolution uses the current request/process snapshot.
pub async fn snapshot_for_execution(state_path: Option<&Path>) -> Result<ProviderRegistry, String> {
    match state_path {
        Some(path) => refresh_provider_registry_async(path).await,
        None => Ok(provider_registry_snapshot()),
    }
}

/// Resolves a model through the authoritative request/process registry.
pub fn resolve_model(model: &str) -> Result<ResolvedProviderModel, String> {
    provider_registry_snapshot().resolve_model(model)
}

/// Resolves a model for a compatibility wire provider through the same
/// authoritative registry used by native execution.
pub fn resolve_model_for_provider(
    model: &str,
    wire_provider: &str,
) -> Result<ResolvedProviderModel, String> {
    provider_registry_snapshot().resolve_model_for_provider(model, wire_provider)
}

/// Returns the authoritative provider identity for an executable model.
pub fn provider_id(model: &str) -> Result<String, String> {
    resolve_model(model).map(|resolved| resolved.provider)
}

/// Compares model aliases using their authoritative canonical identities.
pub fn models_have_same_identity(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    match (resolve_model(left), resolve_model(right)) {
        (Ok(left), Ok(right)) => left.canonical_model == right.canonical_model,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gateway_and_native_resolution_share_the_same_registry_record() {
        let registry = snapshot_for_execution(None).await.unwrap();
        crate::provider_profile::with_provider_registry_snapshot(registry, async {
            let native = resolve_model("openai/gpt-5.5").unwrap();
            let gateway = resolve_model_for_provider("gpt-5.5", "openai").unwrap();

            assert_eq!(gateway.provider, native.provider);
            assert_eq!(gateway.canonical_model, native.canonical_model);
            assert_eq!(gateway.upstream_model, native.upstream_model);
            assert_eq!(gateway.profile_version, native.profile_version);
        })
        .await;
    }
}
