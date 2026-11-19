//! The process registry snapshot is a global, so this check lives in its own
//! test binary where no other test publishes to it.

use chisei_provider::provider_profile::{
    provider_registry_state_version, refresh_provider_registry, update_registry_lifecycle,
};

#[test]
fn a_refresh_that_loaded_an_older_state_never_rolls_the_snapshot_back() {
    let directory = std::env::temp_dir().join(format!(
        "chisei-provider-registry-refresh-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let path = directory.join("registry.json");
    let update = |state: &str, changed_at: &str| {
        update_registry_lifecycle(
            &path, "provider", "meta", state, "operator", "test", changed_at,
        )
        .unwrap();
    };
    refresh_provider_registry(&path).unwrap();
    update("canary", "2026-07-14T00:00:00Z");
    // A refresh that read version 1 before the next update published version 2.
    let stale = directory.join("stale.json");
    std::fs::copy(&path, &stale).unwrap();
    update("enabled", "2026-07-14T00:01:00Z");
    assert_eq!(provider_registry_state_version(), 2);

    refresh_provider_registry(&stale).unwrap();

    assert_eq!(provider_registry_state_version(), 2);
    std::fs::remove_dir_all(directory).unwrap();
}
