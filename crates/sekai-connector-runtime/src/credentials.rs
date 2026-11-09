//! Credential handles, bound in the runtime (ADR 0148, decision 4).
//!
//! The operator issues each handle in the runtime's configuration and binds
//! it to the namespaces and destinations it may serve. A Source names a
//! handle; the plane never holds the value. The runtime refuses a handle
//! for a namespace or destination outside its binding, so a namespace
//! administrator can name a handle but cannot point it elsewhere.
//!
//! Values are read when a claim runs, from the environment or a file, so a
//! rotated value needs no restart. Every refusal is `unavailable`: the
//! Source fails that run visibly and waits for its next interval.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use sekai_source_sdk::{ConnectorType, Destination, EgressAllowlist};
use serde::Deserialize;

/// Where one credential slot's value comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SlotSource {
    /// An environment variable of the runtime process.
    Env(String),
    /// A file, such as a mounted secret; one trailing newline is dropped.
    File(PathBuf),
}

/// What one handle may serve, and where its values live.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    pub namespaces: BTreeSet<String>,
    /// `host` or `host:port` rules, as in a Source's egress allowlist.
    pub destinations: Vec<String>,
    pub slots: BTreeMap<String, SlotSource>,
}

/// The operator's handles, by name.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct CredentialBindings(BTreeMap<String, CredentialBinding>);

/// A resolved value. Debug output never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(pub(crate) String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret(..)")
    }
}

/// The resolved slots of one handle, by slot name.
pub type Credentials = BTreeMap<String, Secret>;

/// Why a handle did not resolve for a Source. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unresolved {
    /// The runtime has no binding for the handle.
    UnknownHandle,
    /// The Source's namespace is outside the handle's binding.
    Namespace,
    /// A destination the Source connects to is outside the binding.
    Destination,
    /// A required slot has no source, or its value is missing or empty.
    Slot(&'static str),
}

impl CredentialBindings {
    pub fn new(bindings: BTreeMap<String, CredentialBinding>) -> Self {
        Self(bindings)
    }

    /// The values of `handle` for a Source of `connector` in `namespace`
    /// that connects to `destinations`. An empty handle resolves to no
    /// values when the type has no required slot.
    pub fn resolve(
        &self,
        handle: &str,
        namespace: &str,
        connector: &ConnectorType,
        destinations: &[Destination],
    ) -> Result<Credentials, Unresolved> {
        if handle.is_empty() {
            return match connector.credential_slots.iter().find(|slot| slot.required) {
                Some(slot) => Err(Unresolved::Slot(slot.name)),
                None => Ok(Credentials::new()),
            };
        }
        let binding = self.0.get(handle).ok_or(Unresolved::UnknownHandle)?;
        if !binding.namespaces.contains(namespace) {
            return Err(Unresolved::Namespace);
        }
        let allowed =
            EgressAllowlist::parse(&binding.destinations).map_err(|_| Unresolved::Destination)?;
        if !destinations
            .iter()
            .all(|destination| allowed.permits(destination))
        {
            return Err(Unresolved::Destination);
        }
        let mut credentials = Credentials::new();
        for slot in connector.credential_slots {
            match binding.slots.get(slot.name).and_then(read_slot) {
                Some(value) => {
                    credentials.insert(slot.name.to_string(), value);
                }
                None if slot.required => return Err(Unresolved::Slot(slot.name)),
                None => {}
            }
        }
        Ok(credentials)
    }
}

fn read_slot(source: &SlotSource) -> Option<Secret> {
    let value = match source {
        SlotSource::Env(name) => std::env::var(name).ok()?,
        SlotSource::File(path) => {
            let mut text = std::fs::read_to_string(path).ok()?;
            if text.ends_with('\n') {
                text.pop();
            }
            text
        }
    };
    (!value.is_empty()).then_some(Secret(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_source_sdk::{GITHUB_CONNECTOR, RELATIONAL_CONNECTOR};

    fn bindings(token: &std::path::Path) -> CredentialBindings {
        serde_json::from_value(serde_json::json!({
            "ops/github-bot": {
                "namespaces": ["ops"],
                "destinations": ["api.github.com:443"],
                "slots": { "token": { "file": token } }
            }
        }))
        .unwrap()
    }

    fn github() -> Vec<Destination> {
        vec![Destination::parse("https://api.github.com").unwrap()]
    }

    #[test]
    fn a_handle_resolves_only_inside_its_binding() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "value\n").unwrap();
        let bindings = bindings(&token);

        let resolved = bindings
            .resolve("ops/github-bot", "ops", &GITHUB_CONNECTOR, &github())
            .unwrap();
        assert_eq!(resolved["token"].expose(), "value");
        assert_eq!(format!("{resolved:?}"), r#"{"token": Secret(..)}"#);

        let elsewhere = [Destination::parse("https://evil.example").unwrap()];
        for (handle, namespace, destinations, refusal) in [
            ("other", "ops", &github()[..], Unresolved::UnknownHandle),
            (
                "ops/github-bot",
                "sales",
                &github()[..],
                Unresolved::Namespace,
            ),
            (
                "ops/github-bot",
                "ops",
                &elsewhere[..],
                Unresolved::Destination,
            ),
        ] {
            assert_eq!(
                bindings.resolve(handle, namespace, &GITHUB_CONNECTOR, destinations),
                Err(refusal)
            );
        }
    }

    #[test]
    fn a_missing_value_is_unresolved() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        let bindings = bindings(&token);
        assert_eq!(
            bindings.resolve("ops/github-bot", "ops", &GITHUB_CONNECTOR, &github()),
            Err(Unresolved::Slot("token"))
        );
        std::fs::write(&token, "").unwrap();
        assert_eq!(
            bindings.resolve("ops/github-bot", "ops", &GITHUB_CONNECTOR, &github()),
            Err(Unresolved::Slot("token"))
        );
        assert_eq!(
            bindings.resolve("", "ops", &GITHUB_CONNECTOR, &github()),
            Err(Unresolved::Slot("token"))
        );
        let required = RELATIONAL_CONNECTOR
            .credential_slots
            .iter()
            .any(|slot| slot.required);
        assert_eq!(
            bindings
                .resolve("", "ops", &RELATIONAL_CONNECTOR, &[])
                .is_ok(),
            !required
        );
    }

    #[test]
    fn a_binding_refuses_unknown_fields() {
        let parsed: Result<CredentialBindings, _> = serde_json::from_value(serde_json::json!({
            "h": { "namespaces": [], "destinations": [], "slots": {}, "value": "x" }
        }));
        assert!(parsed.is_err());
    }
}
