//! Credential handles, bound in the runtime (ADR 0148, decision 4; ADR 0175).
//!
//! The operator issues each handle in the runtime's configuration and binds
//! it to the namespaces and destinations it may serve, or issues a plane-held
//! handle sealed to the fleet key. A Source names a handle; the plane never
//! holds the value. The runtime refuses a handle for a namespace or
//! destination outside its binding, so a namespace administrator can name a
//! handle but cannot point it elsewhere.
//!
//! Static values are read when a claim runs, from the environment or a file,
//! so a rotated value needs no restart. Plane-held slots are opened with the
//! fleet private key from the claim's sealed bytes. A name present in both
//! the static map and on the plane is ambiguous. Every refusal is
//! `unavailable`: the Source fails that run visibly and waits for its next
//! interval.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crypto_box::{PublicKey, SecretKey};
use sekai_client::protocol::sekai::CredentialHandleMaterial;
use sekai_source_sdk::{ConnectorType, Destination, EgressAllowlist};
use serde::Deserialize;

/// Where one credential slot's value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlotSource {
    /// An environment variable of the runtime process.
    Env(String),
    /// A file, such as a mounted secret; one trailing newline is dropped.
    File(PathBuf),
    /// Bytes sealed to a registered fleet public key. Never deserialized
    /// from static configuration.
    Sealed { key_id: String, ciphertext: Vec<u8> },
}

impl<'de> Deserialize<'de> for SlotSource {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Env(String),
            File(PathBuf),
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::Env(name) => Self::Env(name),
            Wire::File(path) => Self::File(path),
        })
    }
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
    /// The name is in both the static configuration and on the plane.
    Ambiguous,
}

/// The X25519 private half every runtime in the fleet holds.
#[derive(Clone)]
pub struct FleetKey {
    id: String,
    secret: SecretKey,
}

impl FleetKey {
    /// A new key for tests and `sekaictl` generation.
    pub fn generate(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            secret: SecretKey::generate(&mut crypto_box::aead::OsRng),
        }
    }

    /// Decode a 32-byte secret from lowercase or uppercase hex.
    pub fn from_hex(id: impl Into<String>, hex: &str) -> Result<Self, String> {
        let bytes = decode_hex(hex.trim())?;
        Self::from_bytes(id, &bytes)
    }

    /// Decode a 32-byte secret from a file of hex, one trailing newline dropped.
    pub fn from_file(id: impl Into<String>, path: &std::path::Path) -> Result<Self, String> {
        let mut text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
        if text.ends_with('\n') {
            text.pop();
        }
        Self::from_hex(id, &text)
    }

    pub fn from_bytes(id: impl Into<String>, bytes: &[u8]) -> Result<Self, String> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "fleet key must be 32 bytes".to_string())?;
        Ok(Self {
            id: id.into(),
            secret: SecretKey::from(bytes),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.secret.public_key().as_bytes()
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Seal `plaintext` to this key's public half.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        seal_to(&self.public_bytes(), plaintext)
    }

    fn unseal(&self, key_id: &str, ciphertext: &[u8]) -> Option<Secret> {
        if key_id != self.id {
            return None;
        }
        let bytes = self.secret.unseal(ciphertext).ok()?;
        let value = String::from_utf8(bytes).ok()?;
        (!value.is_empty()).then_some(Secret(value))
    }
}

/// Seal `plaintext` to an X25519 public key.
pub fn seal_to(public: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    PublicKey::from(*public)
        .seal(&mut crypto_box::aead::OsRng, plaintext)
        .map_err(|_| "failed to seal credential slot".to_string())
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("fleet key hex must have even length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "fleet key is not hex".into()))
        .collect()
}

impl CredentialBindings {
    pub fn new(bindings: BTreeMap<String, CredentialBinding>) -> Self {
        Self(bindings)
    }

    /// The values of `handle` for a Source of `connector` in `namespace`
    /// that connects to `destinations`. An empty handle resolves to no
    /// values when the type has no required slot. Static configuration only.
    pub fn resolve(
        &self,
        handle: &str,
        namespace: &str,
        connector: &ConnectorType,
        destinations: &[Destination],
    ) -> Result<Credentials, Unresolved> {
        self.resolve_claim(handle, namespace, connector, destinations, None, None)
    }

    /// Resolve a claim: static configuration, plane material, or both.
    /// A name in both places is [`Unresolved::Ambiguous`].
    pub fn resolve_claim(
        &self,
        handle: &str,
        namespace: &str,
        connector: &ConnectorType,
        destinations: &[Destination],
        plane: Option<&CredentialHandleMaterial>,
        fleet: Option<&FleetKey>,
    ) -> Result<Credentials, Unresolved> {
        if handle.is_empty() {
            return match connector.credential_slots.iter().find(|slot| slot.required) {
                Some(slot) => Err(Unresolved::Slot(slot.name)),
                None => Ok(Credentials::new()),
            };
        }
        let static_binding = self.0.get(handle);
        if static_binding.is_some() && plane.is_some() {
            return Err(Unresolved::Ambiguous);
        }
        let owned;
        let binding = match (static_binding, plane) {
            (Some(binding), None) => binding,
            (None, Some(material)) => {
                if material.revoked {
                    return Err(Unresolved::UnknownHandle);
                }
                owned = binding_from_plane(material);
                &owned
            }
            (None, None) => return Err(Unresolved::UnknownHandle),
            (Some(_), Some(_)) => unreachable!("ambiguous already returned"),
        };
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
            match binding
                .slots
                .get(slot.name)
                .and_then(|source| read_slot(source, fleet))
            {
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

fn binding_from_plane(material: &CredentialHandleMaterial) -> CredentialBinding {
    CredentialBinding {
        namespaces: material.namespaces.iter().cloned().collect(),
        destinations: material.destinations.clone(),
        slots: material
            .slots
            .iter()
            .map(|slot| {
                (
                    slot.name.clone(),
                    SlotSource::Sealed {
                        key_id: slot.fleet_key_id.clone(),
                        ciphertext: slot.ciphertext.clone(),
                    },
                )
            })
            .collect(),
    }
}

fn read_slot(source: &SlotSource, fleet: Option<&FleetKey>) -> Option<Secret> {
    match source {
        SlotSource::Env(name) => {
            let value = std::env::var(name).ok()?;
            (!value.is_empty()).then_some(Secret(value))
        }
        SlotSource::File(path) => {
            let mut text = std::fs::read_to_string(path).ok()?;
            if text.ends_with('\n') {
                text.pop();
            }
            (!text.is_empty()).then_some(Secret(text))
        }
        SlotSource::Sealed { key_id, ciphertext } => {
            fleet.and_then(|key| key.unseal(key_id, ciphertext))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_client::protocol::sekai::{CredentialHandleMaterial, SealedCredentialSlot};
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

    #[test]
    fn a_sealed_slot_opens_with_the_fleet_key() {
        let fleet = FleetKey::generate("fleet-1");
        let ciphertext = fleet.seal(b"plane-token").unwrap();
        let plane = CredentialHandleMaterial {
            name: "ops/github-bot".into(),
            namespaces: vec!["ops".into()],
            destinations: vec!["api.github.com:443".into()],
            slots: vec![SealedCredentialSlot {
                name: "token".into(),
                fleet_key_id: "fleet-1".into(),
                ciphertext,
            }],
            revoked: false,
        };
        let resolved = CredentialBindings::default()
            .resolve_claim(
                "ops/github-bot",
                "ops",
                &GITHUB_CONNECTOR,
                &github(),
                Some(&plane),
                Some(&fleet),
            )
            .unwrap();
        assert_eq!(resolved["token"].expose(), "plane-token");
        assert_eq!(
            CredentialBindings::default().resolve_claim(
                "ops/github-bot",
                "ops",
                &GITHUB_CONNECTOR,
                &github(),
                Some(&plane),
                None,
            ),
            Err(Unresolved::Slot("token"))
        );
    }

    #[test]
    fn a_name_in_both_places_is_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "value").unwrap();
        let fleet = FleetKey::generate("fleet-1");
        let plane = CredentialHandleMaterial {
            name: "ops/github-bot".into(),
            namespaces: vec!["ops".into()],
            destinations: vec!["api.github.com:443".into()],
            slots: vec![SealedCredentialSlot {
                name: "token".into(),
                fleet_key_id: "fleet-1".into(),
                ciphertext: fleet.seal(b"plane").unwrap(),
            }],
            revoked: false,
        };
        assert_eq!(
            bindings(&token).resolve_claim(
                "ops/github-bot",
                "ops",
                &GITHUB_CONNECTOR,
                &github(),
                Some(&plane),
                Some(&fleet),
            ),
            Err(Unresolved::Ambiguous)
        );
        let mut revoked = plane;
        revoked.revoked = true;
        revoked.slots.clear();
        assert_eq!(
            bindings(&token).resolve_claim(
                "ops/github-bot",
                "ops",
                &GITHUB_CONNECTOR,
                &github(),
                Some(&revoked),
                Some(&fleet),
            ),
            Err(Unresolved::Ambiguous)
        );
    }

    #[test]
    fn a_revoked_plane_handle_is_unknown() {
        let plane = CredentialHandleMaterial {
            name: "ops/github-bot".into(),
            namespaces: vec!["ops".into()],
            destinations: vec!["api.github.com:443".into()],
            slots: vec![],
            revoked: true,
        };
        assert_eq!(
            CredentialBindings::default().resolve_claim(
                "ops/github-bot",
                "ops",
                &GITHUB_CONNECTOR,
                &github(),
                Some(&plane),
                None,
            ),
            Err(Unresolved::UnknownHandle)
        );
    }

    #[test]
    fn a_replaced_runtime_opens_with_the_same_fleet_key() {
        let original = FleetKey::generate("fleet-1");
        let ciphertext = original.seal(b"survives").unwrap();
        let replacement =
            FleetKey::from_bytes("fleet-1", original.secret.to_bytes().as_ref()).unwrap();
        let plane = CredentialHandleMaterial {
            name: "ops/github-bot".into(),
            namespaces: vec!["ops".into()],
            destinations: vec!["api.github.com:443".into()],
            slots: vec![SealedCredentialSlot {
                name: "token".into(),
                fleet_key_id: "fleet-1".into(),
                ciphertext,
            }],
            revoked: false,
        };
        let resolved = CredentialBindings::default()
            .resolve_claim(
                "ops/github-bot",
                "ops",
                &GITHUB_CONNECTOR,
                &github(),
                Some(&plane),
                Some(&replacement),
            )
            .unwrap();
        assert_eq!(resolved["token"].expose(), "survives");
    }
}
