//! Audience-bound identity assertions that fill `AuthenticatedContext` (#888 / ADR 0078).
//!
//! A configured authority signs a short-lived assertion whose claims are the
//! fields already on `AuthenticatedContext`, plus a one-use nonce. No authority
//! configured remains community, tenant-free behavior. Caller-selected tenant
//! headers never construct or widen context.
//!
//! The authority signs either with the shared HMAC key (`sia1.`) or with an
//! Ed25519 private key only it holds (`sia2.`, #2133). The plane verifies
//! `sia2.` with configured public keys by key id, so it holds nothing that
//! signs assertions, and keys rotate by adding the next kid, switching the
//! signer, then removing the old kid. HMAC acceptance can be switched off.
//!
//! An assertion may bind a device (#1697 / ADR 0126): the optional `device`
//! claim names the device and its Ed25519 key. A protected RPC then requires
//! a per-request proof, the device's signature over the assertion's nonce
//! and the request digest ([`verify_device_proof`]). The assertion is one-use,
//! so the proof needs no nonce store of its own.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use sekai_core::enterprise::{
    AuthenticatedContext, AuthenticatedDevice, AuthenticatedPrincipal, CredentialKind,
    IDENTITY_EXTENSION_VERSION, SpaceRole, TenantContext,
};

pub const IDENTITY_ASSERTION_VERSION: &str = "sekai.identity-assertion/v1";
pub const ASSERTION_TOKEN_PREFIX: &str = "sia1.";
/// Prefix of an Ed25519-signed assertion: `sia2.<kid>.<payload>.<signature>`.
/// `payload` is the same claims JSON as `sia1.`; `signature` is the Ed25519
/// signature over the ASCII bytes `sia2.<kid>.<payload>`. Payload and
/// signature are base64url without padding.
pub const ED25519_ASSERTION_TOKEN_PREFIX: &str = "sia2.";
/// Signature schemes this build verifies identity assertions with. An
/// authority switches to `ed25519` only against a plane that lists it.
pub const IDENTITY_ASSERTION_SIGNATURES: &[&str] = &["hmac-sha256", "ed25519"];
const MAX_KID_LEN: usize = 64;
const DEFAULT_SKEW_SECS: i64 = 60;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionReject {
    Issuer,
    Audience,
    Signature,
    Expiry,
    Replay,
    ScopeEscalation,
    CallerTenantHeader,
    /// A device claim without a usable id or Ed25519 key.
    Device,
}

impl AssertionReject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Signature => "signature",
            Self::Expiry => "expiry",
            Self::Replay => "replay",
            Self::ScopeEscalation => "scope_escalation",
            Self::CallerTenantHeader => "caller_tenant_header",
            Self::Device => "device",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAssertion {
    pub contract_version: String,
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub credential_id: String,
    pub credential_kind: String,
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_role: Option<SpaceRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: i64,
    pub nonce: String,
    /// The device this assertion is bound to. Absent, the assertion
    /// authenticates exactly as before the claim existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceClaim>,
}

/// The device claim of an assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceClaim {
    pub id: String,
    /// The device's Ed25519 public key, base64url without padding.
    pub ed25519_pub: String,
    /// The issuer revoked the device and asks it to wipe (#1634): the
    /// assertion is then good only for learning that, on sync.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub wipe: bool,
}

impl DeviceClaim {
    fn public_key(&self) -> Result<[u8; 32], AssertionReject> {
        if self.id.is_empty() || self.id.len() > 256 {
            return Err(AssertionReject::Device);
        }
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&self.ed25519_pub)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(AssertionReject::Device)?;
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| AssertionReject::Device)?;
        Ok(bytes)
    }
}

/// What a device signs for one request.
pub const DEVICE_PROOF_VERSION: &str = "sekai.device-proof/v1";

/// Why a device proof was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceProofReject {
    /// The RPC requires a device-bound assertion and this one binds none.
    Unbound,
    /// The assertion binds a device and the request carries no proof.
    Missing,
    /// The proof is not the bound device's signature over this request.
    Invalid,
}

impl DeviceProofReject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unbound => "device_unbound",
            Self::Missing => "device_proof_missing",
            Self::Invalid => "device_proof_invalid",
        }
    }
}

/// The digest of one request: SHA-256 over the length-prefixed method path
/// and the encoded request message, as `sha256:<hex>`.
pub fn request_digest(method: &str, message: &[u8]) -> String {
    use sha2::Digest as _;
    let mut hasher = Sha256::new();
    for part in [method.as_bytes(), message] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// The bytes a device signs: the proof version, the assertion's nonce and
/// the request digest, one per line.
pub fn device_proof_input(assertion_nonce: &str, request_digest: &str) -> Vec<u8> {
    format!("{DEVICE_PROOF_VERSION}\n{assertion_nonce}\n{request_digest}").into_bytes()
}

/// The device-proof check a protected RPC runs. A device-bound context
/// needs `proof`, base64url without padding of the bound device's Ed25519
/// signature over [`device_proof_input`] for `request_digest`. An unbound
/// context passes unless `device_required`.
pub fn verify_device_proof(
    context: &AuthenticatedContext,
    request_digest: &str,
    proof: Option<&str>,
    device_required: bool,
) -> Result<(), DeviceProofReject> {
    let Some(device) = &context.device else {
        return if device_required {
            Err(DeviceProofReject::Unbound)
        } else {
            Ok(())
        };
    };
    let proof = proof.ok_or(DeviceProofReject::Missing)?;
    let signature = URL_SAFE_NO_PAD
        .decode(proof)
        .ok()
        .and_then(|bytes| ed25519_dalek::Signature::from_slice(&bytes).ok())
        .ok_or(DeviceProofReject::Invalid)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&device.public_key)
        .map_err(|_| DeviceProofReject::Invalid)?;
    key.verify_strict(
        &device_proof_input(&device.assertion_nonce, request_digest),
        &signature,
    )
    .map_err(|_| DeviceProofReject::Invalid)
}

#[derive(Debug, Clone)]
pub struct AssertionAuthority {
    pub issuer: String,
    pub audience: String,
    /// HMAC key for `sia1.` assertions and the plane's own runtime and
    /// service tokens. `None` on an Ed25519-only verifier.
    key: Option<Vec<u8>>,
    accept_hmac_assertions: bool,
    ed25519_keys: AssertionVerifyingKeys,
    pub clock_skew_secs: i64,
    pub allowed_scopes: BTreeSet<String>,
    replayed: Arc<Mutex<ReplayCache>>,
}

/// Nonces of accepted assertions, each kept only while its assertion could
/// still be accepted, so memory is bounded by the live-assertion window
/// rather than by total traffic.
#[derive(Debug, Default)]
struct ReplayCache {
    retain_until: HashMap<String, i64>,
    expiry_order: BinaryHeap<Reverse<(i64, String)>>,
}

impl ReplayCache {
    /// Record `nonce` until `retain_until`; false if it is already held.
    /// Entries are pruned one skew window late, so a small backwards step of
    /// the caller's clock cannot re-admit a nonce that is still acceptable.
    fn insert(&mut self, nonce: &str, retain_until: i64, now: i64, skew: i64) -> bool {
        while let Some(Reverse((until, _))) = self.expiry_order.peek() {
            if until.saturating_add(skew) >= now {
                break;
            }
            let Some(Reverse((_, expired))) = self.expiry_order.pop() else {
                break;
            };
            self.retain_until.remove(&expired);
        }
        if self.retain_until.contains_key(nonce) {
            return false;
        }
        self.retain_until.insert(nonce.to_owned(), retain_until);
        self.expiry_order
            .push(Reverse((retain_until, nonce.to_owned())));
        true
    }
}

impl AssertionAuthority {
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            key: Some(key.into()),
            accept_hmac_assertions: true,
            ed25519_keys: AssertionVerifyingKeys::default(),
            clock_skew_secs: DEFAULT_SKEW_SECS,
            allowed_scopes: BTreeSet::from([
                "sekai.discover".into(),
                "sekai.read".into(),
                "sekai.write".into(),
            ]),
            replayed: Arc::new(Mutex::new(ReplayCache::default())),
        }
    }

    /// A verifier of Ed25519 assertions only. It holds no HMAC key, so it
    /// accepts no `sia1.` assertion and cannot seal runtime or service tokens.
    pub fn ed25519_only(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        keys: AssertionVerifyingKeys,
    ) -> Self {
        Self {
            key: None,
            accept_hmac_assertions: false,
            ..Self::new(issuer, audience, Vec::new()).with_ed25519_keys(keys)
        }
    }

    /// Also verify `sia2.` assertions signed by `keys`.
    pub fn with_ed25519_keys(mut self, keys: AssertionVerifyingKeys) -> Self {
        self.ed25519_keys = keys;
        self
    }

    /// Refuse `sia1.` assertions. The HMAC key still seals and opens the
    /// plane's own runtime and service tokens.
    pub fn without_hmac_assertions(mut self) -> Self {
        self.accept_hmac_assertions = false;
        self
    }

    /// Whether this authority holds the HMAC key that seals runtime and
    /// service tokens. An Ed25519-only verifier does not.
    pub fn can_seal(&self) -> bool {
        self.key.is_some()
    }

    /// HMAC-sign `assertion` as a `sia1.` token.
    pub fn sign(&self, assertion: &IdentityAssertion) -> Result<String, String> {
        let payload = serde_json::to_vec(assertion).map_err(|error| error.to_string())?;
        self.seal(ASSERTION_TOKEN_PREFIX, &payload)
    }

    /// HMAC-seal `payload` as `<prefix><payload>.<signature>`. The prefix
    /// keeps token families apart; each family also pins its own version.
    pub fn seal(&self, prefix: &str, payload: &[u8]) -> Result<String, String> {
        let key = self
            .key
            .as_deref()
            .ok_or("sealing needs SEKAI_ASSERTION_HMAC_KEY")?;
        let mut mac = HmacSha256::new_from_slice(key).map_err(|error| error.to_string())?;
        mac.update(payload);
        let sig = mac.finalize().into_bytes();
        Ok(format!(
            "{prefix}{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(sig)
        ))
    }

    /// Check a token sealed by [`Self::seal`] under `prefix` and return its payload.
    pub fn open(&self, prefix: &str, token: &str) -> Result<Vec<u8>, AssertionReject> {
        let rest = token
            .strip_prefix(prefix)
            .ok_or(AssertionReject::Signature)?;
        let (payload_b64, sig_b64) = rest.split_once('.').ok_or(AssertionReject::Signature)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| AssertionReject::Signature)?;
        let signature = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| AssertionReject::Signature)?;
        let key = self.key.as_deref().ok_or(AssertionReject::Signature)?;
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| AssertionReject::Signature)?;
        mac.update(&payload);
        mac.verify_slice(&signature)
            .map_err(|_| AssertionReject::Signature)?;
        Ok(payload)
    }

    /// Check a `sia2.` token against the configured key named by its kid
    /// and return its payload. An unknown or removed kid is a bad signature.
    fn open_ed25519(&self, token: &str) -> Result<Vec<u8>, AssertionReject> {
        let (signed, sig_b64) = token.rsplit_once('.').ok_or(AssertionReject::Signature)?;
        let (kid, payload_b64) = signed
            .strip_prefix(ED25519_ASSERTION_TOKEN_PREFIX)
            .and_then(|rest| rest.split_once('.'))
            .ok_or(AssertionReject::Signature)?;
        let key = self
            .ed25519_keys
            .0
            .get(kid)
            .ok_or(AssertionReject::Signature)?;
        let signature = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .ok()
            .and_then(|bytes| ed25519_dalek::Signature::from_slice(&bytes).ok())
            .ok_or(AssertionReject::Signature)?;
        key.verify_strict(signed.as_bytes(), &signature)
            .map_err(|_| AssertionReject::Signature)?;
        URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| AssertionReject::Signature)
    }

    pub fn verify(
        &self,
        token: &str,
        now: i64,
        caller_tenant_header: Option<&str>,
    ) -> Result<AuthenticatedContext, AssertionReject> {
        if caller_tenant_header.is_some() {
            return Err(AssertionReject::CallerTenantHeader);
        }
        let payload = if token.starts_with(ED25519_ASSERTION_TOKEN_PREFIX) {
            self.open_ed25519(token)?
        } else if self.accept_hmac_assertions {
            self.open(ASSERTION_TOKEN_PREFIX, token)?
        } else {
            return Err(AssertionReject::Signature);
        };
        let assertion: IdentityAssertion =
            serde_json::from_slice(&payload).map_err(|_| AssertionReject::Signature)?;
        if assertion.contract_version != IDENTITY_ASSERTION_VERSION {
            return Err(AssertionReject::Issuer);
        }
        if assertion.issuer != self.issuer {
            return Err(AssertionReject::Issuer);
        }
        if assertion.audience != self.audience {
            return Err(AssertionReject::Audience);
        }
        if assertion.expires_at.saturating_add(self.clock_skew_secs) < now {
            return Err(AssertionReject::Expiry);
        }
        if assertion.nonce.is_empty() {
            return Err(AssertionReject::Replay);
        }
        let device = assertion
            .device
            .as_ref()
            .map(|claim| {
                Ok::<_, AssertionReject>(AuthenticatedDevice {
                    id: claim.id.clone(),
                    public_key: claim.public_key()?,
                    assertion_nonce: assertion.nonce.clone(),
                    wipe: claim.wipe,
                })
            })
            .transpose()?;
        {
            let mut seen = self.replayed.lock().expect("assertion replay lock");
            let retain_until = assertion.expires_at.saturating_add(self.clock_skew_secs);
            // A negative skew must not prune earlier than expiry allows.
            let grace = self.clock_skew_secs.max(0);
            if !seen.insert(&assertion.nonce, retain_until, now, grace) {
                return Err(AssertionReject::Replay);
            }
        }
        if assertion
            .scopes
            .iter()
            .any(|scope| !self.allowed_scopes.contains(scope))
        {
            return Err(AssertionReject::ScopeEscalation);
        }
        let credential_kind = match assertion.credential_kind.as_str() {
            "human_session" => CredentialKind::HumanSession,
            "machine" => CredentialKind::Machine,
            _ => return Err(AssertionReject::Issuer),
        };
        let subject = assertion.subject.clone();
        let context = AuthenticatedContext {
            contract_version: IDENTITY_EXTENSION_VERSION,
            home_tenant: None,
            principal: AuthenticatedPrincipal {
                subject: assertion.subject,
                credential_id: assertion.credential_id,
            },
            credential_kind,
            tenant: assertion
                .tenant_id
                .map(|tenant_id| TenantContext { tenant_id, subject }),
            space: assertion.space,
            space_role: assertion.space_role,
            act: assertion.act,
            scopes: assertion.scopes,
            issuer: assertion.issuer,
            resource: assertion.audience,
            expires_at: assertion.expires_at,
            device,
        };
        context
            .authorize_space(sekai_core::enterprise::NamespaceAction::Discover)
            .map_err(|_| AssertionReject::ScopeEscalation)?;
        Ok(context)
    }
}

pub fn is_assertion_token(token: &str) -> bool {
    token.starts_with(ASSERTION_TOKEN_PREFIX) || token.starts_with(ED25519_ASSERTION_TOKEN_PREFIX)
}

/// A key id: 1 to 64 ASCII letters, digits, `-` or `_`, so it never holds
/// the `.` that separates token parts or the `=` and `,` of configuration.
fn valid_kid(kid: &str) -> bool {
    (1..=MAX_KID_LEN).contains(&kid.len())
        && kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The Ed25519 public keys a plane verifies `sia2.` assertions with, by kid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssertionVerifyingKeys(BTreeMap<String, ed25519_dalek::VerifyingKey>);

impl AssertionVerifyingKeys {
    /// Parse `SEKAI_ASSERTION_ED25519_KEYS`: comma-separated
    /// `<kid>=<public key>` entries, each key 32 bytes in base64url without
    /// padding. Refuses an empty list, a bad kid or key, and a repeated kid.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut keys = Self::default();
        for entry in spec.split(',').map(str::trim) {
            let (kid, public_key) = entry
                .split_once('=')
                .ok_or("SEKAI_ASSERTION_ED25519_KEYS entries are <kid>=<public key>")?;
            let bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(public_key.trim())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    format!("assertion key {kid}: public key must be 32 bytes of base64url")
                })?;
            keys.insert(kid.trim(), &bytes)?;
        }
        Ok(keys)
    }

    /// Trust `public_key` for assertions carrying `kid`.
    pub fn insert(&mut self, kid: &str, public_key: &[u8; 32]) -> Result<(), String> {
        if !valid_kid(kid) {
            return Err(format!(
                "assertion key id {kid:?} must be 1-{MAX_KID_LEN} letters, digits, - or _"
            ));
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .ok()
            .filter(|key| !key.is_weak())
            .ok_or_else(|| format!("assertion key {kid}: not a usable Ed25519 public key"))?;
        if self.0.insert(kid.to_owned(), key).is_some() {
            return Err(format!("assertion key id {kid} is listed twice"));
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

/// Mints `sia2.` assertions for an identity authority that holds an Ed25519
/// private key. The plane verifies them with [`Self::public_key`] listed
/// under [`Self::kid`] in `SEKAI_ASSERTION_ED25519_KEYS`.
pub struct Ed25519AssertionSigner {
    kid: String,
    key: ed25519_dalek::SigningKey,
}

impl Ed25519AssertionSigner {
    /// A signer for the 32-byte Ed25519 secret key `secret_key` under `kid`.
    pub fn new(kid: impl Into<String>, secret_key: &[u8; 32]) -> Result<Self, String> {
        let kid = kid.into();
        if !valid_kid(&kid) {
            return Err(format!(
                "assertion key id {kid:?} must be 1-{MAX_KID_LEN} letters, digits, - or _"
            ));
        }
        Ok(Self {
            kid,
            key: ed25519_dalek::SigningKey::from_bytes(secret_key),
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public key in base64url without padding, as the plane configures it.
    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.verifying_key().as_bytes())
    }

    /// Sign `assertion` as a `sia2.` token.
    pub fn sign(&self, assertion: &IdentityAssertion) -> Result<String, String> {
        use ed25519_dalek::Signer as _;
        let payload = serde_json::to_vec(assertion).map_err(|error| error.to_string())?;
        let signed = format!(
            "{ED25519_ASSERTION_TOKEN_PREFIX}{}.{}",
            self.kid,
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature = self.key.sign(signed.as_bytes());
        Ok(format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

impl std::fmt::Debug for Ed25519AssertionSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519AssertionSigner")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> AssertionAuthority {
        AssertionAuthority::new(
            "https://issuer.test",
            "https://sekai.test",
            b"test-hmac-key",
        )
    }

    fn claims(nonce: &str, expires_at: i64) -> IdentityAssertion {
        IdentityAssertion {
            contract_version: IDENTITY_ASSERTION_VERSION.into(),
            issuer: "https://issuer.test".into(),
            audience: "https://sekai.test".into(),
            subject: "subject-a".into(),
            credential_id: "credential-a".into(),
            credential_kind: "human_session".into(),
            space: None,
            space_role: None,
            act: None,
            tenant_id: Some("tenant-test".into()),
            scopes: vec!["sekai.read".into(), "sekai.write".into()],
            expires_at,
            nonce: nonce.into(),
            device: None,
        }
    }

    #[test]
    fn valid_assertion_fills_authenticated_context() {
        let authority = authority();
        let mut claims = claims(&uuid::Uuid::new_v4().to_string(), 100);
        claims.space = Some("space-a".into());
        claims.space_role = Some(SpaceRole::Approver);
        claims.act = Some("origin-user".into());
        let token = authority.sign(&claims).unwrap();
        let context = authority.verify(&token, 50, None).unwrap();
        assert_eq!(context.space.as_deref(), Some("space-a"));
        assert_eq!(context.space_role, Some(SpaceRole::Approver));
        assert_eq!(context.act.as_deref(), Some("origin-user"));
        assert_eq!(context.principal.subject, "subject-a");
        assert_eq!(context.principal.credential_id, "credential-a");
        assert_eq!(context.scopes, ["sekai.read", "sekai.write"]);
        assert_eq!(context.issuer, "https://issuer.test");
        assert_eq!(context.resource, "https://sekai.test");
        assert_eq!(
            context
                .tenant
                .as_ref()
                .map(|tenant| tenant.tenant_id.as_str()),
            Some("tenant-test")
        );
        assert_eq!(context.contract_version, IDENTITY_EXTENSION_VERSION);
    }

    #[test]
    fn discoverer_assertion_verifies_below_read() {
        let authority = authority();
        let mut claims = claims(&uuid::Uuid::new_v4().to_string(), 100);
        claims.space = Some("space-a".into());
        claims.space_role = Some(SpaceRole::Discoverer);
        claims.act = Some("origin-user".into());
        claims.scopes = vec!["sekai.discover".into()];
        let token = authority.sign(&claims).unwrap();
        let context = authority.verify(&token, 50, None).unwrap();
        assert_eq!(context.space_role, Some(SpaceRole::Discoverer));
        assert!(
            context
                .authorize_space(sekai_core::enterprise::NamespaceAction::Discover)
                .is_ok()
        );
        assert!(
            context
                .authorize_space(sekai_core::enterprise::NamespaceAction::Read)
                .is_err()
        );
    }

    #[test]
    fn each_failure_class_is_distinct() {
        let authority = authority();
        let token = authority.sign(&claims("n-ok", 100)).unwrap();
        assert_eq!(
            authority
                .verify(&token, 50, Some("tenant-evil"))
                .unwrap_err(),
            AssertionReject::CallerTenantHeader
        );
        let mut bad_iss = claims("n-iss", 100);
        bad_iss.issuer = "https://other.test".into();
        let token = authority.sign(&bad_iss).unwrap();
        assert_eq!(
            authority.verify(&token, 50, None).unwrap_err(),
            AssertionReject::Issuer
        );
        let mut bad_aud = claims("n-aud", 100);
        bad_aud.audience = "https://other.test".into();
        let token = authority.sign(&bad_aud).unwrap();
        assert_eq!(
            authority.verify(&token, 50, None).unwrap_err(),
            AssertionReject::Audience
        );
        let mut token = authority.sign(&claims("n-sig", 100)).unwrap();
        token.push('x');
        assert_eq!(
            authority.verify(&token, 50, None).unwrap_err(),
            AssertionReject::Signature
        );
        let token = authority.sign(&claims("n-exp", 10)).unwrap();
        assert_eq!(
            authority.verify(&token, 100, None).unwrap_err(),
            AssertionReject::Expiry
        );
        let token = authority.sign(&claims("n-replay", 100)).unwrap();
        authority.verify(&token, 50, None).unwrap();
        assert_eq!(
            authority.verify(&token, 50, None).unwrap_err(),
            AssertionReject::Replay
        );
        let mut escalate = claims("n-scope", 100);
        escalate.scopes = vec!["sekai.admin".into()];
        let token = authority.sign(&escalate).unwrap();
        assert_eq!(
            authority.verify(&token, 50, None).unwrap_err(),
            AssertionReject::ScopeEscalation
        );
    }

    /// A random nonce per assertion, as a real issuer mints them.
    fn fresh_nonce() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    #[test]
    fn replay_state_is_bounded_by_live_assertions() {
        let authority = authority();
        let skew = authority.clock_skew_secs;
        // A live assertion is still refused on replay.
        let live = authority.sign(&claims(&fresh_nonce(), 1_000)).unwrap();
        authority.verify(&live, 900, None).unwrap();
        assert_eq!(
            authority.verify(&live, 950, None).unwrap_err(),
            AssertionReject::Replay
        );
        // Many short-lived assertions: once expired past the skew window,
        // their nonces are no longer retained.
        for _ in 0..1_000 {
            let token = authority.sign(&claims(&fresh_nonce(), 1_000)).unwrap();
            authority.verify(&token, 900, None).unwrap();
        }
        assert_eq!(authority.replayed.lock().unwrap().retain_until.len(), 1_001);
        let later = 1_000 + 2 * skew + 1;
        let fresh = authority.sign(&claims(&fresh_nonce(), later + 60)).unwrap();
        authority.verify(&fresh, later, None).unwrap();
        assert_eq!(authority.replayed.lock().unwrap().retain_until.len(), 1);
    }

    #[test]
    fn pruning_never_drops_a_nonce_that_is_still_acceptable() {
        let authority = authority();
        let token = authority.sign(&claims(&fresh_nonce(), 1_000)).unwrap();
        authority.verify(&token, 999, None).unwrap();
        // Still within expiry plus skew: the replay is refused even after
        // another verification ran at a later clock reading.
        let other = authority.sign(&claims(&fresh_nonce(), 2_000)).unwrap();
        authority
            .verify(&other, 1_000 + authority.clock_skew_secs, None)
            .unwrap();
        assert_eq!(
            authority
                .verify(&token, 1_000 + authority.clock_skew_secs, None)
                .unwrap_err(),
            AssertionReject::Replay
        );
    }

    #[test]
    fn far_future_expiry_neither_overflows_nor_re_admits_a_replay() {
        let authority = authority();
        let token = authority
            .sign(&claims(&fresh_nonce(), i64::MAX - 1))
            .unwrap();
        authority.verify(&token, 1_000, None).unwrap();
        assert_eq!(
            authority.verify(&token, 2_000, None).unwrap_err(),
            AssertionReject::Replay
        );
    }

    fn device_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn bound(nonce: &str, key: &ed25519_dalek::SigningKey) -> IdentityAssertion {
        IdentityAssertion {
            device: Some(DeviceClaim {
                id: "device-7".into(),
                ed25519_pub: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                wipe: false,
            }),
            ..claims(nonce, 100)
        }
    }

    fn prove(key: &ed25519_dalek::SigningKey, nonce: &str, digest: &str) -> String {
        use ed25519_dalek::Signer as _;
        URL_SAFE_NO_PAD.encode(key.sign(&device_proof_input(nonce, digest)).to_bytes())
    }

    #[test]
    fn an_assertion_without_a_device_claim_authenticates_as_before() {
        let authority = authority();
        let token = authority.sign(&claims(&fresh_nonce(), 100)).unwrap();
        // The claim is omitted from the wire form, so an assertion signed by
        // an issuer that predates it is byte-for-byte the same.
        let payload = authority.open(ASSERTION_TOKEN_PREFIX, &token).unwrap();
        assert!(!String::from_utf8(payload).unwrap().contains("device"));
        let context = authority.verify(&token, 50, None).unwrap();
        assert_eq!(context.device, None);
        let digest = request_digest("/sekai.v1.Sekai/ReadSyncDeltas", b"request");
        assert_eq!(verify_device_proof(&context, &digest, None, false), Ok(()));
        assert_eq!(
            verify_device_proof(&context, &digest, None, true),
            Err(DeviceProofReject::Unbound)
        );
    }

    #[test]
    fn a_device_bound_assertion_needs_the_device_proof_for_this_request() {
        let authority = authority();
        let key = device_key(7);
        let nonce = fresh_nonce();
        let token = authority.sign(&bound(&nonce, &key)).unwrap();
        let context = authority.verify(&token, 50, None).unwrap();
        let device = context.device.as_ref().unwrap();
        assert_eq!(device.id, "device-7");
        assert_eq!(device.assertion_nonce, nonce);

        let digest = request_digest("/sekai.v1.Sekai/ReadSyncDeltas", b"request");
        let proof = prove(&key, &nonce, &digest);
        assert_eq!(
            verify_device_proof(&context, &digest, Some(&proof), true),
            Ok(())
        );
        let other_request = request_digest("/sekai.v1.Sekai/ReadSyncDeltas", b"other");
        assert_eq!(
            verify_device_proof(&context, &other_request, Some(&proof), false),
            Err(DeviceProofReject::Invalid)
        );
        let other_method = request_digest("/sekai.v1.Sekai/ReadSyncSnapshot", b"request");
        assert_eq!(
            verify_device_proof(&context, &other_method, Some(&proof), false),
            Err(DeviceProofReject::Invalid)
        );
        let stolen = prove(&device_key(8), &nonce, &digest);
        assert_eq!(
            verify_device_proof(&context, &digest, Some(&stolen), false),
            Err(DeviceProofReject::Invalid)
        );
        assert_eq!(
            verify_device_proof(&context, &digest, None, false),
            Err(DeviceProofReject::Missing)
        );
        assert_eq!(
            verify_device_proof(&context, &digest, Some("not base64!"), false),
            Err(DeviceProofReject::Invalid)
        );
        // The assertion stays one-use with the claim.
        assert_eq!(
            authority.verify(&token, 50, None).unwrap_err(),
            AssertionReject::Replay
        );
    }

    #[test]
    fn a_wipe_claim_reaches_the_context() {
        let authority = authority();
        let key = device_key(7);
        let mut assertion = bound(&fresh_nonce(), &key);
        assertion.device.as_mut().unwrap().wipe = true;
        let context = authority
            .verify(&authority.sign(&assertion).unwrap(), 50, None)
            .unwrap();
        assert!(context.device.unwrap().wipe);
        // An assertion without the flag is not a wipe, and omits it on the wire.
        let plain = authority.sign(&bound(&fresh_nonce(), &key)).unwrap();
        let payload = authority.open(ASSERTION_TOKEN_PREFIX, &plain).unwrap();
        assert!(!String::from_utf8(payload).unwrap().contains("wipe"));
    }

    #[test]
    fn a_malformed_device_claim_is_refused() {
        let authority = authority();
        let key = device_key(7);
        let mut claim = serde_json::to_value(bound(&fresh_nonce(), &key)).unwrap();
        claim["device"]["platform"] = "ios".into();
        let token = authority
            .seal(ASSERTION_TOKEN_PREFIX, &serde_json::to_vec(&claim).unwrap())
            .unwrap();
        assert_eq!(
            authority.verify(&token, 50, None).unwrap_err(),
            AssertionReject::Signature
        );
        for (id, public_key) in [
            ("", URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())),
            ("device-7", URL_SAFE_NO_PAD.encode([1u8; 31])),
            ("device-7", "%%".into()),
        ] {
            let mut assertion = bound(&fresh_nonce(), &key);
            assertion.device = Some(DeviceClaim {
                id: id.into(),
                ed25519_pub: public_key,
                wipe: false,
            });
            let token = authority.sign(&assertion).unwrap();
            assert_eq!(
                authority.verify(&token, 50, None).unwrap_err(),
                AssertionReject::Device
            );
        }
    }

    #[test]
    fn a_negative_skew_never_prunes_an_acceptable_nonce() {
        let mut authority = authority();
        authority.clock_skew_secs = -10;
        let token = authority.sign(&claims(&fresh_nonce(), 1_000)).unwrap();
        authority.verify(&token, 980, None).unwrap();
        assert_eq!(
            authority.verify(&token, 981, None).unwrap_err(),
            AssertionReject::Replay
        );
    }

    fn signer(kid: &str, seed: u8) -> Ed25519AssertionSigner {
        Ed25519AssertionSigner::new(kid, &[seed; 32]).unwrap()
    }

    fn verifying_keys(signers: &[&Ed25519AssertionSigner]) -> AssertionVerifyingKeys {
        let spec = signers
            .iter()
            .map(|signer| format!("{}={}", signer.kid(), signer.public_key()))
            .collect::<Vec<_>>()
            .join(",");
        AssertionVerifyingKeys::parse(&spec).unwrap()
    }

    fn ed25519_authority(keys: AssertionVerifyingKeys) -> AssertionAuthority {
        AssertionAuthority::ed25519_only("https://issuer.test", "https://sekai.test", keys)
    }

    #[test]
    fn active_and_next_keys_verify_and_a_removed_key_does_not() {
        let (old, active, next) = (signer("k1", 1), signer("k2", 2), signer("k3", 3));
        let authority = ed25519_authority(verifying_keys(&[&active, &next]));
        for signer in [&active, &next] {
            let token = signer.sign(&claims(&fresh_nonce(), 100)).unwrap();
            assert!(token.starts_with(&format!("sia2.{}.", signer.kid())));
            assert!(is_assertion_token(&token));
            let context = authority.verify(&token, 50, None).unwrap();
            assert_eq!(context.principal.subject, "subject-a");
            assert_eq!(context.issuer, "https://issuer.test");
            // One-use, exactly as `sia1.`.
            assert_eq!(
                authority.verify(&token, 50, None).unwrap_err(),
                AssertionReject::Replay
            );
        }
        let removed = old.sign(&claims(&fresh_nonce(), 100)).unwrap();
        assert_eq!(
            authority.verify(&removed, 50, None).unwrap_err(),
            AssertionReject::Signature
        );
    }

    #[test]
    fn a_tampered_or_relabelled_ed25519_assertion_is_refused() {
        let (active, other) = (signer("k1", 1), signer("k2", 2));
        let authority = ed25519_authority(verifying_keys(&[&active, &other]));
        let token = active.sign(&claims(&fresh_nonce(), 100)).unwrap();
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let (_, payload) = signed.rsplit_once('.').unwrap();

        let mut forged = claims(&fresh_nonce(), 100);
        forged.subject = "subject-b".into();
        let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        let mut flipped = URL_SAFE_NO_PAD.decode(signature).unwrap();
        flipped[0] ^= 1;
        for tampered in [
            format!("sia2.k1.{forged_payload}.{signature}"),
            format!("sia2.k1.{payload}.{}", URL_SAFE_NO_PAD.encode(flipped)),
            // A valid signature under another configured kid's label.
            format!("sia2.k2.{payload}.{signature}"),
            format!("sia2.k1.{payload}"),
            "sia2.".into(),
        ] {
            assert_eq!(
                authority.verify(&tampered, 50, None).unwrap_err(),
                AssertionReject::Signature,
                "{tampered}"
            );
        }
        // Claim checks still apply after the signature.
        let mut wrong_audience = claims(&fresh_nonce(), 100);
        wrong_audience.audience = "https://other.test".into();
        assert_eq!(
            authority
                .verify(&active.sign(&wrong_audience).unwrap(), 50, None)
                .unwrap_err(),
            AssertionReject::Audience
        );
    }

    #[test]
    fn hmac_assertions_verify_until_hmac_acceptance_is_off() {
        let active = signer("k1", 1);
        let authority = authority().with_ed25519_keys(verifying_keys(&[&active]));
        let hmac = authority.sign(&claims(&fresh_nonce(), 100)).unwrap();
        let ed25519 = active.sign(&claims(&fresh_nonce(), 100)).unwrap();
        authority.verify(&hmac, 50, None).unwrap();
        authority.verify(&ed25519, 50, None).unwrap();

        let authority = authority.without_hmac_assertions();
        let hmac = authority.sign(&claims(&fresh_nonce(), 100)).unwrap();
        assert_eq!(
            authority.verify(&hmac, 50, None).unwrap_err(),
            AssertionReject::Signature
        );
        let ed25519 = active.sign(&claims(&fresh_nonce(), 100)).unwrap();
        authority.verify(&ed25519, 50, None).unwrap();
        // The HMAC key keeps sealing the plane's own token families.
        assert!(authority.can_seal());
        let sealed = authority.seal("srt1.", b"{}").unwrap();
        assert_eq!(authority.open("srt1.", &sealed).unwrap(), b"{}");
    }

    #[test]
    fn an_ed25519_only_verifier_holds_no_hmac_key() {
        let active = signer("k1", 1);
        let verifier = ed25519_authority(verifying_keys(&[&active]));
        assert!(!verifier.can_seal());
        assert!(verifier.seal("srt1.", b"{}").is_err());
        let hmac = authority().sign(&claims(&fresh_nonce(), 100)).unwrap();
        assert_eq!(
            verifier.verify(&hmac, 50, None).unwrap_err(),
            AssertionReject::Signature
        );
    }

    #[test]
    fn verifying_keys_refuse_malformed_configuration() {
        let key = signer("k1", 1).public_key();
        let keys = AssertionVerifyingKeys::parse(&format!(" k1 = {key} , k-2_b={key}")).unwrap();
        assert_eq!(keys.kids().collect::<Vec<_>>(), ["k-2_b", "k1"]);
        let weak = URL_SAFE_NO_PAD.encode([0u8; 32]);
        for spec in [
            String::new(),
            key.clone(),
            format!("k1={key},k1={key}"),
            format!("={key}"),
            format!("k.1={key}"),
            format!("{}={key}", "k".repeat(MAX_KID_LEN + 1)),
            "k1=AAAA".into(),
            format!("k1={weak}"),
        ] {
            assert!(AssertionVerifyingKeys::parse(&spec).is_err(), "{spec:?}");
        }
        assert!(Ed25519AssertionSigner::new("k.1", &[1; 32]).is_err());
    }
}
