//! Audience-bound identity assertions that fill `AuthenticatedContext` (#888 / ADR 0078).
//!
//! A configured authority signs a short-lived assertion whose claims are the
//! fields already on `AuthenticatedContext`, plus a one-use nonce. No authority
//! configured remains community, tenant-free behavior. Caller-selected tenant
//! headers never construct or widen context.
//!
//! An assertion may bind a device (#1697 / ADR 0126): the optional `device`
//! claim names the device and its Ed25519 key. A protected RPC then requires
//! a per-request proof, the device's signature over the assertion's nonce
//! and the request digest ([`verify_device_proof`]). The assertion is one-use,
//! so the proof needs no nonce store of its own.

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap};
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
    key: Vec<u8>,
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
            key: key.into(),
            clock_skew_secs: DEFAULT_SKEW_SECS,
            allowed_scopes: BTreeSet::from([
                "sekai.discover".into(),
                "sekai.read".into(),
                "sekai.write".into(),
            ]),
            replayed: Arc::new(Mutex::new(ReplayCache::default())),
        }
    }

    pub fn sign(&self, assertion: &IdentityAssertion) -> Result<String, String> {
        let payload = serde_json::to_vec(assertion).map_err(|error| error.to_string())?;
        self.seal(ASSERTION_TOKEN_PREFIX, &payload)
    }

    /// HMAC-seal `payload` as `<prefix><payload>.<signature>`. The prefix
    /// keeps token families apart; each family also pins its own version.
    pub fn seal(&self, prefix: &str, payload: &[u8]) -> Result<String, String> {
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|error| error.to_string())?;
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
        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|_| AssertionReject::Signature)?;
        mac.update(&payload);
        mac.verify_slice(&signature)
            .map_err(|_| AssertionReject::Signature)?;
        Ok(payload)
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
        let payload = self.open(ASSERTION_TOKEN_PREFIX, token)?;
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
    token.starts_with(ASSERTION_TOKEN_PREFIX)
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
}
