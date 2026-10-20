//! Audience-bound identity assertions that fill `AuthenticatedContext` (#888 / ADR 0078).
//!
//! A configured authority signs a short-lived assertion whose claims are the
//! fields already on `AuthenticatedContext`, plus a one-use nonce. No authority
//! configured remains community, tenant-free behavior. Caller-selected tenant
//! headers never construct or widen context.

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, CredentialKind, IDENTITY_EXTENSION_VERSION,
    SpaceRole, TenantContext,
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
    pub(crate) fn seal(&self, prefix: &str, payload: &[u8]) -> Result<String, String> {
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
    pub(crate) fn open(&self, prefix: &str, token: &str) -> Result<Vec<u8>, AssertionReject> {
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
        };
        context
            .authorize_space(crate::enterprise::NamespaceAction::Discover)
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
                .authorize_space(crate::enterprise::NamespaceAction::Discover)
                .is_ok()
        );
        assert!(
            context
                .authorize_space(crate::enterprise::NamespaceAction::Read)
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
