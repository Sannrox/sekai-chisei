//! Audience-bound identity assertions that fill `AuthenticatedContext` (#888 / ADR 0078).
//!
//! A configured authority signs a short-lived assertion whose claims are the
//! fields already on `AuthenticatedContext`, plus a one-use nonce. No authority
//! configured remains community, tenant-free behavior. Caller-selected tenant
//! headers never construct or widen context.

use std::collections::{BTreeSet, HashSet};
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, CredentialKind, IDENTITY_EXTENSION_VERSION,
    TenantContext,
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
    pub scopes: Vec<String>,
    pub expires_at: i64,
    pub nonce: String,
}

#[derive(Debug)]
pub struct AssertionAuthority {
    pub issuer: String,
    pub audience: String,
    key: Vec<u8>,
    pub clock_skew_secs: i64,
    pub allowed_scopes: BTreeSet<String>,
    replayed: Mutex<HashSet<String>>,
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
            allowed_scopes: BTreeSet::from(["sekai.read".into(), "sekai.write".into()]),
            replayed: Mutex::new(HashSet::new()),
        }
    }

    pub fn sign(&self, assertion: &IdentityAssertion) -> Result<String, String> {
        let payload = serde_json::to_vec(assertion).map_err(|error| error.to_string())?;
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|error| error.to_string())?;
        mac.update(&payload);
        let sig = mac.finalize().into_bytes();
        Ok(format!(
            "{ASSERTION_TOKEN_PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(sig)
        ))
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
        let rest = token
            .strip_prefix(ASSERTION_TOKEN_PREFIX)
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
        if assertion.expires_at + self.clock_skew_secs < now {
            return Err(AssertionReject::Expiry);
        }
        if assertion.nonce.is_empty() {
            return Err(AssertionReject::Replay);
        }
        {
            let mut seen = self.replayed.lock().expect("assertion replay lock");
            if !seen.insert(assertion.nonce.clone()) {
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
        Ok(AuthenticatedContext {
            contract_version: IDENTITY_EXTENSION_VERSION,
            principal: AuthenticatedPrincipal {
                subject: assertion.subject,
                credential_id: assertion.credential_id,
            },
            credential_kind,
            tenant: assertion
                .tenant_id
                .map(|tenant_id| TenantContext { tenant_id, subject }),
            scopes: assertion.scopes,
            issuer: assertion.issuer,
            resource: assertion.audience,
            expires_at: assertion.expires_at,
        })
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
            tenant_id: Some("tenant-test".into()),
            scopes: vec!["sekai.read".into(), "sekai.write".into()],
            expires_at,
            nonce: nonce.into(),
        }
    }

    #[test]
    fn valid_assertion_fills_authenticated_context() {
        let authority = authority();
        let token = authority.sign(&claims("n1", 100)).unwrap();
        let context = authority.verify(&token, 50, None).unwrap();
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
}
