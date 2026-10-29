//! Short-lived runtime tokens for claimed Action work (#1507, ADR 0099) and
//! claimed agent turns (#2005, ADR 0142).
//!
//! A granted claim returns one token bound to the claiming principal, the
//! runtime, the tenant and namespace of the work, the effect and the claim
//! generation. A turn's token is bound to the turn instead, and acts as the
//! turn's instance principal with the claiming worker as its actor. It expires no later than the claim, and the authentication
//! boundary admits it only for the follow-up calls on that claim. It is sealed
//! with the configured identity-assertion key under its own prefix and
//! version, so it never verifies as an identity assertion or the reverse.

use serde::{Deserialize, Serialize};

use crate::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, CredentialKind, IDENTITY_EXTENSION_VERSION,
    SpaceRole, TenantContext,
};
use crate::identity_assertion::{AssertionAuthority, AssertionReject};

pub const RUNTIME_TOKEN_VERSION: &str = "sekai.runtime-token/v1";
pub const RUNTIME_TOKEN_PREFIX: &str = "srt1.";
/// Upper bound on one token's lifetime. A longer claim refreshes its token on
/// heartbeat instead of receiving one that lives as long as the claim.
pub const RUNTIME_TOKEN_MAX_LIFETIME_MS: i64 = 15 * 60 * 1_000;

/// gRPC methods an Action-work token authenticates: the calls made for its
/// claim.
pub const RUNTIME_TOKEN_METHODS: &[&str] = &[
    "HeartbeatActionClaim",
    "AckActionWork",
    "ReportActionClaimEvent",
];

/// gRPC methods a turn token authenticates: its claim's follow-up calls and
/// the Actions the turn submits as its instance principal (ADR 0142).
pub const TURN_TOKEN_METHODS: &[&str] = &[
    "HeartbeatAgentTurnClaim",
    "AckAgentTurn",
    "SubmitActionInstance",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTokenClaims {
    pub contract_version: String,
    pub issuer: String,
    pub audience: String,
    /// Principal that claimed the work; follow-up calls act as it.
    pub subject: String,
    /// Delegating actor of the claiming context, kept so it still narrows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_role: Option<SpaceRole>,
    pub tenant_id: String,
    pub namespace: String,
    /// The claimed Action effect; empty on a turn token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub effect_id: String,
    /// The claimed agent turn; empty on an Action-work token, and absent from
    /// its encoding, so those tokens verify as before (ADR 0142).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub turn_id: String,
    pub runtime_id: String,
    pub claim_generation: u64,
    pub expires_at_ms: i64,
    /// Expiry of the credential the claim was made with. Refreshed tokens
    /// keep it, so heartbeats never outlive the originating authority.
    pub authority_expires_at_ms: i64,
    /// Claimed by a registered service principal, so follow-up calls stay
    /// within its registered scope (#1511).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub service_principal: bool,
    pub jti: String,
}

/// The agent turn a turn token is minted for.
pub struct TurnBinding<'a> {
    pub namespace: &'a str,
    pub turn_id: &'a str,
    /// The instance's principal, whom the token acts as.
    pub principal: &'a str,
    pub runtime_id: &'a str,
    pub claim_generation: u64,
    pub claim_expires_at_ms: i64,
}

/// The claim a runtime token is minted for.
pub struct ClaimBinding<'a> {
    pub namespace: &'a str,
    pub effect_id: &'a str,
    pub runtime_id: &'a str,
    pub claim_generation: u64,
    pub claim_expires_at_ms: i64,
}

impl RuntimeTokenClaims {
    /// Claims for `claim` acting as `context`. `None` when the context has no
    /// tenant or is a guest: without a tenant key the token fails closed, and
    /// guest authority is decided per request rather than carried in a token.
    pub fn for_claim(
        authority: &AssertionAuthority,
        context: &AuthenticatedContext,
        claim: ClaimBinding<'_>,
        now_ms: i64,
    ) -> Option<Self> {
        let tenant = context.tenant.as_ref()?;
        if tenant.tenant_id.trim().is_empty() || context.guest_home_tenant().is_some() {
            return None;
        }
        let authority_expires_at_ms = context.expires_at.saturating_mul(1_000);
        Some(Self {
            contract_version: RUNTIME_TOKEN_VERSION.into(),
            issuer: authority.issuer.clone(),
            audience: authority.audience.clone(),
            subject: context.principal.subject.clone(),
            act: context.act.clone(),
            space: context.space.clone(),
            space_role: context.space_role,
            tenant_id: tenant.tenant_id.clone(),
            namespace: claim.namespace.into(),
            effect_id: claim.effect_id.into(),
            turn_id: String::new(),
            runtime_id: claim.runtime_id.into(),
            claim_generation: claim.claim_generation,
            expires_at_ms: claim
                .claim_expires_at_ms
                .min(now_ms.saturating_add(RUNTIME_TOKEN_MAX_LIFETIME_MS))
                .min(authority_expires_at_ms),
            authority_expires_at_ms,
            service_principal: crate::service_token::is_service_principal_context(context),
            jti: uuid::Uuid::new_v4().to_string(),
        })
    }

    /// Claims for an agent turn claimed by `context` (ADR 0142): the token
    /// acts as the turn's instance principal, with the claiming worker as its
    /// actor, under the worker's tenant. `None` where [`Self::for_claim`]
    /// would mint none.
    pub fn for_turn(
        authority: &AssertionAuthority,
        context: &AuthenticatedContext,
        turn: TurnBinding<'_>,
        now_ms: i64,
    ) -> Option<Self> {
        let mut claims = Self::for_claim(
            authority,
            context,
            ClaimBinding {
                namespace: turn.namespace,
                effect_id: "",
                runtime_id: turn.runtime_id,
                claim_generation: turn.claim_generation,
                claim_expires_at_ms: turn.claim_expires_at_ms,
            },
            now_ms,
        )?;
        if turn.principal.trim().is_empty() || turn.turn_id.trim().is_empty() {
            return None;
        }
        claims.act = Some(context.principal.subject.clone());
        claims.subject = turn.principal.into();
        claims.turn_id = turn.turn_id.into();
        // The worker's registration scopes the worker, not the principal.
        claims.service_principal = false;
        Some(claims)
    }

    /// Whether this token is bound to an agent turn rather than to Action
    /// work.
    pub fn is_turn(&self) -> bool {
        !self.turn_id.is_empty()
    }

    /// Whether this token authenticates calls to `method`.
    pub fn admits(&self, method: &str) -> bool {
        let methods = if self.is_turn() {
            TURN_TOKEN_METHODS
        } else {
            RUNTIME_TOKEN_METHODS
        };
        methods.contains(&method)
    }

    /// Whether this token covers a call on turn `turn_id` in `namespace` by
    /// `runtime_id` at `claim_generation`.
    pub fn covers_turn(
        &self,
        namespace: &str,
        turn_id: &str,
        runtime_id: &str,
        claim_generation: u64,
    ) -> bool {
        self.is_turn()
            && self.namespace == namespace
            && self.turn_id == turn_id
            && self.runtime_id == runtime_id
            && self.claim_generation == claim_generation
    }

    pub fn sign(&self, authority: &AssertionAuthority) -> Result<String, String> {
        let payload = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        authority.seal(RUNTIME_TOKEN_PREFIX, &payload)
    }

    /// Verify signature, version, issuer, audience and expiry. A token is
    /// refused at or after `expires_at_ms`; the issuer is also the verifier,
    /// so no clock tolerance applies.
    pub fn verify(
        authority: &AssertionAuthority,
        token: &str,
        now_ms: i64,
    ) -> Result<Self, AssertionReject> {
        let payload = authority.open(RUNTIME_TOKEN_PREFIX, token)?;
        let claims: Self =
            serde_json::from_slice(&payload).map_err(|_| AssertionReject::Signature)?;
        if claims.contract_version != RUNTIME_TOKEN_VERSION || claims.issuer != authority.issuer {
            return Err(AssertionReject::Issuer);
        }
        if claims.audience != authority.audience {
            return Err(AssertionReject::Audience);
        }
        if now_ms >= claims.expires_at_ms {
            return Err(AssertionReject::Expiry);
        }
        if [
            &claims.subject,
            &claims.tenant_id,
            &claims.namespace,
            &claims.runtime_id,
            &claims.jti,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(AssertionReject::ScopeEscalation);
        }
        // Bound to exactly one claim: an effect or a turn.
        if claims.effect_id.trim().is_empty() == claims.turn_id.trim().is_empty() {
            return Err(AssertionReject::ScopeEscalation);
        }
        Ok(claims)
    }

    /// Whether this token covers a call on `effect_id` in `namespace` by
    /// `runtime_id` at `claim_generation`.
    pub fn covers(
        &self,
        namespace: &str,
        effect_id: &str,
        runtime_id: &str,
        claim_generation: u64,
    ) -> bool {
        !self.is_turn()
            && self.namespace == namespace
            && self.effect_id == effect_id
            && self.runtime_id == runtime_id
            && self.claim_generation == claim_generation
    }

    /// The authenticated context follow-up calls run under: the claiming
    /// principal, narrowed to the token's tenant, space and actor.
    pub fn authenticated_context(&self) -> AuthenticatedContext {
        AuthenticatedContext {
            contract_version: IDENTITY_EXTENSION_VERSION,
            principal: AuthenticatedPrincipal {
                subject: self.subject.clone(),
                credential_id: if self.service_principal {
                    format!(
                        "{}runtime-token:{}",
                        crate::service_token::SERVICE_PRINCIPAL_CREDENTIAL_PREFIX,
                        self.jti
                    )
                } else {
                    format!("runtime-token:{}", self.jti)
                },
            },
            credential_kind: CredentialKind::Machine,
            tenant: Some(TenantContext {
                tenant_id: self.tenant_id.clone(),
                subject: self.subject.clone(),
            }),
            home_tenant: None,
            space: self.space.clone(),
            space_role: self.space_role,
            act: self.act.clone(),
            scopes: Vec::new(),
            issuer: self.issuer.clone(),
            resource: self.audience.clone(),
            expires_at: self.authority_expires_at_ms.div_euclid(1_000),
            device: None,
        }
    }
}

pub fn is_runtime_token(token: &str) -> bool {
    token.starts_with(RUNTIME_TOKEN_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> AssertionAuthority {
        AssertionAuthority::new("https://issuer.test", "https://sekai.test", b"key")
    }

    fn context(tenant: Option<&str>) -> AuthenticatedContext {
        let mut context = AuthenticatedContext::machine(AuthenticatedPrincipal {
            subject: "worker".into(),
            credential_id: "credential-w".into(),
        });
        context.tenant = tenant.map(|tenant_id| TenantContext {
            tenant_id: tenant_id.into(),
            subject: "worker".into(),
        });
        context
    }

    fn binding(claim_expires_at_ms: i64) -> ClaimBinding<'static> {
        ClaimBinding {
            namespace: "ns-a",
            effect_id: "effect-a",
            runtime_id: "runner-a",
            claim_generation: 3,
            claim_expires_at_ms,
        }
    }

    #[test]
    fn expiry_never_exceeds_claim_or_max_lifetime() {
        let authority = authority();
        let short =
            RuntimeTokenClaims::for_claim(&authority, &context(Some("t")), binding(5_000), 0)
                .unwrap();
        assert_eq!(short.expires_at_ms, 5_000);
        let long =
            RuntimeTokenClaims::for_claim(&authority, &context(Some("t")), binding(i64::MAX), 0)
                .unwrap();
        assert_eq!(long.expires_at_ms, RUNTIME_TOKEN_MAX_LIFETIME_MS);
        // Neither issue nor refresh outlives the originating credential.
        let mut expiring = context(Some("t"));
        expiring.expires_at = 2;
        let first =
            RuntimeTokenClaims::for_claim(&authority, &expiring, binding(i64::MAX), 0).unwrap();
        assert_eq!(first.expires_at_ms, 2_000);
        let refreshed = RuntimeTokenClaims::for_claim(
            &authority,
            &first.authenticated_context(),
            binding(i64::MAX),
            1_000,
        )
        .unwrap();
        assert_eq!(refreshed.expires_at_ms, 2_000);
    }

    #[test]
    fn no_token_without_tenant_or_for_guest() {
        let authority = authority();
        assert!(
            RuntimeTokenClaims::for_claim(&authority, &context(None), binding(5_000), 0).is_none()
        );
        let mut guest = context(Some("host"));
        guest.home_tenant = Some("home".into());
        assert!(RuntimeTokenClaims::for_claim(&authority, &guest, binding(5_000), 0).is_none());
    }

    #[test]
    fn verify_refuses_expiry_and_foreign_token_families() {
        let authority = authority();
        let claims =
            RuntimeTokenClaims::for_claim(&authority, &context(Some("t")), binding(5_000), 0)
                .unwrap();
        let token = claims.sign(&authority).unwrap();
        assert_eq!(
            RuntimeTokenClaims::verify(&authority, &token, 4_999).unwrap(),
            claims
        );
        assert_eq!(
            RuntimeTokenClaims::verify(&authority, &token, 5_000).unwrap_err(),
            AssertionReject::Expiry
        );
        let other_key = AssertionAuthority::new("https://issuer.test", "https://sekai.test", b"k2");
        assert_eq!(
            RuntimeTokenClaims::verify(&other_key, &token, 0).unwrap_err(),
            AssertionReject::Signature
        );
        // The identity-assertion verifier never accepts a runtime token.
        assert_eq!(
            authority.verify(&token, 0, None).unwrap_err(),
            AssertionReject::Signature
        );
    }

    #[test]
    fn covers_only_its_own_claim() {
        let claims =
            RuntimeTokenClaims::for_claim(&authority(), &context(Some("t")), binding(5_000), 0)
                .unwrap();
        assert!(claims.covers("ns-a", "effect-a", "runner-a", 3));
        assert!(!claims.covers("ns-b", "effect-a", "runner-a", 3));
        assert!(!claims.covers("ns-a", "effect-b", "runner-a", 3));
        assert!(!claims.covers("ns-a", "effect-a", "runner-b", 3));
        assert!(!claims.covers("ns-a", "effect-a", "runner-a", 4));
    }
}
