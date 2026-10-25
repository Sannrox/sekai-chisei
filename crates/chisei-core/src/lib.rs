//! Chisei policy, budget, routing, evaluation, pipeline, and persistence.
//!
//! This crate sits above `sekai-core` (ADR 0096: Chisei depends on Sekai code)
//! and below composition, gRPC, and CLIs. The root crate re-exports `chisei`
//! and `chisei_store` until a follow-up removes those aliases.

pub mod chisei;
pub mod chisei_store;
pub mod config;
pub mod ext;
pub mod identity_assertion;
pub mod sekai_principal;

pub use chisei_store::ChiseiRuntimeDb;
pub use sekai_core::{db, domain, enterprise, sekai, shomei};

/// Build a tenant-bound context for enterprise resolver tests.
#[cfg(test)]
pub fn tenant_context(
    tenant_id: &str,
    subject: &str,
) -> sekai_core::enterprise::AuthenticatedContext {
    use sekai_core::enterprise::{AuthenticatedContext, AuthenticatedPrincipal, TenantContext};
    let mut ctx = AuthenticatedContext::machine(AuthenticatedPrincipal {
        subject: subject.into(),
        credential_id: format!("tenant-cred:{tenant_id}:{subject}"),
    });
    ctx.tenant = Some(TenantContext {
        tenant_id: tenant_id.into(),
        subject: subject.into(),
    });
    ctx.issuer = "https://issuer.test".into();
    ctx.resource = "https://sekai.test".into();
    ctx
}
