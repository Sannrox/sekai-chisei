#[cfg(test)]
pub use sekai_chisei::enterprise::*;

#[cfg(not(test))]
pub const IDENTITY_EXTENSION_VERSION: &str = "sekai.identity-extension/v1";

#[cfg(not(test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub subject: String,
    pub credential_id: String,
}

#[cfg(not(test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedContext {
    pub contract_version: &'static str,
    pub principal: AuthenticatedPrincipal,
}

#[cfg(not(test))]
impl AuthenticatedContext {
    pub fn machine(principal: AuthenticatedPrincipal) -> Self {
        Self {
            contract_version: IDENTITY_EXTENSION_VERSION,
            principal,
        }
    }
}
