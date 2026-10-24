//! Tenant-free principal credential persistence shared by runtime backends.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::{PrincipalCredential, SekaiDb};

pub trait CredentialBackend: Send + Sync {
    fn get_principal_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<PrincipalCredential>, String>;
    fn create_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
        now: i64,
    ) -> Result<PrincipalCredential, String>;
    fn rotate_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
    ) -> Result<PrincipalCredential, String>;
    fn revoke_principal_credential(
        &self,
        principal: &str,
    ) -> Result<Option<PrincipalCredential>, String>;
    fn list_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn get_principal_credential(
            &self,
            token_hash: &str,
        ) -> Result<Option<PrincipalCredential>, String> {
            <$target>::get_principal_credential(self, token_hash)
        }
        fn create_principal_credential(
            &self,
            principal: &str,
            token_hash: &str,
            now: i64,
        ) -> Result<PrincipalCredential, String> {
            <$target>::create_principal_credential(self, principal, token_hash, now)
        }
        fn rotate_principal_credential(
            &self,
            principal: &str,
            token_hash: &str,
        ) -> Result<PrincipalCredential, String> {
            <$target>::rotate_principal_credential(self, principal, token_hash)
        }
        fn revoke_principal_credential(
            &self,
            principal: &str,
        ) -> Result<Option<PrincipalCredential>, String> {
            <$target>::revoke_principal_credential(self, principal)
        }
        fn list_credentials(
            &self,
            principal: Option<&str>,
            status: Option<&str>,
        ) -> Result<Vec<PrincipalCredential>, String> {
            <$target>::list_credentials(self, principal, status)
        }
    };
}

impl CredentialBackend for SekaiDb {
    forward!(SekaiDb);
}

impl CredentialBackend for PostgresDb {
    forward!(PostgresDb);
}
