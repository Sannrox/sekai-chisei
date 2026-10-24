//! Backend-neutral policy-attestation persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::attestation::{AttestationVerification, PolicyAttestation};
use crate::sekai::audit::Decision;

pub trait AttestationBackend: Send + Sync {
    fn record_decision_with_attestation(
        &self,
        decision: &Decision,
        attestation: Option<&PolicyAttestation>,
    ) -> Result<(), String>;
    fn get_attestation(&self, id: &str) -> Result<Option<PolicyAttestation>, String>;
    fn list_attestations(
        &self,
        decision_id: Option<&str>,
        policy_scope: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<PolicyAttestation>, String>;
    fn verify_attestation(&self, id: &str) -> Result<AttestationVerification, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn record_decision_with_attestation(
            &self,
            decision: &Decision,
            attestation: Option<&PolicyAttestation>,
        ) -> Result<(), String> {
            <$target>::record_decision_with_attestation(self, decision, attestation)
        }
        fn get_attestation(&self, id: &str) -> Result<Option<PolicyAttestation>, String> {
            <$target>::get_attestation(self, id)
        }
        fn list_attestations(
            &self,
            decision: Option<&str>,
            scope: Option<&str>,
            limit: i32,
            offset: i32,
        ) -> Result<Vec<PolicyAttestation>, String> {
            <$target>::list_attestations(self, decision, scope, limit, offset)
        }
        fn verify_attestation(&self, id: &str) -> Result<AttestationVerification, String> {
            <$target>::verify_attestation(self, id)
        }
    };
}

impl AttestationBackend for SekaiDb {
    forward!(SekaiDb);
}
impl AttestationBackend for PostgresDb {
    forward!(PostgresDb);
}
