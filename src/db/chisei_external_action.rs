//! Backend-neutral external-action authorization persistence.

use crate::chisei::external_action::{
    AuthorizationClaim, AuthorizationRecord, ExternalActionRequest,
};
use crate::db::{postgres::PostgresDb, sekai::SekaiDb};

pub trait ChiseiExternalActionBackend: Send + Sync {
    fn claim_external_action_authorization(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
        authorization_id: &str,
        now_ms: i64,
    ) -> Result<AuthorizationClaim, String>;

    fn abandon_external_action_claim(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
    ) -> Result<(), String>;

    fn compare_and_swap_external_action_authorization(
        &self,
        expected: &AuthorizationRecord,
        next: &AuthorizationRecord,
    ) -> Result<bool, String>;

    fn reserve_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
        max_mutations: Option<u32>,
        max_deletes: Option<u32>,
    ) -> Result<(), String>;

    fn release_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
    ) -> Result<(), String>;

    fn get_external_action_authorization(
        &self,
        actor: &str,
        operation_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<AuthorizationRecord>, String>;

    fn put_external_action_authorization(&self, record: &AuthorizationRecord)
    -> Result<(), String>;

    fn get_external_action_authorization_by_id(
        &self,
        authorization_id: &str,
    ) -> Result<Option<AuthorizationRecord>, String>;

    fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn claim_external_action_authorization(
            &self,
            request: &ExternalActionRequest,
            request_digest: &str,
            authorization_id: &str,
            now_ms: i64,
        ) -> Result<AuthorizationClaim, String> {
            <$target>::claim_external_action_authorization(
                self,
                request,
                request_digest,
                authorization_id,
                now_ms,
            )
        }

        fn abandon_external_action_claim(
            &self,
            request: &ExternalActionRequest,
            request_digest: &str,
        ) -> Result<(), String> {
            <$target>::abandon_external_action_claim(self, request, request_digest)
        }

        fn compare_and_swap_external_action_authorization(
            &self,
            expected: &AuthorizationRecord,
            next: &AuthorizationRecord,
        ) -> Result<bool, String> {
            <$target>::compare_and_swap_external_action_authorization(self, expected, next)
        }

        fn reserve_external_action_blast_radius(
            &self,
            authorization_id: &str,
            request: &ExternalActionRequest,
            max_mutations: Option<u32>,
            max_deletes: Option<u32>,
        ) -> Result<(), String> {
            <$target>::reserve_external_action_blast_radius(
                self,
                authorization_id,
                request,
                max_mutations,
                max_deletes,
            )
        }

        fn release_external_action_blast_radius(
            &self,
            authorization_id: &str,
            request: &ExternalActionRequest,
        ) -> Result<(), String> {
            <$target>::release_external_action_blast_radius(self, authorization_id, request)
        }

        fn get_external_action_authorization(
            &self,
            actor: &str,
            operation_id: &str,
            idempotency_key: &str,
        ) -> Result<Option<AuthorizationRecord>, String> {
            <$target>::get_external_action_authorization(self, actor, operation_id, idempotency_key)
        }

        fn put_external_action_authorization(
            &self,
            record: &AuthorizationRecord,
        ) -> Result<(), String> {
            <$target>::put_external_action_authorization(self, record)
        }

        fn get_external_action_authorization_by_id(
            &self,
            authorization_id: &str,
        ) -> Result<Option<AuthorizationRecord>, String> {
            <$target>::get_external_action_authorization_by_id(self, authorization_id)
        }

        fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String> {
            <$target>::list_external_action_authorizations(self)
        }
    };
}

impl ChiseiExternalActionBackend for SekaiDb {
    forward!(SekaiDb);
}
impl ChiseiExternalActionBackend for PostgresDb {
    forward!(PostgresDb);
}
