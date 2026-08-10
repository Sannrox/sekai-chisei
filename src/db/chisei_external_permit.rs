//! Backend-neutral external permit persistence for dual-backend parity.

use crate::chisei::external_permit::{ExternalPermitPolicy, Permit};
use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;

pub trait ChiseiExternalPermitBackend: Send + Sync {
    fn set_external_permit_policy(
        &self,
        policy: &ExternalPermitPolicy,
        now_ms: i64,
    ) -> Result<(), String>;

    fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String>;

    fn put_permit(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        issued_by: &str,
    ) -> Result<Permit, String>;

    fn replay_permit(
        &self,
        authorization_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<Permit>, String>;

    fn revoke_permit(
        &self,
        handle: &str,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn set_permit_kill_switch(
        &self,
        kind: &str,
        value: &str,
        enabled: bool,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String>;
}

macro_rules! forward_external_permit {
    ($target:ty) => {
        fn set_external_permit_policy(
            &self,
            policy: &ExternalPermitPolicy,
            now_ms: i64,
        ) -> Result<(), String> {
            <$target>::set_external_permit_policy(self, policy, now_ms)
        }

        fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String> {
            <$target>::get_external_permit_policy(self, scope)
        }

        fn put_permit(
            &self,
            permit: &Permit,
            idempotency_key: &str,
            issued_by: &str,
        ) -> Result<Permit, String> {
            <$target>::put_permit(self, permit, idempotency_key, issued_by)
        }

        fn replay_permit(
            &self,
            authorization_id: &str,
            idempotency_key: &str,
        ) -> Result<Option<Permit>, String> {
            <$target>::replay_permit(self, authorization_id, idempotency_key)
        }

        fn revoke_permit(
            &self,
            handle: &str,
            actor: &str,
            reason: &str,
            now_ms: i64,
        ) -> Result<bool, String> {
            <$target>::revoke_permit(self, handle, actor, reason, now_ms)
        }

        fn set_permit_kill_switch(
            &self,
            kind: &str,
            value: &str,
            enabled: bool,
            reason: &str,
            now_ms: i64,
        ) -> Result<bool, String> {
            <$target>::set_permit_kill_switch(self, kind, value, enabled, reason, now_ms)
        }
    };
}

impl ChiseiExternalPermitBackend for SekaiDb {
    forward_external_permit!(SekaiDb);
}

impl ChiseiExternalPermitBackend for PostgresDb {
    forward_external_permit!(PostgresDb);
}
