//! Backend-neutral external permit persistence for dual-backend parity.

use crate::chisei::external_permit::{
    ExternalPermitPolicy, HostContext, Permit, Redemption, RedemptionTiming,
};
use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use ed25519_dalek::VerifyingKey;

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

    fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String>;

    fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String>;

    fn validate_permit_state(&self, permit: &Permit) -> Result<(), String>;

    fn validate_permit_for_delegation(&self, permit: &Permit) -> Result<(), String>;

    #[allow(clippy::too_many_arguments)]
    fn redeem_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        now_ms: i64,
    ) -> Result<Redemption, String>;

    #[allow(clippy::too_many_arguments)]
    fn redeem_or_reconcile_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        timing: RedemptionTiming,
    ) -> Result<Redemption, String>;

    fn replay_redemption(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        execution_id: &str,
    ) -> Result<Option<Redemption>, String>;
}

macro_rules! forward_external_permit {
    ($target:ty, $ext:path) => {
        fn set_external_permit_policy(
            &self,
            policy: &ExternalPermitPolicy,
            now_ms: i64,
        ) -> Result<(), String> {
            <$target as $ext>::set_external_permit_policy(self, policy, now_ms)
        }

        fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String> {
            <$target as $ext>::get_external_permit_policy(self, scope)
        }

        fn put_permit(
            &self,
            permit: &Permit,
            idempotency_key: &str,
            issued_by: &str,
        ) -> Result<Permit, String> {
            <$target as $ext>::put_permit(self, permit, idempotency_key, issued_by)
        }

        fn replay_permit(
            &self,
            authorization_id: &str,
            idempotency_key: &str,
        ) -> Result<Option<Permit>, String> {
            <$target as $ext>::replay_permit(self, authorization_id, idempotency_key)
        }

        fn revoke_permit(
            &self,
            handle: &str,
            actor: &str,
            reason: &str,
            now_ms: i64,
        ) -> Result<bool, String> {
            <$target as $ext>::revoke_permit(self, handle, actor, reason, now_ms)
        }

        fn set_permit_kill_switch(
            &self,
            kind: &str,
            value: &str,
            enabled: bool,
            reason: &str,
            now_ms: i64,
        ) -> Result<bool, String> {
            <$target as $ext>::set_permit_kill_switch(self, kind, value, enabled, reason, now_ms)
        }

        fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String> {
            <$target as $ext>::put_delegated_permit(self, permit, issued_by)
        }

        fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String> {
            <$target as $ext>::validate_delegation_chain(self, permit)
        }

        fn validate_permit_state(&self, permit: &Permit) -> Result<(), String> {
            <$target as $ext>::validate_permit_state(self, permit)
        }

        fn validate_permit_for_delegation(&self, permit: &Permit) -> Result<(), String> {
            <$target as $ext>::validate_permit_for_delegation(self, permit)
        }

        fn redeem_permit(
            &self,
            permit: &Permit,
            context: &HostContext,
            trusted_key: &VerifyingKey,
            idempotency_key: &str,
            execution_id: &str,
            host_site_id: &str,
            now_ms: i64,
        ) -> Result<Redemption, String> {
            <$target as $ext>::redeem_permit(
                self,
                permit,
                context,
                trusted_key,
                idempotency_key,
                execution_id,
                host_site_id,
                now_ms,
            )
        }

        fn redeem_or_reconcile_permit(
            &self,
            permit: &Permit,
            context: &HostContext,
            trusted_key: &VerifyingKey,
            idempotency_key: &str,
            execution_id: &str,
            host_site_id: &str,
            timing: RedemptionTiming,
        ) -> Result<Redemption, String> {
            <$target as $ext>::redeem_or_reconcile_permit(
                self,
                permit,
                context,
                trusted_key,
                idempotency_key,
                execution_id,
                host_site_id,
                timing,
            )
        }

        fn replay_redemption(
            &self,
            permit: &Permit,
            idempotency_key: &str,
            execution_id: &str,
        ) -> Result<Option<Redemption>, String> {
            <$target as $ext>::replay_redemption(self, permit, idempotency_key, execution_id)
        }
    };
}

impl ChiseiExternalPermitBackend for SekaiDb {
    forward_external_permit!(
        SekaiDb,
        crate::chisei::external_permit::ExternalPermitSekaiDbExt
    );
}

impl ChiseiExternalPermitBackend for PostgresDb {
    forward_external_permit!(
        PostgresDb,
        crate::chisei_store::postgres_external_permit::PostgresExternalPermitPostgresDbExt
    );
}
