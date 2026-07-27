//! Backend-neutral generation-fenced lease persistence.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::lease::{Lease, LeaseError};

pub trait LeaseBackend: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn acquire_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError>;
    fn get_lease(&self, namespace: &str, key: &str) -> Result<Option<Lease>, LeaseError>;
    #[allow(clippy::too_many_arguments)]
    fn refresh_lease(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError>;
    #[allow(clippy::too_many_arguments)]
    fn release_lease(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError>;
    #[allow(clippy::too_many_arguments)]
    fn takeover_expired_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at_ms: i64,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError>;
}

macro_rules! forward {
    ($target:ty) => {
        fn acquire_lease(
            &self,
            namespace: &str,
            key: &str,
            owner: &str,
            ttl_ms: i64,
            request_id: &str,
            actor: &str,
            site_id: &str,
            now_ms: i64,
        ) -> Result<Lease, LeaseError> {
            <$target>::acquire_lease(
                self, namespace, key, owner, ttl_ms, request_id, actor, site_id, now_ms,
            )
        }
        fn get_lease(&self, namespace: &str, key: &str) -> Result<Option<Lease>, LeaseError> {
            <$target>::get_lease(self, namespace, key)
        }
        fn refresh_lease(
            &self,
            namespace: &str,
            key: &str,
            token: &str,
            ttl_ms: i64,
            request_id: &str,
            actor: &str,
            site_id: &str,
            now_ms: i64,
        ) -> Result<Lease, LeaseError> {
            <$target>::refresh_lease(
                self, namespace, key, token, ttl_ms, request_id, actor, site_id, now_ms,
            )
        }
        fn release_lease(
            &self,
            namespace: &str,
            key: &str,
            token: &str,
            request_id: &str,
            actor: &str,
            site_id: &str,
            now_ms: i64,
        ) -> Result<Lease, LeaseError> {
            <$target>::release_lease(
                self, namespace, key, token, request_id, actor, site_id, now_ms,
            )
        }
        fn takeover_expired_lease(
            &self,
            namespace: &str,
            key: &str,
            owner: &str,
            expected_token: &str,
            expected_expires_at_ms: i64,
            ttl_ms: i64,
            request_id: &str,
            actor: &str,
            site_id: &str,
            now_ms: i64,
        ) -> Result<Lease, LeaseError> {
            <$target>::takeover_expired_lease(
                self,
                namespace,
                key,
                owner,
                expected_token,
                expected_expires_at_ms,
                ttl_ms,
                request_id,
                actor,
                site_id,
                now_ms,
            )
        }
    };
}

impl LeaseBackend for SekaiDb {
    forward!(SekaiDb);
}

impl LeaseBackend for PostgresDb {
    forward!(PostgresDb);
}
