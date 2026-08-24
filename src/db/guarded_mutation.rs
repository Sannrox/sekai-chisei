//! Backend-neutral lease-fenced object mutation persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::domain::Object;
use crate::sekai::lease::LeaseError;
use crate::sekai::object_security::PrincipalPolicyContext;

pub const POSTGRES_GUARDED_MUTATION_SURFACE: &str = "sekai.guarded-mutations";

pub trait GuardedMutationBackend: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn guarded_object_replay(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        operation: &str,
        target_id: &str,
        request_object: &Object,
    ) -> Result<Option<Object>, LeaseError>;

    #[allow(clippy::too_many_arguments)]
    fn guarded_create_object(
        &self,
        object: &Object,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
        policy: Option<&PrincipalPolicyContext>,
    ) -> Result<Object, LeaseError>;

    #[allow(clippy::too_many_arguments)]
    fn guarded_update_object(
        &self,
        object: &Object,
        request_object: &Object,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
        policy: Option<&PrincipalPolicyContext>,
    ) -> Result<Object, LeaseError>;

    #[allow(clippy::too_many_arguments)]
    fn guarded_delete_object(
        &self,
        object_id: &str,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
        policy: Option<&PrincipalPolicyContext>,
    ) -> Result<(), LeaseError>;
}

macro_rules! forward {
    ($target:ty) => {
        fn guarded_object_replay(
            &self,
            namespace: &str,
            key: &str,
            token: &str,
            request_id: &str,
            operation: &str,
            target_id: &str,
            request_object: &Object,
        ) -> Result<Option<Object>, LeaseError> {
            <$target>::guarded_object_replay(
                self,
                namespace,
                key,
                token,
                request_id,
                operation,
                target_id,
                request_object,
            )
        }
        fn guarded_create_object(
            &self,
            object: &Object,
            namespace: &str,
            key: &str,
            token: &str,
            request_id: &str,
            actor: &str,
            now_ms: i64,
            policy: Option<&PrincipalPolicyContext>,
        ) -> Result<Object, LeaseError> {
            <$target>::guarded_create_object(
                self, object, namespace, key, token, request_id, actor, now_ms, policy,
            )
        }
        fn guarded_update_object(
            &self,
            object: &Object,
            request_object: &Object,
            expected: Option<&Object>,
            namespace: &str,
            key: &str,
            token: &str,
            request_id: &str,
            actor: &str,
            now_ms: i64,
            policy: Option<&PrincipalPolicyContext>,
        ) -> Result<Object, LeaseError> {
            <$target>::guarded_update_object(
                self,
                object,
                request_object,
                expected,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
                policy,
            )
        }
        fn guarded_delete_object(
            &self,
            object_id: &str,
            expected: Option<&Object>,
            namespace: &str,
            key: &str,
            token: &str,
            request_id: &str,
            actor: &str,
            now_ms: i64,
            policy: Option<&PrincipalPolicyContext>,
        ) -> Result<(), LeaseError> {
            <$target>::guarded_delete_object(
                self, object_id, expected, namespace, key, token, request_id, actor, now_ms, policy,
            )
        }
    };
}

impl GuardedMutationBackend for SekaiDb {
    forward!(SekaiDb);
}
impl GuardedMutationBackend for PostgresDb {
    forward!(PostgresDb);
}
