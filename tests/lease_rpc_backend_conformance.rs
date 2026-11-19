//! The lease RPCs fence a taken-over owner the same way on SQLite and
//! PostgreSQL (#3266): after takeover-after-expiry, the old fencing token can
//! neither refresh, release, nor take the lease back, and inputs carry the
//! same limits.

use std::sync::Arc;
use std::time::Duration;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    AcquireLeaseRequest, GetLeaseRequest, RefreshLeaseRequest, ReleaseLeaseRequest,
    TakeoverExpiredLeaseRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::security::Role;
use tonic::Code;
use tonic::metadata::MetadataValue;

use crate::postgres_scratch::ScratchDatabase;

const NAMESPACE: &str = "runners";
const KEY: &str = "feed:orders";

fn request<T>(payload: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(payload);
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static("alice"));
    request
}

/// Runs on a multi-threaded runtime, as the server does, so a handler that
/// calls a blocking store on a runtime worker fails here too.
fn exercise(db: Arc<RuntimeDb>) {
    db.ensure_team_namespace(NAMESPACE, "alice", Role::Admin, "local")
        .unwrap();
    let service = SekaiServiceImpl::new(SekaiStore::from_shared_runtime(db));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let first = service
            .acquire_lease(request(AcquireLeaseRequest {
                namespace: NAMESPACE.into(),
                key: KEY.into(),
                owner: "runner-a".into(),
                ttl_ms: 50,
                request_id: "acquire-a".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;

        let takeover = TakeoverExpiredLeaseRequest {
            namespace: NAMESPACE.into(),
            key: KEY.into(),
            owner: "runner-b".into(),
            expected_fencing_token: first.fencing_token.clone(),
            expected_expires_at_ms: first.expires_at_ms,
            ttl_ms: 60_000,
            request_id: "takeover-b".into(),
        };
        let second = service
            .takeover_expired_lease(request(takeover.clone()))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();
        assert_eq!(second.owner, "runner-b");
        assert_eq!(second.generation, first.generation + 1);

        let stale_refresh = service
            .refresh_lease(request(RefreshLeaseRequest {
                namespace: NAMESPACE.into(),
                key: KEY.into(),
                fencing_token: first.fencing_token.clone(),
                ttl_ms: 60_000,
                request_id: "refresh-a".into(),
            }))
            .await
            .expect_err("a taken-over token cannot refresh");
        assert_eq!(stale_refresh.code(), Code::FailedPrecondition);
        let stale_release = service
            .release_lease(request(ReleaseLeaseRequest {
                namespace: NAMESPACE.into(),
                key: KEY.into(),
                fencing_token: first.fencing_token.clone(),
                request_id: "release-a".into(),
            }))
            .await
            .expect_err("a taken-over token cannot release");
        assert_eq!(stale_release.code(), Code::FailedPrecondition);
        let stale_takeover = service
            .takeover_expired_lease(request(TakeoverExpiredLeaseRequest {
                owner: "runner-a".into(),
                request_id: "takeover-a".into(),
                ..takeover
            }))
            .await
            .expect_err("a taken-over token cannot take the lease back");
        assert_eq!(stale_takeover.code(), Code::FailedPrecondition);

        let current = service
            .get_lease(request(GetLeaseRequest {
                namespace: NAMESPACE.into(),
                key: KEY.into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();
        assert_eq!(current, second);

        let oversized = service
            .acquire_lease(request(AcquireLeaseRequest {
                namespace: NAMESPACE.into(),
                key: "k".repeat(513),
                owner: "runner-a".into(),
                ttl_ms: 1_000,
                request_id: "acquire-oversized".into(),
            }))
            .await
            .expect_err("a key over 512 bytes is refused");
        assert_eq!(oversized.code(), Code::InvalidArgument);
    });
}

#[test]
fn sqlite_lease_rpcs_refuse_a_stale_token_after_takeover() {
    exercise(Arc::new(RuntimeDb::memory()));
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_lease_rpcs_refuse_a_stale_token_after_takeover() {
    let scratch = ScratchDatabase::create();
    exercise(Arc::new(RuntimeDb::Postgres(Arc::new(scratch.connect(8)))));
}
