//! Bounded credential/authority cache staleness across replicas (#307 / #117).

use sekai_chisei::db::replica_safety::{ReplicaSafetyInventory, TwoReplicaSqlite};
use sekai_chisei::db::sekai::PrincipalCredential;
use sekai_chisei::gateway_keys::hash_gateway_key;
use sekai_chisei::grpc::TokenAuthInterceptor;
use sekai_chisei::sekai::credentials::{CREDENTIAL_CACHE_MAX_STALE_MS, PrincipalCredentialStore};
use std::sync::Arc;
use tonic::Request;
use tonic::service::Interceptor;

#[test]
fn inventory_documents_credential_cache_bound() {
    let inventory = ReplicaSafetyInventory::load().unwrap();
    let surface = inventory
        .require_authoritative("sekai.credentials")
        .unwrap();
    assert_eq!(
        surface.max_stale_ms,
        Some(CREDENTIAL_CACHE_MAX_STALE_MS as u64)
    );
    assert_eq!(
        PrincipalCredentialStore::max_stale_ms(),
        CREDENTIAL_CACHE_MAX_STALE_MS
    );
}

#[test]
fn revoke_on_one_replica_is_refused_after_reload_on_the_other() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let secret = "replica-secret-token";
    let hash = hash_gateway_key(secret);
    pair.a
        .create_principal_credential("alice", &hash, 1_000)
        .unwrap();

    let store_a = PrincipalCredentialStore::new();
    let store_b = PrincipalCredentialStore::new();
    assert!(store_a.maybe_reload(&pair.a));
    assert!(store_b.maybe_reload(&pair.b));
    assert_eq!(store_b.resolve(secret).unwrap().principal, "alice");

    pair.a.revoke_principal_credential("alice").unwrap();

    assert!(store_b.maybe_reload(&pair.b));
    assert!(
        store_b.resolve(secret).is_none(),
        "revoked credential must not remain in the process cache after reload"
    );
}

#[test]
fn auth_interceptor_rechecks_durable_state_and_refuses_revoked_token() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let secret = "auth-path-secret";
    let hash = hash_gateway_key(secret);
    pair.a
        .create_principal_credential("bob", &hash, 2_000)
        .unwrap();

    let store = Arc::new(PrincipalCredentialStore::new());
    store.maybe_reload(&pair.a);
    let mut interceptor = TokenAuthInterceptor::new(store.clone(), Arc::clone(&pair.b), None);

    let mut request = Request::new(());
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {secret}").parse().unwrap());
    assert!(interceptor.call(request).is_ok());

    pair.a.revoke_principal_credential("bob").unwrap();

    // Poison the process cache with a still-active-looking entry.
    store.load_credential(&PrincipalCredential {
        id: "stale-bob".into(),
        principal: "bob".into(),
        token_hash: hash,
        status: "active".into(),
        created: 1,
        rotated_at: 0,
        revoked_at: 0,
        tenant_id: String::new(),
    });
    assert!(store.resolve(secret).is_some());

    let mut request = Request::new(());
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {secret}").parse().unwrap());
    let err = interceptor.call(request).unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[test]
fn failed_reload_does_not_admit_new_authority() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let store = PrincipalCredentialStore::new();
    {
        let conn = pair.b.conn();
        conn.execute_batch("DROP TABLE sekai_principal_credentials;")
            .unwrap();
    }
    assert!(!store.maybe_reload(&pair.b));
    assert!(!store.has_any());
    assert!(store.resolve("anything").is_none());
}
