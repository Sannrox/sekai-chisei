//! Public RPC maturity table and default-build gate (#871).

use sekai_chisei::rpc_maturity::{
    MATURITY_DOCS, RpcClassification, RpcMaturityLayer, RpcMaturityTable, parse_docs_rpcs,
    require_invokable,
};
use std::convert::Infallible;
use tower::{Layer, Service, ServiceExt};

#[test]
fn classification_table_matches_proto_services() {
    let table = RpcMaturityTable::load().expect("maturity table");
    let docs = parse_docs_rpcs(MATURITY_DOCS).expect("docs table");
    assert_eq!(
        docs.len(),
        table.entries.len(),
        "docs table must list every classified RPC"
    );
    assert_eq!(table.stable_rpcs().len(), 66);
    assert!(
        table
            .entries
            .iter()
            .filter(|entry| entry.real_backend == "fixture only")
            .all(|entry| entry.classification != RpcClassification::Stable)
    );
}

#[test]
fn default_build_cannot_reach_experimental_rpcs() {
    for entry in &RpcMaturityTable::load().expect("maturity table").entries {
        match entry.classification {
            RpcClassification::Stable => {
                require_invokable(&entry.rpc, false).unwrap_or_else(|error| {
                    panic!("stable {} must stay invokable: {error}", entry.rpc)
                });
            }
            RpcClassification::Experimental | RpcClassification::Remove => {
                let error = require_invokable(&entry.rpc, false)
                    .expect_err(&format!("{} must be unreachable by default", entry.rpc));
                assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            }
        }
    }
}

#[tokio::test]
async fn default_server_layer_rejects_experimental_rpc_paths() {
    let inner = tower::service_fn(|_req: http::Request<tonic::body::Body>| async {
        Ok::<_, Infallible>(http::Response::new(tonic::body::Body::default()))
    });
    let mut svc = RpcMaturityLayer::default().layer(inner);
    let request = http::Request::builder()
        .uri("/sekai.SekaiService/CreateDefinitionBranch")
        .body(tonic::body::Body::default())
        .unwrap();
    let response = svc.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(
        response.headers().get("grpc-status").unwrap(),
        "9",
        "default-build integration tests cannot reach experimental RPCs"
    );
}

/// #1150: an RPC whose handler answers `UNAVAILABLE` on community PostgreSQL
/// before any work must not claim a real backend on every runtime.
#[test]
fn postgres_unavailable_rpcs_are_classified_sqlite_only() {
    const RUNTIME_DB: &str = include_str!("../src/db/runtime_db.rs");
    let table = RpcMaturityTable::load().expect("maturity table");
    for (rpc, constant) in [
        ("DecideActionInstance", "DECIDE_ACTION_INSTANCE_UNAVAILABLE"),
        ("PutActionBinding", "ACTION_BINDINGS_UNAVAILABLE"),
        ("RunActionBinding", "ACTION_BINDINGS_UNAVAILABLE"),
    ] {
        if !RUNTIME_DB.contains(&format!("pub(crate) const {constant}")) {
            continue;
        }
        let entry = table
            .entries
            .iter()
            .find(|entry| entry.rpc == rpc)
            .unwrap_or_else(|| panic!("{rpc} missing from the maturity table"));
        assert_eq!(
            entry.real_backend, "sqlite only",
            "{rpc} fails closed on PostgreSQL ({constant})"
        );
        assert_ne!(entry.classification, RpcClassification::Stable);
    }
}
