//! The connector template's gRPC transport against an in-process plane
//! (#1409): the fake source's pages commit under an admitted registered
//! descriptor, one transaction per page, until the source is up to date, and
//! a batch the plane refuses is quarantined.

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::security::Role;
use sekai_chisei::sekai::source_type_descriptor::{
    ProposedSourceTypeDescriptor, register_source_type_descriptor,
};
use sekai_connector_template::config::ConnectorConfig;
use sekai_connector_template::fake::{FakeSource, RECORD_KIND, SCHEMA_REVISION};
use sekai_connector_template::transport::GrpcTransport;
use sekai_connector_template::{RunOutcome, run_once};
use sekai_source_sdk::{GetSourceSyncStateInput, OutboxLimits, SourceOutbox, SourceSyncTransport};
use std::sync::Arc;
use tonic::metadata::MetadataValue;

const OPERATOR: &str = "operator";

/// Serve `SekaiService` on a loopback port from its own runtime thread. The
/// interceptor stands in for the auth layer: every call is `principal`.
fn serve(db: Arc<RuntimeDb>, principal: &'static str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let service =
                SekaiServiceImpl::new(sekai_chisei::db::store::SekaiStore::from_shared_runtime(db));
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(
                tokio::net::TcpListener::from_std(listener).unwrap(),
            );
            tonic::transport::Server::builder()
                .add_service(SekaiServiceServer::with_interceptor(
                    service,
                    move |mut request: tonic::Request<()>| {
                        request
                            .metadata_mut()
                            .insert("x-principal", MetadataValue::from_static(principal));
                        Ok(request)
                    },
                ))
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
    });
    format!("http://{addr}")
}

#[test]
fn template_connector_commits_fake_pages_through_the_plane() {
    let shipped = ConnectorConfig::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("crates/sekai-connector-template/connector.json"),
    )
    .unwrap();
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    db.ensure_team_namespace(&shipped.namespace, OPERATOR, Role::Admin, OPERATOR)
        .unwrap();
    db.ensure_team_namespace(
        &shipped.namespace,
        &shipped.producer_identity,
        Role::Editor,
        OPERATOR,
    )
    .unwrap();
    let descriptor =
        ProposedSourceTypeDescriptor::prepare(&shipped.source, RECORD_KIND, SCHEMA_REVISION)
            .unwrap();
    register_source_type_descriptor(&db, OPERATOR, &shipped.namespace, &descriptor, 10).unwrap();
    let principal: &'static str = shipped.producer_identity.clone().leak();
    let target = serve(db, principal);

    let config = ConnectorConfig {
        target,
        type_digest: descriptor.digest,
        ..shipped
    };
    let connect = || {
        (0..50)
            .find_map(|_| {
                GrpcTransport::connect(&config.target, None)
                    .inspect_err(|_| std::thread::sleep(std::time::Duration::from_millis(100)))
                    .ok()
            })
            .expect("plane accepts connections")
    };

    // A batch the plane refuses outright (here: signed for a producer other
    // than the caller) is quarantined, not retried forever.
    let foreign = ConnectorConfig {
        producer_identity: "connector/foreign".into(),
        ..config.clone()
    };
    let quarantine_root = tempfile::tempdir().unwrap();
    let quarantine_outbox =
        SourceOutbox::open(quarantine_root.path(), OutboxLimits::default()).unwrap();
    assert_eq!(
        run_once(
            &foreign,
            &quarantine_outbox,
            &mut FakeSource::new(&config.source, &config.source_instance),
            &mut connect(),
        ),
        Ok(RunOutcome::Quarantined)
    );
    assert!(quarantine_outbox.pending().unwrap().is_empty());

    let outbox_root = tempfile::tempdir().unwrap();
    let outbox = SourceOutbox::open(outbox_root.path(), OutboxLimits::default()).unwrap();
    let mut source = FakeSource::new(&config.source, &config.source_instance);
    let mut transport = connect();

    let mut outcomes = Vec::new();
    loop {
        let outcome = run_once(&config, &outbox, &mut source, &mut transport).unwrap();
        outcomes.push(outcome.clone());
        if !matches!(
            outcome,
            RunOutcome::Committed {
                complete: false,
                ..
            }
        ) {
            break;
        }
    }
    assert_eq!(
        outcomes,
        [
            RunOutcome::Committed {
                cursor: "page-1".into(),
                complete: false,
            },
            RunOutcome::Committed {
                cursor: "page-2".into(),
                complete: true,
            },
        ]
    );
    let state = transport
        .get_source_sync_state(&GetSourceSyncStateInput {
            namespace: config.namespace.clone(),
            source_instance: config.source_instance.clone(),
            type_digest: config.type_digest.clone(),
        })
        .unwrap();
    assert!(state.found);
    assert_eq!(state.current_cursor.as_deref(), Some("page-2"));
    assert!(!state.open_transaction);
    assert!(outbox.pending().unwrap().is_empty());
}
