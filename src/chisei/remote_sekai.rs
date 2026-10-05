//! Authenticated hop from a Chisei process to a Sekai process.
//!
//! The hop carries a caller credential. Sekai rechecks current authorization
//! on every read served over it; a Chisei decision is not a substitute.

use std::future::Future;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::runtime::{Handle, Runtime};
use tonic::transport::Channel;

use crate::chisei::cross_store_admission::{SekaiCommitLookup, SekaiCommitRef};
use crate::chisei::principal::{MarkingClearance, PrincipalGrant};
use crate::chisei::sekai_facts::{SekaiFactError, SekaiFactReader};
use crate::db::store::SekaiStore;
use crate::domain::{Direction, Object};
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    FindByExternalIdRequest, GetActionInstanceRequest, GetLinkedObjectsRequest, ListGrantsRequest,
    ListSchemaTypesRequest,
};
use crate::sekai::schema::ObjectType;

/// Lazily connected, credential-carrying channel to a Sekai process.
struct SekaiHop {
    endpoint: String,
    credential: Option<String>,
    channel: OnceLock<Channel>,
    fallback_runtime: OnceLock<Runtime>,
}

impl SekaiHop {
    fn new(endpoint: String, credential: Option<String>) -> Self {
        Self {
            endpoint,
            credential: credential.filter(|value| !value.trim().is_empty()),
            channel: OnceLock::new(),
            fallback_runtime: OnceLock::new(),
        }
    }

    fn run<T>(&self, future: impl Future<Output = Result<T, String>>) -> Result<T, String> {
        if let Ok(handle) = Handle::try_current() {
            return tokio::task::block_in_place(|| handle.block_on(future));
        }
        self.fallback_runtime()?.block_on(future)
    }

    fn fallback_runtime(&self) -> Result<&Runtime, String> {
        if let Some(runtime) = self.fallback_runtime.get() {
            return Ok(runtime);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        Ok(self.fallback_runtime.get_or_init(|| runtime))
    }

    fn channel(&self) -> Result<Channel, String> {
        if let Some(channel) = self.channel.get() {
            return Ok(channel.clone());
        }
        let channel = self.run(connect_channel(&self.endpoint))?;
        Ok(self.channel.get_or_init(|| channel.clone()).clone())
    }

    fn client(&self) -> Result<(SekaiServiceClient<Channel>, Option<String>), String> {
        Ok((
            SekaiServiceClient::new(self.channel()?),
            self.credential.clone(),
        ))
    }
}

/// Live Sekai commit lookup over an authenticated gRPC hop.
pub struct RemoteSekaiCommitLookup {
    hop: SekaiHop,
}

impl RemoteSekaiCommitLookup {
    pub fn new(endpoint: String, credential: Option<String>) -> Self {
        Self {
            hop: SekaiHop::new(endpoint, credential),
        }
    }

    pub fn from_env(endpoint: String) -> Self {
        Self::new(endpoint, std::env::var("SEKAI_CREDENTIAL").ok())
    }
}

impl SekaiCommitLookup for RemoteSekaiCommitLookup {
    fn lookup_commit(&self, operation_id: &str) -> Result<Option<SekaiCommitRef>, String> {
        let channel = self.hop.channel()?;
        let credential = self.hop.credential.clone();
        let operation_id = operation_id.to_string();
        self.hop
            .run(lookup_on_channel(channel, credential, operation_id))
    }
}

/// Sekai fact reads over an authenticated gRPC hop (Chisei-only plane).
///
/// Every read uses a public `SekaiService` RPC, so Sekai authorizes it for
/// the hop credential and projects what that principal may see. Chisei then
/// narrows to the request actor exactly as it does in process. Graph-engine
/// reads have no public RPC and refuse with `sekai_read_unsupported`.
pub struct RemoteSekaiFactReader {
    hop: SekaiHop,
}

impl RemoteSekaiFactReader {
    pub fn new(endpoint: String, credential: Option<String>) -> Self {
        Self {
            hop: SekaiHop::new(endpoint, credential),
        }
    }

    pub fn from_env(endpoint: String) -> Self {
        Self::new(endpoint, std::env::var("SEKAI_CREDENTIAL").ok())
    }

    fn call<T>(
        &self,
        read: impl AsyncFnOnce(SekaiServiceClient<Channel>, Option<String>) -> Result<T, String>,
    ) -> Result<T, SekaiFactError> {
        let (client, credential) = self.hop.client().map_err(SekaiFactError::Read)?;
        self.hop
            .run(read(client, credential))
            .map_err(SekaiFactError::Read)
    }
}

impl SekaiFactReader for RemoteSekaiFactReader {
    fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, SekaiFactError> {
        let external_id = external_id.to_string();
        self.call(async move |client, credential| {
            find_by_external_id_on(client, credential, external_id).await
        })
    }

    fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, SekaiFactError> {
        let external_id = format!("namespace:{}", namespace.trim());
        let boundary = self.call(async move |client, credential| {
            find_by_external_id_on(client, credential, external_id).await
        })?;
        match boundary {
            Some(object) if object.kind == "namespace" => Ok(Some(object)),
            Some(_) => Err(SekaiFactError::Read(
                "canonical namespace identity is not held by a namespace boundary".into(),
            )),
            // Sekai hides objects the hop credential may not read, so a
            // missing boundary may be a hidden one. Absence would skip the
            // team-membership check; refuse instead.
            None => Err(SekaiFactError::Unsupported(
                "namespace boundary absence over the Sekai hop",
            )),
        }
    }

    fn list_grants(&self, object_id: &str) -> Result<Vec<PrincipalGrant>, SekaiFactError> {
        let object_id = object_id.to_string();
        self.call(async move |mut client, credential| {
            let request = authorized(ListGrantsRequest { object_id }, credential)?;
            let grants = client
                .list_grants(request)
                .await
                .map_err(|status| format!("sekai hop list_grants: {status}"))?
                .into_inner()
                .grants;
            grants
                .iter()
                .map(|grant| {
                    crate::grpc::sekai_service::from_proto_grant(grant)
                        .map(|grant| PrincipalGrant::from(&grant))
                        .map_err(|status| format!("sekai hop list_grants: {status}"))
                })
                .collect()
        })
    }

    fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, SekaiFactError> {
        let kind = kind.to_string();
        self.call(async move |mut client, credential| {
            let request = authorized(ListSchemaTypesRequest {}, credential)?;
            let types = client
                .list_schema_types(request)
                .await
                .map_err(|status| format!("sekai hop list_schema_types: {status}"))?
                .into_inner()
                .types;
            types
                .iter()
                .find(|object_type| object_type.kind == kind)
                .map(|object_type| {
                    crate::grpc::sekai_service::from_proto_schema_type(object_type)
                        .map_err(|status| format!("sekai hop list_schema_types: {status}"))
                })
                .transpose()
        })
    }

    fn get_linked_objects(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
    ) -> Result<Vec<Object>, SekaiFactError> {
        let request = GetLinkedObjectsRequest {
            object_id: object_id.to_string(),
            relation: relation.to_string(),
            direction: match direction {
                Direction::Incoming => "incoming",
                Direction::Outgoing => "outgoing",
            }
            .into(),
        };
        self.call(async move |mut client, credential| {
            let request = authorized(request, credential)?;
            Ok(client
                .get_linked_objects(request)
                .await
                .map_err(|status| format!("sekai hop get_linked_objects: {status}"))?
                .into_inner()
                .objects
                .iter()
                .map(crate::grpc::sekai_service::from_proto_obj)
                .collect())
        })
    }

    fn marking_clearance(
        &self,
        _: &str,
        _: &Object,
        _: &str,
    ) -> Result<MarkingClearance, SekaiFactError> {
        // The hop exposes no marking evaluation for another principal; refuse
        // so callers deny instead of treating the object as unmarked.
        Err(SekaiFactError::Unsupported(
            "marking clearance over the Sekai hop",
        ))
    }

    fn in_process_store(&self) -> Result<&SekaiStore, SekaiFactError> {
        Err(SekaiFactError::Unsupported(
            "graph retrieval over the Sekai hop",
        ))
    }
}

fn authorized<T>(message: T, credential: Option<String>) -> Result<tonic::Request<T>, String> {
    let mut request = tonic::Request::new(message);
    if let Some(token) = credential {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {token}")
                .parse()
                .map_err(|error| format!("SEKAI_CREDENTIAL: {error}"))?,
        );
    }
    Ok(request)
}

async fn find_by_external_id_on(
    mut client: SekaiServiceClient<Channel>,
    credential: Option<String>,
    external_id: String,
) -> Result<Option<Object>, String> {
    let request = authorized(FindByExternalIdRequest { external_id }, credential)?;
    match client.find_by_external_id(request).await {
        Ok(response) => Ok(response
            .into_inner()
            .object
            .as_ref()
            .map(crate::grpc::sekai_service::from_proto_obj)),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(format!("sekai hop find_by_external_id: {status}")),
    }
}

async fn connect_channel(endpoint: &str) -> Result<Channel, String> {
    tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .map_err(|error| format!("SEKAI_ENDPOINT: {error}"))?
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .map_err(|error| format!("sekai hop connect: {error}"))
}

async fn lookup_on_channel(
    channel: Channel,
    credential: Option<String>,
    operation_id: String,
) -> Result<Option<SekaiCommitRef>, String> {
    let mut client = SekaiServiceClient::new(channel);
    let request = authorized(
        GetActionInstanceRequest {
            instance_id: String::new(),
            namespace: String::new(),
            idempotency_key: String::new(),
            operation_id,
        },
        credential,
    )?;
    match client.get_action_instance(request).await {
        Ok(response) => Ok(response
            .into_inner()
            .instance
            .map(|instance| SekaiCommitRef {
                namespace: instance.namespace,
                instance_id: instance.instance_id,
                status: instance.status,
            })),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(format!("sekai hop lookup: {status}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::principal::PrincipalRole;

    #[test]
    fn lookup_outside_runtime_reports_connect_error() {
        let hop = RemoteSekaiCommitLookup::new("http://127.0.0.1:1".into(), None);
        let error = hop.lookup_commit("op-1").unwrap_err();
        assert!(error.contains("sekai hop connect"), "{error}");
        let again = hop.lookup_commit("op-2").unwrap_err();
        assert!(again.contains("sekai hop connect"), "{again}");
        assert!(hop.hop.channel.get().is_none());
    }

    /// Serve SekaiService on loopback. `Bearer hop-token` authenticates as the
    /// trusted `local` principal and `Bearer reader-token` as the unprivileged
    /// `reader`; anything else is rejected by Sekai.
    async fn serve_sekai(sekai: SekaiStore) -> String {
        use crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service =
            SekaiServiceServer::new(crate::grpc::sekai_service::SekaiServiceImpl::new(sekai));
        let authenticate = |mut request: tonic::Request<()>| {
            let bearer = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let principal = match bearer.as_deref() {
                Some("Bearer hop-token") => "local",
                Some("Bearer reader-token") => "reader",
                _ => return Err(tonic::Status::unauthenticated("bad hop credential")),
            };
            request
                .metadata_mut()
                .insert("x-principal", principal.parse().unwrap());
            Ok(request)
        };
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(tonic::service::interceptor::InterceptedService::new(
                    service,
                    authenticate,
                ))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );
        format!("http://{address}")
    }

    fn seeded_sekai() -> SekaiStore {
        let sekai = SekaiStore::memory();
        crate::chisei::lookup_first::seed_s1_fixture_graph(&sekai).unwrap();
        sekai
            .runtime()
            .ensure_team_namespace("acme", "alice", PrincipalRole::Viewer.into(), "local")
            .unwrap();
        sekai
            .runtime()
            .create_object(&Object {
                id: "hop-context".into(),
                kind: "widget".into(),
                name: "hop-context".into(),
                namespace: "acme".into(),
                external_id: "widget:hop-context".into(),
                properties: std::collections::HashMap::from([(
                    "verdict".into(),
                    "hop verdict".into(),
                )]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        sekai
    }

    fn run_context_pipeline(reader: RemoteSekaiFactReader) -> crate::chisei::pipeline::RunResult {
        let mut request = crate::chisei::pipeline::test_request(
            crate::chisei::sekai_facts::SekaiFacts::new(std::sync::Arc::new(reader)),
        );
        request.namespace = "acme".into();
        request.spec = "inspect widget:hop-context".into();
        request.memory_actor = "alice".into();
        request.external_egress = false;
        crate::chisei::pipeline::default_pipeline()
            .run(&mut request, &crate::db::store::ChiseiStore::memory())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pipeline_context_resolves_over_the_hop_for_an_authorized_actor() {
        let endpoint = serve_sekai(seeded_sekai()).await;
        let result = run_context_pipeline(RemoteSekaiFactReader::new(
            endpoint,
            Some("hop-token".into()),
        ));
        assert_eq!(result.steps[0].action, "enrich", "{:?}", result.steps[0]);
        assert!(result.prepared_spec.contains("hop verdict"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pipeline_context_over_an_unprivileged_hop_is_dropped_not_leaked() {
        let endpoint = serve_sekai(seeded_sekai()).await;
        let result = run_context_pipeline(RemoteSekaiFactReader::new(
            endpoint,
            Some("reader-token".into()),
        ));
        assert_ne!(result.steps[0].action, "enrich", "{:?}", result.steps[0]);
        assert!(!result.prepared_spec.contains("hop verdict"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pipeline_context_reports_an_unreachable_hop() {
        let result = run_context_pipeline(RemoteSekaiFactReader::new(
            "http://127.0.0.1:1".into(),
            Some("hop-token".into()),
        ));
        assert_eq!(result.steps[0].action, "skipped");
        assert!(
            result.steps[0].reasoning.starts_with("sekai_read_failed"),
            "{:?}",
            result.steps[0]
        );
        assert!(!result.prepared_spec.contains("hop verdict"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fact_reader_reads_sekai_facts_over_the_authenticated_hop() {
        let endpoint = serve_sekai(seeded_sekai()).await;
        let reader = RemoteSekaiFactReader::new(endpoint, Some("hop-token".into()));

        let root = reader
            .find_by_external_id("widget:lookup-root")
            .unwrap()
            .expect("root object");
        assert_eq!(root.id, "lookup-root");
        assert!(
            reader
                .find_by_external_id("widget:absent")
                .unwrap()
                .is_none()
        );
        let grants = reader.list_grants("acl-denied").unwrap();
        assert!(grants.iter().any(|grant| grant.principal == "bob"));
        let children = reader
            .get_linked_objects("lookup-root", "contains", &Direction::Outgoing)
            .unwrap();
        assert_eq!(
            children.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(),
            ["lookup-child"]
        );
        let boundary = reader
            .find_namespace_boundary("acme")
            .unwrap()
            .expect("team namespace boundary");
        assert_eq!(boundary.kind, "namespace");
        assert!(matches!(
            reader.find_namespace_boundary("unmanaged"),
            Err(SekaiFactError::Unsupported(_))
        ));
        assert!(reader.attached());
        assert!(matches!(
            reader.in_process_store(),
            Err(SekaiFactError::Unsupported(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fact_reader_hop_without_valid_credential_fails_closed() {
        let endpoint = serve_sekai(seeded_sekai()).await;
        let reader = RemoteSekaiFactReader::new(endpoint, Some("wrong".into()));
        let error = reader
            .find_by_external_id("widget:lookup-root")
            .unwrap_err();
        assert!(
            matches!(&error, SekaiFactError::Read(message) if message.contains("bad hop credential")),
            "{error:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_lookup_first_refuses_graph_reads_the_hop_cannot_serve() {
        let endpoint = serve_sekai(seeded_sekai()).await;
        let reader = RemoteSekaiFactReader::new(endpoint, Some("hop-token".into()));
        let decision = crate::chisei::lookup_first::try_lookup_first(
            crate::sekai::semantic::CAPABILITY_RESOLVE_REF,
            "acme",
            "alice",
            r#"{"external_id":"widget:lookup-root"}"#,
            &reader,
        )
        .unwrap();
        assert_eq!(
            decision,
            crate::chisei::lookup_first::LookupDecision::Refusal {
                capability: crate::sekai::semantic::CAPABILITY_RESOLVE_REF.into(),
                reason: crate::chisei::sekai_facts::SEKAI_READ_UNSUPPORTED.into(),
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lookup_inside_runtime_does_not_need_a_nested_runtime() {
        let hop = RemoteSekaiCommitLookup::new("http://127.0.0.1:1".into(), None);
        let error = hop.lookup_commit("op-1").unwrap_err();
        assert!(error.contains("sekai hop connect"), "{error}");
        assert!(hop.hop.fallback_runtime.get().is_none());
    }
}
