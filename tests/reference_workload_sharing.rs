//! Tenancy, markings and alliance sharing on the game reference workload
//! (#1625).
//!
//! Two players are separate tenants, each owning one namespace of fleets
//! and planets. The local operator first registers the kinds and seals
//! principal profiles on the community server. The same store is then served
//! with an identity extension, the published boundary an enterprise
//! distribution plugs into, where every read and write goes through gRPC
//! with a bearer credential. The extension
//! stands in for the distribution's membership store: it holds the host's
//! guest grant for a spy and both administrators' approvals of an alliance,
//! and the test changes them between requests to revoke access without a
//! restart.
#![cfg(unix)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sekai_chisei::combined_stores::CombinedStoreLayout;
use sekai_chisei::config::{Config, GrpcTcpMode};
use sekai_chisei::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, CredentialKind, EnterpriseExtension,
    ExtensionError, GuestGrant, IDENTITY_EXTENSION_VERSION, NamespaceAction,
    SharedSpaceAuthorization, SharedSpaceGrant, SpaceRole, TenantContext,
};
use sekai_chisei::grpc::client::{GatewayClient, connect_sekai};
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{
    CreateObjectRequest, CreateSchemaTypeRequest, GetObjectRequest, ListFilter, ListObjectsRequest,
    Object, ObjectType, UpdateObjectRequest,
};
use sekai_chisei::runtime_backend::RuntimeBackend;
use tonic::{Code, Request};

const RED: &str = "game-red";
const BLUE: &str = "game-blue";
const ALLIANCE: &str = "red-blue-alliance";

/// Who a bearer credential is. The token is the lookup key.
struct Identity {
    subject: &'static str,
    tenant: &'static str,
    home_tenant: Option<&'static str>,
    space: Option<(&'static str, SpaceRole)>,
}

fn identity(token: &str) -> Option<Identity> {
    let id = |subject, tenant, home_tenant, space| Identity {
        subject,
        tenant,
        home_tenant,
        space,
    };
    Some(match token {
        "red-commander" => id("red-commander", "red", None, None),
        "blue-commander" => id("blue-commander", "blue", None, None),
        // Blue's spy acts in red's tenant as a guest from blue.
        "blue-spy" => id("blue-spy", "red", Some("blue"), None),
        // Blue's commander acting through the alliance space.
        "blue-ally" => id(
            "blue-commander",
            "blue",
            None,
            Some((ALLIANCE, SpaceRole::Viewer)),
        ),
        _ => return None,
    })
}

/// The membership store an enterprise distribution would own.
#[derive(Default)]
struct Membership {
    /// Red's grant to blue's spy on red's namespace.
    spy_grant: Option<GuestGrant>,
    /// Red's and blue's administrators' approvals of the alliance.
    red_approves: bool,
    blue_approves: bool,
}

#[derive(Default)]
struct GameIdentity(Mutex<Membership>);

impl EnterpriseExtension for GameIdentity {
    fn authenticate_bearer(&self, token: &str) -> Result<AuthenticatedPrincipal, ExtensionError> {
        self.authenticate_context(token)
            .map(|context| context.principal)
    }

    fn authenticate_context(&self, token: &str) -> Result<AuthenticatedContext, ExtensionError> {
        let who = identity(token).ok_or(ExtensionError::PermissionDenied)?;
        Ok(AuthenticatedContext {
            contract_version: IDENTITY_EXTENSION_VERSION,
            principal: AuthenticatedPrincipal {
                subject: who.subject.into(),
                credential_id: format!("credential-{token}"),
            },
            credential_kind: CredentialKind::Machine,
            tenant: Some(TenantContext {
                tenant_id: who.tenant.into(),
                subject: who.subject.into(),
            }),
            home_tenant: who.home_tenant.map(Into::into),
            space: who.space.map(|(space, _)| space.into()),
            space_role: who.space.map(|(_, role)| role),
            act: None,
            scopes: vec!["sekai.read".into(), "sekai.write".into()],
            issuer: "game-test".into(),
            resource: "sekai:control-plane".into(),
            expires_at: i64::MAX,
            device: None,
        })
    }

    fn tenant_context(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<TenantContext, ExtensionError> {
        let token = principal
            .credential_id
            .strip_prefix("credential-")
            .unwrap_or_default();
        let who = identity(token).ok_or(ExtensionError::PermissionDenied)?;
        Ok(TenantContext {
            tenant_id: who.tenant.into(),
            subject: who.subject.into(),
        })
    }

    /// Each tenant owns only its own namespace.
    fn authorize_namespace(
        &self,
        context: &TenantContext,
        namespace: &str,
        _action: NamespaceAction,
    ) -> Result<(), ExtensionError> {
        match (context.tenant_id.as_str(), namespace) {
            ("red", RED) | ("blue", BLUE) => Ok(()),
            _ => Err(ExtensionError::PermissionDenied),
        }
    }

    fn authorize_guest_namespace(
        &self,
        context: &AuthenticatedContext,
        namespace: &str,
        _action: NamespaceAction,
    ) -> Result<GuestGrant, ExtensionError> {
        let membership = self.0.lock().unwrap();
        membership
            .spy_grant
            .clone()
            .filter(|_| context.guest_home_tenant() == Some("blue") && namespace == RED)
            .ok_or(ExtensionError::PermissionDenied)
    }

    fn authorize_shared_space(
        &self,
        context: &AuthenticatedContext,
        namespace: &str,
        _action: NamespaceAction,
    ) -> Result<SharedSpaceAuthorization, ExtensionError> {
        if context.named_space() != Some(ALLIANCE) {
            return Ok(SharedSpaceAuthorization::Unshared);
        }
        let membership = self.0.lock().unwrap();
        Ok(
            if membership.red_approves && membership.blue_approves && namespace == RED {
                SharedSpaceAuthorization::Granted(SharedSpaceGrant {
                    owner_tenant: "red".into(),
                    namespaces: vec![RED.into()],
                    kinds: vec!["fleet".into()],
                    marking_ceiling: "confidential".into(),
                })
            } else {
                SharedSpaceAuthorization::Denied {
                    owner_tenant: "red".into(),
                }
            },
        )
    }

    fn authorize_unscoped_namespace(
        &self,
        _principal: &AuthenticatedPrincipal,
        _namespace: &str,
        _action: NamespaceAction,
    ) -> Result<(), ExtensionError> {
        Err(ExtensionError::PermissionDenied)
    }
}

/// One server process over the store in `dir`, composed with `extension`
/// when given. Without one it is the community server, where the local
/// operator provisions kinds and principal profiles.
struct Server {
    socket: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn spawn(dir: &Path, name: &str, extension: Option<Arc<GameIdentity>>) -> Self {
        let socket = dir
            .join(format!("{name}.sock"))
            .to_str()
            .unwrap()
            .to_string();
        let store = dir.join("sekai.db").to_str().unwrap().to_string();
        let extension = extension.map(|extension| extension as Arc<dyn EnterpriseExtension>);
        let backend =
            RuntimeBackend::from_sqlite_with_enterprise_extension(&store, extension).unwrap();
        let mut config = Config::from_env();
        config.sekai_socket = Some(socket.clone());
        config.db_path = store;
        config.ops_port = None;
        config.http_port = None;
        config.insecure = false;
        config.scoring_enabled = false;
        let server = sekai_chisei::grpc::run(
            config,
            Arc::new(CombinedStoreLayout::from_backend(backend)),
            Vec::new(),
            GrpcTcpMode {
                bind_addr: "127.0.0.1".into(),
                token_auth_mode: false,
                auth_configured: false,
                bind_inferred_from_active_credentials: false,
            },
        )
        .unwrap();
        let task = tokio::spawn(async move {
            server.await.expect("server");
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            assert!(Instant::now() < deadline, "socket never became ready");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Self { socket, task }
    }

    async fn client(&self) -> SekaiServiceClient<GatewayClient> {
        SekaiServiceClient::new(connect_sekai(&self.socket).await.unwrap())
    }
}

fn bearer<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

/// The workload's object kinds.
fn workload_kinds() -> Vec<ObjectType> {
    [
        ("fleet", "A player's fleet, stationed at a planet."),
        ("planet", "A planet a player controls."),
    ]
    .into_iter()
    .map(|(kind, description)| ObjectType {
        kind: kind.into(),
        description: description.into(),
        ..Default::default()
    })
    .collect()
}

fn object(namespace: &str, id: &str, kind: &str, marking: &str) -> Object {
    Object {
        id: id.into(),
        kind: kind.into(),
        name: id.into(),
        namespace: namespace.into(),
        external_id: format!("{kind}:{id}"),
        properties: HashMap::from([("access_marking".into(), marking.into())]),
        ..Default::default()
    }
}

fn profile(principal: &str, ceiling: &str) -> Object {
    Object {
        id: format!("profile-{principal}"),
        kind: "principal_profile".into(),
        name: principal.into(),
        namespace: "game-ops".into(),
        external_id: format!("principal:{principal}"),
        properties: HashMap::from([("classification_ceiling".into(), ceiling.into())]),
        ..Default::default()
    }
}

/// Ids `token` reads back, each by get, in request order; a hidden
/// object must fail exactly like an absent one.
async fn visible(
    client: &SekaiServiceClient<GatewayClient>,
    token: &str,
    ids: &[&str],
) -> Vec<String> {
    let mut seen = Vec::new();
    for id in ids {
        match client
            .clone()
            .get_object(bearer(token, GetObjectRequest { id: (*id).into() }))
            .await
        {
            Ok(response) => seen.push(response.into_inner().object.unwrap().id),
            Err(status) => assert_eq!(
                (status.code(), status.message()),
                (Code::NotFound, "not found"),
                "{token} get {id}"
            ),
        }
    }
    seen
}

async fn listed(
    client: &SekaiServiceClient<GatewayClient>,
    token: &str,
    namespace: &str,
    kind: &str,
) -> Result<(Vec<String>, i32), tonic::Status> {
    let response = client
        .clone()
        .list_objects(bearer(
            token,
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: kind.into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ))
        .await?
        .into_inner();
    let mut ids: Vec<_> = response
        .objects
        .into_iter()
        .map(|object| object.id)
        .collect();
    ids.sort();
    Ok((ids, response.total))
}

#[tokio::test(flavor = "multi_thread")]
async fn players_share_only_what_markings_spies_and_alliances_allow() {
    let dir = tempfile::tempdir().unwrap();
    {
        let operator = Server::spawn(dir.path(), "operator", None).await;
        let mut client = operator.client().await;
        for kind in workload_kinds() {
            client
                .create_schema_type(CreateSchemaTypeRequest { r#type: Some(kind) })
                .await
                .expect("register kind");
        }
        for principal in ["red-commander", "blue-commander", "blue-spy"] {
            client
                .create_object(CreateObjectRequest {
                    object: Some(profile(principal, "restricted")),
                    lease_precondition: None,
                })
                .await
                .unwrap_or_else(|error| panic!("profile {principal}: {error:?}"));
        }
    }
    let membership = Arc::new(GameIdentity::default());
    let server = Server::spawn(dir.path(), "players", Some(membership.clone())).await;
    let mut client = server.client().await;
    for (token, namespace, objects) in [
        (
            "red-commander",
            RED,
            vec![
                ("red-scout", "fleet", "internal"),
                ("red-main", "fleet", "confidential"),
                ("red-reserve", "fleet", "restricted"),
                ("red-home", "planet", "internal"),
            ],
        ),
        (
            "blue-commander",
            BLUE,
            vec![("blue-main", "fleet", "confidential")],
        ),
    ] {
        for (id, kind, marking) in objects {
            client
                .create_object(bearer(
                    token,
                    CreateObjectRequest {
                        object: Some(object(namespace, id, kind, marking)),
                        lease_precondition: None,
                    },
                ))
                .await
                .unwrap_or_else(|error| panic!("{token} create {id}: {error:?}"));
        }
    }
    let red_ids = [
        "red-scout",
        "red-main",
        "red-reserve",
        "red-home",
        "red-missing",
    ];

    // 1. Players are separate tenants: each sees its own objects, and the
    //    other's look exactly like ids and namespaces that do not exist.
    assert_eq!(
        visible(&client, "red-commander", &red_ids).await,
        ["red-scout", "red-main", "red-reserve", "red-home"]
    );
    assert!(
        visible(&client, "blue-commander", &red_ids)
            .await
            .is_empty()
    );
    assert!(
        visible(&client, "red-commander", &["blue-main"])
            .await
            .is_empty()
    );
    let foreign = listed(&client, "blue-commander", RED, "fleet")
        .await
        .unwrap_err();
    let absent = listed(&client, "blue-commander", "game-absent", "fleet")
        .await
        .unwrap_err();
    assert_eq!(
        (foreign.code(), foreign.message()),
        (absent.code(), absent.message())
    );

    // 2. A spy report: red admits blue's spy as a guest capped at
    //    `internal`, so only the objects red marked that low are visible.
    assert!(visible(&client, "blue-spy", &red_ids).await.is_empty());
    membership.0.lock().unwrap().spy_grant = Some(GuestGrant {
        role: SpaceRole::Viewer,
        marking_ceiling: "internal".into(),
    });
    assert_eq!(
        visible(&client, "blue-spy", &red_ids).await,
        ["red-scout", "red-home"]
    );
    assert_eq!(
        listed(&client, "blue-spy", RED, "fleet").await.unwrap(),
        (vec!["red-scout".to_string()], 1)
    );
    let refused = client
        .update_object(bearer(
            "blue-spy",
            UpdateObjectRequest {
                object: Some(object(RED, "red-scout", "fleet", "internal")),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied, "{refused:?}");
    membership.0.lock().unwrap().spy_grant = None;
    assert!(visible(&client, "blue-spy", &red_ids).await.is_empty());

    // 3. An alliance: a space owned by red that exposes red's fleets up to
    //    `confidential`. One-sided approval shares nothing.
    membership.0.lock().unwrap().red_approves = true;
    assert!(visible(&client, "blue-ally", &red_ids).await.is_empty());
    membership.0.lock().unwrap().blue_approves = true;
    assert_eq!(
        visible(&client, "blue-ally", &red_ids).await,
        ["red-scout", "red-main"]
    );
    assert_eq!(
        listed(&client, "blue-ally", RED, "fleet").await.unwrap(),
        (vec!["red-main".to_string(), "red-scout".to_string()], 2)
    );
    // The member's viewer role in the space reads but never moves red's fleets.
    let refused = client
        .update_object(bearer(
            "blue-ally",
            UpdateObjectRequest {
                object: Some(object(RED, "red-main", "fleet", "confidential")),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied, "{refused:?}");

    // 4. Ending the alliance revokes it on the next read, same server.
    membership.0.lock().unwrap().red_approves = false;
    assert!(visible(&client, "blue-ally", &red_ids).await.is_empty());
    let ended = listed(&client, "blue-ally", RED, "fleet")
        .await
        .unwrap_err();
    assert_eq!(
        (ended.code(), ended.message()),
        (absent.code(), absent.message())
    );
}
