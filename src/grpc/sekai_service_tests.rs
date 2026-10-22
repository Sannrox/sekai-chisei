use super::*;
use std::collections::HashMap;
use tonic::metadata::MetadataValue;

fn operator_pipeline(op: &str, relation: &str, func: &str, alias: &str) -> PipelineStep {
    proto_operator_step(op, "", relation, func, "", alias)
}

fn service() -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
}

struct TestEnterpriseExtension;

impl crate::enterprise::EnterpriseExtension for TestEnterpriseExtension {
    fn authenticate_bearer(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError> {
        (bearer_token == "enterprise-token")
            .then(|| crate::enterprise::AuthenticatedPrincipal {
                subject: "subject-a".into(),
                credential_id: "credential-a".into(),
            })
            .ok_or(crate::enterprise::ExtensionError::CredentialNotFound)
    }

    fn authenticate_context(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError> {
        let principal = self.authenticate_bearer(bearer_token)?;
        Ok(crate::enterprise::AuthenticatedContext {
            contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
            home_tenant: None,
            tenant: Some(self.tenant_context(&principal)?),
            principal,
            credential_kind: crate::enterprise::CredentialKind::HumanSession,
            space: None,
            space_role: None,
            act: None,
            scopes: vec!["sekai.read".into(), "sekai.write".into()],
            issuer: "https://issuer.test".into(),
            resource: "https://sekai.test".into(),
            expires_at: 100,
        })
    }

    fn tenant_context(
        &self,
        principal: &crate::enterprise::AuthenticatedPrincipal,
    ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
        if principal.credential_id != "credential-a" {
            return Err(crate::enterprise::ExtensionError::Unauthenticated);
        }
        Ok(crate::enterprise::TenantContext {
            tenant_id: "tenant-test".into(),
            subject: principal.subject.clone(),
        })
    }

    fn authorize_namespace(
        &self,
        _context: &crate::enterprise::TenantContext,
        namespace: &str,
        _action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        (namespace == "allowed")
            .then_some(())
            .ok_or(crate::enterprise::ExtensionError::PermissionDenied)
    }

    fn authorize_unscoped_namespace(
        &self,
        principal: &crate::enterprise::AuthenticatedPrincipal,
        namespace: &str,
        _action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        (principal.credential_id == "community-credential" && namespace == "community")
            .then_some(())
            .ok_or(crate::enterprise::ExtensionError::PermissionDenied)
    }
}

#[test]
fn injected_enterprise_extension_derives_context_and_authorizes_namespace() {
    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(TestEnterpriseExtension)))
            .unwrap(),
    ));
    let mut request = Request::new(());
    request
        .extensions_mut()
        .insert(crate::enterprise::AuthenticatedContext {
            contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
            home_tenant: None,
            principal: crate::enterprise::AuthenticatedPrincipal {
                subject: "subject-a".into(),
                credential_id: "credential-a".into(),
            },
            credential_kind: crate::enterprise::CredentialKind::HumanSession,
            space: None,
            space_role: None,
            act: None,
            tenant: Some(crate::enterprise::TenantContext {
                tenant_id: "tenant-test".into(),
                subject: "subject-a".into(),
            }),
            scopes: vec!["sekai.read".into()],
            issuer: "https://issuer.test".into(),
            resource: "https://sekai.test".into(),
            expires_at: 100,
        });
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static("attacker"));
    request.metadata_mut().insert(
        "x-sekai-tenant-id",
        MetadataValue::from_static("attacker-tenant"),
    );
    let tenant = request_tenant_context(&db, &request).unwrap().unwrap();
    assert_eq!(caller_principals(&request), ["subject-a"]);
    assert_eq!(
        tenant
            .tenant
            .as_ref()
            .map(|context| context.tenant_id.as_str()),
        Some("tenant-test")
    );
    assert!(enforce_namespace_tenant_context(&db, Some(&tenant), "allowed", false).is_ok());
    assert_eq!(
        enforce_namespace_tenant_context(&db, Some(&tenant), "denied", true)
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}

#[test]
fn optional_ontology_revision_pin_is_absent_or_current() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    assert!(enforce_optional_ontology_revision_pin(&db, None, "demo").is_ok());
    let err = enforce_optional_ontology_revision_pin(
        &db,
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "demo",
    )
    .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(err.message(), "ontology client revision pin is stale");
}

#[test]
fn tenantless_context_is_rejected_by_installed_enterprise_extension() {
    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(TestEnterpriseExtension)))
            .unwrap(),
    ));
    let mut request = Request::new(());
    request
        .extensions_mut()
        .insert(crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: "community-user".into(),
                credential_id: "community-credential".into(),
            },
        ));

    assert_eq!(
        request_tenant_context(&db, &request).unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
}

#[test]
fn enterprise_rejects_community_credentials_on_every_rpc() {
    use tonic::service::Interceptor;
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(TestEnterpriseExtension)))
            .unwrap(),
    )));
    db.create_principal_credential(
        "machine-a",
        &sekai_domain::gateway_keys::hash_gateway_key("machine-token"),
        1,
    )
    .unwrap();
    let mut interceptor = crate::grpc::TokenAuthInterceptor::new(
        Arc::new(crate::sekai::credentials::PrincipalCredentialStore::new()),
        crate::db::store::SekaiStore::from_shared_runtime(db),
    );
    let mut local = crate::grpc::LocalOrTokenAuthInterceptor {
        local: crate::grpc::LocalInterceptor::new(true),
        token: interceptor.clone(),
    };
    for (service, protocol) in [
        (
            "sekai.SekaiService",
            include_str!("../../proto/sekai.proto"),
        ),
        (
            "chisei.ChiseiService",
            include_str!("../../proto/chisei.proto"),
        ),
    ] {
        for method in protocol.lines().filter_map(|line| {
            line.trim()
                .strip_prefix("rpc ")
                .and_then(|rpc| rpc.split_once('(').map(|(name, _)| name.trim()))
        }) {
            if service == "sekai.SekaiService" && method == "IssueServicePrincipalToken" {
                // Client-credentials issuance authenticates from the request body.
                continue;
            }
            let mut request = Request::new(());
            request.metadata_mut().insert(
                "authorization",
                MetadataValue::from_static("Bearer machine-token"),
            );
            request
                .extensions_mut()
                .insert(tonic::GrpcMethod::new(service, method));
            assert_eq!(
                interceptor.call(request).unwrap_err().code(),
                tonic::Code::Unauthenticated,
                "{service}/{method}"
            );
            let mut request = Request::new(());
            request
                .extensions_mut()
                .insert(tonic::GrpcMethod::new(service, method));
            assert_eq!(
                local.call(request).unwrap_err().code(),
                tonic::Code::Unauthenticated,
                "local {service}/{method}"
            );
        }
    }
}

#[test]
fn missing_authenticated_context_is_ok_without_enterprise_extension() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    let request = Request::new(());
    assert!(request_tenant_context(&db, &request).unwrap().is_none());
    assert!(enforce_namespace_tenant_context(&db, None, "anything", false).is_ok());
}

#[test]
fn missing_authenticated_context_fails_closed_when_enterprise_is_enabled() {
    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(TestEnterpriseExtension)))
            .unwrap(),
    ));
    let request = Request::new(());
    assert_eq!(
        request_tenant_context(&db, &request).unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        enforce_namespace_tenant_context(&db, None, "allowed", false)
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
}

fn enterprise_service() -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(TestEnterpriseExtension)))
            .unwrap(),
    )));
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
}

fn test_tenant_context() -> crate::enterprise::AuthenticatedContext {
    crate::enterprise::AuthenticatedContext {
        contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
        home_tenant: None,
        principal: crate::enterprise::AuthenticatedPrincipal {
            subject: "subject-a".into(),
            credential_id: "credential-a".into(),
        },
        credential_kind: crate::enterprise::CredentialKind::HumanSession,
        space: None,
        space_role: None,
        act: None,
        tenant: Some(crate::enterprise::TenantContext {
            tenant_id: "tenant-test".into(),
            subject: "subject-a".into(),
        }),
        scopes: vec!["sekai.read".into()],
        issuer: "https://issuer.test".into(),
        resource: "https://sekai.test".into(),
        expires_at: 100,
    }
}

fn with_tenant_context<T>(payload: T) -> Request<T> {
    let mut req = with_named_principal(payload, "subject-a");
    req.extensions_mut().insert(test_tenant_context());
    req
}

fn seed_lineage_object(svc: &SekaiServiceImpl, id: &str, namespace: &str) {
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: id.into(),
            kind: "widget".into(),
            name: id.into(),
            namespace: namespace.into(),
            external_id: format!("widget:{id}"),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
}

#[tokio::test]
async fn get_object_without_authenticated_context_fails_closed_when_enterprise_is_enabled() {
    let svc = enterprise_service();
    seed_lineage_object(&svc, "tenant-object", "allowed");
    let err = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "tenant-object".into(),
            },
            "subject-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn get_lineage_loads_tenant_context_and_hides_unauthorized_root() {
    let svc = enterprise_service();
    seed_lineage_object(&svc, "denied-root", "denied");
    let get_err = svc
        .get_object(with_tenant_context(GetObjectRequest {
            id: "denied-root".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(get_err.code(), tonic::Code::NotFound);
    let lineage_err = svc
        .get_lineage(with_tenant_context(GetLineageRequest {
            object_id: "denied-root".into(),
            max_nodes: 10,
        }))
        .await
        .unwrap_err();
    assert_eq!(lineage_err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn get_lineage_without_authenticated_context_fails_closed_when_enterprise_is_enabled() {
    let svc = enterprise_service();
    seed_lineage_object(&svc, "lineage-root", "allowed");
    let err = svc
        .get_lineage(with_named_principal(
            GetLineageRequest {
                object_id: "lineage-root".into(),
                max_nodes: 10,
            },
            "subject-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn get_lineage_filters_nodes_outside_tenant_namespace() {
    let svc = enterprise_service();
    seed_lineage_object(&svc, "lineage-root", "allowed");
    seed_lineage_object(&svc, "other-tenant-node", "denied");
    svc.db
        .runtime()
        .create_link(&domain::Link {
            id: "lineage-edge".into(),
            from_id: "lineage-root".into(),
            to_id: "other-tenant-node".into(),
            relation: "derived_from".into(),
            created: 0,
        })
        .unwrap();
    let result = svc
        .get_lineage(with_tenant_context(GetLineageRequest {
            object_id: "lineage-root".into(),
            max_nodes: 10,
        }))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    let ids = result
        .nodes
        .iter()
        .filter_map(|node| node.object.as_ref().map(|object| object.id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(ids, ["lineage-root"]);
    assert!(result.edges.is_empty());
}

#[tokio::test]
async fn semantic_reads_apply_the_enterprise_tenant_gate() {
    // #1147: expand, explain, and retrieve apply the same tenant gate as
    // object reads before capability or ACL work.
    let svc = enterprise_service();
    seed_lineage_object(&svc, "semantic-root", "allowed");
    seed_lineage_object(&svc, "other-tenant-leaf", "denied");
    svc.db
        .runtime()
        .create_link(&domain::Link {
            id: "semantic-edge".into(),
            from_id: "semantic-root".into(),
            to_id: "other-tenant-leaf".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();
    let expand = |namespace: &str| ExpandRelationsRequest {
        namespace: namespace.into(),
        root: Some(ContextRoot {
            object_id: "semantic-root".into(),
            ..Default::default()
        }),
        relations: vec!["contains".into()],
        direction: "outgoing".into(),
        max_depth: 2,
        ..Default::default()
    };

    let missing = svc
        .expand_relations(with_named_principal(expand("allowed"), "subject-a"))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::Unauthenticated);
    let foreign = svc
        .expand_relations(with_tenant_context(expand("denied")))
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), tonic::Code::PermissionDenied);
    let explain = svc
        .explain_derivation(with_tenant_context(ExplainDerivationRequest {
            namespace: "denied".into(),
            from: Some(ContextRoot {
                object_id: "semantic-root".into(),
                ..Default::default()
            }),
            to: Some(ContextRoot {
                object_id: "other-tenant-leaf".into(),
                ..Default::default()
            }),
            relations: vec!["contains".into()],
            direction: "outgoing".into(),
            max_depth: 2,
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(explain.code(), tonic::Code::PermissionDenied);

    let retrieve = RetrieveContextRequest {
        roots: vec![ContextRoot {
            object_id: "semantic-root".into(),
            ..Default::default()
        }],
        relations: vec!["contains".into()],
        direction: "outgoing".into(),
        max_depth: 2,
        max_objects: 20,
        ..Default::default()
    };
    let missing = svc
        .retrieve_context(with_named_principal(retrieve.clone(), "subject-a"))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::Unauthenticated);
    let retrieved = svc
        .retrieve_context(with_tenant_context(retrieve))
        .await
        .unwrap()
        .into_inner();
    let ids = retrieved
        .candidates
        .iter()
        .filter_map(|candidate| candidate.object.as_ref().map(|object| object.id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(ids, ["semantic-root"]);
    assert!(!format!("{retrieved:?}").contains("other-tenant-leaf"));
}

fn with_principal<T>(payload: T) -> Request<T> {
    with_named_principal(payload, "tester")
}

fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    req
}

fn with_catalog_action<T>(
    payload: T,
    principal: &str,
    capability: &str,
    namespace: &str,
) -> Request<T> {
    let mut req = with_named_principal(payload, principal);
    req.metadata_mut().insert(
        "x-sekai-capability",
        MetadataValue::try_from(capability).unwrap(),
    );
    req.metadata_mut().insert(
        "x-sekai-namespace",
        MetadataValue::try_from(namespace).unwrap(),
    );
    req
}

fn with_operation_identity<T>(payload: T, operation_id: &str) -> Request<T> {
    let mut req = with_principal(payload);
    req.metadata_mut().insert(
        crate::sekai::operation_correlation::OPERATION_METADATA,
        MetadataValue::try_from(operation_id).unwrap(),
    );
    req.metadata_mut().insert(
        crate::sekai::operation_correlation::TRACEPARENT,
        MetadataValue::try_from("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap(),
    );
    req
}

fn span_operation_id(logs: &str, expected: &str) -> String {
    if logs.contains(&format!("sekai.operation_id=\"{expected}\""))
        || logs.contains(&format!("sekai.operation_id={expected}"))
    {
        expected.to_string()
    } else {
        String::new()
    }
}

async fn capture_submit_logs<F, Fut>(work: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("log buffer").write(data)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let buf = Buf(Arc::new(Mutex::new(Vec::new())));
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // #1200: callsite interest is cached process-wide. A callsite another
    // test thread hit first can be cached as uninterested before this
    // thread-local subscriber existed, so it would record nothing.
    tracing::callsite::rebuild_interest_cache();
    work().await;
    String::from_utf8(buf.0.lock().expect("log buffer").clone()).expect("utf8 logs")
}

const SOURCE_TYPE_DIGEST: &str = source_sync_domain::GITHUB_OBJECT_SYNC_TYPE_DIGEST;
const SOURCE_PAYLOAD_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn seed_agent_eval_run(svc: &SekaiServiceImpl, id: &str, suite_id: &str, passed: bool) {
    svc.db
        .runtime()
        .put_eval_run(&crate::chisei::eval::Run {
            id: id.into(),
            suite_id: suite_id.into(),
            config_ref: "native-default".into(),
            results: vec![crate::chisei::eval::CaseResult {
                case_id: "case-1".into(),
                passed,
                status: if passed { "done" } else { "failed" }.into(),
                result: "result".into(),
                score: if passed { 100 } else { 0 },
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 1,
        })
        .unwrap();
}

fn grant_source_namespace(
    svc: &SekaiServiceImpl,
    namespace: &str,
    principal: &str,
    role: security::Role,
) {
    let (_, grants) = svc
        .db
        .runtime()
        .ensure_team_namespace(namespace, principal, role, "local")
        .unwrap();
    for grant in grants {
        svc.security.add_grant(&grant);
    }
}

fn seed_definition_parent(
    svc: &SekaiServiceImpl,
    namespace: &str,
) -> definition_branch_domain::DefinitionRevision {
    let member = definition_branch_domain::DefinitionMemberInput {
        member_kind: "object_type".into(),
        member_id: "Ticket".into(),
        definition_json: r#"{"name":"Ticket"}"#.into(),
        member_digest: String::new(),
    }
    .prepare(namespace)
    .unwrap();
    let revision = definition_branch_domain::prepare_revision(
        namespace,
        "",
        [definition_branch_domain::DefinitionRevisionMember {
            member_kind: member.member_kind.clone(),
            member_id: member.member_id.clone(),
            member_digest: member.member_digest.clone(),
        }],
        true,
        "root",
        1,
    )
    .unwrap();
    let RuntimeDb::Sqlite(db) = svc.db.runtime() else {
        panic!("test service must use SQLite");
    };
    db.seed_published_definition_revision(&revision, &[member])
        .unwrap();
    revision
}

/// Exercise definition reads through the actual assertion interceptor, then
/// the handler, so transport admission cannot bypass resource authorization.
#[tokio::test]
async fn published_definition_assertions_preserve_namespace_and_member_authorization() {
    use crate::enterprise::{
        AuthenticatedPrincipal, EnterpriseExtension, ExtensionError, NamespaceAction, TenantContext,
    };
    use crate::identity_assertion::{
        AssertionAuthority, IDENTITY_ASSERTION_VERSION, IdentityAssertion,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use tonic::service::Interceptor;

    struct DefinitionReadExtension(Arc<AtomicBool>);
    impl EnterpriseExtension for DefinitionReadExtension {
        fn authenticate_bearer(&self, _: &str) -> Result<AuthenticatedPrincipal, ExtensionError> {
            Err(ExtensionError::CredentialNotFound)
        }
        fn authenticate_context(
            &self,
            _: &str,
        ) -> Result<crate::enterprise::AuthenticatedContext, ExtensionError> {
            Err(ExtensionError::CredentialNotFound)
        }
        fn tenant_context(
            &self,
            _: &AuthenticatedPrincipal,
        ) -> Result<TenantContext, ExtensionError> {
            Err(ExtensionError::Unauthenticated)
        }
        fn authorize_namespace(
            &self,
            context: &TenantContext,
            namespace: &str,
            action: NamespaceAction,
        ) -> Result<(), ExtensionError> {
            if self.0.load(Ordering::SeqCst)
                && context.tenant_id == "tenant-test"
                && context.subject == "subject-a"
                && namespace == "allowed"
                && action == NamespaceAction::Read
            {
                Ok(())
            } else {
                Err(ExtensionError::PermissionDenied)
            }
        }
        fn authorize_unscoped_namespace(
            &self,
            _: &AuthenticatedPrincipal,
            _: &str,
            _: NamespaceAction,
        ) -> Result<(), ExtensionError> {
            Err(ExtensionError::PermissionDenied)
        }
    }

    let active = Arc::new(AtomicBool::new(true));
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(
            ":memory:",
            Some(Arc::new(DefinitionReadExtension(active.clone()))),
        )
        .unwrap(),
    )));
    let store = crate::db::store::SekaiStore::from_shared_runtime(db);
    let svc = SekaiServiceImpl::new(store.clone());
    let parent = seed_definition_parent(&svc, "allowed");
    let authority =
        AssertionAuthority::new("https://issuer.test", "https://sekai.test", b"test-key");
    let mut interceptor = crate::grpc::TokenAuthInterceptor::from_runtime(
        Arc::new(crate::sekai::credentials::PrincipalCredentialStore::new()),
        store,
        Some(Arc::new(authority.clone())),
    );
    let claims = |nonce: &str| IdentityAssertion {
        contract_version: IDENTITY_ASSERTION_VERSION.into(),
        issuer: "https://issuer.test".into(),
        audience: "https://sekai.test".into(),
        subject: "subject-a".into(),
        credential_id: "credential-a".into(),
        credential_kind: "human_session".into(),
        space: None,
        space_role: None,
        act: None,
        tenant_id: Some("tenant-test".into()),
        scopes: vec!["sekai.read".into()],
        expires_at: chrono::Utc::now().timestamp() + 60,
        nonce: nonce.into(),
    };
    let request = |token: &str, method: &'static str| {
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
        );
        req.metadata_mut()
            .insert("x-principal", MetadataValue::from_static("root"));
        req.extensions_mut()
            .insert(tonic::GrpcMethod::new("sekai.SekaiService", method));
        req
    };
    let read = |authenticated: Request<()>, namespace: &str| {
        let (metadata, extensions, ()) = authenticated.into_parts();
        Request::from_parts(
            metadata,
            extensions,
            GetPublishedDefinitionRevisionRequest {
                namespace: namespace.into(),
            },
        )
    };
    let token = authority.sign(&claims("valid")).unwrap();
    let authenticated = interceptor
        .call(request(&token, "GetPublishedDefinitionRevision"))
        .unwrap();
    let context = authenticated
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
        .unwrap();
    assert_eq!(context.principal.subject, "subject-a");
    assert_eq!(context.tenant.as_ref().unwrap().tenant_id, "tenant-test");
    assert_eq!(
        authenticated.metadata().get("x-principal").unwrap(),
        "subject-a"
    );
    let revision = svc
        .get_published_definition_revision(read(authenticated, "allowed"))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap();
    assert_eq!(revision.revision_digest, parent.revision_digest);
    assert_eq!(
        interceptor
            .call(request(&token, "GetPublishedDefinitionRevision"))
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );

    for (nonce, namespace, scopes, tenant) in [
        (
            "foreign-namespace",
            "denied",
            vec!["sekai.read".into()],
            "tenant-test",
        ),
        (
            "foreign-tenant",
            "allowed",
            vec!["sekai.read".into()],
            "other-tenant",
        ),
        ("missing-scope", "allowed", vec![], "tenant-test"),
    ] {
        let mut assertion = claims(nonce);
        assertion.scopes = scopes;
        assertion.tenant_id = Some(tenant.into());
        let token = authority.sign(&assertion).unwrap();
        let authenticated = interceptor.call(request(&token, "GetPublishedDefinitionRevision"));
        if nonce == "missing-scope" {
            assert_eq!(
                authenticated.unwrap_err().code(),
                tonic::Code::PermissionDenied
            );
            continue;
        }
        assert_eq!(
            svc.get_published_definition_revision(read(authenticated.unwrap(), namespace))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    for (nonce, object_id, expected) in [
        (
            "namespace-grant",
            "namespace:allowed",
            tonic::Code::PermissionDenied,
        ),
        ("member-grant", "schema:Ticket", tonic::Code::NotFound),
    ] {
        let grant = security::Grant {
            id: nonce.into(),
            object_id: object_id.into(),
            principal: "other-reader".into(),
            role: security::Role::Viewer,
            created: 1,
            ..Default::default()
        };
        svc.security.add_grant(&grant);
        let token = authority.sign(&claims(nonce)).unwrap();
        let authenticated = interceptor
            .call(request(&token, "GetPublishedDefinitionRevision"))
            .unwrap();
        assert_eq!(
            svc.get_published_definition_revision(read(authenticated, "allowed"))
                .await
                .unwrap_err()
                .code(),
            expected
        );
        svc.security.remove_grant(object_id, "other-reader");
    }
    active.store(false, Ordering::SeqCst);
    let token = authority.sign(&claims("revoked-membership")).unwrap();
    let authenticated = interceptor
        .call(request(&token, "GetPublishedDefinitionRevision"))
        .unwrap();
    assert_eq!(
        svc.get_published_definition_revision(read(authenticated, "allowed"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    active.store(true, Ordering::SeqCst);

    for (nonce, audience, expires_at) in [
        (
            "wrong-audience",
            "https://other.test",
            chrono::Utc::now().timestamp() + 60,
        ),
        (
            "expired",
            "https://sekai.test",
            chrono::Utc::now().timestamp() - 120,
        ),
    ] {
        let mut assertion = claims(nonce);
        assertion.audience = audience.into();
        assertion.expires_at = expires_at;
        let token = authority.sign(&assertion).unwrap();
        assert_eq!(
            interceptor
                .call(request(&token, "GetPublishedDefinitionRevision"))
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }
    for method in [
        "CreateDefinitionProposal",
        "ApproveDefinitionProposal",
        "MergeDefinitionProposal",
    ] {
        let token = authority.sign(&claims(method)).unwrap();
        assert_eq!(
            interceptor
                .call(request(&token, method))
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
}

#[tokio::test]
async fn definition_branch_rpc_preserves_parent_and_rejects_stale_head() {
    let svc = service();
    let parent = seed_definition_parent(&svc, "definition-team");
    let created = svc
        .create_definition_branch(with_named_principal(
            CreateDefinitionBranchRequest {
                namespace: "definition-team".into(),
                branch_id: "feature".into(),
                parent_revision_digest: parent.revision_digest.clone(),
                idempotency_key: "create-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .branch
        .unwrap();
    assert_eq!(created.head_revision_digest, parent.revision_digest);
    assert!(created.pin_digest.starts_with("sha256:"));
    assert_eq!(created.pin_digest.len(), 71);

    let edit = ApplyDefinitionBranchEditRequest {
        namespace: "definition-team".into(),
        branch_id: "feature".into(),
        expected_head_digest: parent.revision_digest.clone(),
        upserts: vec![DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
            member_digest: String::new(),
        }],
        removals: Vec::new(),
        idempotency_key: "edit-1".into(),
    };
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(edit.clone(), "root"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(applied.previous_head_digest, parent.revision_digest);
    assert!(!applied.revision.unwrap().published);
    assert_eq!(applied.changed_member_digests.len(), 1);
    let current = svc
        .get_definition_branch(with_named_principal(
            GetDefinitionBranchRequest {
                namespace: "definition-team".into(),
                branch_id: "feature".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .branch
        .unwrap();
    let applied_branch = applied.branch.clone().unwrap();
    assert_eq!(
        current.head_revision_digest,
        applied_branch.head_revision_digest
    );
    assert_eq!(current.pin_digest, applied_branch.pin_digest);
    assert_ne!(current.pin_digest, created.pin_digest);

    let mut stale = edit;
    stale.idempotency_key = "edit-2".into();
    let error = svc
        .apply_definition_branch_edit(with_named_principal(stale, "root"))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        svc.db
            .runtime()
            .get_definition_revision("definition-team", &parent.revision_digest)
            .unwrap()
            .unwrap(),
        parent
    );
}

#[tokio::test]
async fn definition_branch_edit_rechecks_member_admin() {
    let svc = service();
    let parent = seed_definition_parent(&svc, "definition-denial");
    let read_grant = security::Grant {
        id: "definition-ticket-reader".into(),
        object_id: schema_object_id("Ticket"),
        principal: "tester".into(),
        role: security::Role::Viewer,
        created: 1,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&read_grant).unwrap();
    svc.security.add_grant(&read_grant);
    svc.create_definition_branch(with_principal(CreateDefinitionBranchRequest {
        namespace: "definition-denial".into(),
        branch_id: "feature".into(),
        parent_revision_digest: parent.revision_digest.clone(),
        idempotency_key: "create-1".into(),
    }))
    .await
    .unwrap();

    let error = svc
        .apply_definition_branch_edit(with_principal(ApplyDefinitionBranchEditRequest {
            namespace: "definition-denial".into(),
            branch_id: "feature".into(),
            expected_head_digest: parent.revision_digest.clone(),
            upserts: vec![DefinitionMemberInput {
                member_kind: "object_type".into(),
                member_id: "Ticket".into(),
                definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
                member_digest: String::new(),
            }],
            removals: Vec::new(),
            idempotency_key: "edit-1".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(error.message(), "schema admin required");

    let object_admin_grant = security::Grant {
        id: "definition-ticket-admin".into(),
        object_id: schema_object_id("Ticket"),
        principal: "tester".into(),
        role: security::Role::Admin,
        created: 2,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&object_admin_grant).unwrap();
    svc.security.add_grant(&object_admin_grant);
    let error = svc
        .apply_definition_branch_edit(with_principal(ApplyDefinitionBranchEditRequest {
            namespace: "definition-denial".into(),
            branch_id: "feature".into(),
            expected_head_digest: parent.revision_digest,
            upserts: vec![DefinitionMemberInput {
                member_kind: "interface_type".into(),
                member_id: "Ticket".into(),
                definition_json: r#"{"name":"Ticket"}"#.into(),
                member_digest: String::new(),
            }],
            removals: Vec::new(),
            idempotency_key: "edit-interface".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(error.message(), "schema admin required");
}

#[tokio::test]
async fn compare_definition_revisions_hides_unauthorized_members() {
    let svc = service();
    let parent = seed_definition_parent(&svc, "definition-diff");
    grant_source_namespace(&svc, "definition-diff", "tester", security::Role::Editor);
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: "definition-diff".into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: "definition-diff".into(),
                branch_id: "feature".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "object_type".into(),
                    member_id: "Ticket".into(),
                    definition_json: r#"{"name":"Ticket","properties":["title","body"]}"#.into(),
                    member_digest: String::new(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let denied = svc
        .compare_definition_revisions(with_named_principal(
            CompareDefinitionRevisionsRequest {
                namespace: "definition-diff".into(),
                from_revision_digest: parent.revision_digest.clone(),
                to_revision_digest: applied.revision.as_ref().unwrap().revision_digest.clone(),
            },
            "nobody",
        ))
        .await
        .unwrap_err();
    assert!(
        denied.code() == tonic::Code::PermissionDenied || denied.code() == tonic::Code::NotFound,
        "{}",
        denied.code()
    );
    let compared = svc
        .compare_definition_revisions(with_named_principal(
            CompareDefinitionRevisionsRequest {
                namespace: "definition-diff".into(),
                from_revision_digest: parent.revision_digest.clone(),
                to_revision_digest: applied.revision.as_ref().unwrap().revision_digest.clone(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let diff = compared.diff.unwrap();
    assert_eq!(diff.changed[0].member_id, "Ticket");
    assert_eq!(diff.changed[0].added_properties, ["body", "title"]);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    let classified = svc
        .classify_definition_revision_compatibility(with_named_principal(
            ClassifyDefinitionRevisionCompatibilityRequest {
                namespace: "definition-diff".into(),
                from_revision_digest: parent.revision_digest.clone(),
                to_revision_digest: applied.revision.as_ref().unwrap().revision_digest.clone(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let compatibility = classified.compatibility.unwrap();
    assert_eq!(compatibility.class, "compatible");
    assert_eq!(compatibility.reasons[0].code, "added_optional_property");
    assert_eq!(compatibility.reasons[0].property, "body");
    let denied_classify = svc
        .classify_definition_revision_compatibility(with_named_principal(
            ClassifyDefinitionRevisionCompatibilityRequest {
                namespace: "definition-diff".into(),
                from_revision_digest: parent.revision_digest,
                to_revision_digest: applied.revision.unwrap().revision_digest,
            },
            "nobody",
        ))
        .await
        .unwrap_err();
    assert!(
        denied_classify.code() == tonic::Code::PermissionDenied
            || denied_classify.code() == tonic::Code::NotFound,
        "{}",
        denied_classify.code()
    );
    assert!(!denied_classify.message().contains("Ticket"));
    assert!(!denied_classify.message().contains("body"));
}

#[tokio::test]
async fn definition_fact_migration_hides_unauthorized_revisions() {
    let svc = service();
    let namespace = "fact-mig-hide";
    grant_source_namespace(&svc, namespace, "root", security::Role::Admin);
    grant_source_namespace(&svc, namespace, "tester", security::Role::Viewer);
    let ticket_admin = security::Grant {
        id: "fact-mig-ticket-admin".into(),
        object_id: schema_object_id("Ticket"),
        principal: "root".into(),
        role: security::Role::Admin,
        created: 1,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&ticket_admin).unwrap();
    svc.security.add_grant(&ticket_admin);

    let parent_member = definition_branch_domain::DefinitionMemberInput {
        member_kind: "object_type".into(),
        member_id: "Ticket".into(),
        definition_json: r#"{"name":"Ticket","properties":["title","secret"]}"#.into(),
        member_digest: String::new(),
    }
    .prepare(namespace)
    .unwrap();
    let parent = definition_branch_domain::prepare_revision(
        namespace,
        "",
        [definition_branch_domain::DefinitionRevisionMember {
            member_kind: parent_member.member_kind.clone(),
            member_id: parent_member.member_id.clone(),
            member_digest: parent_member.member_digest.clone(),
        }],
        true,
        "root",
        1,
    )
    .unwrap();
    svc.db
        .runtime()
        .seed_published_definition_revision(&parent, &[parent_member])
        .unwrap();
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "migrate".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: "migrate".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "object_type".into(),
                    member_id: "Ticket".into(),
                    definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
                    member_digest: String::new(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let candidate = applied.revision.unwrap().revision_digest;
    svc.create_definition_proposal(with_named_principal(
        CreateDefinitionProposalRequest {
            namespace: namespace.into(),
            branch_id: "migrate".into(),
            proposal_id: "mig".into(),
            base_digest: parent.revision_digest.clone(),
            candidate_digest: candidate.clone(),
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: "propose-1".into(),
            major_revision: false,
        },
        "root",
    ))
    .await
    .unwrap();
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: namespace.into(),
            proposal_id: "mig".into(),
            idempotency_key: "approve-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.merge_definition_proposal(with_named_principal(
        MergeDefinitionProposalRequest {
            namespace: namespace.into(),
            proposal_id: "mig".into(),
            expected_published_digest: parent.revision_digest.clone(),
            idempotency_key: "merge-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.db
        .runtime()
        .create_object(&crate::domain::Object {
            id: format!("{namespace}:open"),
            kind: "Ticket".into(),
            name: "open".into(),
            namespace: namespace.into(),
            external_id: format!("{namespace}:open"),
            properties: HashMap::from([
                ("title".into(), "hello".into()),
                ("secret".into(), "classified".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();

    let denied_execute = svc
        .execute_definition_fact_migration(with_named_principal(
            ExecuteDefinitionFactMigrationRequest {
                namespace: namespace.into(),
                migration_id: "m1".into(),
                from_revision_digest: parent.revision_digest.clone(),
                to_revision_digest: candidate.clone(),
                mode: "execute".into(),
                idempotency_key: "run".into(),
            },
            "tester",
        ))
        .await
        .unwrap_err();
    assert!(
        denied_execute.code() == tonic::Code::PermissionDenied
            || denied_execute.code() == tonic::Code::NotFound,
        "{}",
        denied_execute.code()
    );
    assert!(!denied_execute.message().contains("classified"));

    svc.execute_definition_fact_migration(with_named_principal(
        ExecuteDefinitionFactMigrationRequest {
            namespace: namespace.into(),
            migration_id: "m1".into(),
            from_revision_digest: parent.revision_digest.clone(),
            to_revision_digest: candidate,
            mode: "execute".into(),
            idempotency_key: "run".into(),
        },
        "root",
    ))
    .await
    .unwrap();

    let missing = svc
        .get_definition_fact_migration(with_named_principal(
            GetDefinitionFactMigrationRequest {
                namespace: namespace.into(),
                migration_id: "missing".into(),
            },
            "tester",
        ))
        .await
        .unwrap_err();
    let hidden = svc
        .get_definition_fact_migration(with_named_principal(
            GetDefinitionFactMigrationRequest {
                namespace: namespace.into(),
                migration_id: "m1".into(),
            },
            "tester",
        ))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
    assert_eq!(hidden.code(), tonic::Code::NotFound);
    assert_eq!(missing.message(), "definition resource unavailable");
    assert_eq!(hidden.message(), missing.message());
    assert!(!hidden.message().contains("classified"));
    assert!(!hidden.message().contains(&parent.revision_digest));

    let loaded = svc
        .get_definition_fact_migration(with_named_principal(
            GetDefinitionFactMigrationRequest {
                namespace: namespace.into(),
                migration_id: "m1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .migration
        .unwrap();
    assert_eq!(loaded.status, "committed");
}

#[tokio::test]
async fn definition_proposal_close_rechecks_member_admin() {
    let svc = service();
    let parent = seed_definition_parent(&svc, "proposal-close");
    grant_source_namespace(&svc, "proposal-close", "tester", security::Role::Editor);
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: "proposal-close".into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: "proposal-close".into(),
                branch_id: "feature".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "object_type".into(),
                    member_id: "Ticket".into(),
                    definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
                    member_digest: String::new(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    svc.create_definition_proposal(with_named_principal(
        CreateDefinitionProposalRequest {
            namespace: "proposal-close".into(),
            branch_id: "feature".into(),
            proposal_id: "cs-1".into(),
            base_digest: parent.revision_digest,
            candidate_digest: applied.revision.unwrap().revision_digest,
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: "propose-1".into(),
            major_revision: false,
        },
        "root",
    ))
    .await
    .unwrap();
    let error = svc
        .close_definition_proposal(with_principal(CloseDefinitionProposalRequest {
            namespace: "proposal-close".into(),
            proposal_id: "cs-1".into(),
            reason_code: "operator_abort".into(),
            idempotency_key: "close-1".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(error.message(), "schema admin required");
}

#[tokio::test]
async fn definition_proposal_merge_accepts_one_live_approval() {
    let svc = service();
    let parent = seed_definition_parent(&svc, "proposal-live");
    grant_source_namespace(&svc, "proposal-live", "tester", security::Role::Editor);
    for (id, principal) in [
        ("proposal-live-ticket-root", "root"),
        ("proposal-live-ticket-tester", "tester"),
    ] {
        let grant = security::Grant {
            id: id.into(),
            object_id: schema_object_id("Ticket"),
            principal: principal.into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: "proposal-live".into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: "proposal-live".into(),
                branch_id: "feature".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "object_type".into(),
                    member_id: "Ticket".into(),
                    definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
                    member_digest: String::new(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    svc.create_definition_proposal(with_named_principal(
        CreateDefinitionProposalRequest {
            namespace: "proposal-live".into(),
            branch_id: "feature".into(),
            proposal_id: "cs-1".into(),
            base_digest: parent.revision_digest.clone(),
            candidate_digest: applied.revision.unwrap().revision_digest,
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: "propose-1".into(),
            major_revision: false,
        },
        "root",
    ))
    .await
    .unwrap();
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: "proposal-live".into(),
            proposal_id: "cs-1".into(),
            idempotency_key: "approve-root".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.approve_definition_proposal(with_principal(ApproveDefinitionProposalRequest {
        namespace: "proposal-live".into(),
        proposal_id: "cs-1".into(),
        idempotency_key: "approve-tester".into(),
    }))
    .await
    .unwrap();
    svc.security
        .remove_grant(&schema_object_id("Ticket"), "tester");
    let merged = svc
        .merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: "proposal-live".into(),
                proposal_id: "cs-1".into(),
                expected_published_digest: parent.revision_digest,
                idempotency_key: "merge-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(merged.proposal.unwrap().status, "merged");
}

#[tokio::test]
async fn definition_proposal_rpc_publishes_or_rejects_without_partial_head_move() {
    let svc = service();
    let parent = seed_definition_parent(&svc, "proposal-team");
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: "proposal-team".into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: "proposal-team".into(),
                branch_id: "feature".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "object_type".into(),
                    member_id: "Ticket".into(),
                    definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
                    member_digest: String::new(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let candidate = applied.revision.unwrap().revision_digest;
    svc.create_definition_proposal(with_named_principal(
        CreateDefinitionProposalRequest {
            namespace: "proposal-team".into(),
            branch_id: "feature".into(),
            proposal_id: "cs-1".into(),
            base_digest: parent.revision_digest.clone(),
            candidate_digest: candidate.clone(),
            eval_plan_digests: vec![format!("sha256:{}", "e".repeat(64))],
            named_foreign_digests: vec![format!("sha256:{}", "f".repeat(64))],
            idempotency_key: "propose-1".into(),
            major_revision: false,
        },
        "root",
    ))
    .await
    .unwrap();
    let missing = svc
        .merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: "proposal-team".into(),
                proposal_id: "cs-1".into(),
                expected_published_digest: parent.revision_digest.clone(),
                idempotency_key: "merge-missing".into(),
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        svc.get_published_definition_revision(with_named_principal(
            GetPublishedDefinitionRevisionRequest {
                namespace: "proposal-team".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .revision_digest,
        parent.revision_digest
    );
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: "proposal-team".into(),
            proposal_id: "cs-1".into(),
            idempotency_key: "approve-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let stale = svc
        .merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: "proposal-team".into(),
                proposal_id: "cs-1".into(),
                expected_published_digest: candidate.clone(),
                idempotency_key: "merge-stale-head".into(),
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        svc.get_published_definition_revision(with_named_principal(
            GetPublishedDefinitionRevisionRequest {
                namespace: "proposal-team".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .revision_digest,
        parent.revision_digest
    );
    let merged = svc
        .merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: "proposal-team".into(),
                proposal_id: "cs-1".into(),
                expected_published_digest: parent.revision_digest.clone(),
                idempotency_key: "merge-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(merged.proposal.as_ref().unwrap().status, "merged");
    assert!(!merged.receipt_id.is_empty());
    assert_eq!(
        merged.proposal.as_ref().unwrap().receipt_id,
        merged.receipt_id
    );
    assert_eq!(merged.previous_published_digest, parent.revision_digest);
    assert_eq!(
        merged.published_revision.unwrap().revision_digest,
        candidate
    );
    assert_eq!(
        svc.get_published_definition_revision(with_named_principal(
            GetPublishedDefinitionRevisionRequest {
                namespace: "proposal-team".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .revision_digest,
        candidate
    );
}

async fn publish_definition_history_entry(
    svc: &SekaiServiceImpl,
    namespace: &str,
    parent: &str,
    branch_id: &str,
    proposal_id: &str,
    upserts: Vec<DefinitionMemberInput>,
) -> (String, String) {
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: branch_id.into(),
            parent_revision_digest: parent.into(),
            idempotency_key: format!("{branch_id}-create"),
        },
        "root",
    ))
    .await
    .unwrap();
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: branch_id.into(),
                expected_head_digest: parent.into(),
                upserts,
                removals: Vec::new(),
                idempotency_key: format!("{branch_id}-edit"),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let candidate = applied.revision.unwrap().revision_digest;
    svc.create_definition_proposal(with_named_principal(
        CreateDefinitionProposalRequest {
            namespace: namespace.into(),
            branch_id: branch_id.into(),
            proposal_id: proposal_id.into(),
            base_digest: parent.into(),
            candidate_digest: candidate.clone(),
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: format!("{branch_id}-propose"),
            major_revision: false,
        },
        "root",
    ))
    .await
    .unwrap();
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: namespace.into(),
            proposal_id: proposal_id.into(),
            idempotency_key: format!("{branch_id}-approve"),
        },
        "root",
    ))
    .await
    .unwrap();
    let merged = svc
        .merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: namespace.into(),
                proposal_id: proposal_id.into(),
                expected_published_digest: parent.into(),
                idempotency_key: format!("{branch_id}-merge"),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    (
        merged.published_revision.unwrap().revision_digest,
        merged.receipt_id,
    )
}

#[tokio::test]
async fn propose_definition_rollback_restores_as_descendant_and_gates_live_values() {
    let svc = service();
    let namespace = "rollback-team";
    let parent = seed_definition_parent(&svc, namespace);
    let (first, _) = publish_definition_history_entry(
        &svc,
        namespace,
        &parent.revision_digest,
        "rb-a",
        "rb-cs-a",
        vec![DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
            member_digest: String::new(),
        }],
    )
    .await;
    let (second, _) = publish_definition_history_entry(
        &svc,
        namespace,
        &first,
        "rb-b",
        "rb-cs-b",
        vec![DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"name":"Ticket","properties":["title","secret"]}"#.into(),
            member_digest: String::new(),
        }],
    )
    .await;

    let proposed = svc
        .propose_definition_rollback(with_named_principal(
            ProposeDefinitionRollbackRequest {
                namespace: namespace.into(),
                branch_id: "rb-restore".into(),
                proposal_id: "rb-cs-restore".into(),
                restore_from_digest: first.clone(),
                migration_plan_digest: String::new(),
                idempotency_key: "rb-restore-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let proposal = proposed.proposal.unwrap();
    let preview = proposed.preview.unwrap();
    assert_eq!(proposal.base_digest, second);
    assert_eq!(proposal.restored_from_digest, first);
    assert_ne!(proposal.candidate_digest, first);
    assert_eq!(preview.from_revision_digest, second);
    assert_eq!(preview.to_revision_digest, proposal.candidate_digest);
    assert!(preview.changed.iter().any(|change| {
        change.member_id == "Ticket"
            && change
                .removed_properties
                .iter()
                .any(|property| property == "secret")
    }));
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: namespace.into(),
            proposal_id: "rb-cs-restore".into(),
            idempotency_key: "rb-restore-approve".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let merged = svc
        .merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: namespace.into(),
                proposal_id: "rb-cs-restore".into(),
                expected_published_digest: second.clone(),
                idempotency_key: "rb-restore-merge".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let published = merged.published_revision.unwrap();
    assert_ne!(published.revision_digest, first);
    assert_eq!(published.parent_revision_digest, second);
    assert_eq!(merged.proposal.unwrap().restored_from_digest, first);

    let live_namespace = "rollback-live-team";
    let live_parent = seed_definition_parent(&svc, live_namespace);
    let (live_a, _) = publish_definition_history_entry(
        &svc,
        live_namespace,
        &live_parent.revision_digest,
        "rb-live-a",
        "rb-live-cs-a",
        vec![DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
            member_digest: String::new(),
        }],
    )
    .await;
    let (live_b, _) = publish_definition_history_entry(
        &svc,
        live_namespace,
        &live_a,
        "rb-live-b",
        "rb-live-cs-b",
        vec![DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"name":"Ticket","properties":["title","secret"]}"#.into(),
            member_digest: String::new(),
        }],
    )
    .await;
    svc.db
        .runtime()
        .create_object(&crate::domain::Object {
            id: format!("{live_namespace}:open"),
            kind: "Ticket".into(),
            name: "open".into(),
            namespace: live_namespace.into(),
            external_id: format!("{live_namespace}:open"),
            properties: HashMap::from([
                ("title".into(), "hello".into()),
                ("secret".into(), "classified".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.propose_definition_rollback(with_named_principal(
        ProposeDefinitionRollbackRequest {
            namespace: live_namespace.into(),
            branch_id: "rb-live".into(),
            proposal_id: "rb-live-cs".into(),
            restore_from_digest: live_a.clone(),
            migration_plan_digest: String::new(),
            idempotency_key: "rb-live-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: live_namespace.into(),
            proposal_id: "rb-live-cs".into(),
            idempotency_key: "rb-live-approve".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    assert_eq!(
        svc.merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: live_namespace.into(),
                proposal_id: "rb-live-cs".into(),
                expected_published_digest: live_b.clone(),
                idempotency_key: "rb-live-merge".into(),
            },
            "root",
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::FailedPrecondition
    );
    svc.propose_definition_rollback(with_named_principal(
        ProposeDefinitionRollbackRequest {
            namespace: live_namespace.into(),
            branch_id: "rb-live-plan".into(),
            proposal_id: "rb-live-cs-plan".into(),
            restore_from_digest: live_a.clone(),
            migration_plan_digest: format!("sha256:{}", "c".repeat(64)),
            idempotency_key: "rb-live-plan-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: live_namespace.into(),
            proposal_id: "rb-live-cs-plan".into(),
            idempotency_key: "rb-live-plan-approve".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let planned = svc
        .merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: live_namespace.into(),
                proposal_id: "rb-live-cs-plan".into(),
                expected_published_digest: live_b,
                idempotency_key: "rb-live-plan-merge".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(planned.proposal.unwrap().restored_from_digest, live_a);
}

#[tokio::test]
async fn list_published_definition_revisions_chains_filters_and_paginates() {
    let svc = service();
    let namespace = "history-team";
    let parent = seed_definition_parent(&svc, namespace);
    let (first, first_receipt) = publish_definition_history_entry(
        &svc,
        namespace,
        &parent.revision_digest,
        "hist-1",
        "hist-cs-1",
        vec![DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
            member_digest: String::new(),
        }],
    )
    .await;
    let (second, second_receipt) = publish_definition_history_entry(
        &svc,
        namespace,
        &first,
        "hist-2",
        "hist-cs-2",
        vec![
            DefinitionMemberInput {
                member_kind: "object_type".into(),
                member_id: "Ticket".into(),
                definition_json: r#"{"name":"Ticket","properties":["title","body"]}"#.into(),
                member_digest: String::new(),
            },
            DefinitionMemberInput {
                member_kind: "ontology_class".into(),
                member_id: "TicketClass".into(),
                definition_json: r#"{"name":"TicketClass"}"#.into(),
                member_digest: String::new(),
            },
        ],
    )
    .await;
    let (third, third_receipt) = publish_definition_history_entry(
        &svc,
        namespace,
        &second,
        "hist-3",
        "hist-cs-3",
        vec![DefinitionMemberInput {
            member_kind: "action_type".into(),
            member_id: "AssignTicket".into(),
            definition_json: r#"{"name":"AssignTicket"}"#.into(),
            member_digest: String::new(),
        }],
    )
    .await;

    let listed = svc
        .list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: String::new(),
                member_id: String::new(),
                page_token: String::new(),
                page_size: 0,
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(listed.next_page_token.is_empty());
    assert_eq!(listed.entries.len(), 3);
    assert_eq!(
        listed
            .entries
            .iter()
            .map(|entry| entry.revision_digest.as_str())
            .collect::<Vec<_>>(),
        vec![third.as_str(), second.as_str(), first.as_str()]
    );
    assert_eq!(listed.entries[0].previous_published_digest, second);
    assert_eq!(listed.entries[1].previous_published_digest, first);
    assert_eq!(
        listed.entries[2].previous_published_digest,
        parent.revision_digest
    );
    assert_eq!(
        listed
            .entries
            .iter()
            .map(|entry| entry.receipt_id.as_str())
            .collect::<Vec<_>>(),
        [
            third_receipt.as_str(),
            second_receipt.as_str(),
            first_receipt.as_str()
        ]
    );
    for entry in &listed.entries {
        assert_eq!(entry.actor, "root");
        let proposal = svc
            .get_definition_proposal(with_named_principal(
                GetDefinitionProposalRequest {
                    namespace: namespace.into(),
                    proposal_id: entry.proposal_id.clone(),
                },
                "root",
            ))
            .await
            .unwrap()
            .into_inner()
            .proposal
            .unwrap();
        assert_eq!(proposal.receipt_id, entry.receipt_id);
        assert_eq!(proposal.status, "merged");
    }

    let ticket = svc
        .list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: "object_type".into(),
                member_id: "Ticket".into(),
                page_token: String::new(),
                page_size: 50,
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        ticket
            .entries
            .iter()
            .map(|entry| entry.revision_digest.as_str())
            .collect::<Vec<_>>(),
        vec![second.as_str(), first.as_str()]
    );

    let first_page = svc
        .list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: String::new(),
                member_id: String::new(),
                page_token: String::new(),
                page_size: 2,
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first_page.entries.len(), 2);
    assert!(!first_page.next_page_token.is_empty());
    publish_definition_history_entry(
        &svc,
        namespace,
        &third,
        "hist-4",
        "hist-cs-4",
        vec![DefinitionMemberInput {
            member_kind: "ontology_class".into(),
            member_id: "LaterClass".into(),
            definition_json: r#"{"name":"LaterClass"}"#.into(),
            member_digest: String::new(),
        }],
    )
    .await;
    let second_page = svc
        .list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: String::new(),
                member_id: String::new(),
                page_token: first_page.next_page_token,
                page_size: 2,
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second_page.entries.len(), 1);
    assert_eq!(second_page.entries[0].revision_digest, first);
    assert!(second_page.next_page_token.is_empty());

    assert_eq!(
        svc.list_published_definition_revisions(Request::new(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: String::new(),
                member_id: String::new(),
                page_token: String::new(),
                page_size: 10,
            },
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::Unauthenticated
    );
    let get_as_tester = svc
        .get_published_definition_revision(with_named_principal(
            GetPublishedDefinitionRevisionRequest {
                namespace: namespace.into(),
            },
            "tester",
        ))
        .await;
    let list_as_tester = svc
        .list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: String::new(),
                member_id: String::new(),
                page_token: String::new(),
                page_size: 10,
            },
            "tester",
        ))
        .await;
    assert_eq!(
        get_as_tester.as_ref().err().map(|error| error.code()),
        list_as_tester.as_ref().err().map(|error| error.code())
    );
    let get_missing = svc
        .get_published_definition_revision(with_named_principal(
            GetPublishedDefinitionRevisionRequest {
                namespace: "history-missing".into(),
            },
            "root",
        ))
        .await;
    let list_missing = svc
        .list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: "history-missing".into(),
                member_kind: String::new(),
                member_id: String::new(),
                page_token: String::new(),
                page_size: 10,
            },
            "root",
        ))
        .await;
    assert_eq!(
        get_missing.as_ref().err().map(|error| error.code()),
        list_missing.as_ref().err().map(|error| error.code())
    );
    assert_eq!(get_missing.unwrap_err().code(), tonic::Code::NotFound);
    assert_eq!(
        svc.list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: "object_type".into(),
                member_id: String::new(),
                page_token: String::new(),
                page_size: 10,
            },
            "root",
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        svc.list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: " object_type".into(),
                member_id: "Ticket".into(),
                page_token: String::new(),
                page_size: 10,
            },
            "root",
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        svc.list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: String::new(),
                member_id: String::new(),
                page_token: "not-a-token".into(),
                page_size: 10,
            },
            "root",
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::InvalidArgument
    );

    let current = svc
        .get_published_definition_revision(with_named_principal(
            GetPublishedDefinitionRevisionRequest {
                namespace: namespace.into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .revision_digest;
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "hist-drop-class".into(),
            parent_revision_digest: current.clone(),
            idempotency_key: "hist-drop-class-create".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let dropped = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: "hist-drop-class".into(),
                expected_head_digest: current.clone(),
                upserts: Vec::new(),
                removals: vec![DefinitionMemberRef {
                    member_kind: "ontology_class".into(),
                    member_id: "TicketClass".into(),
                }],
                idempotency_key: "hist-drop-class-edit".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let candidate = dropped.revision.unwrap().revision_digest;
    svc.create_definition_proposal(with_named_principal(
        CreateDefinitionProposalRequest {
            namespace: namespace.into(),
            branch_id: "hist-drop-class".into(),
            proposal_id: "hist-cs-drop".into(),
            base_digest: current.clone(),
            candidate_digest: candidate.clone(),
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: "hist-drop-class-propose".into(),
            major_revision: false,
        },
        "root",
    ))
    .await
    .unwrap();
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: namespace.into(),
            proposal_id: "hist-cs-drop".into(),
            idempotency_key: "hist-drop-class-approve".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.merge_definition_proposal(with_named_principal(
        MergeDefinitionProposalRequest {
            namespace: namespace.into(),
            proposal_id: "hist-cs-drop".into(),
            expected_published_digest: current,
            idempotency_key: "hist-drop-class-merge".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let protected = security::Grant {
        id: "history-ticketclass-reader".into(),
        object_id: ontology_class_object_id("TicketClass"),
        principal: "other-reader".into(),
        role: security::Role::Viewer,
        created: 1,
        ..Default::default()
    };
    svc.security.add_grant(&protected);
    assert!(
        !svc.get_published_definition_revision(with_named_principal(
            GetPublishedDefinitionRevisionRequest {
                namespace: namespace.into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .members
        .iter()
        .any(|member| member.member_id == "TicketClass")
    );
    svc.list_published_definition_revisions(with_named_principal(
        ListPublishedDefinitionRevisionsRequest {
            namespace: namespace.into(),
            member_kind: String::new(),
            member_id: String::new(),
            page_token: String::new(),
            page_size: 10,
        },
        "root",
    ))
    .await
    .unwrap();
    assert_eq!(
        svc.list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: namespace.into(),
                member_kind: "ontology_class".into(),
                member_id: "TicketClass".into(),
                page_token: String::new(),
                page_size: 10,
            },
            "root",
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::NotFound
    );
}

fn source_batch(
    namespace: &str,
    producer: &str,
    current_cursor: &str,
    proposed_next_cursor: &str,
    idempotency_key: &str,
) -> SourceBatch {
    let source_instance = "acme/ops".to_string();
    let mut domain = source_sync_domain::SourceBatch {
        contract_version: source_sync_domain::SOURCE_BATCH_VERSION.into(),
        namespace: namespace.into(),
        producer_identity: producer.into(),
        source: source_sync_domain::SOURCE_GITHUB.into(),
        source_instance: source_instance.clone(),
        family: source_sync_domain::FAMILY_OBJECT_SYNC.into(),
        adapter_id: source_sync_domain::ADAPTER_GITHUB_OBJECT_SYNC.into(),
        adapter_version: source_sync_domain::ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        type_digest: SOURCE_TYPE_DIGEST.into(),
        current_cursor: current_cursor.into(),
        proposed_next_cursor: proposed_next_cursor.into(),
        idempotency_key: idempotency_key.into(),
        batch_digest: String::new(),
        collected_at_ms: 20,
        records: vec![source_sync_domain::SourceRecord {
            source: source_sync_domain::SOURCE_GITHUB.into(),
            source_instance,
            external_id: "12".into(),
            source_version: "node-v1".into(),
            type_name: "Issue".into(),
            display_name: "Bounded sync".into(),
            payload_digest: SOURCE_PAYLOAD_DIGEST.into(),
            properties: std::collections::BTreeMap::from([
                ("state".into(), "open".into()),
                ("title".into(), "Bounded sync".into()),
            ]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        }],
        delivery: None,
    };
    domain.batch_digest = domain.canonical_digest().unwrap();
    SourceBatch {
        contract_version: domain.contract_version,
        namespace: domain.namespace,
        producer_identity: domain.producer_identity,
        source: domain.source,
        source_instance: domain.source_instance,
        family: domain.family,
        adapter_id: domain.adapter_id,
        adapter_version: domain.adapter_version,
        type_digest: domain.type_digest,
        current_cursor: domain.current_cursor,
        proposed_next_cursor: domain.proposed_next_cursor,
        idempotency_key: domain.idempotency_key,
        batch_digest: domain.batch_digest,
        collected_at_ms: domain.collected_at_ms,
        records: domain
            .records
            .into_iter()
            .map(|record| SourceRecord {
                source: record.source,
                source_instance: record.source_instance,
                external_id: record.external_id,
                source_version: record.source_version,
                type_name: record.type_name,
                display_name: record.display_name,
                payload_digest: record.payload_digest,
                properties: record.properties.into_iter().collect(),
                deleted: record.deleted,
                observed_at_ms: record.observed_at_ms,
                source_sequence: record.source_sequence,
            })
            .collect(),
        delivery: None,
    }
}

fn redigest_source_batch(batch: &mut SourceBatch) {
    let mut domain = from_proto_source_batch(batch.clone()).unwrap();
    domain.batch_digest.clear();
    batch.batch_digest = domain.canonical_digest().unwrap();
}

#[tokio::test]
async fn source_sync_authorized_success_replay_and_state_are_exact() {
    let svc = service();
    let namespace = "sync-authorized";
    let producer = "connector/github-primary";
    grant_source_namespace(&svc, namespace, producer, security::Role::Editor);
    let page_1 = source_batch(namespace, producer, "", "cursor:1", "batch-1");

    let first = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(page_1.clone()),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    let transaction = first.transaction.as_ref().unwrap();
    assert_eq!(transaction.status, "COMMITTED");
    assert_eq!(transaction.outcome, "success");
    assert_eq!(transaction.producer_identity, producer);
    assert!(first.checkpoint_advanced);
    assert_eq!(first.records[0].decision, "upsert");
    assert_eq!(first.records[0].outcome, "success");
    let object = first.records[0].object.as_ref().unwrap();
    let lineage = first.records[0].lineage.as_ref().unwrap();
    assert_eq!(lineage.object_id, object.object_id);
    assert_eq!(lineage.source_id, object.source_id);
    assert_eq!(object.properties["title"], "Bounded sync");
    let object_id = object.object_id.clone();

    let page_1_state = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(page_1_state.found);
    let page_1_state = page_1_state.state.unwrap();
    let page_1_cursor = page_1_state.checkpoint.as_ref().unwrap().cursor.clone();
    assert_eq!(page_1_cursor, "cursor:1");
    assert!(page_1_state.open_transaction.is_none());
    assert_eq!(page_1_state.last_result.unwrap(), first);

    let mut page_2 = source_batch(namespace, producer, &page_1_cursor, "cursor:2", "batch-2");
    page_2.collected_at_ms = 30;
    page_2.records[0].source_version = "node-v2".into();
    page_2.records[0].payload_digest =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
    page_2.records[0].display_name = "Bounded sync, page 2".into();
    page_2.records[0]
        .properties
        .insert("title".into(), "Bounded sync, page 2".into());
    page_2.records[0].observed_at_ms = 20;
    redigest_source_batch(&mut page_2);

    let second = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(page_2),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert!(second.checkpoint_advanced);
    let second_object = second.records[0].object.as_ref().unwrap();
    assert_eq!(second_object.object_id, object_id);
    assert_eq!(second_object.source_version, "node-v2");
    assert_eq!(second_object.properties["title"], "Bounded sync, page 2");

    let page_2_state = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .state
        .unwrap();
    assert_eq!(page_2_state.checkpoint.as_ref().unwrap().cursor, "cursor:2");
    assert_eq!(page_2_state.last_result.as_ref(), Some(&second));

    let mut replay = page_1;
    replay.collected_at_ms += 1_000;
    let replayed = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(replay),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(replayed, first);

    let state_after_older_replay = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .state
        .unwrap();
    assert_eq!(
        state_after_older_replay.checkpoint.as_ref().unwrap().cursor,
        "cursor:2"
    );
    assert_eq!(state_after_older_replay.last_result.as_ref(), Some(&second));
}

fn source_batch_domain_with_records(
    namespace: &str,
    producer: &str,
    n: usize,
    idempotency_key: &str,
) -> crate::sekai::object_sync::SourceBatch {
    let proto = source_batch(namespace, producer, "", "cursor:1", idempotency_key);
    let mut domain = from_proto_source_batch(proto).unwrap();
    let template = domain.records[0].clone();
    domain.records = (0..n)
        .map(|i| {
            let mut record = template.clone();
            record.external_id = format!("{}", 1000 + i);
            record
        })
        .collect();
    domain.batch_digest = domain.canonical_digest().unwrap();
    domain
}

#[test]
fn source_batch_object_policy_queries_are_constant_in_record_count() {
    let svc = service();
    let namespace = "sync-auth-batch";
    let producer = "connector/github-primary";
    grant_source_namespace(&svc, namespace, producer, security::Role::Editor);
    let principals = vec![producer.to_string()];
    let measure = |n: usize, key: &str| {
        crate::db::runtime_db::source_batch_auth_counters::LOOKUP_QUERIES.with(|c| c.set(0));
        crate::db::runtime_db::source_batch_auth_counters::POLICY_LOOKUPS.with(|c| c.set(0));
        let batch = source_batch_domain_with_records(namespace, producer, n, key);
        authorize_source_batch_object_policy(svc.db.runtime(), &batch, &principals, None).unwrap();
        (
            crate::db::runtime_db::source_batch_auth_counters::LOOKUP_QUERIES.with(|c| c.get()),
            crate::db::runtime_db::source_batch_auth_counters::POLICY_LOOKUPS.with(|c| c.get()),
        )
    };
    let (lookups_25, policies_25) = measure(25, "batch-25");
    let (lookups_80, policies_80) = measure(80, "batch-80");
    assert_eq!(
        lookups_25, 1,
        "25-record authorize used {lookups_25} lookups"
    );
    assert_eq!(
        lookups_80, 1,
        "80-record authorize used {lookups_80} lookups"
    );
    assert_eq!(policies_25, policies_80);
    assert!(
        policies_25 <= 2,
        "same-kind batch should resolve policy once, got {policies_25}"
    );
}

#[tokio::test]
async fn source_sync_rejects_anonymous_ambiguous_and_unauthorized_principals() {
    let svc = service();
    let namespace = "sync-authority";
    let producer = "connector/github-primary";
    grant_source_namespace(&svc, namespace, producer, security::Role::Editor);
    let batch = source_batch(namespace, producer, "", "cursor:1", "batch-1");
    let viewer = "connector/github-viewer";
    let boundary_id = svc
        .db
        .runtime()
        .find_namespace_boundary(namespace)
        .unwrap()
        .unwrap()
        .id;
    grant_object_role(&svc, &boundary_id, viewer, security::Role::Viewer);

    let viewer_state = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            viewer,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!viewer_state.found);

    let viewer_batch = source_batch(
        namespace,
        viewer,
        "",
        "cursor:viewer",
        "batch-viewer-denied",
    );
    let viewer_denied = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(viewer_batch),
            },
            viewer,
        ))
        .await
        .unwrap_err();
    assert_eq!(viewer_denied.code(), tonic::Code::PermissionDenied);
    let viewer_state_after_denial = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            viewer,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!viewer_state_after_denial.found);

    let anonymous = svc
        .apply_source_batch(Request::new(ApplySourceBatchRequest {
            batch: Some(batch.clone()),
        }))
        .await
        .unwrap_err();
    assert_eq!(anonymous.code(), tonic::Code::Unauthenticated);

    let ambiguous = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(batch.clone()),
            },
            "connector/github-primary,connector/other",
        ))
        .await
        .unwrap_err();
    assert_eq!(ambiguous.code(), tonic::Code::PermissionDenied);

    let mut mismatch = batch.clone();
    mismatch.producer_identity = "connector/other".into();
    redigest_source_batch(&mut mismatch);
    let mismatch = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(mismatch),
            },
            producer,
        ))
        .await
        .unwrap_err();
    assert_eq!(mismatch.code(), tonic::Code::PermissionDenied);

    let unauthorized = "connector/no-authority";
    let unauthorized_batch = source_batch(
        namespace,
        unauthorized,
        "",
        "cursor:1",
        "batch-unauthorized",
    );
    let denied = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(unauthorized_batch),
            },
            unauthorized,
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    let read_denied = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            unauthorized,
        ))
        .await
        .unwrap_err();
    assert_eq!(read_denied.code(), tonic::Code::PermissionDenied);

    let editor_result = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest { batch: Some(batch) },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(editor_result.transaction.unwrap().status, "COMMITTED");
    assert!(editor_result.checkpoint_advanced);

    let viewer_state_after_commit = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            viewer,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(viewer_state_after_commit.found);
    assert_eq!(
        viewer_state_after_commit
            .state
            .unwrap()
            .checkpoint
            .unwrap()
            .cursor,
        "cursor:1"
    );
}

#[tokio::test]
async fn source_sync_maps_version_cursor_and_secret_failures() {
    let svc = service();
    let namespace = "sync-failures";
    let producer = "connector/github-primary";
    grant_source_namespace(&svc, namespace, producer, security::Role::Editor);

    let mut unknown_version =
        source_batch(namespace, producer, "", "cursor:ignored", "batch-version");
    unknown_version.contract_version = "sekai.source-batch/v3".into();
    let version_error = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(unknown_version),
            },
            producer,
        ))
        .await
        .unwrap_err();
    assert_eq!(version_error.code(), tonic::Code::FailedPrecondition);
    assert!(!version_error.message().contains("v2"));

    let mut unbound_revision =
        source_batch(namespace, producer, "", "cursor:ignored", "batch-unbound");
    unbound_revision.type_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    redigest_source_batch(&mut unbound_revision);
    let revision_error = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(unbound_revision),
            },
            producer,
        ))
        .await
        .unwrap_err();
    assert_eq!(revision_error.code(), tonic::Code::FailedPrecondition);
    assert!(!revision_error.message().contains("sha256"));

    let lookup_error = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
            },
            producer,
        ))
        .await
        .unwrap_err();
    assert_eq!(lookup_error.code(), tonic::Code::FailedPrecondition);
    assert!(!lookup_error.message().contains("aaaa"));

    let empty_state = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!empty_state.found);

    let first = source_batch(namespace, producer, "", "cursor:1", "batch-1");
    let first_result = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest { batch: Some(first) },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(
        first_result.transaction.as_ref().unwrap().status,
        "COMMITTED"
    );
    assert!(first_result.checkpoint_advanced);

    let mut source_revision_conflict = source_batch(
        namespace,
        producer,
        "cursor:1",
        "cursor:blocked",
        "batch-revision-conflict",
    );
    source_revision_conflict.records[0].payload_digest =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
    redigest_source_batch(&mut source_revision_conflict);
    let quarantined = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(source_revision_conflict.clone()),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(
        quarantined.transaction.as_ref().unwrap().status,
        "QUARANTINED"
    );
    assert!(!quarantined.checkpoint_advanced);
    assert!(
        quarantined.records[0]
            .reason
            .starts_with("source_revision_conflict:")
    );
    assert!(!quarantined.records[0].reason.contains("cccc"));
    let replay = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(source_revision_conflict),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(replay.transaction.as_ref().unwrap().status, "QUARANTINED");
    assert!(!replay.checkpoint_advanced);

    let stale = source_batch(
        namespace,
        producer,
        "cursor:foreign",
        "cursor:2",
        "batch-stale",
    );
    let cursor_error = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest { batch: Some(stale) },
            producer,
        ))
        .await
        .unwrap_err();
    assert_eq!(cursor_error.code(), tonic::Code::Aborted);
    assert!(!cursor_error.message().contains("foreign"));

    let mut secret = source_batch(namespace, producer, "cursor:1", "cursor:2", "batch-secret");
    secret.records[0]
        .properties
        .insert("access_token".into(), "redacted".into());
    redigest_source_batch(&mut secret);
    let secret_error = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(secret),
            },
            producer,
        ))
        .await
        .unwrap_err();
    assert_eq!(secret_error.code(), tonic::Code::InvalidArgument);
    assert!(!secret_error.message().contains("access_token"));

    let state_after_failures = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .state
        .unwrap();
    assert_eq!(
        state_after_failures.checkpoint.as_ref().unwrap().cursor,
        "cursor:1"
    );
    assert_eq!(
        state_after_failures.last_result.as_ref(),
        Some(&quarantined)
    );
}

#[tokio::test]
async fn source_sync_v2_state_and_bounded_errors_are_exposed() {
    let svc = service();
    let namespace = "sync-v2-state";
    let producer = "connector/github-primary";
    grant_source_namespace(&svc, namespace, producer, security::Role::Editor);

    let mut snapshot = source_batch(namespace, producer, "", "cursor:snapshot", "snapshot-1");
    snapshot.contract_version = source_sync_domain::SOURCE_BATCH_V2_VERSION.into();
    snapshot.delivery = Some(SourceDeliveryWindow {
        mode: SourceDeliveryMode::Snapshot as i32,
        sync_generation: 1,
        source_feed_epoch: Some("epoch-1".into()),
        offset_start: None,
        offset_end: Some(40),
        snapshot_complete: true,
    });
    redigest_source_batch(&mut snapshot);
    svc.apply_source_batch(with_named_principal(
        ApplySourceBatchRequest {
            batch: Some(snapshot),
        },
        producer,
    ))
    .await
    .unwrap();

    let active = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .state
        .unwrap();
    let generation = active.current_generation.unwrap();
    assert_eq!(generation.status, SourceSyncGenerationStatus::Active as i32);
    assert_eq!(generation.committed_offset, Some(40));
    let checkpoint = active.checkpoint.unwrap();
    assert_eq!(checkpoint.sync_generation, Some(1));
    assert_eq!(checkpoint.committed_offset, Some(40));

    let mut missing = source_batch(
        namespace,
        producer,
        "cursor:snapshot",
        "cursor:missing",
        "feed-missing",
    );
    missing.contract_version = source_sync_domain::SOURCE_BATCH_V2_VERSION.into();
    missing.records[0].source_sequence = Some(51);
    missing.delivery = Some(SourceDeliveryWindow {
        mode: SourceDeliveryMode::ChangeFeed as i32,
        sync_generation: 1,
        source_feed_epoch: Some("epoch-1".into()),
        offset_start: Some(50),
        offset_end: Some(51),
        snapshot_complete: false,
    });
    redigest_source_batch(&mut missing);
    let missing_error = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(missing),
            },
            producer,
        ))
        .await
        .unwrap_err();
    assert_eq!(missing_error.code(), tonic::Code::Aborted);
    assert!(!missing_error.message().contains("50"));

    let recovery = svc
        .get_source_sync_state(with_named_principal(
            GetSourceSyncStateRequest {
                namespace: namespace.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .state
        .unwrap();
    assert_eq!(
        recovery.current_generation.unwrap().status,
        SourceSyncGenerationStatus::RecoveryRequired as i32
    );
    assert_eq!(recovery.latest_transaction.unwrap().status, "ABORTED");

    for error in [
        "generation_conflict: 999",
        "feed_epoch_conflict: private-epoch",
        "phase_conflict: internal-phase",
    ] {
        let status = map_source_sync_apply_error(error.into());
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(!status.message().contains("999"));
        assert!(!status.message().contains("private-epoch"));
        assert!(!status.message().contains("internal-phase"));
    }
}

#[test]
fn source_sync_proto_rejects_unspecified_delivery_mode() {
    let mut proto = source_batch("sync-v2-conversion", "connector/test", "", "next", "key");
    proto.contract_version = source_sync_domain::SOURCE_BATCH_V2_VERSION.into();
    proto.delivery = Some(SourceDeliveryWindow {
        mode: SourceDeliveryMode::Unspecified as i32,
        sync_generation: 1,
        source_feed_epoch: None,
        offset_start: None,
        offset_end: None,
        snapshot_complete: false,
    });
    let error = from_proto_source_batch(proto).unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}

fn widget_schema_type() -> ObjectType {
    ObjectType {
        kind: "widget".into(),
        description: "A widget".into(),
        properties: vec![
            PropertyDef {
                name: "name".into(),
                r#type: "string".into(),
                required: true,
                description: "".into(),
                enum_values: vec![],
                link_kind: "".into(),
                compute_expr: "".into(),
                classification: "public".into(),
                struct_fields: vec![],
            },
            PropertyDef {
                name: "color".into(),
                r#type: "enum".into(),
                required: false,
                description: "".into(),
                enum_values: vec!["red".into(), "blue".into()],
                link_kind: "".into(),
                compute_expr: "".into(),
                classification: "public".into(),
                struct_fields: vec![],
            },
        ],
        is_builtin: false,
        implements: vec![],
    }
}

fn widget_object(id: &str, properties: HashMap<String, String>) -> Object {
    Object {
        id: id.into(),
        kind: "widget".into(),
        name: "widget".into(),
        namespace: "".into(),
        external_id: "".into(),
        properties,
        created: 0,
        updated: 0,
    }
}

fn grant_schema_admin(svc: &SekaiServiceImpl) {
    let grant = security::Grant {
        id: format!("schema-admin-{}", uuid::Uuid::new_v4().simple()),
        object_id: "schema".into(),
        principal: "tester".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

fn grant_ontology_admin(svc: &SekaiServiceImpl) {
    let grant = security::Grant {
        id: format!("ontology-admin-{}", uuid::Uuid::new_v4().simple()),
        object_id: "ontology".into(),
        principal: "tester".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

fn grant_ontology_reader(svc: &SekaiServiceImpl, object_id: &str) {
    let grant = security::Grant {
        id: format!("ontology-reader-{}", uuid::Uuid::new_v4().simple()),
        object_id: object_id.into(),
        principal: "tester".into(),
        role: security::Role::Viewer,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

fn ontology_class(name: &str) -> OntologyClass {
    OntologyClass {
        name: name.into(),
        description: String::new(),
        superclasses: vec![],
        equivalent_classes: vec![],
        disjoint_classes: vec![],
        properties: vec![],
        is_builtin: false,
        mapped_kind: String::new(),
    }
}

fn grant_action_admin(svc: &SekaiServiceImpl) {
    let grant = security::Grant {
        id: format!("action-admin-{}", uuid::Uuid::new_v4().simple()),
        object_id: "action".into(),
        principal: "tester".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

fn grant_object_role(
    svc: &SekaiServiceImpl,
    object_id: &str,
    principal: &str,
    role: security::Role,
) {
    let grant = security::Grant {
        id: format!("grant-{}", uuid::Uuid::new_v4().simple()),
        object_id: object_id.into(),
        principal: principal.into(),
        role,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

fn seed_scoring_namespace(svc: &SekaiServiceImpl, namespace: &str) -> String {
    let id = format!("namespace-{namespace}");
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: id.clone(),
            kind: "namespace".into(),
            name: namespace.into(),
            namespace: String::new(),
            external_id: format!("namespace:{namespace}"),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    id
}

fn scored_knowledge_request(namespace: &str, request_id: &str) -> KnowledgeWriteRequest {
    KnowledgeWriteRequest {
        request_id: request_id.into(),
        namespace: namespace.into(),
        task_class: "primary".into(),
        model: "claude-opus-4-8".into(),
        score: 84,
        passed: true,
        reasoning: "The implementation satisfies the requested behavior.".into(),
    }
}

#[tokio::test]
async fn get_object_denies_marked_artifact_without_clearance() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "artifact-1".into(),
            kind: "artifact".into(),
            name: "secret".into(),
            namespace: "ns".into(),
            external_id: "artifact:1".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    // No grants on object => world-readable ACL, but marking fails closed.
    let err = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "artifact-1".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[test]
fn activated_direct_read_error_hides_only_permission_denials() {
    assert_eq!(
        map_direct_read_visibility_error(false, Status::permission_denied("legacy access denied"))
            .code(),
        tonic::Code::PermissionDenied
    );
    let hidden = map_direct_read_visibility_error(true, Status::permission_denied("access denied"));
    assert_eq!(hidden.code(), tonic::Code::NotFound);
    assert_eq!(hidden.message(), "not found");
    assert_eq!(
        map_direct_read_visibility_error(true, Status::unavailable("storage unavailable")).code(),
        tonic::Code::Unavailable
    );
}

#[test]
fn postgres_object_change_store_maps_to_unavailable() {
    let status = map_runtime_store_error(
        "list_visible_object_changes is unavailable on the PostgreSQL community runtime".into(),
    );
    assert_eq!(status.code(), tonic::Code::Unavailable);
    let status = map_runtime_store_error("sqlite busy".into());
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[test]
fn postgres_execution_evidence_admission_maps_to_unavailable() {
    let status =
        map_evidence_admission_lifecycle_error(EvidenceAdmissionLifecycleError::Admission(
            "record_execution_evidence is unavailable on the PostgreSQL community runtime".into(),
        ));
    assert_eq!(status.code(), tonic::Code::Unavailable);
    let status = map_evidence_admission_lifecycle_error(
        EvidenceAdmissionLifecycleError::Rejection("invalid_execution_evidence".into()),
    );
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[test]
fn read_root_hides_denials_and_preserves_outages() {
    assert_eq!(
        hide_read_root_as_missing(Status::permission_denied("access denied")).code(),
        tonic::Code::NotFound
    );
    assert_eq!(
        hide_read_root_as_missing(Status::unauthenticated(
            "enterprise tenant context required"
        ))
        .code(),
        tonic::Code::NotFound
    );
    assert_eq!(
        hide_read_root_as_missing(Status::unavailable("object authorization unavailable")).code(),
        tonic::Code::Unavailable
    );
    assert_eq!(
        hide_read_root_as_missing(Status::internal("policy store failed")).code(),
        tonic::Code::Internal
    );
}

#[tokio::test]
async fn deny_unmarked_denies_unmarked_reads_and_keeps_marked_rules() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "namespace-ns".into(),
            kind: "namespace".into(),
            name: "ns".into(),
            namespace: "ns".into(),
            external_id: "namespace:ns".into(),
            properties: HashMap::from([(markings::DENY_UNMARKED_PROPERTY.into(), "true".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "unmarked-open".into(),
            kind: "artifact".into(),
            name: "open".into(),
            namespace: "ns".into(),
            external_id: "artifact:unmarked-open".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "unmarked-granted".into(),
            kind: "artifact".into(),
            name: "granted".into(),
            namespace: "ns".into(),
            external_id: "artifact:unmarked-granted".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    grant_object_role(&svc, "unmarked-granted", "alice", security::Role::Viewer);
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "marked-confidential".into(),
            kind: "artifact".into(),
            name: "secret".into(),
            namespace: "ns".into(),
            external_id: "artifact:marked-confidential".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            )]),
            created: 1,
            updated: 1,
        })
        .unwrap();

    let unmarked_denied = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "unmarked-open".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(unmarked_denied.code(), tonic::Code::PermissionDenied);

    let granted = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "unmarked-granted".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(granted.object.unwrap().id, "unmarked-granted");

    let marked_denied = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "marked-confidential".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(marked_denied.code(), tonic::Code::PermissionDenied);

    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "principal-alice-deny-unmarked".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "alice".into(),
            namespace: "ns".into(),
            external_id: markings::principal_profile_external_id("alice"),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    "confidential".into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    grant_object_role(
        &svc,
        "principal-alice-deny-unmarked",
        "root",
        security::Role::Admin,
    );
    let marked_allowed = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "marked-confidential".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(marked_allowed.object.unwrap().id, "marked-confidential");

    let listed = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: "ns".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    let listed_ids: Vec<&str> = listed
        .objects
        .iter()
        .map(|object| object.id.as_str())
        .collect();
    assert!(!listed_ids.contains(&"unmarked-open"));
    assert!(listed_ids.contains(&"unmarked-granted"));
    assert!(listed_ids.contains(&"marked-confidential"));
}

#[tokio::test]
async fn owner_admin_cannot_declassify_without_grant_and_granted_principal_is_audited() {
    let svc = service();
    let marked = Object {
        id: "marked-secret".into(),
        kind: "document".into(),
        name: "secret".into(),
        namespace: "ns".into(),
        external_id: "document:marked-secret".into(),
        properties: HashMap::from([(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "confidential".into(),
        )]),
        created: 1,
        updated: 1,
    };
    svc.db
        .runtime()
        .create_object(&from_proto_obj(&marked))
        .unwrap();
    grant_object_role(&svc, "marked-secret", "alice", security::Role::Admin);
    grant_object_role(&svc, "marked-secret", "bob", security::Role::Editor);
    for (id, actor, declassify) in [
        ("principal-alice-admin", "alice", None),
        ("principal-bob-declassify", "bob", Some("confidential")),
    ] {
        let mut properties = HashMap::from([
            (
                markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                "restricted".into(),
            ),
            (
                markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                "true".into(),
            ),
        ]);
        if let Some(marking) = declassify {
            properties.insert(
                markings::PRINCIPAL_DECLASSIFY_MARKINGS_PROPERTY.into(),
                marking.into(),
            );
        }
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: id.into(),
                kind: markings::PRINCIPAL_PROFILE_KIND.into(),
                name: actor.into(),
                namespace: "ns".into(),
                external_id: markings::principal_profile_external_id(actor),
                properties,
                created: 1,
                updated: 1,
            })
            .unwrap();
        grant_object_role(&svc, id, "root", security::Role::Admin);
    }

    let mut stripped = marked.clone();
    stripped
        .properties
        .remove(markings::OBJECT_CLASSIFICATION_PROPERTY);
    stripped.updated = 2;
    let denied = svc
        .guarded_update_object(with_named_principal(
            GuardedUpdateObjectRequest {
                object: Some(stripped.clone()),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    let still = svc
        .db
        .runtime()
        .get_object("marked-secret")
        .unwrap()
        .unwrap();
    assert_eq!(
        still
            .properties
            .get(markings::OBJECT_CLASSIFICATION_PROPERTY),
        Some(&"confidential".to_string())
    );

    svc.guarded_update_object(with_named_principal(
        GuardedUpdateObjectRequest {
            object: Some(stripped),
            lease_precondition: None,
        },
        "bob",
    ))
    .await
    .unwrap();
    let updated = svc
        .db
        .runtime()
        .get_object("marked-secret")
        .unwrap()
        .unwrap();
    assert!(markings::object_is_unmarked(&updated));
    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some("declassify".into()),
            target_id: Some("marked-secret".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        decisions
            .iter()
            .any(|decision| decision.actor == "alice" && decision.outcome == "denied")
    );
    assert!(
        decisions
            .iter()
            .any(|decision| decision.actor == "bob" && decision.outcome == "allowed")
    );
}

#[tokio::test]
async fn delegated_actor_without_declassify_grant_cannot_strip_marking() {
    let svc = service();
    let marked = Object {
        id: "delegated-marked".into(),
        kind: "document".into(),
        name: "secret".into(),
        namespace: "ns".into(),
        external_id: "document:delegated-marked".into(),
        properties: HashMap::from([(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "confidential".into(),
        )]),
        created: 1,
        updated: 1,
    };
    svc.db
        .runtime()
        .create_object(&from_proto_obj(&marked))
        .unwrap();
    grant_object_role(&svc, "delegated-marked", "service-a", security::Role::Admin);
    grant_object_role(&svc, "delegated-marked", "human-a", security::Role::Editor);
    for (id, actor, declassify) in [
        (
            "principal-service-declassify",
            "service-a",
            Some("confidential"),
        ),
        ("principal-human-no-declassify", "human-a", None),
    ] {
        let mut properties = HashMap::from([
            (
                markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                "restricted".into(),
            ),
            (
                markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                "true".into(),
            ),
        ]);
        if let Some(marking) = declassify {
            properties.insert(
                markings::PRINCIPAL_DECLASSIFY_MARKINGS_PROPERTY.into(),
                marking.into(),
            );
        }
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: id.into(),
                kind: markings::PRINCIPAL_PROFILE_KIND.into(),
                name: actor.into(),
                namespace: "ns".into(),
                external_id: markings::principal_profile_external_id(actor),
                properties,
                created: 1,
                updated: 1,
            })
            .unwrap();
        grant_object_role(&svc, id, "root", security::Role::Admin);
    }

    let mut stripped = marked.clone();
    stripped
        .properties
        .remove(markings::OBJECT_CLASSIFICATION_PROPERTY);
    stripped.updated = 2;
    let mut request = Request::new(GuardedUpdateObjectRequest {
        object: Some(stripped),
        lease_precondition: None,
    });
    let mut delegated = crate::enterprise::AuthenticatedContext::machine(
        crate::enterprise::AuthenticatedPrincipal {
            subject: "service-a".into(),
            credential_id: "service-credential".into(),
        },
    );
    delegated.act = Some("human-a".into());
    request.extensions_mut().insert(delegated);
    let denied = svc.guarded_update_object(request).await.unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    let still = svc
        .db
        .runtime()
        .get_object("delegated-marked")
        .unwrap()
        .unwrap();
    assert_eq!(
        still
            .properties
            .get(markings::OBJECT_CLASSIFICATION_PROPERTY),
        Some(&"confidential".to_string())
    );
    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some("declassify".into()),
            target_id: Some("delegated-marked".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(decisions.iter().any(|decision| {
        decision.actor == "human-a"
            && decision.outcome == "denied"
            && decision.evidence.get("act").map(String::as_str) == Some("human-a")
    }));
}

#[tokio::test]
async fn trusted_principal_declassify_uses_profile_grant() {
    let svc = service();
    let marked = Object {
        id: "trusted-marked".into(),
        kind: "document".into(),
        name: "secret".into(),
        namespace: "ns".into(),
        external_id: "document:trusted-marked".into(),
        properties: HashMap::from([(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "confidential".into(),
        )]),
        created: 1,
        updated: 1,
    };
    svc.db
        .runtime()
        .create_object(&from_proto_obj(&marked))
        .unwrap();
    grant_object_role(&svc, "trusted-marked", "root", security::Role::Admin);
    let mut stripped = marked.clone();
    stripped
        .properties
        .remove(markings::OBJECT_CLASSIFICATION_PROPERTY);
    stripped.updated = 2;
    let denied = svc
        .guarded_update_object(with_named_principal(
            GuardedUpdateObjectRequest {
                object: Some(stripped.clone()),
                lease_precondition: None,
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "principal-root-declassify".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "root".into(),
            namespace: "ns".into(),
            external_id: markings::principal_profile_external_id("root"),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    "restricted".into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
                (
                    markings::PRINCIPAL_DECLASSIFY_MARKINGS_PROPERTY.into(),
                    "confidential".into(),
                ),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    grant_object_role(
        &svc,
        "principal-root-declassify",
        "root",
        security::Role::Admin,
    );
    svc.guarded_update_object(with_named_principal(
        GuardedUpdateObjectRequest {
            object: Some(stripped),
            lease_precondition: None,
        },
        "root",
    ))
    .await
    .unwrap();
    let updated = svc
        .db
        .runtime()
        .get_object("trusted-marked")
        .unwrap()
        .unwrap();
    assert!(markings::object_is_unmarked(&updated));
}

#[tokio::test]
async fn activated_get_object_hides_acl_and_marking_denials_as_missing() {
    for (id, namespace, properties, acl_denied) in [
        (
            "activated-marked",
            "activated-marking-ns",
            HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            )]),
            false,
        ),
        ("activated-acl", "activated-acl-ns", HashMap::new(), true),
    ] {
        let svc = service();
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: id.into(),
                kind: "document".into(),
                name: id.into(),
                namespace: namespace.into(),
                external_id: format!("{namespace}:{id}"),
                properties,
                created: 1,
                updated: 1,
            })
            .unwrap();
        if acl_denied {
            grant_object_role(&svc, id, "bob", security::Role::Viewer);
        }
        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: namespace.into(),
            kind: "document".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: None,
            value_instance_grants: None,
            required_purpose: None,
        };
        let revision = svc
            .db
            .runtime()
            .put_object_security_policy(&policy, "root", &format!("put-{id}"), 1)
            .unwrap();
        svc.db
            .runtime()
            .activate_object_security_policies(
                namespace,
                &BTreeMap::from([("document".into(), revision.revision_digest)]),
                "root",
                &format!("activate-{id}"),
                2,
            )
            .unwrap();

        let error = svc
            .get_object(with_named_principal(
                GetObjectRequest { id: id.into() },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);
        assert_eq!(error.message(), "not found");
    }
}

fn with_named_principal_and_purpose<T>(payload: T, principal: &str, purpose: &str) -> Request<T> {
    let mut req = with_named_principal(payload, principal);
    req.metadata_mut()
        .insert("x-sekai-purpose", MetadataValue::try_from(purpose).unwrap());
    req
}

#[tokio::test]
async fn purpose_bound_reads_record_success_and_hide_denials() {
    let svc = service();
    let namespace = "purpose-bound";
    for (id, name) in [("purpose-doc-a", "alpha"), ("purpose-doc-b", "beta")] {
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: id.into(),
                kind: "document".into(),
                name: name.into(),
                namespace: namespace.into(),
                external_id: format!("{namespace}:{id}"),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
    }
    let policy = crate::sekai::object_security::ObjectSecurityPolicy {
        contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "document".into(),
        rules: vec![crate::sekai::object_security::ObjectSecurityRule {
            operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
            predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: None,
        value_instance_grants: None,
        required_purpose: Some("incident-response".into()),
    };
    let revision = svc
        .db
        .runtime()
        .put_object_security_policy(&policy, "root", "put-purpose-bound", 1)
        .unwrap();
    let activation = svc
        .db
        .runtime()
        .activate_object_security_policies(
            namespace,
            &BTreeMap::from([("document".into(), revision.revision_digest)]),
            "root",
            "activate-purpose-bound",
            2,
        )
        .unwrap();
    let digest =
        crate::sekai::object_security::object_security_activation_digest(&activation).unwrap();
    let now = now_millis();
    let live = crate::sekai::purpose_authorization::PurposeAuthorization {
        contract_version: crate::sekai::purpose_authorization::PURPOSE_AUTHORIZATION_VERSION.into(),
        authorization_id: "pa-live".into(),
        actor: "alice".into(),
        purpose: "incident-response".into(),
        namespace: namespace.into(),
        kind: "document".into(),
        not_before_ms: now.saturating_sub(1_000),
        not_after_ms: now.saturating_add(60_000),
        policy_activation_digest: digest,
        created_by: "root".into(),
        created_at_ms: now,
        revoked_at_ms: 0,
    };
    svc.put_purpose_authorization(with_named_principal(
        PutPurposeAuthorizationRequest {
            authorization: Some(to_proto_purpose_authorization(&live)),
        },
        "root",
    ))
    .await
    .unwrap();

    let missing = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "purpose-doc-a".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
    assert_eq!(missing.message(), "not found");

    let incompatible = svc
        .get_object(with_named_principal_and_purpose(
            GetObjectRequest {
                id: "purpose-doc-a".into(),
            },
            "alice",
            "analytics",
        ))
        .await
        .unwrap_err();
    assert_eq!(incompatible.code(), tonic::Code::NotFound);
    assert_eq!(incompatible.message(), "not found");

    let other_actor = svc
        .get_object(with_named_principal_and_purpose(
            GetObjectRequest {
                id: "purpose-doc-a".into(),
            },
            "bob",
            "incident-response",
        ))
        .await
        .unwrap_err();
    assert_eq!(other_actor.code(), tonic::Code::NotFound);

    let allowed = svc
        .get_object(with_named_principal_and_purpose(
            GetObjectRequest {
                id: "purpose-doc-a".into(),
            },
            "alice",
            "incident-response",
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(allowed.id, "purpose-doc-a");

    let decisions = svc
        .db
        .runtime()
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            actor: Some("alice".into()),
            action: Some("purpose.read".into()),
            target_id: Some("get_object:purpose-doc-a".into()),
            after: 0,
            limit: 10,
            offset: 0,
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "allowed");
    assert_eq!(
        decisions[0]
            .evidence
            .get("required_purpose")
            .map(String::as_str),
        Some("incident-response")
    );

    let hidden_list = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: "document".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(hidden_list.total, 0);
    assert!(hidden_list.objects.is_empty());

    let first_page = svc
        .list_objects(with_named_principal_and_purpose(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: "document".into(),
                    order_by: "name".into(),
                    limit: 1,
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
            "incident-response",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first_page.total, 2);
    assert_eq!(first_page.objects.len(), 1);
    assert!(!first_page.next_page_token.is_empty());
    let list_decisions = svc
        .db
        .runtime()
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            actor: Some("alice".into()),
            action: Some("purpose.read".into()),
            target_id: Some("purpose-filter:purpose-bound:document".into()),
            after: 0,
            limit: 10,
            offset: 0,
        })
        .unwrap();
    assert_eq!(list_decisions.len(), 1);
    assert_eq!(list_decisions[0].outcome, "allowed");

    let crossed = svc
        .list_objects(with_named_principal_and_purpose(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: "document".into(),
                    order_by: "name".into(),
                    limit: 1,
                    ..Default::default()
                }),
                page_token: first_page.next_page_token.clone(),
            },
            "alice",
            "analytics",
        ))
        .await
        .unwrap_err();
    assert_eq!(crossed.code(), tonic::Code::FailedPrecondition);

    let second_page = svc
        .list_objects(with_named_principal_and_purpose(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: "document".into(),
                    order_by: "name".into(),
                    limit: 1,
                    ..Default::default()
                }),
                page_token: first_page.next_page_token,
            },
            "alice",
            "incident-response",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second_page.total, 2);
    assert_eq!(second_page.objects.len(), 1);
    assert_ne!(first_page.objects[0].id, second_page.objects[0].id);

    svc.revoke_purpose_authorization(with_named_principal(
        RevokePurposeAuthorizationRequest {
            authorization_id: live.authorization_id.clone(),
        },
        "root",
    ))
    .await
    .unwrap();
    let revoked = svc
        .get_object(with_named_principal_and_purpose(
            GetObjectRequest {
                id: "purpose-doc-a".into(),
            },
            "alice",
            "incident-response",
        ))
        .await
        .unwrap_err();
    assert_eq!(revoked.code(), tonic::Code::NotFound);

    let trusted = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "purpose-doc-a".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(trusted.id, "purpose-doc-a");
}

#[tokio::test]
async fn hierarchical_classifications_enforce_lattice_and_hide_denials() {
    let svc = service();
    let namespace = "lattice-ops";
    let lattice = crate::sekai::classification_lattice::ClassificationLattice {
        contract_version: crate::sekai::classification_lattice::CLASSIFICATION_LATTICE_VERSION
            .into(),
        namespace: namespace.into(),
        tokens: vec![
            "public".into(),
            "internal".into(),
            "confidential".into(),
            "secret".into(),
            "health".into(),
        ],
        parents: BTreeMap::from([
            ("public".into(), vec!["internal".into()]),
            ("internal".into(), vec!["confidential".into()]),
            ("confidential".into(), vec!["secret".into()]),
            ("health".into(), vec!["secret".into()]),
        ]),
        incomparable: vec![("confidential".into(), "health".into())],
    };
    let stored = svc
        .put_classification_lattice(with_named_principal(
            PutClassificationLatticeRequest {
                lattice: Some(to_proto_classification_lattice(&lattice).unwrap()),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .lattice
        .unwrap();
    assert!(!stored.digest.is_empty());
    let loaded = svc
        .get_classification_lattice(with_named_principal(
            GetClassificationLatticeRequest {
                namespace: namespace.into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .lattice
        .unwrap();
    assert_eq!(loaded.digest, stored.digest);

    for (id, marking) in [
        ("lattice-health", "health"),
        ("lattice-confidential", "confidential"),
        ("lattice-unknown", "unknown"),
    ] {
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: id.into(),
                kind: "document".into(),
                name: id.into(),
                namespace: namespace.into(),
                external_id: format!("{namespace}:{id}"),
                properties: HashMap::from([(
                    markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    marking.into(),
                )]),
                created: 1,
                updated: 1,
            })
            .unwrap();
    }
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "legacy-unknown".into(),
            kind: "document".into(),
            name: "legacy".into(),
            namespace: "legacy-ns".into(),
            external_id: "legacy-ns:unknown".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "health".into(),
            )]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    for (id, actor, ceiling) in [
        ("principal-alice-secret", "alice", "secret"),
        ("principal-bob-conf", "bob", "confidential"),
    ] {
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: id.into(),
                kind: markings::PRINCIPAL_PROFILE_KIND.into(),
                name: actor.into(),
                namespace: namespace.into(),
                external_id: markings::principal_profile_external_id(actor),
                properties: HashMap::from([
                    (
                        markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        ceiling.into(),
                    ),
                    (
                        markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                        "true".into(),
                    ),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        grant_object_role(&svc, id, "root", security::Role::Admin);
    }

    let unknown = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "lattice-unknown".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(unknown.code(), tonic::Code::PermissionDenied);
    assert_eq!(unknown.message(), "access denied");

    let denied = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "lattice-health".into(),
            },
            "bob",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    assert_eq!(denied.message(), "access denied");

    let allowed = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "lattice-health".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(allowed.id, "lattice-health");

    let legacy = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "legacy-unknown".into(),
            },
            "bob",
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(legacy.id, "legacy-unknown");

    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "foreign-health".into(),
            kind: "document".into(),
            name: "foreign".into(),
            namespace: "foreign-ns".into(),
            external_id: "foreign-ns:health".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "health".into(),
            )]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_link(&domain::Link {
            id: "lattice-hop".into(),
            from_id: "lattice-confidential".into(),
            to_id: "lattice-health".into(),
            relation: "contains".into(),
            created: 1,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_link(&domain::Link {
            id: "lattice-foreign-hop".into(),
            from_id: "lattice-confidential".into(),
            to_id: "foreign-health".into(),
            relation: "contains".into(),
            created: 1,
        })
        .unwrap();
    let traversed = svc
        .traverse(with_named_principal(
            TraverseRequest {
                query: Some(GraphQuery {
                    start_id: "lattice-confidential".into(),
                    relations: vec!["contains".into()],
                    direction: "outgoing".into(),
                    max_depth: 1,
                    ..Default::default()
                }),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert!(
        traversed.objects.is_empty(),
        "incomparable or cross-namespace hops must not expand"
    );
    let trusted = svc
        .traverse(with_named_principal(
            TraverseRequest {
                query: Some(GraphQuery {
                    start_id: "lattice-confidential".into(),
                    relations: vec!["contains".into()],
                    direction: "outgoing".into(),
                    max_depth: 1,
                    ..Default::default()
                }),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    let trusted_ids = trusted
        .objects
        .iter()
        .map(|object| object.id.as_str())
        .collect::<Vec<_>>();
    assert!(trusted_ids.contains(&"lattice-health"));
    assert!(trusted_ids.contains(&"foreign-health"));
}

#[tokio::test]
async fn get_object_allows_marked_artifact_with_sufficient_ceiling() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "artifact-2".into(),
            kind: "artifact".into(),
            name: "secret".into(),
            namespace: "ns".into(),
            external_id: "artifact:2".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "principal-alice".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "alice".into(),
            namespace: "ns".into(),
            external_id: markings::principal_profile_external_id("alice"),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    "confidential".into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    // Credential-admin seal + Admin grant required for trust.
    grant_object_role(&svc, "principal-alice", "root", security::Role::Admin);
    let resp = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "artifact-2".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.object.unwrap().id, "artifact-2");
    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some("marking.read".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(decisions.iter().any(|d| d.outcome == "allowed"));
}

#[tokio::test]
async fn find_by_external_id_hides_marked_artifact_without_clearance() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "artifact-3".into(),
            kind: "artifact".into(),
            name: "secret".into(),
            namespace: "ns".into(),
            external_id: "artifact:hidden".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "restricted".into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let err = svc
        .find_by_external_id(with_named_principal(
            FindByExternalIdRequest {
                external_id: "artifact:hidden".into(),
            },
            "bob",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn find_by_external_id_hides_activated_marking_denial_as_missing() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "artifact-activated-hidden".into(),
            kind: "artifact".into(),
            name: "secret".into(),
            namespace: "ns".into(),
            external_id: "artifact:activated-hidden".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "restricted".into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let policy = crate::sekai::object_security::ObjectSecurityPolicy {
        contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: "ns".into(),
        kind: "artifact".into(),
        rules: vec![crate::sekai::object_security::ObjectSecurityRule {
            operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
            predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: None,
        value_instance_grants: None,
        required_purpose: None,
    };
    let revision = svc
        .db
        .runtime()
        .put_object_security_policy(&policy, "root", "put-find-activated", 1)
        .unwrap();
    svc.db
        .runtime()
        .activate_object_security_policies(
            "ns",
            &BTreeMap::from([("artifact".into(), revision.revision_digest)]),
            "root",
            "activate-find-activated",
            2,
        )
        .unwrap();
    let err = svc
        .find_by_external_id(with_named_principal(
            FindByExternalIdRequest {
                external_id: "artifact:activated-hidden".into(),
            },
            "bob",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn record_decision_clamps_future_timestamp() {
    let svc = service();
    let future = now_millis() + 86_400_000;
    let recorded = svc
        .record_decision(with_principal(RecordDecisionRequest {
            decision: Some(Decision {
                id: String::new(),
                timestamp: future,
                actor: "tester".into(),
                action: "act".into(),
                reason: String::new(),
                evidence: HashMap::new(),
                target_id: String::new(),
                outcome: "done".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .decision
        .unwrap();
    // A future timestamp would pin the ledger's purgeable prefix forever.
    assert!(recorded.timestamp < future);
    assert!(recorded.timestamp <= now_millis());
}

#[tokio::test]
async fn record_decision_strips_reserved_attestation_evidence_keys() {
    let svc = service();
    let recorded = svc
        .record_decision(with_principal(RecordDecisionRequest {
            decision: Some(Decision {
                id: String::new(),
                timestamp: 0,
                actor: "tester".into(),
                action: "act".into(),
                reason: String::new(),
                evidence: HashMap::from([
                    ("attestation_id".into(), "forged".into()),
                    ("attestation_hash".into(), "forged".into()),
                    ("note".into(), "kept".into()),
                ]),
                target_id: String::new(),
                outcome: "done".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .decision
        .unwrap();
    assert!(!recorded.evidence.contains_key("attestation_id"));
    assert!(!recorded.evidence.contains_key("attestation_hash"));
    assert_eq!(recorded.evidence["note"], "kept");
    let stored = svc
        .db
        .runtime()
        .get_decision(&recorded.id)
        .unwrap()
        .unwrap();
    assert!(!stored.evidence.contains_key("attestation_id"));
    assert!(!stored.evidence.contains_key("attestation_hash"));
}

#[tokio::test]
async fn struct_property_round_trips_through_create_update_and_list() {
    let svc = service();
    grant_schema_admin(&svc);
    let mut schema_type = widget_schema_type();
    schema_type.properties.push(PropertyDef {
        name: "ai_result".into(),
        r#type: "struct".into(),
        required: false,
        description: "AI generated compound value".into(),
        enum_values: vec![],
        link_kind: "".into(),
        compute_expr: "".into(),
        classification: "public".into(),
        struct_fields: vec![
            StructFieldDef {
                name: "value".into(),
                r#type: "string".into(),
                required: true,
                description: "".into(),
                enum_values: vec![],
            },
            StructFieldDef {
                name: "confidence".into(),
                r#type: "float".into(),
                required: true,
                description: "".into(),
                enum_values: vec![],
            },
            StructFieldDef {
                name: "generated_at".into(),
                r#type: "timestamp".into(),
                required: false,
                description: "".into(),
                enum_values: vec![],
            },
        ],
    });
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(schema_type),
    }))
    .await
    .unwrap();

    let initial_value = r#"{"value":"approve","confidence":0.91,"source_objects":["widget:1"]}"#;
    let created = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "widget-ai",
                HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "blue".into()),
                    ("ai_result".into(), initial_value.into()),
                ]),
            )),
            lease_precondition: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(created.properties["ai_result"], initial_value);

    let listed = svc
        .list_objects(with_principal(ListObjectsRequest {
            filter: Some(ListFilter {
                kind: "widget".into(),
                limit: 10,
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.objects[0].properties["ai_result"], initial_value);

    let updated_value =
        r#"{"value":"reject","confidence":0.12,"generated_at":"2026-07-06T12:00:00Z"}"#;
    let mut updated = created;
    updated
        .properties
        .insert("ai_result".into(), updated_value.into());
    svc.update_object(with_principal(UpdateObjectRequest {
        object: Some(updated),
        lease_precondition: None,
    }))
    .await
    .unwrap();
    let stored = svc.db.runtime().get_object("widget-ai").unwrap().unwrap();
    assert_eq!(stored.properties["ai_result"], updated_value);

    let err = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "widget-ai-invalid",
                HashMap::from([
                    ("name".into(), "bad".into()),
                    ("color".into(), "blue".into()),
                    ("ai_result".into(), r#"{"value":"approve"}"#.into()),
                ]),
            )),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("confidence"));

    let err = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "widget-ai-type-mismatch",
                HashMap::from([
                    ("name".into(), "bad".into()),
                    ("color".into(), "blue".into()),
                    (
                        "ai_result".into(),
                        r#"{"value":"approve","confidence":"high"}"#.into(),
                    ),
                ]),
            )),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("expected float"));
}

#[tokio::test]
async fn dataset_rpc_round_trip() {
    let svc = service();
    let created = svc
        .create_dataset(with_principal(CreateDatasetRequest {
            dataset: Some(Dataset {
                id: "ds1".into(),
                name: "metrics".into(),
                columns: vec![ColumnDef {
                    name: "value".into(),
                    r#type: "int".into(),
                    classification: "public".into(),
                }],
                object_id: "".into(),
                created: 1,
                partition_keys: Vec::new(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.dataset.unwrap().id, "ds1");

    let rows = vec![
        Row {
            values: HashMap::from([("value".into(), "1".into())]),
        },
        Row {
            values: HashMap::from([("value".into(), "2".into())]),
        },
    ];
    let append = svc
        .append_rows(with_principal(AppendRowsRequest {
            dataset_id: "ds1".into(),
            rows,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(append.count, 2);

    let queried = svc
        .query_rows(with_principal(QueryRowsRequest {
            dataset_id: "ds1".into(),
            query: Some(RowQuery {
                filters: vec![RowFilter {
                    column: "value".into(),
                    op: "gte".into(),
                    value: "2".into(),
                }],
                columns: vec![],
                limit: 0,
                offset: 0,
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(queried.rows.len(), 1);
}

#[tokio::test]
async fn list_datasets_omits_bindings_above_marking_ceiling() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "marked-dataset-object".into(),
            kind: "artifact".into(),
            name: "secret-metrics".into(),
            namespace: "ns".into(),
            external_id: "artifact:marked-dataset".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_dataset(&dataset::Dataset {
            id: "marked-ds".into(),
            name: "secret-metrics".into(),
            columns: vec![],
            object_id: "marked-dataset-object".into(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    svc.db
        .runtime()
        .create_dataset(&dataset::Dataset {
            id: "open-ds".into(),
            name: "open-metrics".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    let denied = svc
        .list_datasets(with_named_principal(ListDatasetsRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    let denied_ids: Vec<&str> = denied
        .datasets
        .iter()
        .map(|dataset| dataset.id.as_str())
        .collect();
    assert!(denied_ids.contains(&"open-ds"));
    assert!(!denied_ids.contains(&"marked-ds"));

    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "principal-alice-dataset".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "alice".into(),
            namespace: "ns".into(),
            external_id: markings::principal_profile_external_id("alice"),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    "confidential".into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    grant_object_role(
        &svc,
        "principal-alice-dataset",
        "root",
        security::Role::Admin,
    );
    let allowed = svc
        .list_datasets(with_named_principal(ListDatasetsRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    let allowed_ids: Vec<&str> = allowed
        .datasets
        .iter()
        .map(|dataset| dataset.id.as_str())
        .collect();
    assert!(allowed_ids.contains(&"open-ds"));
    assert!(allowed_ids.contains(&"marked-ds"));
}

#[tokio::test]
async fn list_schema_types_omits_marked_catalog_objects_above_ceiling() {
    let svc = service();
    grant_schema_admin(&svc);
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(widget_schema_type()),
    }))
    .await
    .unwrap();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: schema_object_id("widget"),
            kind: "schema_type".into(),
            name: "widget".into(),
            namespace: "ns".into(),
            external_id: "schema:widget".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let denied = svc
        .list_schema_types(with_named_principal(ListSchemaTypesRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    assert!(
        !denied
            .types
            .iter()
            .any(|object_type| object_type.kind == "widget")
    );

    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "principal-alice-schema".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "alice".into(),
            namespace: "ns".into(),
            external_id: markings::principal_profile_external_id("alice"),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    "confidential".into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    grant_object_role(
        &svc,
        "principal-alice-schema",
        "root",
        security::Role::Admin,
    );
    let allowed = svc
        .list_schema_types(with_named_principal(ListSchemaTypesRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    assert!(
        allowed
            .types
            .iter()
            .any(|object_type| object_type.kind == "widget")
    );
}

#[tokio::test]
async fn catalog_listings_omit_bindings_when_object_policy_cannot_be_evaluated() {
    let svc = service();
    grant_schema_admin(&svc);
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(widget_schema_type()),
    }))
    .await
    .unwrap();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: schema_object_id("widget"),
            kind: "schema_type".into(),
            name: "widget".into(),
            namespace: "ns".into(),
            external_id: "schema:widget".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "policy-outage-object".into(),
            kind: "artifact".into(),
            name: "metrics".into(),
            namespace: "ns".into(),
            external_id: "artifact:policy-outage".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_dataset(&dataset::Dataset {
            id: "policy-outage-ds".into(),
            name: "metrics".into(),
            columns: vec![],
            object_id: "policy-outage-object".into(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    svc.db
        .runtime()
        .create_dataset(&dataset::Dataset {
            id: "unbound-ds".into(),
            name: "global".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    svc.db
        .runtime()
        .conn()
        .execute(
            "INSERT INTO sekai_classification_lattices
             (namespace, contract_version, digest, lattice_json, created_by, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            ("ns", "v1", "stale", "{", "root", 1_i64),
        )
        .unwrap();

    let datasets = svc
        .list_datasets(with_named_principal(ListDatasetsRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    let dataset_ids: Vec<&str> = datasets
        .datasets
        .iter()
        .map(|dataset| dataset.id.as_str())
        .collect();
    assert!(dataset_ids.contains(&"unbound-ds"));
    assert!(!dataset_ids.contains(&"policy-outage-ds"));

    let types = svc
        .list_schema_types(with_named_principal(ListSchemaTypesRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    assert!(
        !types
            .types
            .iter()
            .any(|object_type| object_type.kind == "widget")
    );
    assert!(
        types
            .types
            .iter()
            .any(|object_type| object_type.kind == "namespace")
    );
}

fn discoverer_context(subject: &str) -> crate::enterprise::AuthenticatedContext {
    crate::enterprise::AuthenticatedContext {
        contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
        home_tenant: None,
        principal: crate::enterprise::AuthenticatedPrincipal {
            subject: subject.into(),
            credential_id: "credential-a".into(),
        },
        credential_kind: crate::enterprise::CredentialKind::HumanSession,
        tenant: Some(crate::enterprise::TenantContext {
            tenant_id: "tenant-test".into(),
            subject: subject.into(),
        }),
        space: Some("space-a".into()),
        space_role: Some(crate::enterprise::SpaceRole::Discoverer),
        act: Some("origin-user".into()),
        scopes: vec!["sekai.discover".into()],
        issuer: "https://issuer.test".into(),
        resource: "https://sekai.test".into(),
        expires_at: i64::MAX,
    }
}

fn with_discoverer<T>(payload: T, subject: &str) -> Request<T> {
    let mut req = with_named_principal(payload, subject);
    req.extensions_mut().insert(discoverer_context(subject));
    req
}

#[tokio::test]
async fn discoverer_lists_catalog_and_is_denied_object_reads() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "catalog-bound".into(),
            kind: "artifact".into(),
            name: "metrics".into(),
            namespace: "ns".into(),
            external_id: "artifact:catalog-bound".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_dataset(&dataset::Dataset {
            id: "bound-ds".into(),
            name: "metrics".into(),
            columns: vec![],
            object_id: "catalog-bound".into(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    svc.db
        .runtime()
        .create_dataset(&dataset::Dataset {
            id: "unbound-ds".into(),
            name: "global".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();

    let listed = svc
        .list_schema_types(with_discoverer(ListSchemaTypesRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    assert!(
        listed
            .types
            .iter()
            .any(|object_type| object_type.kind == "namespace")
    );

    let datasets = svc
        .list_datasets(with_discoverer(ListDatasetsRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    let ids: Vec<&str> = datasets
        .datasets
        .iter()
        .map(|dataset| dataset.id.as_str())
        .collect();
    assert!(ids.contains(&"bound-ds"));
    assert!(!ids.contains(&"unbound-ds"));

    let read = svc
        .get_object(with_discoverer(
            GetObjectRequest {
                id: "catalog-bound".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert!(
        read.code() == tonic::Code::PermissionDenied || read.code() == tonic::Code::NotFound,
        "{read:?}"
    );

    let mut community = with_named_principal(ListDatasetsRequest {}, "alice");
    community
        .extensions_mut()
        .insert(crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: "alice".into(),
                credential_id: "credential-a".into(),
            },
        ));
    let community_ids: Vec<String> = svc
        .list_datasets(community)
        .await
        .unwrap()
        .into_inner()
        .datasets
        .into_iter()
        .map(|dataset| dataset.id)
        .collect();
    assert!(community_ids.iter().any(|id| id == "unbound-ds"));
    assert!(community_ids.iter().any(|id| id == "bound-ds"));

    grant_schema_admin(&svc);
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(widget_schema_type()),
    }))
    .await
    .unwrap();
    let scoped_types = svc
        .list_schema_types(with_discoverer(ListSchemaTypesRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    assert!(
        scoped_types
            .types
            .iter()
            .any(|object_type| object_type.kind == "namespace" && object_type.is_builtin)
    );
    assert!(
        !scoped_types
            .types
            .iter()
            .any(|object_type| object_type.kind == "widget")
    );

    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "marked-catalog-bound".into(),
            kind: "artifact".into(),
            name: "secret-metrics".into(),
            namespace: "ns".into(),
            external_id: "artifact:marked-catalog".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_dataset(&dataset::Dataset {
            id: "marked-bound-ds".into(),
            name: "secret-metrics".into(),
            columns: vec![],
            object_id: "marked-catalog-bound".into(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "principal-alice-discover".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "alice".into(),
            namespace: "ns".into(),
            external_id: markings::principal_profile_external_id("alice"),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    "confidential".into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    grant_object_role(
        &svc,
        "principal-alice-discover",
        "root",
        security::Role::Admin,
    );
    let delegated = svc
        .list_datasets(with_discoverer(ListDatasetsRequest {}, "alice"))
        .await
        .unwrap()
        .into_inner();
    assert!(
        !delegated
            .datasets
            .iter()
            .any(|dataset| dataset.id == "marked-bound-ds")
    );
}

#[tokio::test]
async fn query_rows_reports_corrupt_storage_as_internal() {
    let svc = service();
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "corrupt-dataset".into(),
            name: "corrupt".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    svc.db
        .runtime()
        .with_sqlite_conn(|connection| {
            connection.execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data) VALUES (?1, ?2)",
                ["corrupt-dataset", "not-json"],
            )
        })
        .unwrap()
        .unwrap();

    let error = svc
        .query_rows(with_principal(QueryRowsRequest {
            dataset_id: "corrupt-dataset".into(),
            query: None,
        }))
        .await
        .unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(error.message().contains("corrupt dataset row"));
}

#[tokio::test]
async fn rollback_dataset_restores_prior_snapshot_as_new_version() {
    let svc = service();
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "versioned".into(),
            name: "versioned".into(),
            columns: vec![ColumnDef {
                name: "kind".into(),
                r#type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    for kind in ["v1", "v2", "v3"] {
        svc.append_rows(with_principal(AppendRowsRequest {
            dataset_id: "versioned".into(),
            rows: vec![Row {
                values: [("kind".into(), kind.into())].into(),
            }],
        }))
        .await
        .unwrap();
    }
    let listed = svc
        .list_dataset_versions(with_principal(ListDatasetVersionsRequest {
            dataset_id: "versioned".into(),
            as_of_ms: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.versions.len(), 3);
    let first = listed.versions[0].clone();
    let rolled = svc
        .rollback_dataset(with_principal(RollbackDatasetRequest {
            dataset_id: "versioned".into(),
            restore_from_version_id: first.version_id.clone(),
            reason: "bad sync".into(),
            tenant: "tenant-a".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    let version = rolled.version.unwrap();
    assert_eq!(version.seq, 4);
    assert_eq!(version.restored_from_version_id, first.version_id);
    assert_eq!(version.actor, "tester");
    let live = svc
        .query_rows(with_principal(QueryRowsRequest {
            dataset_id: "versioned".into(),
            query: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .rows;
    assert_eq!(live, rolled.rows);
    svc.db
        .runtime()
        .set_dataset_version_retention("versioned", 2)
        .unwrap();
    svc.append_rows(with_principal(AppendRowsRequest {
        dataset_id: "versioned".into(),
        rows: vec![Row {
            values: [("kind".into(), "v5".into())].into(),
        }],
    }))
    .await
    .unwrap();
    let error = svc
        .get_dataset_version(with_principal(GetDatasetVersionRequest {
            dataset_id: "versioned".into(),
            version_id: first.version_id,
            as_of_ms: 0,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("past retention"));
}

#[tokio::test]
async fn rollback_dataset_requires_write_access() {
    let svc = service();
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "protected-versions".into(),
            name: "protected".into(),
            columns: vec![ColumnDef {
                name: "kind".into(),
                r#type: "string".into(),
                classification: "public".into(),
            }],
            object_id: "protected-version-object".into(),
            created: 1,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    let grant = security::Grant {
        id: "dataset-version-owner".into(),
        object_id: "protected-version-object".into(),
        principal: "tester".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
    svc.append_rows(with_principal(AppendRowsRequest {
        dataset_id: "protected-versions".into(),
        rows: vec![Row {
            values: [("kind".into(), "v1".into())].into(),
        }],
    }))
    .await
    .unwrap();
    let listed = svc
        .list_dataset_versions(with_principal(ListDatasetVersionsRequest {
            dataset_id: "protected-versions".into(),
            as_of_ms: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    let error = svc
        .rollback_dataset(with_named_principal(
            RollbackDatasetRequest {
                dataset_id: "protected-versions".into(),
                restore_from_version_id: listed.versions[0].version_id.clone(),
                reason: "intruder".into(),
                tenant: String::new(),
            },
            "intruder",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn rollback_dataset_rejects_tenant_mismatch() {
    let svc = enterprise_service();
    svc.db
        .runtime()
        .create_dataset(&crate::sekai::dataset::Dataset {
            id: "mismatch-versions".into(),
            name: "mismatch".into(),
            columns: vec![crate::sekai::dataset::ColumnDef {
                name: "kind".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    svc.db
        .runtime()
        .append_rows(
            "mismatch-versions",
            &[std::collections::HashMap::from([(
                "kind".into(),
                "v1".into(),
            )])],
        )
        .unwrap();
    let versions = svc
        .db
        .runtime()
        .list_dataset_versions("mismatch-versions")
        .unwrap();
    let restore = versions[0].version_id.clone();
    let error = svc
        .rollback_dataset(with_tenant_context(RollbackDatasetRequest {
            dataset_id: "mismatch-versions".into(),
            restore_from_version_id: restore.clone(),
            reason: "spoof".into(),
            tenant: "other-tenant".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    let rolled = svc
        .rollback_dataset(with_tenant_context(RollbackDatasetRequest {
            dataset_id: "mismatch-versions".into(),
            restore_from_version_id: restore,
            reason: "restore".into(),
            tenant: "tenant-test".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rolled.version.unwrap().tenant, "tenant-test");
}

#[tokio::test]
async fn dataset_health_checks_quarantine_and_schedule_alerts() {
    let svc = service();
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "health".into(),
            name: "health".into(),
            columns: vec![ColumnDef {
                name: "kind".into(),
                r#type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    svc.put_dataset_health_check(with_principal(PutDatasetHealthCheckRequest {
        check: Some(DatasetHealthCheck {
            dataset_id: "health".into(),
            check_id: "count".into(),
            kind: "row_count".into(),
            max_age_ms: 0,
            min_rows: 1,
            max_rows: 1,
            columns: Vec::new(),
            predicate: Vec::new(),
            blocking: true,
            every_ms: 0,
            tenant: "acme".into(),
            space: "ops".into(),
        }),
    }))
    .await
    .unwrap();
    svc.append_rows(with_principal(AppendRowsRequest {
        dataset_id: "health".into(),
        rows: vec![Row {
            values: [("kind".into(), "v1".into())].into(),
        }],
    }))
    .await
    .unwrap();
    svc.append_rows(with_principal(AppendRowsRequest {
        dataset_id: "health".into(),
        rows: vec![Row {
            values: [("kind".into(), "v2".into())].into(),
        }],
    }))
    .await
    .unwrap();
    let live = svc
        .query_rows(with_principal(QueryRowsRequest {
            dataset_id: "health".into(),
            query: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .rows;
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].values["kind"], "v1");
    let status = svc
        .list_dataset_health_results(with_principal(ListDatasetHealthResultsRequest {
            dataset_id: "health".into(),
            version_id: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(status.quarantined);

    svc.put_dataset_health_check(with_principal(PutDatasetHealthCheckRequest {
        check: Some(DatasetHealthCheck {
            dataset_id: "health".into(),
            check_id: "fresh".into(),
            kind: "freshness".into(),
            max_age_ms: 10_000,
            min_rows: 0,
            max_rows: 0,
            columns: Vec::new(),
            predicate: Vec::new(),
            blocking: false,
            every_ms: 1_000,
            tenant: "acme".into(),
            space: "ops".into(),
        }),
    }))
    .await
    .unwrap();
    svc.run_dataset_health_checks(with_principal(RunDatasetHealthChecksRequest {
        dataset_id: "health".into(),
        now_ms: 5_000,
    }))
    .await
    .unwrap();
    svc.run_dataset_health_checks(with_principal(RunDatasetHealthChecksRequest {
        dataset_id: "health".into(),
        now_ms: 7_000,
    }))
    .await
    .unwrap();
    let alerts = svc
        .list_dataset_alerts(with_principal(ListDatasetAlertsRequest {
            dataset_id: "health".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .alerts;
    let late: Vec<_> = alerts
        .iter()
        .filter(|alert| alert.reason == "late")
        .collect();
    assert_eq!(late.len(), 1);
    assert_eq!(late[0].state, "firing");
    svc.run_dataset_health_checks(with_principal(RunDatasetHealthChecksRequest {
        dataset_id: "health".into(),
        now_ms: 7_500,
    }))
    .await
    .unwrap();
    let alerts = svc
        .list_dataset_alerts(with_principal(ListDatasetAlertsRequest {
            dataset_id: "health".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .alerts;
    assert_eq!(
        alerts.iter().filter(|alert| alert.reason == "late").count(),
        1
    );
    svc.run_dataset_health_checks(with_principal(RunDatasetHealthChecksRequest {
        dataset_id: "health".into(),
        now_ms: 8_000,
    }))
    .await
    .unwrap();
    let alerts = svc
        .list_dataset_alerts(with_principal(ListDatasetAlertsRequest {
            dataset_id: "health".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .alerts;
    let late: Vec<_> = alerts
        .iter()
        .filter(|alert| alert.reason == "late")
        .collect();
    assert_eq!(late.len(), 2);
    assert_eq!(late[1].state, "resolved");
}

#[tokio::test]
async fn update_dataset_requires_write_access_to_existing_binding() {
    let svc = service();
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "protected-dataset".into(),
            name: "original".into(),
            columns: vec![ColumnDef {
                name: "value".into(),
                r#type: "string".into(),
                classification: "public".into(),
            }],
            object_id: "protected-object".into(),
            created: 1,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    let grant = security::Grant {
        id: "dataset-owner".into(),
        object_id: "protected-object".into(),
        principal: "tester".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);

    let error = svc
        .update_dataset(with_named_principal(
            UpdateDatasetRequest {
                dataset: Some(Dataset {
                    id: "protected-dataset".into(),
                    name: "hijacked".into(),
                    columns: vec![],
                    object_id: String::new(),
                    created: 999,
                    partition_keys: Vec::new(),
                }),
            },
            "intruder",
        ))
        .await
        .unwrap_err();

    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    let stored = svc
        .db
        .runtime()
        .get_dataset("protected-dataset")
        .unwrap()
        .unwrap();
    assert_eq!(stored.name, "original");
    assert_eq!(stored.object_id, "protected-object");
}

#[tokio::test]
async fn update_unbound_dataset_requires_gateway_service_principal() {
    let mut svc = service();
    svc.gateway_schema_principals = vec!["gateway-prod".into()];
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "llm_calls".into(),
            name: "original".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    let update = UpdateDatasetRequest {
        dataset: Some(Dataset {
            id: "llm_calls".into(),
            name: "updated".into(),
            columns: vec![ColumnDef {
                name: "receipt_id".into(),
                r#type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 999,
            partition_keys: Vec::new(),
        }),
    };

    let error = svc
        .update_dataset(with_principal(update.clone()))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);

    let updated = svc
        .update_dataset(with_named_principal(update.clone(), "gateway-prod"))
        .await
        .unwrap()
        .into_inner()
        .dataset
        .unwrap();
    assert_eq!(updated.name, "updated");
    assert_eq!(updated.columns[0].name, "receipt_id");
    assert_eq!(updated.created, 1);

    // Reserved UDS/local-socket admin can converge llm_calls without a
    // spoofed gateway principal (matches force-local transport identity).
    let local_updated = svc
        .update_dataset(with_named_principal(
            UpdateDatasetRequest {
                dataset: Some(Dataset {
                    id: "llm_calls".into(),
                    name: "local-admin".into(),
                    columns: vec![ColumnDef {
                        name: "receipt_id".into(),
                        r#type: "string".into(),
                        classification: "public".into(),
                    }],
                    object_id: String::new(),
                    created: 1000,
                    partition_keys: Vec::new(),
                }),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .dataset
        .unwrap();
    assert_eq!(local_updated.name, "local-admin");

    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "other-system-dataset".into(),
            name: "original".into(),
            columns: vec![],
            object_id: String::new(),
            created: 2,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    let error = svc
        .update_dataset(with_named_principal(
            UpdateDatasetRequest {
                dataset: Some(Dataset {
                    id: "other-system-dataset".into(),
                    name: "hijacked".into(),
                    columns: vec![],
                    object_id: String::new(),
                    created: 2,
                    partition_keys: Vec::new(),
                }),
            },
            "gateway-prod",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn create_function_rejects_an_empty_pipeline_step() {
    let svc = service();
    let error = svc
        .create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "empty-step".into(),
                pipeline: vec![PipelineStep {
                    step: None,
                    ..Default::default()
                }],
                ..Default::default()
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(error.message().contains("pipeline step required"));
}

#[tokio::test]
async fn create_function_refuses_an_ungated_llm_step_and_invoke_fail_closes_without_a_host() {
    let svc = service();
    let schema =
        r#"{"type":"object","properties":{"label":{"type":"string"}},"required":["label"]}"#;
    let function = Function {
        name: "classify".into(),
        pipeline: vec![PipelineStep {
            step: Some(pipeline_step::Step::Llm(LlmStep {
                prompt_revision: "classify/v1".into(),
                input_bindings: HashMap::from([("language".into(), "language".into())]),
                output_schema: schema.into(),
                model_route: "native/scripted".into(),
                minimum_confidence_micros: 800_000,
            })),
            ..Default::default()
        }],
        ..Default::default()
    };
    let refused = svc
        .create_function(with_principal(CreateFunctionRequest {
            function: Some(function.clone()),
        }))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        refused.message(),
        crate::sekai::function::LLM_FUNCTION_REQUIRES_GATE
    );
    let invoke = || {
        svc.invoke_function(with_principal(InvokeFunctionRequest {
            name: "classify".into(),
            ..Default::default()
        }))
    };
    // A row stored before gate approvals were recorded is not invokable.
    let crate::db::runtime_db::RuntimeDb::Sqlite(sqlite) = svc.db.runtime() else {
        panic!("sqlite test service");
    };
    sqlite
        .create_function(&from_proto_function(&function).unwrap())
        .unwrap();
    let legacy = invoke().await.unwrap_err();
    assert_eq!(legacy.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        legacy.message(),
        crate::sekai::function::LLM_FUNCTION_REQUIRES_GATE
    );
    // Once the revision's gate approval exists, invoke reaches the (absent) LLM host.
    let parsed = from_proto_function(&function).unwrap();
    sqlite
        .approve_function_gate(
            &crate::sekai::function::function_digest(&parsed),
            "classify",
        )
        .unwrap();
    let listed = svc
        .list_functions(with_principal(ListFunctionsRequest {}))
        .await
        .unwrap()
        .into_inner()
        .functions;
    let function = listed
        .iter()
        .find(|function| function.name == "classify")
        .expect("classify function");
    match function.pipeline[0].step.as_ref() {
        Some(pipeline_step::Step::Llm(step)) => {
            assert_eq!(step.prompt_revision, "classify/v1");
            assert_eq!(step.model_route, "native/scripted");
            assert_eq!(step.output_schema, schema);
            assert_eq!(step.minimum_confidence_micros, 800_000);
        }
        other => panic!("expected llm step, got {other:?}"),
    }
    let error = invoke().await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(error.message().contains("llm step requires a host"));
}

#[tokio::test]
async fn computed_property_resolves_from_function_without_persisting() {
    let svc = service();
    grant_schema_admin(&svc);
    svc.create_function(with_principal(CreateFunctionRequest {
        function: Some(Function {
            name: "count_children".into(),
            description: "".into(),
            params: vec![],
            pipeline: vec![
                operator_pipeline("self", "", "", ""),
                operator_pipeline("traverse", "contains", "", ""),
                operator_pipeline("aggregate", "", "count", "child_count"),
            ],
            created: 1,
        }),
    }))
    .await
    .unwrap();
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(ObjectType {
            kind: "cluster".into(),
            description: "Cluster".into(),
            properties: vec![PropertyDef {
                name: "child_count".into(),
                r#type: "computed".into(),
                required: false,
                description: "".into(),
                enum_values: vec![],
                link_kind: "".into(),
                compute_expr: "count_children".into(),
                classification: "public".into(),
                struct_fields: vec![],
            }],
            is_builtin: false,
            implements: vec![],
        }),
    }))
    .await
    .unwrap();
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(Object {
            id: "cluster-1".into(),
            kind: "cluster".into(),
            name: "cluster".into(),
            namespace: "".into(),
            external_id: "cluster:one".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }),
        lease_precondition: None,
    }))
    .await
    .unwrap();
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(Object {
            id: "component-1".into(),
            kind: "component".into(),
            name: "component".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }),
        lease_precondition: None,
    }))
    .await
    .unwrap();
    svc.create_link(with_principal(CreateLinkRequest {
        fail_if_exists: false,
        link: Some(Link {
            id: "cluster-component".into(),
            from_id: "cluster-1".into(),
            to_id: "component-1".into(),
            relation: "contains".into(),
            created: 0,
        }),
    }))
    .await
    .unwrap();
    let duplicate = svc
        .create_link(with_principal(CreateLinkRequest {
            fail_if_exists: true,
            link: Some(Link {
                id: "cluster-component".into(),
                from_id: "cluster-1".into(),
                to_id: "component-1".into(),
                relation: "contains".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(duplicate.code(), tonic::Code::AlreadyExists);

    let got = svc
        .get_object(with_principal(GetObjectRequest {
            id: "cluster-1".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(got.properties["child_count"], "1");

    let listed = svc
        .list_objects(with_principal(ListObjectsRequest {
            filter: Some(ListFilter {
                kind: "cluster".into(),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.objects[0].properties["child_count"], "1");

    let stored = svc.db.runtime().get_object("cluster-1").unwrap().unwrap();
    assert!(!stored.properties.contains_key("child_count"));
}

#[tokio::test]
async fn create_link_assigns_empty_id_and_returns_stored_row() {
    let svc = service();
    for id in ["link-from", "link-to"] {
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: id.into(),
                kind: "widget".into(),
                name: id.into(),
                ..Default::default()
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();
    }
    let created = svc
        .create_link(with_principal(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(Link {
                id: "existing-link".into(),
                from_id: "link-from".into(),
                to_id: "link-to".into(),
                relation: "pairs_with".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .link
        .unwrap();
    assert_eq!(created.id, "existing-link");
    let replayed = svc
        .create_link(with_principal(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(Link {
                id: "existing-link".into(),
                from_id: "link-from".into(),
                to_id: "link-to".into(),
                relation: "pairs_with".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .link
        .unwrap();
    assert_eq!(replayed.id, "existing-link");
    assert_eq!(replayed.from_id, "link-from");
    assert_eq!(replayed.to_id, "link-to");
    let collided = svc
        .create_link(with_principal(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(Link {
                id: "existing-link".into(),
                from_id: "link-to".into(),
                to_id: "link-from".into(),
                relation: "pairs_with".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(collided.code(), tonic::Code::AlreadyExists);
    let assigned = svc
        .create_link(with_principal(CreateLinkRequest {
            fail_if_exists: true,
            link: Some(Link {
                id: String::new(),
                from_id: "link-from".into(),
                to_id: "link-to".into(),
                relation: "feeds".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .link
        .unwrap();
    assert!(assigned.id.starts_with("link-"), "{assigned:?}");
    assert_ne!(assigned.id, "existing-link");
    assert!(assigned.created > 0);
    let feeds = svc
        .get_links(with_principal(GetLinksRequest {
            object_id: "link-from".into(),
            relation: "feeds".into(),
            direction: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
        .links;
    assert_eq!(feeds.len(), 1, "{feeds:?}");
    assert_eq!(feeds[0].id, assigned.id);
}

#[tokio::test]
async fn computed_aggregates_exclude_objects_denied_by_active_policy() {
    let svc = service();
    grant_schema_admin(&svc);
    svc.create_function(with_principal(CreateFunctionRequest {
        function: Some(Function {
            name: "count_policy_children".into(),
            pipeline: vec![
                operator_pipeline("self", "", "", ""),
                operator_pipeline("traverse", "contains", "", ""),
                operator_pipeline("aggregate", "", "count", "child_count"),
            ],
            ..Default::default()
        }),
    }))
    .await
    .unwrap();
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(ObjectType {
            kind: "policy-cluster".into(),
            properties: vec![PropertyDef {
                name: "child_count".into(),
                r#type: "computed".into(),
                compute_expr: "count_policy_children".into(),
                classification: "public".into(),
                ..Default::default()
            }],
            ..Default::default()
        }),
    }))
    .await
    .unwrap();

    let namespace = "computed-policy";
    for (id, kind, owner) in [
        ("policy-cluster", "policy-cluster", "alice"),
        ("allowed-child", "policy-component", "alice"),
        ("denied-child", "policy-component", "bob"),
    ] {
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: id.into(),
                kind: kind.into(),
                name: id.into(),
                namespace: namespace.into(),
                external_id: format!("{namespace}:{id}"),
                properties: HashMap::from([("owner".into(), owner.into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();
    }
    for child in ["allowed-child", "denied-child"] {
        svc.db
            .runtime()
            .create_link(&domain::Link {
                id: format!("policy-cluster->{child}"),
                from_id: "policy-cluster".into(),
                to_id: child.into(),
                relation: "contains".into(),
                created: 1,
            })
            .unwrap();
    }

    let allow_cluster = crate::sekai::object_security::ObjectSecurityPolicy {
        contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "policy-cluster".into(),
        rules: vec![crate::sekai::object_security::ObjectSecurityRule {
            operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
            predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: None,
        value_instance_grants: None,
        required_purpose: None,
    };
    let owned_component = crate::sekai::object_security::ObjectSecurityPolicy {
        contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "policy-component".into(),
        rules: vec![crate::sekai::object_security::ObjectSecurityRule {
            operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
            predicates: vec![
                crate::sekai::object_security::ObjectSecurityPredicate::SubjectEqualsProperty {
                    property: "owner".into(),
                },
            ],
        }],
        property_grants: None,
        value_instance_grants: None,
        required_purpose: None,
    };
    let cluster_revision = svc
        .db
        .runtime()
        .put_object_security_policy(&allow_cluster, "root", "put-computed-cluster", 1)
        .unwrap();
    let component_revision = svc
        .db
        .runtime()
        .put_object_security_policy(&owned_component, "root", "put-computed-component", 2)
        .unwrap();
    svc.db
        .runtime()
        .activate_object_security_policies(
            namespace,
            &BTreeMap::from([
                ("policy-cluster".into(), cluster_revision.revision_digest),
                (
                    "policy-component".into(),
                    component_revision.revision_digest,
                ),
            ]),
            "root",
            "activate-computed-policy",
            3,
        )
        .unwrap();

    let got = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "policy-cluster".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(got.properties["child_count"], "1");

    let listed = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: "policy-cluster".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.objects[0].properties["child_count"], "1");
}

#[tokio::test]
async fn computed_properties_respect_team_namespace_boundaries() {
    let svc = service();
    svc.ensure_team_namespace(with_named_principal(
        EnsureTeamNamespaceRequest {
            namespace: "acme".into(),
            principal: "alice".into(),
            role: "viewer".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    svc.create_function(with_named_principal(
        CreateFunctionRequest {
            function: Some(Function {
                name: "count_team_children".into(),
                pipeline: vec![
                    operator_pipeline("self", "", "", ""),
                    operator_pipeline("traverse", "contains", "", ""),
                    operator_pipeline("aggregate", "", "count", "child_count"),
                ],
                ..Default::default()
            }),
        },
        "local",
    ))
    .await
    .unwrap();
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "team-cluster".into(),
                properties: vec![PropertyDef {
                    name: "child_count".into(),
                    r#type: "computed".into(),
                    compute_expr: "count_team_children".into(),
                    classification: "public".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        },
        "local",
    ))
    .await
    .unwrap();
    for (id, kind, namespace) in [
        ("team-cluster", "team-cluster", "acme"),
        ("acme-child", "component", "acme"),
        ("beta-child", "component", "beta"),
    ] {
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(Object {
                    id: id.into(),
                    kind: kind.into(),
                    name: id.into(),
                    namespace: namespace.into(),
                    ..Default::default()
                }),
                lease_precondition: None,
            },
            "local",
        ))
        .await
        .unwrap();
    }
    for child in ["acme-child", "beta-child"] {
        svc.create_link(with_named_principal(
            CreateLinkRequest {
                fail_if_exists: false,
                link: Some(Link {
                    id: format!("team-cluster->{child}"),
                    from_id: "team-cluster".into(),
                    to_id: child.into(),
                    relation: "contains".into(),
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap();
    }

    let cluster = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "team-cluster".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(cluster.properties["child_count"], "1");
}

#[tokio::test]
async fn schema_type_rejects_unknown_computed_function() {
    let svc = service();
    grant_schema_admin(&svc);
    let err = svc
        .create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "cluster".into(),
                description: "Cluster".into(),
                properties: vec![PropertyDef {
                    name: "child_count".into(),
                    r#type: "computed".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "missing_function".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                }],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("missing_function"));
}

#[tokio::test]
async fn unresolved_computed_property_hides_stored_value() {
    let svc = service();
    grant_schema_admin(&svc);
    svc.create_function(with_principal(CreateFunctionRequest {
        function: Some(Function {
            name: "ambiguous_child_count".into(),
            description: "".into(),
            params: vec![],
            pipeline: vec![
                operator_pipeline("self", "", "", ""),
                operator_pipeline("aggregate", "", "count", "first"),
                operator_pipeline("aggregate", "", "count", "second"),
            ],
            created: 1,
        }),
    }))
    .await
    .unwrap();
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(ObjectType {
            kind: "cluster".into(),
            description: "Cluster".into(),
            properties: vec![PropertyDef {
                name: "child_count".into(),
                r#type: "computed".into(),
                required: false,
                description: "".into(),
                enum_values: vec![],
                link_kind: "".into(),
                compute_expr: "ambiguous_child_count".into(),
                classification: "public".into(),
                struct_fields: vec![],
            }],
            is_builtin: false,
            implements: vec![],
        }),
    }))
    .await
    .unwrap();
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(Object {
            id: "cluster-spoofed".into(),
            kind: "cluster".into(),
            name: "cluster".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("child_count".into(), "spoofed".into())]),
            created: 0,
            updated: 0,
        }),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    let got = svc
        .get_object(with_principal(GetObjectRequest {
            id: "cluster-spoofed".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert!(!got.properties.contains_key("child_count"));

    let stored = svc
        .db
        .runtime()
        .get_object("cluster-spoofed")
        .unwrap()
        .unwrap();
    assert_eq!(stored.properties["child_count"], "spoofed");
}

#[tokio::test]
async fn object_mutations_record_audit_changes() {
    let svc = service();
    svc.create_object(with_named_principal(
        CreateObjectRequest {
            object: Some(Object {
                id: "audit-1".into(),
                kind: "component".into(),
                name: "api".into(),
                namespace: "default".into(),
                external_id: "component:api".into(),
                properties: HashMap::from([("status".into(), "todo".into())]),
                created: 1,
                updated: 1,
            }),
            lease_precondition: None,
        },
        "alice",
    ))
    .await
    .unwrap();

    svc.update_object(with_named_principal(
        UpdateObjectRequest {
            object: Some(Object {
                id: "audit-1".into(),
                kind: "component".into(),
                name: "worker".into(),
                namespace: "default".into(),
                external_id: "component:api".into(),
                properties: HashMap::from([("status".into(), "done".into())]),
                created: 1,
                updated: 2,
            }),
            lease_precondition: None,
        },
        "alice",
    ))
    .await
    .unwrap();

    svc.delete_object(with_named_principal(
        DeleteObjectRequest {
            id: "audit-1".into(),
            lease_precondition: None,
        },
        "alice",
    ))
    .await
    .unwrap();

    let changes = svc
        .list_object_changes(with_named_principal(
            ListObjectChangesRequest {
                object_id: "audit-1".into(),
                limit: 10,
                offset: 0,
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .changes;

    assert_eq!(changes.len(), 4);
    assert_eq!(
        changes
            .iter()
            .map(|change| change.field.as_str())
            .collect::<Vec<_>>(),
        vec!["_deleted", "properties.status", "name", "_created"]
    );
    assert!(changes.iter().all(|change| change.changed_by == "alice"));
    assert_eq!(changes[0].old_value, "component/worker");
    assert_eq!(changes[1].old_value, "todo");
    assert_eq!(changes[1].new_value, "done");
    assert_eq!(changes[2].old_value, "api");
    assert_eq!(changes[2].new_value, "worker");
}

#[tokio::test]
async fn unified_direct_admission_preserves_reserved_ids_and_missing_updates() {
    let svc = service();
    let reserved = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "reserved-principal-id".into(),
                kind: "component".into(),
                name: "ordinary".into(),
                namespace: "default".into(),
                external_id: "principal:alice".into(),
                properties: HashMap::from([(
                    markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "malformed".into(),
                )]),
                created: 1,
                updated: 1,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(reserved.code(), tonic::Code::InvalidArgument);

    let missing = svc
        .update_object(with_principal(UpdateObjectRequest {
            object: Some(Object {
                id: "missing".into(),
                kind: "unloaded_kind".into(),
                name: "missing".into(),
                namespace: "default".into(),
                external_id: "component:missing".into(),
                properties: HashMap::from([(
                    markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "malformed".into(),
                )]),
                created: 1,
                updated: 1,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn noop_update_does_not_record_audit_change() {
    let svc = service();
    let object = Object {
        id: "audit-noop".into(),
        kind: "component".into(),
        name: "api".into(),
        namespace: "default".into(),
        external_id: "component:api".into(),
        properties: HashMap::from([("status".into(), "todo".into())]),
        created: 1,
        updated: 1,
    };
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(object.clone()),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    svc.update_object(with_principal(UpdateObjectRequest {
        object: Some(object),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    let changes = svc
        .list_object_changes(with_principal(ListObjectChangesRequest {
            object_id: "audit-noop".into(),
            limit: 10,
            offset: 0,
        }))
        .await
        .unwrap()
        .into_inner()
        .changes;

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].field, "_created");
}

#[tokio::test]
async fn audit_insert_failure_rolls_back_create() {
    let svc = service();
    svc.db
        .runtime()
        .conn()
        .execute("DROP TABLE sekai_object_changes", [])
        .unwrap();

    let err = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "audit-fail-closed".into(),
                kind: "component".into(),
                name: "api".into(),
                namespace: "default".into(),
                external_id: "component:api".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Internal);
    assert!(
        svc.db
            .runtime()
            .get_object("audit-fail-closed")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn delete_fails_closed_when_delete_audit_insert_fails() {
    let svc = service();
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(Object {
            id: "delete-audit-fail".into(),
            kind: "component".into(),
            name: "api".into(),
            namespace: "default".into(),
            external_id: "component:api".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        }),
        lease_precondition: None,
    }))
    .await
    .unwrap();
    svc.db
        .runtime()
        .conn()
        .execute("DROP TABLE sekai_object_changes", [])
        .unwrap();

    let err = svc
        .delete_object(with_principal(DeleteObjectRequest {
            id: "delete-audit-fail".into(),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Internal);
    assert!(
        svc.db
            .runtime()
            .get_object("delete-audit-fail")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn delete_object_remains_idempotent_when_missing() {
    let svc = service();

    svc.delete_object(with_principal(DeleteObjectRequest {
        id: "missing-object".into(),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    let changes = svc
        .list_object_changes(with_principal(ListObjectChangesRequest {
            object_id: "missing-object".into(),
            limit: 10,
            offset: 0,
        }))
        .await
        .unwrap()
        .into_inner()
        .changes;

    assert!(changes.is_empty());
}

#[tokio::test]
async fn schema_type_enforces_create_and_update() {
    let svc = service();
    grant_schema_admin(&svc);
    let created = svc
        .create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.r#type.unwrap().kind, "widget");

    let missing_required = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object("w1", HashMap::new())),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(missing_required.code(), tonic::Code::InvalidArgument);
    assert!(missing_required.message().contains("name"));

    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(widget_object(
            "w1",
            HashMap::from([
                ("name".into(), "first".into()),
                ("color".into(), "red".into()),
            ]),
        )),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    let invalid_update = svc
        .update_object(with_principal(UpdateObjectRequest {
            object: Some(widget_object(
                "w1",
                HashMap::from([
                    ("name".into(), "first".into()),
                    ("color".into(), "green".into()),
                ]),
            )),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(invalid_update.code(), tonic::Code::InvalidArgument);
    assert!(invalid_update.message().contains("color"));
}

#[tokio::test]
async fn untyped_kind_still_writes_and_schema_types_list() {
    let svc = service();
    grant_schema_admin(&svc);
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(widget_schema_type()),
    }))
    .await
    .unwrap();

    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(Object {
            id: "loose-1".into(),
            kind: "loose".into(),
            name: "loose".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    let listed = svc
        .list_schema_types(with_principal(ListSchemaTypesRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(
        listed
            .types
            .iter()
            .any(|object_type| object_type.kind == "widget" && !object_type.is_builtin)
    );
    assert!(
        listed
            .types
            .iter()
            .any(|object_type| object_type.kind == "namespace" && object_type.is_builtin)
    );
}

#[tokio::test]
async fn object_bound_lease_requires_target_object_authorization() {
    let svc = service();
    let target = Object {
        id: "coord-target".into(),
        kind: "component".into(),
        name: "target".into(),
        namespace: "default".into(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    };
    svc.db
        .runtime()
        .create_object_with_audit(&from_proto_obj(&target), "alice")
        .unwrap();
    grant_object_role(&svc, "coord-target", "alice", security::Role::Editor);

    let key = "object:coord-target".to_string();
    // Principal without object write cannot squat the coordination identity.
    let denied = svc
        .acquire_lease(with_named_principal(
            AcquireLeaseRequest {
                namespace: "default".into(),
                key: key.clone(),
                owner: "bob".into(),
                ttl_ms: 60_000,
                request_id: "bob-acq".into(),
            },
            "bob",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    let lease = svc
        .acquire_lease(with_named_principal(
            AcquireLeaseRequest {
                namespace: "default".into(),
                key: key.clone(),
                owner: "alice".into(),
                ttl_ms: 60_000,
                request_id: "alice-acq".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .lease
        .unwrap();
    assert_eq!(lease.key, key);
    assert!(!lease.fencing_token.is_empty());

    // Inspect also requires object read access.
    let inspect_denied = svc
        .get_lease(with_named_principal(
            GetLeaseRequest {
                namespace: "default".into(),
                key: key.clone(),
            },
            "bob",
        ))
        .await
        .unwrap_err();
    assert_eq!(inspect_denied.code(), tonic::Code::PermissionDenied);

    let got = svc
        .get_lease(with_named_principal(
            GetLeaseRequest {
                namespace: "default".into(),
                key: key.clone(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .lease
        .unwrap();
    assert_eq!(got.fencing_token, lease.fencing_token);

    // Wrong namespace fails closed even with object write rights.
    let wrong_ns = svc
        .acquire_lease(with_named_principal(
            AcquireLeaseRequest {
                namespace: "other".into(),
                key: key.clone(),
                owner: "alice".into(),
                ttl_ms: 60_000,
                request_id: "wrong-ns".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(wrong_ns.code(), tonic::Code::PermissionDenied);

    // Missing object cannot be used as a coordination target.
    let missing = svc
        .acquire_lease(with_named_principal(
            AcquireLeaseRequest {
                namespace: "default".into(),
                key: "object:does-not-exist".into(),
                owner: "alice".into(),
                ttl_ms: 60_000,
                request_id: "missing".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    // Stale token release fails closed; holder with object write can release.
    let stale = svc
        .release_lease(with_named_principal(
            ReleaseLeaseRequest {
                namespace: "default".into(),
                key: key.clone(),
                fencing_token: "not-the-token".into(),
                request_id: "stale".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::FailedPrecondition);

    svc.release_lease(with_named_principal(
        ReleaseLeaseRequest {
            namespace: "default".into(),
            key: key.clone(),
            fencing_token: lease.fencing_token,
            request_id: "release".into(),
        },
        "alice",
    ))
    .await
    .unwrap();

    // After release, a second authorized acquire succeeds (new generation).
    let again = svc
        .acquire_lease(with_named_principal(
            AcquireLeaseRequest {
                namespace: "default".into(),
                key: key.clone(),
                owner: "alice".into(),
                ttl_ms: 60_000,
                request_id: "reacquire".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .lease
        .unwrap();
    assert!(again.generation >= 1);

    // Non-canonical object keys are rejected (no whitespace aliases).
    let non_canonical = svc
        .acquire_lease(with_named_principal(
            AcquireLeaseRequest {
                namespace: "default".into(),
                key: "object: coord-target".into(),
                owner: "alice".into(),
                ttl_ms: 60_000,
                request_id: "non-canonical".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(non_canonical.code(), tonic::Code::InvalidArgument);

    // Object-bound lease cannot guard a different object mutation.
    let other = Object {
        id: "other-target".into(),
        kind: "component".into(),
        name: "other".into(),
        namespace: "default".into(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    };
    svc.db
        .runtime()
        .create_object_with_audit(&from_proto_obj(&other), "alice")
        .unwrap();
    grant_object_role(&svc, "other-target", "alice", security::Role::Editor);
    let mismatch = svc
        .guarded_update_object(with_named_principal(
            GuardedUpdateObjectRequest {
                object: Some(other),
                lease_precondition: Some(LeasePrecondition {
                    namespace: "default".into(),
                    key,
                    fencing_token: again.fencing_token,
                    request_id: "mismatch".into(),
                }),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(mismatch.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn guarded_update_requires_object_and_lease_namespace_authorization() {
    let svc = service();
    let lease = svc
        .acquire_lease(with_named_principal(
            AcquireLeaseRequest {
                namespace: "default".into(),
                key: "environment".into(),
                owner: "alice".into(),
                ttl_ms: 60_000,
                request_id: "acquire".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .lease
        .unwrap();
    let original = Object {
        id: "guarded-auth".into(),
        kind: "component".into(),
        name: "before".into(),
        namespace: "default".into(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    };
    svc.db
        .runtime()
        .create_object_with_audit(&from_proto_obj(&original), "alice")
        .unwrap();
    grant_object_role(&svc, "guarded-auth", "alice", security::Role::Editor);

    let mut updated = original.clone();
    updated.name = "after".into();
    updated.updated = 2;
    let precondition = LeasePrecondition {
        namespace: "default".into(),
        key: "environment".into(),
        fencing_token: lease.fencing_token,
        request_id: "update".into(),
    };
    svc.guarded_update_object(with_named_principal(
        GuardedUpdateObjectRequest {
            object: Some(updated.clone()),
            lease_precondition: Some(precondition.clone()),
        },
        "alice",
    ))
    .await
    .unwrap();

    updated.name = "unauthorized".into();
    let error = svc
        .guarded_update_object(with_named_principal(
            GuardedUpdateObjectRequest {
                object: Some(updated),
                lease_precondition: Some(LeasePrecondition {
                    request_id: "denied".into(),
                    ..precondition
                }),
            },
            "bob",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        svc.db
            .runtime()
            .get_object("guarded-auth")
            .unwrap()
            .unwrap()
            .name,
        "after"
    );
}

#[tokio::test]
async fn update_object_with_lease_precondition_enforces_fencing() {
    // #388: Create/Update/DeleteObject with lease_precondition share Guarded* semantics.
    let svc = service();
    let lease = svc
        .acquire_lease(with_named_principal(
            AcquireLeaseRequest {
                namespace: "default".into(),
                key: "environment".into(),
                owner: "alice".into(),
                ttl_ms: 60_000,
                request_id: "acquire-unified".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .lease
        .unwrap();
    let original = Object {
        id: "unified-guarded".into(),
        kind: "component".into(),
        name: "before".into(),
        namespace: "default".into(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    };
    svc.db
        .runtime()
        .create_object_with_audit(&from_proto_obj(&original), "alice")
        .unwrap();
    grant_object_role(&svc, "unified-guarded", "alice", security::Role::Editor);

    let mut updated = original.clone();
    updated.name = "fenced".into();
    updated.updated = 2;
    svc.update_object(with_named_principal(
        UpdateObjectRequest {
            object: Some(updated.clone()),
            lease_precondition: Some(LeasePrecondition {
                namespace: "default".into(),
                key: "environment".into(),
                fencing_token: lease.fencing_token.clone(),
                request_id: "update-unified".into(),
            }),
        },
        "alice",
    ))
    .await
    .unwrap();
    assert_eq!(
        svc.db
            .runtime()
            .get_object("unified-guarded")
            .unwrap()
            .unwrap()
            .name,
        "fenced"
    );

    updated.name = "stale".into();
    updated.updated = 3;
    let stale = svc
        .update_object(with_named_principal(
            UpdateObjectRequest {
                object: Some(updated),
                lease_precondition: Some(LeasePrecondition {
                    namespace: "default".into(),
                    key: "environment".into(),
                    fencing_token: "not-the-token".into(),
                    request_id: "update-stale".into(),
                }),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        svc.db
            .runtime()
            .get_object("unified-guarded")
            .unwrap()
            .unwrap()
            .name,
        "fenced"
    );
}

#[tokio::test]
async fn update_object_without_lease_precondition_remains_unguarded() {
    let svc = service();
    let original = Object {
        id: "unified-unguarded".into(),
        kind: "component".into(),
        name: "before".into(),
        namespace: "default".into(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    };
    svc.db
        .runtime()
        .create_object_with_audit(&from_proto_obj(&original), "alice")
        .unwrap();
    grant_object_role(&svc, "unified-unguarded", "alice", security::Role::Editor);

    let mut updated = original;
    updated.name = "after".into();
    updated.updated = 2;
    svc.update_object(with_named_principal(
        UpdateObjectRequest {
            object: Some(updated),
            lease_precondition: None,
        },
        "alice",
    ))
    .await
    .unwrap();
    assert_eq!(
        svc.db
            .runtime()
            .get_object("unified-unguarded")
            .unwrap()
            .unwrap()
            .name,
        "after"
    );
}

#[tokio::test]
async fn governed_action_type_registry_put_get_list_disable() {
    // #396: namespace-scoped governed Action type registry (not graph ActionType).
    let svc = service();
    grant_action_admin(&svc);
    let type_def = GovernedActionType {
        approvers: Vec::new(),
        namespace: "acme".into(),
        type_id: "review.intake".into(),
        version: "1.0.0".into(),
        description: "Admit review".into(),
        parameter_schema_json:
            r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#.into(),
        allowed_effect_kinds: vec!["runtime_dispatch".into(), "notify".into()],
        policy_scope: String::new(),
        budget_scope: String::new(),
        enabled: true,
        created_by: String::new(),
        created_at_ms: 0,
        updated_at_ms: 0,
        disabled_at_ms: 0,
        object_kind: String::new(),
        object_mutation: String::new(),
        submission_criteria: vec![],
        declared_effect_kinds: vec![],
        system_one_json: String::new(),
        review_queue_id: String::new(),
        review_sla_ms: 0,
        review_escalate: String::new(),
        review_escalate_to: String::new(),
        review_threshold_param: String::new(),
        review_threshold: 0,
        review_pool: vec![],
        review_agent_reviewers: vec![],
    };
    let put = svc
        .put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
            r#type: Some(type_def.clone()),
            request_id: "put-1".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .r#type
        .unwrap();
    assert!(put.enabled);
    assert_eq!(put.created_by, "tester");

    let mut invalid_schema = type_def.clone();
    invalid_schema.version = "2.0.0".into();
    invalid_schema.parameter_schema_json = r#"{"type":"object"}"#.into();
    let invalid_schema_error = svc
        .put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
            r#type: Some(invalid_schema),
            request_id: "put-invalid-schema".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(invalid_schema_error.code(), tonic::Code::InvalidArgument);

    let got = svc
        .get_governed_action_type(with_principal(GetGovernedActionTypeRequest {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .r#type
        .unwrap();
    assert_eq!(got.type_id, "review.intake");

    let listed = svc
        .list_governed_action_types(with_principal(ListGovernedActionTypesRequest {
            namespace: "acme".into(),
            type_id: String::new(),
            enabled_only: true,
        }))
        .await
        .unwrap()
        .into_inner()
        .types;
    assert_eq!(listed.len(), 1);

    // Version immutability
    let mut changed = type_def.clone();
    changed.description = "nope".into();
    let err = svc
        .put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
            r#type: Some(changed),
            request_id: "put-bad".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    svc.set_governed_action_type_enabled(with_principal(SetGovernedActionTypeEnabledRequest {
        namespace: "acme".into(),
        type_id: "review.intake".into(),
        version: "1.0.0".into(),
        enabled: false,
        request_id: "disable-1".into(),
    }))
    .await
    .unwrap();
    let deny = svc
        .db
        .runtime()
        .require_enabled_governed_action_type("acme", "review.intake", "1.0.0")
        .unwrap_err();
    assert!(deny.contains("disabled"), "{deny}");

    // Unauthorized principal
    let denied = svc
        .put_governed_action_type(with_named_principal(
            PutGovernedActionTypeRequest {
                r#type: Some(type_def),
                request_id: "put-denied".into(),
            },
            "bob",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn submit_action_instance_admit_replay_conflict_policy_budget() {
    // #397: submit/admit ActionInstance with idempotency, policy, budget.
    use crate::chisei::budget::{BudgetTracker, PeriodType};
    use crate::sekai::action_instance::{STATUS_ADMITTED, STATUS_DENIED, SUBMIT_POLICY_ACTION};

    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let sekai_store = crate::db::store::SekaiStore::from_shared_runtime(db.clone());
    let chisei_store = crate::chisei_store::ChiseiStore::from_shared_runtime(db);
    let budget = Arc::new(BudgetTracker::new(chisei_store.clone()));
    budget
        .set_limit("action:governed", 1, PeriodType::Daily)
        .unwrap();
    let clerk = crate::composition::cross_store_admission::CrossStoreAdmission::new(
        chisei_store,
        sekai_store.clone(),
        Some(budget.clone()),
    );
    let svc = SekaiServiceImpl::new(sekai_store).with_cross_store_admission(Arc::new(clerk));
    grant_action_admin(&svc);

    let type_def = GovernedActionType {
        approvers: Vec::new(),
        namespace: "acme".into(),
        type_id: "review.intake".into(),
        version: "1.0.0".into(),
        description: "Admit review".into(),
        parameter_schema_json: r#"{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}"#.into(),
        allowed_effect_kinds: vec!["runtime_dispatch".into()],
        policy_scope: String::new(),
        budget_scope: String::new(),
        enabled: true,
        created_by: String::new(),
        created_at_ms: 0,
        updated_at_ms: 0,
        disabled_at_ms: 0,
        object_kind: String::new(),
        object_mutation: String::new(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
        system_one_json: String::new(),
        review_queue_id: String::new(),
        review_sla_ms: 0,
        review_escalate: String::new(),
        review_escalate_to: String::new(),
        review_threshold_param: String::new(),
        review_threshold: 0,
        review_pool: vec![],
        review_agent_reviewers: vec![],
    };
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(type_def),
        request_id: "put-1".into(),
    }))
    .await
    .unwrap();

    let params = r#"{"summary":"ship it"}"#.to_string();
    let admit = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            parameters_json: params.clone(),
            idempotency_key: "idem-1".into(),
            evidence_submission_ids: vec!["ev-1".into()],
            request_id: "req-1".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!admit.replay);
    let inst = admit.instance.unwrap();
    assert_eq!(inst.status, STATUS_ADMITTED);
    assert_eq!(inst.operation_id, "req-1");
    assert!(!inst.instance_id.is_empty());
    assert!(!inst.request_digest.is_empty());
    assert_eq!(inst.evidence_submission_ids, vec!["ev-1".to_string()]);

    // Receipt spine bound to operation_id.
    let receipt = svc
        .db
        .runtime()
        .get_operation_receipt(&inst.operation_id)
        .unwrap()
        .expect("operation receipt");
    assert_eq!(receipt.operation_class, "governed_action_instance");
    assert_eq!(receipt.namespace, "acme");
    assert_eq!(receipt.ontology_digest, None);

    // Idempotent replay
    let replay = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            parameters_json: params.clone(),
            idempotency_key: "idem-1".into(),
            evidence_submission_ids: vec!["ev-1".into()],
            request_id: "req-1".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(replay.replay);
    assert_eq!(replay.instance.unwrap().instance_id, inst.instance_id);

    // Key conflict on different digest
    let conflict = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            parameters_json: r#"{"summary":"other"}"#.into(),
            idempotency_key: "idem-1".into(),
            evidence_submission_ids: vec![],
            request_id: "req-1".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(conflict.code(), tonic::Code::AlreadyExists);

    // Get + list
    let got = svc
        .get_action_instance(with_principal(GetActionInstanceRequest {
            instance_id: inst.instance_id.clone(),
            namespace: String::new(),
            idempotency_key: String::new(),
            operation_id: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(got.instance_id, inst.instance_id);

    let listed = svc
        .list_action_instances(with_principal(ListActionInstancesRequest {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            status: STATUS_ADMITTED.into(),
            limit: 10,
        }))
        .await
        .unwrap()
        .into_inner()
        .instances;
    assert_eq!(listed.len(), 1);

    // Clerk refuses a second operation before Sekai records a denied instance.
    let budget_denied = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            parameters_json: r#"{"summary":"second"}"#.into(),
            idempotency_key: "idem-budget".into(),
            evidence_submission_ids: vec![],
            request_id: "req-budget".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(budget_denied.code(), tonic::Code::FailedPrecondition);
    assert!(budget_denied.message().contains("budget"));

    budget
        .set_limit("action:governed", 8, PeriodType::Daily)
        .unwrap();

    // Policy deny
    svc.db
        .runtime()
        .upsert_action_policy(&action_policy::ActionPolicy {
            scope: "agent:tester".into(),
            default_decision: action_policy::ActionDecision::Allow,
            action_overrides: HashMap::from([(
                SUBMIT_POLICY_ACTION.into(),
                action_policy::ActionDecision::Deny,
            )]),
            risk_overrides: HashMap::new(),
            max_mutations_per_work_unit: None,
            max_deletes_per_work_unit: None,
        })
        .unwrap();
    let policy_denied = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            parameters_json: r#"{"summary":"policy"}"#.into(),
            idempotency_key: "idem-policy".into(),
            evidence_submission_ids: vec![],
            request_id: "req-policy".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(policy_denied.status, STATUS_DENIED);
    assert_eq!(policy_denied.policy_decision, "deny");
    assert!(policy_denied.deny_reason.contains("policy"));
}

#[tokio::test]
async fn submit_rejects_parameters_outside_governed_action_schema() {
    use crate::sekai::action_instance::STATUS_ADMITTED;

    let svc = service();
    grant_action_admin(&svc);
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            approvers: Vec::new(),
            namespace: "acme".into(),
            type_id: "validated.action".into(),
            version: "1.0.0".into(),
            description: "validate action parameters".into(),
            parameter_schema_json: r#"{
                "type":"object",
                "properties":{
                    "mode":{"type":"string","enum":["safe","fast"]},
                    "label":{"type":"string","minLength":2,"maxLength":4},
                    "count":{"type":"integer","minimum":1,"maximum":3},
                    "ratio":{"type":"number","minimum":0.5,"maximum":1.5},
                    "enabled":{"type":"boolean"}
                },
                "required":["mode","label","count","ratio","enabled"],
                "additionalProperties":false
            }"#
            .into(),
            allowed_effect_kinds: vec!["notify".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            object_kind: String::new(),
            object_mutation: String::new(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
            system_one_json: String::new(),
            review_queue_id: String::new(),
            review_sla_ms: 0,
            review_escalate: String::new(),
            review_escalate_to: String::new(),
            review_threshold_param: String::new(),
            review_threshold: 0,
            review_pool: vec![],
            review_agent_reviewers: vec![],
        }),
        request_id: "put-validated-action".into(),
    }))
    .await
    .unwrap();

    let invalid = [
        (
            "missing-required",
            r#"{"mode":"safe","label":"ok","count":1,"ratio":1.0}"#,
            "required",
        ),
        (
            "unknown-field",
            r#"{"mode":"safe","label":"ok","count":1,"ratio":1.0,"enabled":true,"extra":true}"#,
            "unknown",
        ),
        (
            "wrong-type",
            r#"{"mode":"safe","label":"ok","count":"1","ratio":1.0,"enabled":true}"#,
            "does not match type",
        ),
        (
            "invalid-enum",
            r#"{"mode":"slow","label":"ok","count":1,"ratio":1.0,"enabled":true}"#,
            "enum",
        ),
        (
            "out-of-range",
            r#"{"mode":"safe","label":"ok","count":4,"ratio":1.0,"enabled":true}"#,
            "outside",
        ),
        (
            "string-length",
            r#"{"mode":"safe","label":"s","count":1,"ratio":1.0,"enabled":true}"#,
            "length",
        ),
    ];
    for (key, parameters_json, expected_error) in invalid {
        let error = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "validated.action".into(),
                version: "1.0.0".into(),
                parameters_json: parameters_json.into(),
                idempotency_key: key.into(),
                evidence_submission_ids: vec![],
                request_id: format!("request-{key}"),
                ontology_digest: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument, "{key}");
        assert!(error.message().contains("action parameters invalid"));
        assert!(error.message().contains(expected_error), "{key}: {error}");
        assert!(
            svc.db
                .runtime()
                .get_action_instance_by_idempotency("acme", key)
                .unwrap()
                .is_none(),
            "{key} must not persist an ActionInstance"
        );
    }

    let duplicate_error = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "validated.action".into(),
            version: "1.0.0".into(),
            parameters_json:
                r#"{"mode":"safe","mode":"fast","label":"ok","count":1,"ratio":1.0,"enabled":true}"#
                    .into(),
            idempotency_key: "duplicate-key".into(),
            evidence_submission_ids: vec![],
            request_id: "request-duplicate-key".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(duplicate_error.code(), tonic::Code::InvalidArgument);
    assert!(duplicate_error.message().contains("duplicate object keys"));
    assert!(
        svc.db
            .runtime()
            .get_action_instance_by_idempotency("acme", "duplicate-key")
            .unwrap()
            .is_none()
    );

    let valid = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "validated.action".into(),
            version: "1.0.0".into(),
            parameters_json: r#"{"mode":"safe","label":"ok","count":1,"ratio":1.0,"enabled":true}"#
                .into(),
            idempotency_key: "valid".into(),
            evidence_submission_ids: vec![],
            request_id: "request-valid".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(valid.status, STATUS_ADMITTED);
    assert_eq!(
        svc.db
            .runtime()
            .list_action_effects_for_instance(&valid.instance_id)
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn submit_rejects_invalid_materialized_effect_before_admit() {
    use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;

    let svc = service();
    grant_action_admin(&svc);
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            approvers: Vec::new(),
            namespace: "acme".into(),
            type_id: "dispatch.nul".into(),
            version: "1.0.0".into(),
            description: "reject malformed effect".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            object_kind: String::new(),
            object_mutation: String::new(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
            system_one_json: String::new(),
            review_queue_id: String::new(),
        review_sla_ms: 0,
        review_escalate: String::new(),
        review_escalate_to: String::new(),
        review_threshold_param: String::new(),
        review_threshold: 0,
        review_pool: vec![],
        review_agent_reviewers: vec![],
        }),
        request_id: "put-nul".into(),
    }))
    .await
    .unwrap();

    let error = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "dispatch.nul".into(),
            version: "1.0.0".into(),
            parameters_json: r#"{"runtime":"\u0000"}"#.into(),
            idempotency_key: "nul-admission".into(),
            evidence_submission_ids: vec![],
            request_id: "req-nul".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(
        svc.db
            .runtime()
            .get_action_instance_by_idempotency("acme", "nul-admission")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn list_schema_types_requires_principal() {
    let svc = service();
    let err = svc
        .list_schema_types(Request::new(ListSchemaTypesRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn create_schema_type_requires_schema_admin() {
    let svc = service();
    let err = svc
        .create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn ontology_list_requires_authentication() {
    let svc = service();
    let err = svc
        .list_ontology_classes(Request::new(ListOntologyClassesRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn create_ontology_class_requires_admin() {
    let svc = service();
    let err = svc
        .create_ontology_class(with_principal(CreateOntologyClassRequest {
            class: Some(ontology_class("Person")),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn ontology_list_hides_unreadable_definitions() {
    let svc = service();
    for name in ["Visible", "Hidden"] {
        svc.create_ontology_class(with_named_principal(
            CreateOntologyClassRequest {
                class: Some(ontology_class(name)),
            },
            "local",
        ))
        .await
        .unwrap();
    }
    grant_ontology_reader(&svc, "ontology:class:Visible");
    let hidden_grant = security::Grant {
        id: format!("ontology-hidden-{}", uuid::Uuid::new_v4().simple()),
        object_id: "ontology:class:Hidden".into(),
        principal: "other-reader".into(),
        role: security::Role::Viewer,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&hidden_grant).unwrap();
    svc.security.add_grant(&hidden_grant);

    let listed = svc
        .list_ontology_classes(with_principal(ListOntologyClassesRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        listed
            .classes
            .iter()
            .map(|class| class.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Visible"]
    );

    let now = chrono::Utc::now();
    let artifact =
        crate::ontology_inspect::render_html(&crate::ontology_inspect::InspectionSnapshot::new(
            &crate::ontology_inspect::InspectConfig {
                root: "visible-root".into(),
                authorization_context: "tester-visible-scope".into(),
                output: "unused.html".into(),
                ttl_seconds: 60,
                target: "authenticated-test-service".into(),
            },
            now,
            listed.classes,
            vec![],
            vec![],
            "test-revision".into(),
            "authorized-test-revision".into(),
        ))
        .unwrap();
    assert!(artifact.contains("Visible"));
    assert!(!artifact.contains("Hidden"));
    assert!(!artifact.contains("denied_objects"));
    assert!(!artifact.contains("Bearer"));
}

#[tokio::test]
async fn create_ontology_class_ensures_mapped_kind() {
    let svc = service();
    grant_ontology_admin(&svc);
    let mut incident = ontology_class("Incident");
    incident.mapped_kind = "incident_kind".into();
    incident.description = "Operational incident".into();

    // Kind must not exist yet.
    assert!(
        svc.schema_definitions
            .snapshot()
            .unwrap()
            .get("incident_kind")
            .is_none()
    );

    let created = svc
        .create_ontology_class(with_principal(CreateOntologyClassRequest {
            class: Some(incident),
        }))
        .await
        .unwrap()
        .into_inner()
        .class
        .unwrap();
    assert_eq!(created.mapped_kind, "incident_kind");
    assert!(
        svc.schema_definitions
            .snapshot()
            .unwrap()
            .get("incident_kind")
            .is_some(),
        "mapped kind must be ensured for ontology-first product path"
    );

    // Creating an object of the ensured kind must validate.
    let obj = Object {
        id: "inc-ensure-1".into(),
        kind: "incident_kind".into(),
        name: "outage".into(),
        namespace: "demo".into(),
        external_id: String::new(),
        properties: Default::default(),
        created: 0,
        updated: 0,
    };
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(obj),
        lease_precondition: None,
    }))
    .await
    .expect("object create after kind ensure");
}

#[tokio::test]
async fn submit_action_instance_creates_record_of_ensured_kind() {
    let svc = service();
    grant_ontology_admin(&svc);
    grant_action_admin(&svc);

    let mut class = ontology_class("CustomerRecord");
    class.mapped_kind = "customer_record".into();
    class.description = "Fixture customer record".into();
    svc.create_ontology_class(with_principal(CreateOntologyClassRequest {
        class: Some(class),
    }))
    .await
    .unwrap();

    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            approvers: Vec::new(),
            namespace: "acme".into(),
            type_id: "customer.record.create".into(),
            version: "1".into(),
            description: "Create one customer record".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"title":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            object_kind: "customer_record".into(),
            object_mutation: "create".into(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
            system_one_json: String::new(),
            review_queue_id: String::new(),
        review_sla_ms: 0,
        review_escalate: String::new(),
        review_escalate_to: String::new(),
        review_threshold_param: String::new(),
        review_threshold: 0,
        review_pool: vec![],
        review_agent_reviewers: vec![],
        }),
        request_id: "put-record".into(),
    }))
    .await
    .unwrap();

    let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let admit = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "customer.record.create".into(),
            version: "1".into(),
            parameters_json: r#"{"object_id":"rec-grpc-1","name":"Northwind","title":"account"}"#
                .into(),
            idempotency_key: "record-grpc-1".into(),
            evidence_submission_ids: Vec::new(),
            request_id: "operation-record-grpc".into(),
            ontology_digest: digest.into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!admit.replay);
    let instance = admit.instance.unwrap();
    assert_eq!(instance.operation_id, "operation-record-grpc");
    let stored = svc
        .db
        .runtime()
        .get_object("rec-grpc-1")
        .unwrap()
        .expect("created record");
    assert_eq!(stored.kind, "customer_record");
    assert_eq!(stored.namespace, "acme");
    assert_eq!(stored.name, "Northwind");
    let receipt = svc
        .db
        .runtime()
        .get_operation_receipt("operation-record-grpc")
        .unwrap()
        .expect("receipt");
    assert_eq!(receipt.ontology_digest.as_deref(), Some(digest));
    assert!(receipt.completeness().complete);
}

#[tokio::test]
async fn submit_action_instance_propagates_one_operation_identity() {
    let svc = service();
    grant_ontology_admin(&svc);
    grant_action_admin(&svc);

    let mut class = ontology_class("CustomerRecord");
    class.mapped_kind = "customer_record".into();
    svc.create_ontology_class(with_principal(CreateOntologyClassRequest {
        class: Some(class),
    }))
    .await
    .unwrap();
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            approvers: Vec::new(),
            namespace: "acme".into(),
            type_id: "customer.record.create".into(),
            version: "1".into(),
            description: "Create one customer record".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            object_kind: "customer_record".into(),
            object_mutation: "create".into(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
            system_one_json: String::new(),
            review_queue_id: String::new(),
        review_sla_ms: 0,
        review_escalate: String::new(),
        review_escalate_to: String::new(),
        review_threshold_param: String::new(),
        review_threshold: 0,
        review_pool: vec![],
        review_agent_reviewers: vec![],
        }),
        request_id: "put-record-corr".into(),
    }))
    .await
    .unwrap();

    let operation_id = "op-cross-plane-1";
    let digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let logs = capture_submit_logs(|| async {
        svc.submit_action_instance(with_operation_identity(
            SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "customer.record.create".into(),
                version: "1".into(),
                parameters_json: r#"{"object_id":"rec-corr-1","name":"Northwind"}"#.into(),
                idempotency_key: "record-corr-1".into(),
                evidence_submission_ids: Vec::new(),
                request_id: operation_id.into(),
                ontology_digest: digest.into(),
            },
            operation_id,
        ))
        .await
        .unwrap();
    })
    .await;
    assert!(
        logs.contains("sekai.operation_id") && logs.contains(operation_id),
        "span must carry the caller identity: {logs}"
    );

    let receipt = svc
        .db
        .runtime()
        .get_operation_receipt(operation_id)
        .unwrap()
        .expect("receipt");
    let changes = svc
        .list_object_changes(with_principal(ListObjectChangesRequest {
            object_id: "rec-corr-1".into(),
            limit: 16,
            offset: 0,
        }))
        .await
        .unwrap()
        .into_inner()
        .changes;
    let object_change = changes
        .iter()
        .find(|change| !change.operation_id.is_empty())
        .expect("object-change event");
    crate::sekai::operation_correlation::OperationCarriers {
        span: span_operation_id(&logs, operation_id),
        receipt: receipt.operation_id,
        object_change_event: object_change.operation_id.clone(),
    }
    .require_same_identity(operation_id)
    .expect("span, receipt, and object-change event must share the identity");
}

#[tokio::test]
async fn submit_action_instance_rejects_mismatched_operation_header() {
    let svc = service();
    grant_action_admin(&svc);
    let error = svc
        .submit_action_instance(with_operation_identity(
            SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "customer.record.create".into(),
                version: "1".into(),
                parameters_json: r#"{"object_id":"rec-corr-mismatch"}"#.into(),
                idempotency_key: "record-corr-mismatch".into(),
                evidence_submission_ids: Vec::new(),
                request_id: "op-a".into(),
                ontology_digest: String::new(),
            },
            "op-b",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(
        error.message().contains("must match request_id"),
        "{}",
        error.message()
    );
}

#[tokio::test]
async fn describe_and_preview_object_action_are_observational() {
    let svc = service();
    grant_action_admin(&svc);
    svc.db
        .runtime()
        .upsert_object_type(&crate::sekai::schema::ObjectType {
            kind: "customer_record".into(),
            description: "fixture".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
    let object = crate::domain::Object {
        id: "cust-preview".into(),
        kind: "customer_record".into(),
        name: "Northwind".into(),
        namespace: "acme".into(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 10,
        updated: 20,
    };
    svc.db.runtime().create_object(&object).unwrap();
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            approvers: Vec::new(),
            namespace: "acme".into(),
            type_id: "customer.record.update".into(),
            version: "1".into(),
            description: "Update one customer".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            object_kind: "customer_record".into(),
            object_mutation: "update".into(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
            system_one_json: String::new(),
            review_queue_id: String::new(),
        review_sla_ms: 0,
        review_escalate: String::new(),
        review_escalate_to: String::new(),
        review_threshold_param: String::new(),
        review_threshold: 0,
        review_pool: vec![],
        review_agent_reviewers: vec![],
        }),
        request_id: "put-update".into(),
    }))
    .await
    .unwrap();

    let first = svc
        .describe_object_action(with_principal(DescribeObjectActionRequest {
            namespace: "acme".into(),
            object_id: "cust-preview".into(),
            type_id: "customer.record.update".into(),
            version: "1".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    let second = svc
        .describe_object_action(with_principal(DescribeObjectActionRequest {
            namespace: "acme".into(),
            object_id: "cust-preview".into(),
            type_id: "customer.record.update".into(),
            version: "1".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.parameter_schema_json, second.parameter_schema_json);
    assert_eq!(first.object_revision, second.object_revision);
    assert!(first.preview_supported);
    assert_eq!(first.compensation, "unsupported");

    let preview = svc
        .preview_object_action(with_principal(PreviewObjectActionRequest {
            namespace: "acme".into(),
            object_id: "cust-preview".into(),
            type_id: "customer.record.update".into(),
            version: "1".into(),
            parameters_json: r#"{"object_id":"cust-preview","name":"Updated"}"#.into(),
            expected_object_updated_ms: first.object_updated_ms,
            expected_object_revision: first.object_revision.clone(),
            evidence_submission_ids: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(preview.outcome, "valid");
    assert!(!preview.request_digest.is_empty());
    assert_eq!(
        svc.db
            .runtime()
            .list_action_instances("acme", None, None, 10)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        svc.db
            .runtime()
            .get_object("cust-preview")
            .unwrap()
            .unwrap()
            .name,
        "Northwind"
    );

    let stale = svc
        .preview_object_action(with_principal(PreviewObjectActionRequest {
            namespace: "acme".into(),
            object_id: "cust-preview".into(),
            type_id: "customer.record.update".into(),
            version: "1".into(),
            parameters_json: r#"{"object_id":"cust-preview"}"#.into(),
            expected_object_updated_ms: first.object_updated_ms + 1,
            expected_object_revision: String::new(),
            evidence_submission_ids: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(stale.outcome, "stale");

    let hidden = svc
        .describe_object_action(with_named_principal(
            DescribeObjectActionRequest {
                namespace: "acme".into(),
                object_id: "missing".into(),
                type_id: "customer.record.update".into(),
                version: "1".into(),
            },
            "mallory",
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden.code(), tonic::Code::PermissionDenied);
    assert_eq!(hidden.message(), "object action unavailable");
    assert!(!hidden.message().contains("missing"));
}

fn system_one_bind_json() -> String {
    serde_json::json!({
        "model": "jev-1.13.0",
        "questions": [{
            "parameter": "department",
            "type": "choice",
            "instructions": "Which team should handle this",
            "criteria": {"billing": null, "technical": null, "sales": null}
        }]
    })
    .to_string()
}

static TYPE_SAFE_TEST_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn put_system_one_ticket_type(svc: &SekaiServiceImpl) {
    svc.db
        .runtime()
        .upsert_object_type(&crate::sekai::schema::ObjectType {
            kind: "support_ticket".into(),
            description: "fixture".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
    let object = crate::domain::Object {
        id: "ticket-preview".into(),
        kind: "support_ticket".into(),
        name: "Payouts".into(),
        namespace: "acme".into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("title".into(), "payouts failing".into()),
            (
                crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                "title".into(),
            ),
            ("secret".into(), "do-not-send".into()),
        ]),
        created: 10,
        updated: 20,
    };
    svc.db.runtime().create_object(&object).unwrap();
}

#[tokio::test]
async fn preview_does_not_fill_system_one_when_stale_or_denied() {
    let svc = service();
    grant_action_admin(&svc);
    put_system_one_ticket_type(&svc);
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            approvers: Vec::new(),
            namespace: "acme".into(),
            type_id: "support.triage".into(),
            version: "1".into(),
            description: "Triage a support ticket".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"department":{"type":"string","enum":["billing","technical","sales"]}},"required":["object_id","department"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            object_kind: "support_ticket".into(),
            object_mutation: "update".into(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
            system_one_json: system_one_bind_json(),
            review_queue_id: String::new(),
        review_sla_ms: 0,
        review_escalate: String::new(),
        review_escalate_to: String::new(),
        review_threshold_param: String::new(),
        review_threshold: 0,
        review_pool: vec![],
        review_agent_reviewers: vec![],
        }),
        request_id: "put-triage".into(),
    }))
    .await
    .unwrap();

    let stale = svc
        .preview_object_action(with_principal(PreviewObjectActionRequest {
            namespace: "acme".into(),
            object_id: "ticket-preview".into(),
            type_id: "support.triage".into(),
            version: "1".into(),
            parameters_json: String::new(),
            expected_object_updated_ms: 21,
            expected_object_revision: String::new(),
            evidence_submission_ids: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(stale.outcome, "stale");
    assert!(stale.proposed_parameters_json.is_empty());
    assert!(
        svc.db
            .runtime()
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("preview_object_action".into()),
                ..Default::default()
            })
            .unwrap()
            .is_empty()
    );

    svc.db
        .runtime()
        .upsert_action_policy(&action_policy::ActionPolicy {
            scope: "agent:tester".into(),
            default_decision: action_policy::ActionDecision::Allow,
            action_overrides: HashMap::from([(
                crate::sekai::action_instance::SUBMIT_POLICY_ACTION.into(),
                action_policy::ActionDecision::Deny,
            )]),
            risk_overrides: HashMap::new(),
            max_mutations_per_work_unit: None,
            max_deletes_per_work_unit: None,
        })
        .unwrap();
    let denied = svc
        .preview_object_action(with_principal(PreviewObjectActionRequest {
            namespace: "acme".into(),
            object_id: "ticket-preview".into(),
            type_id: "support.triage".into(),
            version: "1".into(),
            parameters_json: String::new(),
            expected_object_updated_ms: 20,
            expected_object_revision: String::new(),
            evidence_submission_ids: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(denied.outcome, "denied");
    assert!(denied.proposed_parameters_json.is_empty());
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn preview_records_typesafe_egress_after_admission() {
    let _env = TYPE_SAFE_TEST_ENV
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let app = axum::Router::new().route(
        "/v1/systemone",
        axum::routing::post(|| async {
            axum::Json(chisei_provider::system_one::SystemOneResponse {
                model: "jev-1.13.0".into(),
                answers: [(
                    "department".into(),
                    serde_json::json!({"type":"choice","choice":"technical"}),
                )]
                .into_iter()
                .collect(),
                usage: None,
            })
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    unsafe {
        std::env::set_var(chisei_provider::system_one::API_KEY_ENV, "test-key");
        std::env::set_var(
            chisei_provider::system_one::BASE_URL_ENV,
            format!("http://{addr}/v1/systemone"),
        );
    }

    let svc = service();
    grant_action_admin(&svc);
    put_system_one_ticket_type(&svc);
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            approvers: Vec::new(),
            namespace: "acme".into(),
            type_id: "support.triage".into(),
            version: "1".into(),
            description: "Triage a support ticket".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"department":{"type":"string","enum":["billing","technical","sales"]}},"required":["object_id","department"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            object_kind: "support_ticket".into(),
            object_mutation: "update".into(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
            system_one_json: system_one_bind_json(),
            review_queue_id: String::new(),
        review_sla_ms: 0,
        review_escalate: String::new(),
        review_escalate_to: String::new(),
        review_threshold_param: String::new(),
        review_threshold: 0,
        review_pool: vec![],
        review_agent_reviewers: vec![],
        }),
        request_id: "put-triage-fill".into(),
    }))
    .await
    .unwrap();

    let preview = svc
        .preview_object_action(with_principal(PreviewObjectActionRequest {
            namespace: "acme".into(),
            object_id: "ticket-preview".into(),
            type_id: "support.triage".into(),
            version: "1".into(),
            parameters_json: String::new(),
            expected_object_updated_ms: 20,
            expected_object_revision: String::new(),
            evidence_submission_ids: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(preview.outcome, "valid");
    assert!(
        preview
            .proposed_parameters_json
            .contains("\"department\":\"technical\""),
        "{}",
        preview.proposed_parameters_json
    );
    let audits = svc
        .db
        .runtime()
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            action: Some("preview_object_action".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(
        audits[0].evidence.get("provider").map(String::as_str),
        Some("typesafe")
    );
    assert_eq!(
        svc.db
            .runtime()
            .list_action_instances("acme", None, None, 10)
            .unwrap()
            .len(),
        0
    );
    unsafe {
        std::env::remove_var(chisei_provider::system_one::API_KEY_ENV);
        std::env::remove_var(chisei_provider::system_one::BASE_URL_ENV);
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn preview_does_not_record_typesafe_egress_when_filled_preview_is_invalid() {
    let _env = TYPE_SAFE_TEST_ENV
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let app = axum::Router::new().route(
        "/v1/systemone",
        axum::routing::post(|| async {
            axum::Json(chisei_provider::system_one::SystemOneResponse {
                model: "jev-1.13.0".into(),
                answers: [(
                    "dept-name".into(),
                    serde_json::json!({"type":"choice","choice":"technical"}),
                )]
                .into_iter()
                .collect(),
                usage: None,
            })
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    unsafe {
        std::env::set_var(chisei_provider::system_one::API_KEY_ENV, "test-key");
        std::env::set_var(
            chisei_provider::system_one::BASE_URL_ENV,
            format!("http://{addr}/v1/systemone"),
        );
    }

    let svc = service();
    grant_action_admin(&svc);
    put_system_one_ticket_type(&svc);
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            approvers: Vec::new(),
            namespace: "acme".into(),
            type_id: "support.triage".into(),
            version: "1".into(),
            description: "Triage a support ticket".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"dept-name":{"type":"string","enum":["billing","technical","sales"]}},"required":["object_id","dept-name"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            object_kind: "support_ticket".into(),
            object_mutation: "update".into(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
            system_one_json: serde_json::json!({
                "model": "jev-1.13.0",
                "questions": [{
                    "parameter": "dept-name",
                    "type": "choice",
                    "instructions": "Which team should handle this",
                    "criteria": {"billing": null, "technical": null, "sales": null}
                }]
            })
            .to_string(),
            review_queue_id: String::new(),
            review_sla_ms: 0,
            review_escalate: String::new(),
            review_escalate_to: String::new(),
            review_threshold_param: String::new(),
            review_threshold: 0,
            review_pool: vec![],
            review_agent_reviewers: vec![],
        }),
        request_id: "put-triage-invalid-fill".into(),
    }))
    .await
    .unwrap();

    let preview = svc
        .preview_object_action(with_principal(PreviewObjectActionRequest {
            namespace: "acme".into(),
            object_id: "ticket-preview".into(),
            type_id: "support.triage".into(),
            version: "1".into(),
            parameters_json: String::new(),
            expected_object_updated_ms: 20,
            expected_object_revision: String::new(),
            evidence_submission_ids: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(preview.outcome, "invalid");
    assert!(preview.proposed_parameters_json.is_empty());
    assert!(
        svc.db
            .runtime()
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("preview_object_action".into()),
                ..Default::default()
            })
            .unwrap()
            .is_empty()
    );
    unsafe {
        std::env::remove_var(chisei_provider::system_one::API_KEY_ENV);
        std::env::remove_var(chisei_provider::system_one::BASE_URL_ENV);
    }
}

#[tokio::test]
async fn ontology_class_crud_round_trip() {
    let svc = service();
    grant_ontology_admin(&svc);
    let mut person = ontology_class("Person");
    person.description = "A human".into();
    person.properties = vec![OntologyProperty {
        name: "email".into(),
        r#type: "string".into(),
        required: false,
        description: String::new(),
    }];

    let created = svc
        .create_ontology_class(with_principal(CreateOntologyClassRequest {
            class: Some(person),
        }))
        .await
        .unwrap()
        .into_inner()
        .class
        .unwrap();
    assert!(created.mapped_kind.is_empty());
    assert_eq!(created.properties.len(), 1);

    let fetched = svc
        .get_ontology_class(with_principal(GetOntologyClassRequest {
            name: "Person".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .class
        .unwrap();
    assert_eq!(fetched.description, "A human");

    let listed = svc
        .list_ontology_classes(with_principal(ListOntologyClassesRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(listed.classes.iter().any(|class| class.name == "Person"));

    svc.delete_ontology_class(with_principal(DeleteOntologyClassRequest {
        name: "Person".into(),
    }))
    .await
    .unwrap();
    let err = svc
        .get_ontology_class(with_principal(GetOntologyClassRequest {
            name: "Person".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    let audit = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            target_id: Some("ontology:class:Person".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        audit
            .iter()
            .any(|decision| decision.action == "ontology.class.create")
    );
    assert!(
        audit
            .iter()
            .any(|decision| decision.action == "ontology.class.delete")
    );
    assert!(audit.iter().all(|decision| decision.actor == "tester"));
}

#[tokio::test]
async fn create_ontology_class_rejects_unknown_superclass() {
    let svc = service();
    grant_ontology_admin(&svc);
    let mut engineer = ontology_class("Engineer");
    engineer.superclasses = vec!["Person".into()];
    let err = svc
        .create_ontology_class(with_principal(CreateOntologyClassRequest {
            class: Some(engineer),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("unknown superclass"));
}

#[tokio::test]
async fn ontology_relation_requires_known_endpoints() {
    let svc = service();
    grant_ontology_admin(&svc);
    let relation = OntologyRelation {
        name: "works_for".into(),
        description: String::new(),
        domain: "Person".into(),
        range: "Company".into(),
        cardinality: None,
        inverse: String::new(),
        transitive: false,
        is_builtin: false,
        mapped_relation: String::new(),
    };
    // Endpoints do not exist yet.
    let err = svc
        .create_ontology_relation(with_principal(CreateOntologyRelationRequest {
            relation: Some(relation.clone()),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    for name in ["Person", "Company"] {
        svc.create_ontology_class(with_principal(CreateOntologyClassRequest {
            class: Some(ontology_class(name)),
        }))
        .await
        .unwrap();
    }
    let created = svc
        .create_ontology_relation(with_principal(CreateOntologyRelationRequest {
            relation: Some(relation),
        }))
        .await
        .unwrap()
        .into_inner()
        .relation
        .unwrap();
    assert_eq!(created.domain, "Person");
    assert_eq!(created.range, "Company");
}

#[tokio::test]
async fn ontology_mutations_cannot_reference_unreadable_definitions() {
    let svc = service();
    for name in ["Visible", "Hidden"] {
        svc.create_ontology_class(with_named_principal(
            CreateOntologyClassRequest {
                class: Some(ontology_class(name)),
            },
            "local",
        ))
        .await
        .unwrap();
    }
    grant_ontology_admin(&svc);
    grant_object_role(
        &svc,
        "ontology:class:Hidden",
        "other-reader",
        security::Role::Viewer,
    );

    let mut child = ontology_class("Child");
    child.superclasses = vec!["Hidden".into()];
    let class_denied = svc
        .create_ontology_class(with_principal(CreateOntologyClassRequest {
            class: Some(child),
        }))
        .await
        .unwrap_err();
    assert_eq!(class_denied.code(), tonic::Code::PermissionDenied);

    let relation_denied = svc
        .create_ontology_relation(with_principal(CreateOntologyRelationRequest {
            relation: Some(OntologyRelation {
                name: "reveals_hidden".into(),
                description: String::new(),
                domain: "Visible".into(),
                range: "Hidden".into(),
                cardinality: None,
                inverse: String::new(),
                transitive: false,
                is_builtin: false,
                mapped_relation: String::new(),
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(relation_denied.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn ontology_reads_hide_definitions_with_unreadable_references() {
    let svc = service();
    for name in ["Visible", "Hidden"] {
        svc.create_ontology_class(with_named_principal(
            CreateOntologyClassRequest {
                class: Some(ontology_class(name)),
            },
            "local",
        ))
        .await
        .unwrap();
    }
    let mut child = ontology_class("Child");
    child.superclasses = vec!["Hidden".into()];
    svc.create_ontology_class(with_named_principal(
        CreateOntologyClassRequest { class: Some(child) },
        "local",
    ))
    .await
    .unwrap();
    svc.create_ontology_relation(with_named_principal(
        CreateOntologyRelationRequest {
            relation: Some(OntologyRelation {
                name: "reveals_hidden".into(),
                description: String::new(),
                domain: "Visible".into(),
                range: "Hidden".into(),
                cardinality: None,
                inverse: String::new(),
                transitive: false,
                is_builtin: false,
                mapped_relation: String::new(),
            }),
        },
        "local",
    ))
    .await
    .unwrap();
    grant_object_role(
        &svc,
        "ontology:class:Hidden",
        "other-reader",
        security::Role::Viewer,
    );

    let class_denied = svc
        .get_ontology_class(with_principal(GetOntologyClassRequest {
            name: "Child".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(class_denied.code(), tonic::Code::PermissionDenied);
    let relation_denied = svc
        .get_ontology_relation(with_principal(GetOntologyRelationRequest {
            name: "reveals_hidden".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(relation_denied.code(), tonic::Code::PermissionDenied);

    let classes = svc
        .list_ontology_classes(with_principal(ListOntologyClassesRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(!classes.classes.iter().any(|class| class.name == "Child"));
    let relations = svc
        .list_ontology_relations(with_principal(ListOntologyRelationsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(relations.relations.is_empty());
}

#[tokio::test]
async fn delete_ontology_class_blocked_by_relation_reference() {
    let svc = service();
    grant_ontology_admin(&svc);
    for name in ["Person", "Company"] {
        svc.create_ontology_class(with_principal(CreateOntologyClassRequest {
            class: Some(ontology_class(name)),
        }))
        .await
        .unwrap();
    }
    svc.create_ontology_relation(with_principal(CreateOntologyRelationRequest {
        relation: Some(OntologyRelation {
            name: "works_for".into(),
            description: String::new(),
            domain: "Person".into(),
            range: "Company".into(),
            cardinality: None,
            inverse: String::new(),
            transitive: false,
            is_builtin: false,
            mapped_relation: String::new(),
        }),
    }))
    .await
    .unwrap();
    let err = svc
        .delete_ontology_class(with_principal(DeleteOntologyClassRequest {
            name: "Company".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn delete_ontology_relation_blocked_by_inverse_reference() {
    let svc = service();
    grant_ontology_admin(&svc);
    for name in ["Person", "Company"] {
        svc.create_ontology_class(with_principal(CreateOntologyClassRequest {
            class: Some(ontology_class(name)),
        }))
        .await
        .unwrap();
    }
    for (name, domain, range, inverse) in [
        ("works_for", "Person", "Company", ""),
        ("employs", "Company", "Person", "works_for"),
    ] {
        svc.create_ontology_relation(with_principal(CreateOntologyRelationRequest {
            relation: Some(OntologyRelation {
                name: name.into(),
                description: String::new(),
                domain: domain.into(),
                range: range.into(),
                cardinality: None,
                inverse: inverse.into(),
                transitive: false,
                is_builtin: false,
                mapped_relation: String::new(),
            }),
        }))
        .await
        .unwrap();
    }

    let incompatible_update = svc
        .create_ontology_relation(with_principal(CreateOntologyRelationRequest {
            relation: Some(OntologyRelation {
                name: "works_for".into(),
                description: String::new(),
                domain: "Company".into(),
                range: "Person".into(),
                cardinality: None,
                inverse: String::new(),
                transitive: false,
                is_builtin: false,
                mapped_relation: String::new(),
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(incompatible_update.code(), tonic::Code::InvalidArgument);
    assert!(incompatible_update.message().contains("no longer reverse"));

    let err = svc
        .delete_ontology_relation(with_principal(DeleteOntologyRelationRequest {
            name: "works_for".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn ontology_delete_clears_durable_and_cached_grants() {
    let svc = service();
    for name in ["Person", "Company"] {
        svc.create_ontology_class(with_named_principal(
            CreateOntologyClassRequest {
                class: Some(ontology_class(name)),
            },
            "local",
        ))
        .await
        .unwrap();
    }
    svc.create_ontology_relation(with_named_principal(
        CreateOntologyRelationRequest {
            relation: Some(OntologyRelation {
                name: "works_for".into(),
                description: String::new(),
                domain: "Person".into(),
                range: "Company".into(),
                cardinality: None,
                inverse: String::new(),
                transitive: false,
                is_builtin: false,
                mapped_relation: String::new(),
            }),
        },
        "local",
    ))
    .await
    .unwrap();
    for object_id in ["ontology:class:Person", "ontology:relation:works_for"] {
        grant_object_role(&svc, object_id, "tester", security::Role::Admin);
    }

    svc.delete_ontology_relation(with_principal(DeleteOntologyRelationRequest {
        name: "works_for".into(),
    }))
    .await
    .unwrap();
    svc.delete_ontology_class(with_principal(DeleteOntologyClassRequest {
        name: "Person".into(),
    }))
    .await
    .unwrap();

    for object_id in ["ontology:class:Person", "ontology:relation:works_for"] {
        assert!(svc.db.runtime().list_grants(object_id).unwrap().is_empty());
        assert!(svc.security.can_access(object_id, &["other-reader"]));
    }
}

#[tokio::test]
async fn ontology_grants_are_managed_through_public_rpcs() {
    let svc = service();
    svc.create_ontology_class(with_named_principal(
        CreateOntologyClassRequest {
            class: Some(ontology_class("Restricted")),
        },
        "local",
    ))
    .await
    .unwrap();
    grant_ontology_admin(&svc);

    let created = svc
        .create_grant(with_principal(CreateGrantRequest {
            grant: Some(Grant {
                id: "ontology-viewer".into(),
                object_id: "ontology:class:Restricted".into(),
                principal: "alice".into(),
                role: "viewer".into(),
                created: 1,
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .grant
        .unwrap();
    assert_eq!(created.principal, "alice");

    let grants = svc
        .list_grants(with_principal(ListGrantsRequest {
            object_id: "ontology:class:Restricted".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(grants.grants.len(), 1);
    svc.get_ontology_class(with_named_principal(
        GetOntologyClassRequest {
            name: "Restricted".into(),
        },
        "alice",
    ))
    .await
    .unwrap();

    svc.delete_grant(with_principal(DeleteGrantRequest {
        id: "ontology-viewer".into(),
    }))
    .await
    .unwrap();
    assert!(
        svc.db
            .runtime()
            .list_grants("ontology:class:Restricted")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn namespace_policy_requires_purpose_and_end_date() {
    let svc = service();
    grant_schema_admin(&svc);
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(widget_schema_type()),
    }))
    .await
    .unwrap();
    svc.create_object(with_named_principal(
        CreateObjectRequest {
            object: Some(Object {
                id: "term-widget".into(),
                kind: "widget".into(),
                name: "widget".into(),
                namespace: "ops".into(),
                external_id: "".into(),
                properties: HashMap::from([("name".into(), "w".into())]),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        },
        "local",
    ))
    .await
    .unwrap();
    svc.db
        .runtime()
        .apply_namespace_grant_policy(
            &svc.security,
            &security::NamespaceGrantPolicy {
                namespace: "ops".into(),
                max_duration_ms: 86_400_000,
                require_terms: true,
            },
        )
        .unwrap();
    let denied = svc
        .create_grant(with_named_principal(
            CreateGrantRequest {
                grant: Some(Grant {
                    id: "term-alice".into(),
                    object_id: "term-widget".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 1,
                    purpose: "audit".into(),
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::InvalidArgument);
    assert!(denied.message().contains("end date"));
    let created = svc
        .create_grant(with_named_principal(
            CreateGrantRequest {
                grant: Some(Grant {
                    id: "term-alice".into(),
                    object_id: "term-widget".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 1,
                    purpose: "audit".into(),
                    not_after_ms: crate::sekai::security::unix_now_ms() + 60_000,
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .grant
        .unwrap();
    assert_eq!(created.purpose, "audit");
    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some("grant.create".into()),
            target_id: Some("term-widget".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "allowed");
    assert_eq!(decisions[0].target_id, "term-widget");
    assert_eq!(
        decisions[0].evidence.get("grant_id").map(String::as_str),
        Some("term-alice")
    );
    let listed = svc
        .list_decisions(with_named_principal(
            ListDecisionsRequest {
                actor: String::new(),
                action: "grant.create".into(),
                after: 0,
                limit: 10,
                target_id: "term-widget".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.decisions.len(), 1);
    let stranger = svc
        .list_decisions(with_named_principal(
            ListDecisionsRequest {
                actor: String::new(),
                action: "grant.create".into(),
                after: 0,
                limit: 10,
                target_id: String::new(),
            },
            "stranger",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(stranger.decisions.is_empty());
    let denied_target = svc
        .list_decisions(with_named_principal(
            ListDecisionsRequest {
                actor: String::new(),
                action: "grant.create".into(),
                after: 0,
                limit: 10,
                target_id: "term-widget".into(),
            },
            "stranger",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied_target.code(), tonic::Code::PermissionDenied);
    let renewed = svc
        .create_grant(with_named_principal(
            CreateGrantRequest {
                grant: Some(Grant {
                    id: "term-alice".into(),
                    object_id: "term-widget".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 2,
                    purpose: "audit".into(),
                    not_after_ms: crate::sekai::security::unix_now_ms() + 120_000,
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .grant
        .unwrap();
    let again = svc
        .create_grant(with_named_principal(
            CreateGrantRequest {
                grant: Some(Grant {
                    id: "term-alice".into(),
                    object_id: "term-widget".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 3,
                    purpose: "audit".into(),
                    not_after_ms: crate::sekai::security::unix_now_ms() + 180_000,
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .grant
        .unwrap();
    assert!(again.not_after_ms >= renewed.not_after_ms);
    let renewals = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some("grant.renew".into()),
            target_id: Some("term-widget".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(renewals.len(), 2);
    assert!(renewals.iter().all(|decision| {
        decision.target_id == "term-widget"
            && decision.evidence.get("grant_id").map(String::as_str) == Some("term-alice")
    }));
}

#[tokio::test]
async fn grant_receipt_accepts_asia_shaped_identifiers() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "asia-widget".into(),
            kind: "note".into(),
            name: "asia".into(),
            namespace: "asia-ops".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let created = svc
        .create_grant(with_named_principal(
            CreateGrantRequest {
                grant: Some(Grant {
                    id: "asia-grant".into(),
                    object_id: "asia-widget".into(),
                    principal: "asia".into(),
                    role: "viewer".into(),
                    created: 1,
                    purpose: "regional review".into(),
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .grant
        .unwrap();
    assert_eq!(created.principal, "asia");
    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some("grant.create".into()),
            target_id: Some("asia-widget".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0].evidence.get("namespace").map(String::as_str),
        Some("asia-ops")
    );
    assert_eq!(
        decisions[0].evidence.get("principal").map(String::as_str),
        Some("asia")
    );
}

#[tokio::test]
async fn grant_receipt_rejects_secret_shaped_exception_reason() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "secret-widget".into(),
            kind: "note".into(),
            name: "secret".into(),
            namespace: "ops".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let denied = svc
        .create_grant(with_named_principal(
            CreateGrantRequest {
                grant: Some(Grant {
                    id: "secret-grant".into(),
                    object_id: "secret-widget".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 1,
                    purpose: "audit".into(),
                    exception_reason: "sk-live-secret".into(),
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::Internal);
    assert!(denied.message().contains("secret material"));
    let denied_aws = svc
        .create_grant(with_named_principal(
            CreateGrantRequest {
                grant: Some(Grant {
                    id: "aws-grant".into(),
                    object_id: "secret-widget".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 1,
                    purpose: "ASIAIOSFODNN7EXAMPLE".into(),
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied_aws.code(), tonic::Code::Internal);
    assert!(denied_aws.message().contains("secret material"));
}

#[tokio::test]
async fn schema_type_implements_interface_and_list_filters_by_interface() {
    let svc = service();
    grant_schema_admin(&svc);
    let interface = schema::InterfaceDef {
        name: "Trackable".into(),
        description: "Trackable object".into(),
        properties: vec![schema::PropertyDef {
            name: "tracking_id".into(),
            prop_type: schema::PropertyType::String,
            required: true,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        }],
        is_builtin: false,
    };
    svc.db.runtime().upsert_interface(&interface).unwrap();
    svc.schema_definitions
        .register_interface(interface)
        .unwrap();

    let mut invalid_type = widget_schema_type();
    invalid_type.implements = vec!["Trackable".into()];
    let err = svc
        .create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(invalid_type),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("tracking_id"));

    let mut optional_required_property = widget_schema_type();
    optional_required_property.implements = vec!["Trackable".into()];
    optional_required_property.properties.push(PropertyDef {
        name: "tracking_id".into(),
        r#type: "string".into(),
        required: false,
        description: "".into(),
        enum_values: vec![],
        link_kind: "".into(),
        compute_expr: "".into(),
        classification: "public".into(),
        struct_fields: vec![],
    });
    let err = svc
        .create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(optional_required_property),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("must be required"));

    let mut valid_type = widget_schema_type();
    valid_type.implements = vec!["Trackable".into()];
    valid_type.properties.push(PropertyDef {
        name: "tracking_id".into(),
        r#type: "string".into(),
        required: true,
        description: "".into(),
        enum_values: vec![],
        link_kind: "".into(),
        compute_expr: "".into(),
        classification: "public".into(),
        struct_fields: vec![],
    });
    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(valid_type),
    }))
    .await
    .unwrap();

    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(widget_object(
            "tracked",
            HashMap::from([
                ("name".into(), "tracked".into()),
                ("tracking_id".into(), "trk-1".into()),
            ]),
        )),
        lease_precondition: None,
    }))
    .await
    .unwrap();
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(Object {
            id: "loose-2".into(),
            kind: "loose".into(),
            name: "loose".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    let listed = svc
        .list_objects(with_principal(ListObjectsRequest {
            filter: Some(ListFilter {
                interface_filter: vec!["Trackable".into()],
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.total, 1);
    assert_eq!(listed.objects[0].id, "tracked");
}

#[tokio::test]
async fn corrupt_schema_row_only_blocks_that_kind_until_repaired() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    {
        let conn = db.conn();
        conn.execute(
            "INSERT INTO sekai_object_types (kind, description, properties_json, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            ("broken", "Broken schema", "[", 1_i64),
        )
        .unwrap();
    }
    let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
        db.clone(),
    ));
    grant_schema_admin(&svc);

    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(Object {
            id: "loose-1".into(),
            kind: "loose".into(),
            name: "loose".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    let err = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "broken-1".into(),
                kind: "broken".into(),
                name: "broken".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);
    assert!(err.message().contains("broken"));

    svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
        r#type: Some(ObjectType {
            kind: "broken".into(),
            description: "Repaired".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        }),
    }))
    .await
    .unwrap();

    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(Object {
            id: "broken-2".into(),
            kind: "broken".into(),
            name: "broken".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }),
        lease_precondition: None,
    }))
    .await
    .unwrap();
}

#[tokio::test]
async fn schema_table_read_failure_blocks_object_writes() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    {
        let conn = db.conn();
        conn.execute("DROP TABLE sekai_object_types", []).unwrap();
        conn.execute(
            "CREATE TABLE sekai_object_types (kind TEXT PRIMARY KEY)",
            [],
        )
        .unwrap();
    }
    let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
        db.clone(),
    ));

    let err = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-1".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);
    assert!(err.message().contains("schema registry unavailable"));

    {
        let conn = db.conn();
        conn.execute("DROP TABLE sekai_object_types", []).unwrap();
    }
    db.migrate_all().unwrap();
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(Object {
            id: "loose-2".into(),
            kind: "loose".into(),
            name: "loose".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }),
        lease_precondition: None,
    }))
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_object_row_returns_internal_and_next_request_succeeds() {
    let svc = service();
    {
        let conn = svc.db.runtime().conn();
        conn.execute(
            "INSERT INTO sekai_objects
             (id, kind, name, namespace, external_id, properties, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            ("good", "widget", "good", "", "", "{}", 1000_i64, 1000_i64),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sekai_objects
             (id, kind, name, namespace, external_id, properties, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                "bad",
                "widget",
                "bad",
                "",
                "",
                "{}",
                "not-an-integer",
                1000_i64,
            ),
        )
        .unwrap();
    }

    let err = svc
        .get_object(with_principal(GetObjectRequest { id: "bad".into() }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);

    let good = svc
        .get_object(with_principal(GetObjectRequest { id: "good".into() }))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(good.id, "good");
}

#[tokio::test]
async fn grant_and_audit_rpcs_round_trip() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "o1".into(),
            kind: "note".into(),
            name: "target".into(),
            namespace: String::new(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let admin_grant = security::Grant {
        id: "admin".into(),
        object_id: "o1".into(),
        principal: "tester".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&admin_grant).unwrap();
    svc.security.add_grant(&admin_grant);
    svc.db
        .runtime()
        .record_decision(&audit::Decision {
            id: "d1".into(),
            timestamp: 10,
            actor: "tester".into(),
            action: "create".into(),
            reason: "".into(),
            evidence: HashMap::new(),
            target_id: "o1".into(),
            outcome: "ok".into(),
        })
        .unwrap();
    svc.db
        .runtime()
        .record_object_change(&audit::ObjectChange {
            id: "c1".into(),
            object_id: "o1".into(),
            field: "name".into(),
            old_value: "a".into(),
            new_value: "b".into(),
            changed_by: "tester".into(),
            timestamp: 11,
        })
        .unwrap();

    let created = svc
        .create_grant(with_principal(CreateGrantRequest {
            grant: Some(Grant {
                id: "g1".into(),
                object_id: "o1".into(),
                principal: "alice".into(),
                role: "viewer".into(),
                created: 1,
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.grant.unwrap().principal, "alice");

    let access = svc
        .check_access(with_principal(CheckAccessRequest {
            object_id: "o1".into(),
            principals: vec!["alice".into()],
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(access.allowed);

    let recorded = svc
        .record_decision(with_principal(RecordDecisionRequest {
            decision: Some(Decision {
                id: "".into(),
                timestamp: 0,
                actor: "tester".into(),
                action: "gateway.budget_denied".into(),
                reason: "budget exceeded".into(),
                evidence: HashMap::from([("user_id".into(), "agent:codex-app".into())]),
                target_id: "o1".into(),
                outcome: "denied".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .decision
        .unwrap();
    assert!(!recorded.id.is_empty());
    assert!(recorded.timestamp > 0);

    let listed = svc
        .list_decisions(with_principal(ListDecisionsRequest {
            actor: "tester".into(),
            action: "".into(),
            after: 0,
            limit: 10,
            target_id: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.decisions.len(), 3);
    assert!(
        listed
            .decisions
            .iter()
            .any(|decision| decision.action == "grant.create")
    );

    let changes = svc
        .list_object_changes(with_principal(ListObjectChangesRequest {
            object_id: "o1".into(),
            limit: 10,
            offset: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(changes.changes.len(), 1);
}

#[tokio::test]
async fn control_plane_admin_can_recover_managed_acl() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "namespace:acme".into(),
            kind: "namespace".into(),
            name: "acme".into(),
            namespace: "acme".into(),
            external_id: "namespace:acme".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let member_grant = security::Grant {
        id: "member".into(),
        object_id: "namespace:acme".into(),
        principal: "alice".into(),
        role: security::Role::Viewer,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&member_grant).unwrap();
    svc.security.add_grant(&member_grant);

    svc.create_grant(with_named_principal(
        CreateGrantRequest {
            grant: Some(Grant {
                id: "recovery".into(),
                object_id: "namespace:acme".into(),
                principal: "root".into(),
                role: "admin".into(),
                created: 1,
                ..Default::default()
            }),
        },
        "local",
    ))
    .await
    .unwrap();

    assert!(svc.security.can_admin("namespace:acme", &["root"]));
}

#[tokio::test]
async fn team_namespace_bootstrap_is_atomic_and_admin_only() {
    let svc = service();
    let denied = svc
        .ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: "acme".into(),
                principal: "alice".into(),
                role: "viewer".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    assert!(
        svc.db
            .runtime()
            .find_namespace_boundary("acme")
            .unwrap()
            .is_none()
    );

    let created = svc
        .ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: "acme".into(),
                principal: "alice".into(),
                role: "viewer".into(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let namespace = created.namespace.unwrap();
    assert_eq!(namespace.external_id, "namespace:acme");
    assert_eq!(created.grants.len(), 3);
    assert!(svc.security.can_access(&namespace.id, &["alice"]));

    let forged_namespace = svc
        .create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(Object {
                    id: "namespace-forged".into(),
                    kind: "namespace".into(),
                    name: "forged".into(),
                    namespace: "forged".into(),
                    external_id: "namespace:forged".into(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                }),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(forged_namespace.code(), tonic::Code::PermissionDenied);

    let forged_external_id = svc
        .create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(Object {
                    id: "ordinary-object".into(),
                    kind: "note".into(),
                    name: "forged identity".into(),
                    namespace: "acme".into(),
                    external_id: "namespace:future".into(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                }),
                lease_precondition: None,
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(forged_external_id.code(), tonic::Code::InvalidArgument);

    let root_grant = created
        .grants
        .into_iter()
        .find(|grant| grant.principal == "root")
        .unwrap();
    let delete_root = svc
        .delete_grant(with_named_principal(
            DeleteGrantRequest { id: root_grant.id },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(delete_root.code(), tonic::Code::PermissionDenied);

    let delete_namespace = svc
        .delete_object(with_named_principal(
            DeleteObjectRequest {
                id: namespace.id.clone(),
                lease_precondition: None,
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(delete_namespace.code(), tonic::Code::FailedPrecondition);
    assert!(
        svc.db
            .runtime()
            .find_namespace_boundary("acme")
            .unwrap()
            .is_some()
    );

    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "legacy-boundary".into(),
            kind: "namespace".into(),
            name: "legacy".into(),
            namespace: String::new(),
            external_id: "namespace:legacy".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    let adopted = svc
        .ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: "legacy".into(),
                principal: "bob".into(),
                role: "viewer".into(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .namespace
        .unwrap();
    assert_eq!(adopted.namespace, "legacy");
    assert_eq!(
        adopted.properties.get("team_managed").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        svc.delete_object(with_named_principal(
            DeleteObjectRequest {
                id: adopted.id,
                lease_precondition: None
            },
            "local",
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::FailedPrecondition
    );
}

#[tokio::test]
async fn grants_cannot_preclaim_future_namespace_boundaries() {
    let svc = service();
    svc.ensure_team_namespace(with_named_principal(
        EnsureTeamNamespaceRequest {
            namespace: "acme".into(),
            principal: "bob".into(),
            role: "editor".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    assert_eq!(
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(Object {
                    id: "namespace:future".into(),
                    kind: "note".into(),
                    name: "preclaim".into(),
                    namespace: "acme".into(),
                    ..Default::default()
                }),
                lease_precondition: None,
            },
            "bob",
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::InvalidArgument
    );
    let denied = svc
        .create_grant(with_named_principal(
            CreateGrantRequest {
                grant: Some(Grant {
                    id: "orphan".into(),
                    object_id: "namespace:future".into(),
                    principal: "mallory".into(),
                    role: "admin".into(),
                    created: 1,
                    ..Default::default()
                }),
            },
            "mallory",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::InvalidArgument);

    svc.db
        .runtime()
        .create_grant(&security::Grant {
            id: "legacy-orphan".into(),
            object_id: "namespace:future".into(),
            principal: "mallory".into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        })
        .unwrap();
    let bootstrap = svc
        .ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: "future".into(),
                principal: "alice".into(),
                role: "viewer".into(),
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(bootstrap.code(), tonic::Code::Internal);
    assert!(
        svc.db
            .runtime()
            .find_namespace_boundary("future")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn coordination_rpcs_round_trip() {
    let svc = service();
    let scope = svc
        .create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-1".into(),
            scope: Some(ContentionScope {
                id: "scope-1".into(),
                name: "build".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 100,
                updated: 100,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .scope
        .unwrap();
    assert_eq!(scope.owner_principal, "tester");

    let work_unit = svc
        .create_work_unit(with_principal(CreateWorkUnitRequest {
            work_unit: Some(WorkUnit {
                id: "wu-1".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "cargo test -q".into(),
                scope_id: "scope-1".into(),
                priority: 0,
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at: 101,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "idem-wu-1".into(),
                updated_at: 101,
            }),
            request_id: "req-wu-1".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    assert_eq!(work_unit.owner_principal, "tester");

    let admitted = svc
        .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
            work_unit_id: "wu-1".into(),
            request_id: "req-admit-wu-1".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(admitted.admitted);
    assert_eq!(admitted.reservations.len(), 1);

    let reservations = svc
        .list_reservations(with_principal(ListReservationsRequest {
            work_unit_id: "wu-1".into(),
            scope_id: String::new(),
            status: coordination::RESERVATION_STATUS_ACTIVE.into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reservations.reservations.len(), 1);

    let heartbeat = svc
        .heartbeat_work_unit(with_principal(HeartbeatWorkUnitRequest {
            work_unit_id: "wu-1".into(),
            request_id: "req-heartbeat-wu-1".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    assert!(heartbeat.last_heartbeat_at > 0);

    let completed = svc
        .complete_work_unit(with_principal(CompleteWorkUnitRequest {
            work_unit_id: "wu-1".into(),
            request_id: "req-complete-wu-1".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    assert_eq!(completed.status, coordination::WORK_UNIT_STATUS_COMPLETED);

    let events = svc
        .list_run_events(with_principal(ListRunEventsRequest {
            work_unit_id: "wu-1".into(),
            limit: 20,
            after: 0,
            event_types: vec![],
            page_token: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(
        events
            .events
            .iter()
            .any(|event| event.event_type == "created")
    );
    assert!(
        events
            .events
            .iter()
            .any(|event| event.event_type == "admitted")
    );
    assert!(
        events
            .events
            .iter()
            .any(|event| event.event_type == coordination::WORK_UNIT_STATUS_COMPLETED)
    );
}

#[tokio::test]
async fn coordination_create_and_transition_requests_are_idempotent() {
    let svc = service();
    svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
        request_id: "req-scope-idem".into(),
        scope: Some(ContentionScope {
            id: "scope-idem".into(),
            name: "idem".into(),
            parent_scope_id: String::new(),
            max_concurrency: 1,
            admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 30,
            timeout_seconds: 60,
            owner_principal: String::new(),
            created: 1,
            updated: 1,
        }),
    }))
    .await
    .unwrap();

    let create = CreateWorkUnitRequest {
        request_id: "req-create-idem".into(),
        work_unit: Some(WorkUnit {
            id: "wu-idem".into(),
            kind: "build".into(),
            actor: "tester".into(),
            target_object_id: String::new(),
            status: coordination::WORK_UNIT_STATUS_PENDING.into(),
            requested_spec: "echo hi".into(),
            scope_id: "scope-idem".into(),
            priority: 0,
            timeout_seconds: 60,
            heartbeat_ttl_seconds: 30,
            created_at: 2,
            admitted_at: 0,
            started_at: 0,
            finished_at: 0,
            last_heartbeat_at: 0,
            failure_reason: String::new(),
            cancel_reason: String::new(),
            owner_principal: String::new(),
            creator_principal: String::new(),
            idempotency_key: "idem-key-1".into(),
            updated_at: 2,
        }),
    };
    let first = svc
        .create_work_unit(with_principal(create.clone()))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    let second = svc
        .create_work_unit(with_principal(create))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    assert_eq!(first.id, second.id);

    let admit = TryAdmitWorkUnitRequest {
        work_unit_id: "wu-idem".into(),
        request_id: "req-admit-idem".into(),
    };
    let first_admit = svc
        .try_admit_work_unit(with_principal(admit.clone()))
        .await
        .unwrap()
        .into_inner();
    let second_admit = svc
        .try_admit_work_unit(with_principal(admit))
        .await
        .unwrap()
        .into_inner();
    assert!(first_admit.admitted);
    assert!(second_admit.admitted);

    let complete = CompleteWorkUnitRequest {
        work_unit_id: "wu-idem".into(),
        request_id: "req-complete-idem".into(),
    };
    let first_complete = svc
        .complete_work_unit(with_principal(complete.clone()))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    let second_complete = svc
        .complete_work_unit(with_principal(complete))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    assert_eq!(
        first_complete.status,
        coordination::WORK_UNIT_STATUS_COMPLETED
    );
    assert_eq!(second_complete.status, first_complete.status);
}

#[tokio::test]
async fn coordination_filters_paginates_and_dry_run_reconciles() {
    let svc = service();
    svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
        request_id: "req-scope-filter".into(),
        scope: Some(ContentionScope {
            id: "scope-filter".into(),
            name: "filter".into(),
            parent_scope_id: String::new(),
            max_concurrency: 1,
            admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 1,
            timeout_seconds: 1,
            owner_principal: String::new(),
            created: 10,
            updated: 10,
        }),
    }))
    .await
    .unwrap();

    for (id, key, created_at) in [("wu-f1", "filter-1", 11), ("wu-f2", "filter-2", 12)] {
        svc.create_work_unit(with_principal(CreateWorkUnitRequest {
            request_id: format!("req-create-{}", id),
            work_unit: Some(WorkUnit {
                id: id.into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: format!("spec {}", id),
                scope_id: "scope-filter".into(),
                priority: 0,
                timeout_seconds: 1,
                heartbeat_ttl_seconds: 1,
                created_at,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: key.into(),
                updated_at: created_at,
            }),
        }))
        .await
        .unwrap();
    }
    svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
        work_unit_id: "wu-f1".into(),
        request_id: "req-admit-f1".into(),
    }))
    .await
    .unwrap();
    let mut stale_candidate = svc.db.runtime().get_work_unit("wu-f1").unwrap().unwrap();
    stale_candidate.started_at = 1;
    stale_candidate.last_heartbeat_at = 1;
    stale_candidate.updated_at = 1;
    svc.db.runtime().update_work_unit(&stale_candidate).unwrap();
    svc.db
        .runtime()
        .conn()
        .execute(
            "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
            ["wu-f1"],
        )
        .unwrap();

    let first_page = svc
        .list_work_units(with_principal(ListWorkUnitsRequest {
            filter: Some(WorkUnitFilter {
                status: String::new(),
                actor: String::new(),
                scope_id: "scope-filter".into(),
                target_object_id: String::new(),
                owner_principal: String::new(),
                limit: 1,
                offset: 0,
                statuses: vec![
                    coordination::WORK_UNIT_STATUS_PENDING.into(),
                    coordination::WORK_UNIT_STATUS_RUNNING.into(),
                ],
                created_after: 0,
                updated_after: 0,
                creator_principal: String::new(),
                page_token: String::new(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first_page.work_units.len(), 1);
    assert!(!first_page.next_page_token.is_empty());

    let second_page = svc
        .list_work_units(with_principal(ListWorkUnitsRequest {
            filter: Some(WorkUnitFilter {
                status: String::new(),
                actor: String::new(),
                scope_id: "scope-filter".into(),
                target_object_id: String::new(),
                owner_principal: String::new(),
                limit: 1,
                offset: 0,
                statuses: vec![
                    coordination::WORK_UNIT_STATUS_PENDING.into(),
                    coordination::WORK_UNIT_STATUS_RUNNING.into(),
                ],
                created_after: 0,
                updated_after: 0,
                creator_principal: String::new(),
                page_token: first_page.next_page_token,
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second_page.work_units.len(), 1);

    let reconcile = svc
        .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
            dry_run: true,
            work_unit_id: "wu-f1".into(),
            scope_id: String::new(),
            limit: 10,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!reconcile.details.is_empty());

    let still_running = svc
        .get_work_unit(with_principal(GetWorkUnitRequest { id: "wu-f1".into() }))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
}

#[tokio::test]
async fn list_work_units_paginates_over_visible_rows_only() {
    let svc = service();
    svc.db
        .runtime()
        .create_contention_scope(&coordination::ContentionScope {
            id: "scope-visible-page".into(),
            name: "visible".into(),
            parent_scope_id: String::new(),
            max_concurrency: 4,
            admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 30,
            timeout_seconds: 60,
            owner_principal: "alice".into(),
            created: 1,
            updated: 1,
        })
        .unwrap();

    // Interleave alice-visible and bob-only units in storage order so a
    // naive LIMIT+filter page would stop after alice's first unit.
    for (id, owner, created_at) in [
        ("wu-vis-1", "alice", 11),
        ("wu-hid-1", "bob", 12),
        ("wu-vis-2", "alice", 13),
    ] {
        svc.db
            .runtime()
            .create_work_unit(&coordination::WorkUnit {
                id: id.into(),
                kind: "build".into(),
                actor: owner.into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "{}".into(),
                scope_id: "scope-visible-page".into(),
                priority: 0,
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: owner.into(),
                creator_principal: owner.into(),
                idempotency_key: format!("key-{id}"),
                updated_at: created_at,
            })
            .unwrap();
    }

    let first_page = svc
        .list_work_units(with_named_principal(
            ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-visible-page".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: String::new(),
                }),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first_page.work_units.len(), 1);
    assert_eq!(first_page.work_units[0].id, "wu-vis-1");
    assert!(
        !first_page.next_page_token.is_empty(),
        "invisible rows must not make a short page look like end-of-storage"
    );

    let second_page = svc
        .list_work_units(with_named_principal(
            ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-visible-page".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: first_page.next_page_token,
                }),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second_page.work_units.len(), 1);
    assert_eq!(second_page.work_units[0].id, "wu-vis-2");
}

#[tokio::test]
async fn create_work_unit_ignores_client_supplied_lifecycle_state() {
    let svc = service();
    svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
        request_id: "req-scope-sanitize".into(),
        scope: Some(ContentionScope {
            id: "scope-sanitize".into(),
            name: "sanitize".into(),
            parent_scope_id: String::new(),
            max_concurrency: 1,
            admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 30,
            timeout_seconds: 60,
            owner_principal: String::new(),
            created: 1,
            updated: 1,
        }),
    }))
    .await
    .unwrap();

    let created = svc
        .create_work_unit(with_principal(CreateWorkUnitRequest {
            request_id: "req-create-sanitize".into(),
            work_unit: Some(WorkUnit {
                id: "wu-sanitize".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_RUNNING.into(),
                requested_spec: "echo hi".into(),
                scope_id: "scope-sanitize".into(),
                priority: 0,
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at: 5,
                admitted_at: 99,
                started_at: 99,
                finished_at: 99,
                last_heartbeat_at: 99,
                failure_reason: "boom".into(),
                cancel_reason: "stop".into(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "sanitize-1".into(),
                updated_at: 77,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();

    assert_eq!(created.status, coordination::WORK_UNIT_STATUS_PENDING);
    assert_eq!(created.admitted_at, 0);
    assert_eq!(created.started_at, 0);
    assert_eq!(created.finished_at, 0);
    assert_eq!(created.last_heartbeat_at, 0);
    assert!(created.failure_reason.is_empty());
    assert!(created.cancel_reason.is_empty());
    assert_eq!(created.updated_at, created.created_at);
}

#[tokio::test]
async fn reconcile_requires_scope_ownership_for_target_scope() {
    let svc = service();
    for (scope_id, owner, created) in [("scope-a", "tester", 1), ("scope-b", "other", 2)] {
        svc.create_contention_scope(with_named_principal(
            CreateContentionScopeRequest {
                request_id: format!("req-{}", scope_id),
                scope: Some(ContentionScope {
                    id: scope_id.into(),
                    name: scope_id.into(),
                    parent_scope_id: String::new(),
                    max_concurrency: 1,
                    admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                    heartbeat_ttl_seconds: 1,
                    timeout_seconds: 1,
                    owner_principal: String::new(),
                    created,
                    updated: created,
                }),
            },
            owner,
        ))
        .await
        .unwrap();
    }

    svc.create_work_unit(with_named_principal(
        CreateWorkUnitRequest {
            request_id: "req-wu-other".into(),
            work_unit: Some(WorkUnit {
                id: "wu-other".into(),
                kind: "build".into(),
                actor: "other".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "run".into(),
                scope_id: "scope-b".into(),
                priority: 0,
                timeout_seconds: 1,
                heartbeat_ttl_seconds: 1,
                created_at: 10,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "other-1".into(),
                updated_at: 10,
            }),
        },
        "other",
    ))
    .await
    .unwrap();
    svc.try_admit_work_unit(with_named_principal(
        TryAdmitWorkUnitRequest {
            work_unit_id: "wu-other".into(),
            request_id: "req-admit-other".into(),
        },
        "other",
    ))
    .await
    .unwrap();
    let mut stale_candidate = svc.db.runtime().get_work_unit("wu-other").unwrap().unwrap();
    stale_candidate.started_at = 1;
    stale_candidate.last_heartbeat_at = 1;
    stale_candidate.updated_at = 1;
    svc.db.runtime().update_work_unit(&stale_candidate).unwrap();
    svc.db
        .runtime()
        .conn()
        .execute(
            "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
            ["wu-other"],
        )
        .unwrap();

    let denied = svc
        .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
            dry_run: false,
            work_unit_id: String::new(),
            scope_id: "scope-b".into(),
            limit: 10,
        }))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    let still_running = svc
        .get_work_unit(with_named_principal(
            GetWorkUnitRequest {
                id: "wu-other".into(),
            },
            "other",
        ))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
}

#[tokio::test]
async fn reconcile_with_mismatched_scope_and_work_unit_returns_empty() {
    let svc = service();
    for scope in [
        ContentionScope {
            id: "scope-one".into(),
            name: "scope-one".into(),
            parent_scope_id: String::new(),
            max_concurrency: 1,
            admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 1,
            timeout_seconds: 1,
            owner_principal: String::new(),
            created: 1,
            updated: 1,
        },
        ContentionScope {
            id: "scope-two".into(),
            name: "scope-two".into(),
            parent_scope_id: String::new(),
            max_concurrency: 1,
            admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 1,
            timeout_seconds: 1,
            owner_principal: String::new(),
            created: 2,
            updated: 2,
        },
    ] {
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: format!("req-{}", scope.id),
            scope: Some(scope),
        }))
        .await
        .unwrap();
    }

    svc.create_work_unit(with_principal(CreateWorkUnitRequest {
        request_id: "req-wu-mismatch".into(),
        work_unit: Some(WorkUnit {
            id: "wu-mismatch".into(),
            kind: "build".into(),
            actor: "tester".into(),
            target_object_id: String::new(),
            status: coordination::WORK_UNIT_STATUS_PENDING.into(),
            requested_spec: "run".into(),
            scope_id: "scope-one".into(),
            priority: 0,
            timeout_seconds: 1,
            heartbeat_ttl_seconds: 1,
            created_at: 10,
            admitted_at: 0,
            started_at: 0,
            finished_at: 0,
            last_heartbeat_at: 0,
            failure_reason: String::new(),
            cancel_reason: String::new(),
            owner_principal: String::new(),
            creator_principal: String::new(),
            idempotency_key: "mismatch-1".into(),
            updated_at: 10,
        }),
    }))
    .await
    .unwrap();
    svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
        work_unit_id: "wu-mismatch".into(),
        request_id: "req-admit-mismatch".into(),
    }))
    .await
    .unwrap();
    let mut stale_candidate = svc
        .db
        .runtime()
        .get_work_unit("wu-mismatch")
        .unwrap()
        .unwrap();
    stale_candidate.started_at = 1;
    stale_candidate.last_heartbeat_at = 1;
    stale_candidate.updated_at = 1;
    svc.db.runtime().update_work_unit(&stale_candidate).unwrap();
    svc.db
        .runtime()
        .conn()
        .execute(
            "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
            ["wu-mismatch"],
        )
        .unwrap();

    let reconcile = svc
        .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
            dry_run: false,
            work_unit_id: "wu-mismatch".into(),
            scope_id: "scope-two".into(),
            limit: 10,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reconcile.work_units_reconciled, 0);
    assert_eq!(reconcile.reservations_released, 0);
    assert!(reconcile.details.is_empty());

    let still_running = svc
        .get_work_unit(with_principal(GetWorkUnitRequest {
            id: "wu-mismatch".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .work_unit
        .unwrap();
    assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
}

#[tokio::test]
async fn list_objects_without_filters_keeps_unactivated_namespace_compatibility() {
    let svc = service();
    for (id, namespace) in [
        ("activated-list-object", "activated-list"),
        ("legacy-list-object", "legacy-list"),
    ] {
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: id.into(),
                kind: "document".into(),
                name: id.into(),
                namespace: namespace.into(),
                external_id: format!("{namespace}:{id}"),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
    }
    let policy = crate::sekai::object_security::ObjectSecurityPolicy {
        contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: "activated-list".into(),
        kind: "document".into(),
        rules: vec![crate::sekai::object_security::ObjectSecurityRule {
            operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
            predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: None,
        value_instance_grants: None,
        required_purpose: None,
    };
    let revision = svc
        .db
        .runtime()
        .put_object_security_policy(&policy, "root", "put-list-compat", 1)
        .unwrap();
    svc.db
        .runtime()
        .activate_object_security_policies(
            "activated-list",
            &BTreeMap::from([("document".into(), revision.revision_digest)]),
            "root",
            "activate-list-compat",
            2,
        )
        .unwrap();

    let response = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: None,
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.total, 2);
    assert!(
        response
            .objects
            .iter()
            .any(|object| object.id == "legacy-list-object")
    );
}

#[tokio::test]
async fn list_objects_enforces_limit_and_returns_total() {
    let svc = service();
    for i in 0..1105 {
        let object = domain::Object {
            id: format!("obj-{i}"),
            kind: "query-demo".into(),
            name: format!("object-{i}"),
            namespace: String::new(),
            external_id: String::new(),
            properties: HashMap::from([("team".into(), "backend".into())]),
            created: i64::from(i),
            updated: i64::from(i),
        };
        svc.db.runtime().create_object(&object).unwrap();
    }

    let response = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    order_by: "name".into(),
                    limit: 2000,
                    offset: 0,
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.total, 1105);
    assert_eq!(response.objects.len(), 1000);
}

#[tokio::test]
async fn list_objects_omits_filter_uses_defaults() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "default-filter".into(),
            kind: "query-demo".into(),
            name: "default-filter".into(),
            namespace: String::new(),
            external_id: String::new(),
            properties: HashMap::from([("team".into(), "backend".into())]),
            created: 1,
            updated: 1,
        })
        .unwrap();

    let response = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: None,
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.total, 1);
    assert_eq!(response.objects.len(), 1);
    assert_eq!(response.objects[0].id, "default-filter");
}

#[tokio::test]
async fn list_objects_rejects_unknown_property_operator() {
    let svc = service();
    let err = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    property_filters: vec![PropertyFilter {
                        key: "team".into(),
                        op: "nope".into(),
                        value: "backend".into(),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn list_objects_rejects_invalid_property_key() {
    let svc = service();
    let err = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    property_filters: vec![PropertyFilter {
                        key: "team.name".into(),
                        op: "eq".into(),
                        value: "backend".into(),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn action_policy_set_get_list_round_trip() {
    let svc = service();
    grant_action_admin(&svc);

    let policy = ActionPolicy {
        scope: "agent:codex-app".into(),
        default_decision: "allow".into(),
        action_overrides: HashMap::from([("delete_link".to_string(), "deny".to_string())]),
        risk_overrides: HashMap::from([(
            "destructive".to_string(),
            "require_approval".to_string(),
        )]),
        max_mutations_per_work_unit: 0,
        max_deletes_per_work_unit: 5,
    };

    let stored = svc
        .set_action_policy(with_principal(SetActionPolicyRequest {
            policy: Some(policy.clone()),
        }))
        .await
        .unwrap()
        .into_inner()
        .policy
        .unwrap();
    assert_eq!(stored.scope, "agent:codex-app");
    assert_eq!(stored.action_overrides.get("delete_link").unwrap(), "deny");

    let fetched = svc
        .get_action_policy(with_principal(GetActionPolicyRequest {
            scope: "agent:codex-app".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .policy
        .unwrap();
    assert_eq!(fetched.default_decision, "allow");
    assert_eq!(
        fetched.risk_overrides.get("destructive").unwrap(),
        "require_approval"
    );
    assert_eq!(fetched.max_deletes_per_work_unit, 5);

    let listed = svc
        .list_action_policies(with_principal(ListActionPoliciesRequest {}))
        .await
        .unwrap()
        .into_inner()
        .policies;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].scope, "agent:codex-app");
}

#[tokio::test]
async fn action_policy_set_requires_action_admin() {
    let svc = service();
    // No action-admin grant for "tester".
    let err = svc
        .set_action_policy(with_principal(SetActionPolicyRequest {
            policy: Some(ActionPolicy {
                scope: "agent:codex-app".into(),
                default_decision: "deny".into(),
                ..Default::default()
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // Nothing was persisted.
    assert!(
        svc.db
            .runtime()
            .get_action_policy("agent:codex-app")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn action_policy_set_rejects_invalid_decision() {
    let svc = service();
    grant_action_admin(&svc);
    let err = svc
        .set_action_policy(with_principal(SetActionPolicyRequest {
            policy: Some(ActionPolicy {
                scope: "agent:codex-app".into(),
                default_decision: "maybe".into(),
                ..Default::default()
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn scoring_writer_records_private_typed_learning_and_retries_idempotently() {
    let svc = service();
    let namespace_id = seed_scoring_namespace(&svc, "acme");
    let request = scored_knowledge_request("acme", "request-42");
    let learning_id = scoring_learning_id("acme", "request-42");

    assert_eq!(
        svc.write_knowledge(&request).await.unwrap(),
        KnowledgeWriteOutcome::Accepted
    );
    let learning = svc.db.runtime().get_object(&learning_id).unwrap().unwrap();
    assert_eq!(learning.kind, domain::KIND_LEARNING);
    assert_eq!(learning.namespace, "acme");
    assert_eq!(learning.name, "Scored learning");
    assert_eq!(learning.properties["producer"], "chisei.scoring");
    assert_eq!(learning.properties["status"], "candidate");
    assert_eq!(
        learning.properties["title"],
        "Scored primary task outcome: passed"
    );
    assert!(
        learning.properties["prevention"]
            .contains("The implementation satisfies the requested behavior.")
    );
    assert_eq!(learning.properties["source_request_id"], "request-42");
    let long_source = knowledge_source_request_id(&"x".repeat(300));
    assert!(long_source.starts_with("sha256:"));
    assert_eq!(long_source.chars().count(), 71);

    let link = svc
        .db
        .runtime()
        .get_link(&format!("{learning_id}->{namespace_id}"))
        .unwrap()
        .unwrap();
    assert_eq!(link.from_id, learning_id);
    assert_eq!(link.to_id, namespace_id);
    assert_eq!(link.relation, domain::REL_TOUCHES);

    let grants = svc.db.runtime().list_grants(&learning.id).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].principal, "chisei.scoring");
    assert_eq!(grants[0].role, security::Role::Admin);

    // The action inserted the fallback ACL directly in its transaction. Admission refreshes
    // the in-process checker before post-commit audit so the learning is never left
    // world-readable on a cache miss if later bookkeeping fails.
    let denied = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: learning.id.clone(),
            },
            "unrelated",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    // The same namespace/request pair produces the same id and the action's exact-retry path
    // does not duplicate the object, link, or grant.
    assert_eq!(
        svc.write_knowledge(&request).await.unwrap(),
        KnowledgeWriteOutcome::Accepted
    );
    let learnings = svc
        .db
        .runtime()
        .list_objects(&domain::ListFilter {
            kind: Some(domain::KIND_LEARNING.into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(learnings.len(), 1);
    assert_eq!(svc.db.runtime().list_grants(&learning.id).unwrap().len(), 1);

    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some(crate::sekai::learning::RECORD_LEARNING_ACTION.into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 2);
    for field in [
        "title",
        "prevention",
        "reasoning",
        "source_request_id",
        "score",
        "passed",
        "task_class",
        "model",
        "producer",
        "status",
    ] {
        assert_eq!(decisions[0].evidence[field], "[redacted]");
    }
}

#[tokio::test]
async fn scoring_writer_uses_a_project_target_when_namespace_object_is_absent() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "project-acme".into(),
            kind: "project".into(),
            name: "acme".into(),
            namespace: "acme".into(),
            external_id: "project:acme".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let request = scored_knowledge_request("acme", "project-request");
    let learning_id = scoring_learning_id("acme", "project-request");

    assert_eq!(
        svc.write_knowledge(&request).await.unwrap(),
        KnowledgeWriteOutcome::Accepted
    );
    assert!(svc.db.runtime().get_object(&learning_id).unwrap().is_some());
    assert!(
        svc.db
            .runtime()
            .get_link(&format!("{learning_id}->project-acme"))
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn scoring_writer_uses_an_explicit_service_grant_for_protected_targets() {
    let svc = service();
    let target_id = seed_scoring_namespace(&svc, "acme");
    grant_object_role(&svc, &target_id, "namespace-owner", security::Role::Admin);
    let request = scored_knowledge_request("acme", "protected-request");

    assert!(svc.write_knowledge(&request).await.is_err());

    grant_object_role(&svc, &target_id, "chisei.scoring", security::Role::Editor);
    assert_eq!(
        svc.write_knowledge(&request).await.unwrap(),
        KnowledgeWriteOutcome::Accepted
    );
}

#[tokio::test]
async fn scoring_writer_obeys_namespace_deny_and_approval_policies() {
    let denied_svc = service();
    seed_scoring_namespace(&denied_svc, "denied");
    denied_svc
        .db
        .runtime()
        .upsert_action_policy(&action_policy::ActionPolicy {
            scope: "denied".into(),
            default_decision: action_policy::ActionDecision::Allow,
            action_overrides: HashMap::from([(
                crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
                action_policy::ActionDecision::Deny,
            )]),
            risk_overrides: HashMap::new(),
            max_mutations_per_work_unit: None,
            max_deletes_per_work_unit: None,
        })
        .unwrap();
    let denied_request = scored_knowledge_request("denied", "request-denied");
    let denied_id = scoring_learning_id("denied", "request-denied");

    assert_eq!(
        denied_svc.write_knowledge(&denied_request).await.unwrap(),
        KnowledgeWriteOutcome::PolicyDenied
    );
    assert!(
        denied_svc
            .db
            .runtime()
            .get_object(&denied_id)
            .unwrap()
            .is_none()
    );
    let denied_decisions = denied_svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some(crate::sekai::learning::RECORD_LEARNING_ACTION.into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(denied_decisions.len(), 1);
    assert_eq!(denied_decisions[0].reason, "action_policy_denied");
    assert_eq!(denied_decisions[0].evidence["policy_scope"], "denied");

    let approval_svc = service();
    seed_scoring_namespace(&approval_svc, "approval");
    approval_svc
        .db
        .runtime()
        .upsert_action_policy(&action_policy::ActionPolicy {
            scope: "approval".into(),
            default_decision: action_policy::ActionDecision::Allow,
            action_overrides: HashMap::from([(
                crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
                action_policy::ActionDecision::RequireApproval,
            )]),
            risk_overrides: HashMap::new(),
            max_mutations_per_work_unit: None,
            max_deletes_per_work_unit: None,
        })
        .unwrap();
    let approval_request = scored_knowledge_request("approval", "request-approval");
    let approval_id = scoring_learning_id("approval", "request-approval");

    assert_eq!(
        approval_svc
            .write_knowledge(&approval_request)
            .await
            .unwrap(),
        KnowledgeWriteOutcome::PolicyDenied
    );
    assert!(
        approval_svc
            .db
            .runtime()
            .get_object(&approval_id)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn list_attestations_paginates_over_visible_rows_only() {
    let svc = service();
    // tester administers scope-a only; scope-b attestations stay hidden.
    let grant = security::Grant {
        id: "scope-a-admin".into(),
        object_id: action_object_id("scope-a"),
        principal: "tester".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);

    for (scope, created) in [
        ("scope-a", 300),
        ("scope-b", 250),
        ("scope-a", 200),
        ("scope-b", 150),
        ("scope-a", 100),
    ] {
        let attestation =
            attestation::build_action_attestation(attestation::ActionAttestationInput {
                decision_id: &format!("dec-{scope}-{created}"),
                policy: &action_policy::ActionPolicy::allow_all(scope),
                action: "set_property",
                actor: "tester",
                risk: RiskClass::Write,
                namespace: "default",
                decision: action_policy::ActionDecision::Allow,
                created,
            });
        svc.db.runtime().insert_attestation(&attestation).unwrap();
    }

    // limit/offset apply to visible rows: skipping 1 of the 3 visible
    // scope-a rows (created DESC) yields the 200 and 100 entries, even
    // though hidden scope-b rows are interleaved in the raw table order.
    let page = svc
        .list_attestations(with_principal(ListAttestationsRequest {
            decision_id: String::new(),
            policy_scope: String::new(),
            limit: 2,
            offset: 1,
        }))
        .await
        .unwrap()
        .into_inner()
        .attestations;
    assert_eq!(page.len(), 2);
    assert!(page.iter().all(|a| a.policy_scope == "scope-a"));
    assert_eq!(page[0].created, 200);
    assert_eq!(page[1].created, 100);
}

#[tokio::test]
async fn reserved_governance_objects_are_hidden_from_generic_crud() {
    let svc = service();
    svc.db
        .runtime()
        .upsert_action_policy(&action_policy::ActionPolicy::allow_all("agent:tester"))
        .unwrap();

    // CreateObject cannot forge a governance kind (policy escalation guard).
    let err = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "forged".into(),
                kind: "action_policy".into(),
                name: "forged".into(),
                namespace: String::new(),
                external_id: "action_policy:agent:tester".into(),
                properties: HashMap::from([("default_decision".into(), "allow".into())]),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "retired-approval".into(),
                kind: "action_approval".into(),
                name: "must remain reserved".into(),
                ..Default::default()
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // find_by_external_id hides the governance object.
    let err = svc
        .find_by_external_id(with_principal(FindByExternalIdRequest {
            external_id: "action_policy:agent:tester".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    // ListObjects filtered by the reserved kind returns nothing.
    let listed = svc
        .list_objects(with_principal(ListObjectsRequest {
            filter: Some(ListFilter {
                kind: "action_policy".into(),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.objects.len(), 0);
    assert_eq!(listed.total, 0);
}

async fn seed_authorized_query_visibility_graph(svc: &SekaiServiceImpl) {
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        },
        "root",
    ))
    .await
    .unwrap();
    for (id, external_id) in [
        ("context-root", "widget:context-root"),
        ("context-allowed", "widget:context-allowed"),
        ("context-denied", "widget:context-denied"),
        ("behind-denied", "widget:behind-denied"),
        ("behind-governance", "widget:behind-governance"),
    ] {
        let mut object = widget_object(id, HashMap::from([("name".into(), id.into())]));
        object.external_id = external_id.into();
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(object),
                lease_precondition: None,
            },
            "root",
        ))
        .await
        .unwrap();
    }
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "internal-policy".into(),
            kind: action_policy::ACTION_POLICY_KIND.into(),
            name: "internal".into(),
            namespace: String::new(),
            external_id: "policy:internal".into(),
            properties: HashMap::from([("default_decision".into(), "deny".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    for link in [
        domain::Link {
            id: "context-visible-link".into(),
            from_id: "context-root".into(),
            to_id: "context-allowed".into(),
            relation: "contains".into(),
            created: 0,
        },
        domain::Link {
            id: "context-denied-link".into(),
            from_id: "context-root".into(),
            to_id: "context-denied".into(),
            relation: "contains".into(),
            created: 0,
        },
        domain::Link {
            id: "context-behind-denied-link".into(),
            from_id: "context-denied".into(),
            to_id: "behind-denied".into(),
            relation: "contains".into(),
            created: 0,
        },
        domain::Link {
            id: "context-governance-link".into(),
            from_id: "context-root".into(),
            to_id: "internal-policy".into(),
            relation: "contains".into(),
            created: 0,
        },
        domain::Link {
            id: "context-behind-governance-link".into(),
            from_id: "internal-policy".into(),
            to_id: "behind-governance".into(),
            relation: "contains".into(),
            created: 0,
        },
    ] {
        svc.db.runtime().create_link(&link).unwrap();
    }
    grant_object_role(svc, "context-denied", "bob", security::Role::Viewer);
}

#[tokio::test]
async fn authorized_graph_queries_hide_reserved_kinds_and_objects_behind_hidden_nodes() {
    let svc = service();
    seed_authorized_query_visibility_graph(&svc).await;

    let hidden = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "internal-policy".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden.code(), tonic::Code::NotFound);

    let links = svc
        .get_links(with_named_principal(
            GetLinksRequest {
                object_id: "context-root".into(),
                relation: "contains".into(),
                direction: "outgoing".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .links;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].id, "context-visible-link");

    let linked_ids = svc
        .get_linked_objects(with_named_principal(
            GetLinkedObjectsRequest {
                object_id: "context-root".into(),
                relation: "contains".into(),
                direction: "outgoing".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .objects
        .into_iter()
        .map(|object| object.id)
        .collect::<Vec<_>>();
    assert_eq!(linked_ids, vec!["context-allowed"]);

    let traversed = svc
        .traverse(with_named_principal(
            TraverseRequest {
                query: Some(GraphQuery {
                    start_id: "context-root".into(),
                    relations: vec!["contains".into()],
                    direction: "outgoing".into(),
                    max_depth: 3,
                    ..Default::default()
                }),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    let traversed_ids = traversed
        .objects
        .iter()
        .map(|object| object.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(traversed_ids, vec!["context-allowed"]);
    assert!(
        traversed
            .objects
            .iter()
            .all(|object| object.kind != action_policy::ACTION_POLICY_KIND)
    );

    let hidden_root = svc
        .get_links(with_named_principal(
            GetLinksRequest {
                object_id: "internal-policy".into(),
                relation: "contains".into(),
                direction: "outgoing".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden_root.code(), tonic::Code::NotFound);

    let denied_root = svc
        .get_links(with_named_principal(
            GetLinksRequest {
                object_id: "context-denied".into(),
                relation: "contains".into(),
                direction: "outgoing".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied_root.code(), tonic::Code::PermissionDenied);

    let traverse_hidden = svc
        .traverse(with_named_principal(
            TraverseRequest {
                query: Some(GraphQuery {
                    start_id: "internal-policy".into(),
                    relations: vec!["contains".into()],
                    direction: "outgoing".into(),
                    max_depth: 2,
                    ..Default::default()
                }),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(traverse_hidden.code(), tonic::Code::NotFound);

    let lineage = svc
        .get_lineage(with_named_principal(
            GetLineageRequest {
                object_id: "context-root".into(),
                max_nodes: 20,
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    let lineage_ids = lineage
        .nodes
        .iter()
        .map(|node| node.object.as_ref().unwrap().id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(lineage_ids, vec!["context-root", "context-allowed"]);
    assert!(
        lineage
            .nodes
            .iter()
            .all(|node| node.object.as_ref().unwrap().kind != action_policy::ACTION_POLICY_KIND)
    );

    let lineage_hidden = svc
        .get_lineage(with_named_principal(
            GetLineageRequest {
                object_id: "internal-policy".into(),
                max_nodes: 20,
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(lineage_hidden.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn blast_radius_object_not_writable_via_update_object() {
    let svc = service();
    svc.db.runtime().add_blast_radius("wu-1", 1, 0).unwrap();
    let counter_id = svc
        .db
        .runtime()
        .find_by_external_id("action_blast_radius:wu-1")
        .unwrap()
        .unwrap()
        .id;
    let err = svc
        .update_object(with_principal(UpdateObjectRequest {
            object: Some(Object {
                id: counter_id,
                kind: "widget".into(),
                name: "tamper".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("mutations".into(), "0".into())]),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert_eq!(svc.db.runtime().get_blast_radius("wu-1").unwrap(), (1, 0));
}

#[tokio::test]
async fn retrieve_context_enforces_graph_visibility_and_response_redaction() {
    let svc = service();
    let mut schema_type = widget_schema_type();
    schema_type.properties.push(PropertyDef {
        name: "secret_note".into(),
        r#type: "string".into(),
        required: false,
        description: String::new(),
        enum_values: Vec::new(),
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: "sensitive".into(),
        struct_fields: Vec::new(),
    });
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        },
        "root",
    ))
    .await
    .unwrap();

    for (id, external_id, secret) in [
        ("context-root", "widget:context-root", true),
        ("context-allowed", "widget:context-allowed", false),
        ("context-denied", "widget:context-denied", false),
        ("behind-denied", "widget:behind-denied", false),
        ("behind-governance", "widget:behind-governance", false),
    ] {
        let mut properties = HashMap::from([("name".into(), id.into())]);
        if secret {
            properties.insert("secret_note".into(), "launch code".into());
        }
        let mut object = widget_object(id, properties);
        object.external_id = external_id.into();
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(object),
                lease_precondition: None,
            },
            "root",
        ))
        .await
        .unwrap();
    }
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "internal-policy".into(),
            kind: action_policy::ACTION_POLICY_KIND.into(),
            name: "internal".into(),
            namespace: String::new(),
            external_id: "policy:internal".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    for link in [
        domain::Link {
            id: "context-visible-link".into(),
            from_id: "context-root".into(),
            to_id: "context-allowed".into(),
            relation: "contains".into(),
            created: 0,
        },
        domain::Link {
            id: "context-denied-link".into(),
            from_id: "context-root".into(),
            to_id: "context-denied".into(),
            relation: "contains".into(),
            created: 0,
        },
        domain::Link {
            id: "context-behind-denied-link".into(),
            from_id: "context-denied".into(),
            to_id: "behind-denied".into(),
            relation: "contains".into(),
            created: 0,
        },
        domain::Link {
            id: "context-governance-link".into(),
            from_id: "context-root".into(),
            to_id: "internal-policy".into(),
            relation: "contains".into(),
            created: 0,
        },
        domain::Link {
            id: "context-behind-governance-link".into(),
            from_id: "internal-policy".into(),
            to_id: "behind-governance".into(),
            relation: "contains".into(),
            created: 0,
        },
    ] {
        svc.db.runtime().create_link(&link).unwrap();
    }
    let denied_grant = security::Grant {
        id: "context-denied-grant".into(),
        object_id: "context-denied".into(),
        principal: "bob".into(),
        role: security::Role::Viewer,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&denied_grant).unwrap();
    svc.security.add_grant(&denied_grant);

    let response = svc
        .retrieve_context(with_named_principal(
            RetrieveContextRequest {
                roots: vec![ContextRoot {
                    external_id: "widget:context-root".into(),
                    ..Default::default()
                }],
                relations: vec!["contains".into()],
                direction: "outgoing".into(),
                max_depth: 3,
                max_objects: 20,
                max_links: 20,
                kind_filter: Vec::new(),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();

    let candidate_ids = response
        .candidates
        .iter()
        .map(|candidate| candidate.object.as_ref().unwrap().id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(candidate_ids, vec!["context-root", "context-allowed"]);
    assert_eq!(response.candidates[0].depth, 0);
    assert_eq!(
        response.epistemic_descriptor_version,
        EPISTEMIC_DESCRIPTOR_VERSION
    );
    let root_descriptor = response.candidates[0].descriptor.as_ref().unwrap();
    assert_eq!(
        root_descriptor.origin_class,
        crate::chisei::epistemic_descriptor::OriginClass::Asserted.as_str()
    );
    assert_eq!(
        root_descriptor.evidence_status,
        crate::chisei::epistemic_descriptor::EvidenceStatus::Unknown.as_str()
    );
    assert_eq!(
        response.candidates[0].object.as_ref().unwrap().properties["secret_note"],
        REDACTED_VALUE
    );
    assert_eq!(response.denied_objects, 0);
    assert_eq!(response.unresolved_roots, 0);
    assert_eq!(response.links.len(), 1);
    assert_eq!(response.links[0].id, "context-visible-link");
    assert!(!response.truncated);

    let denied_root = svc
        .retrieve_context(with_named_principal(
            RetrieveContextRequest {
                roots: vec![ContextRoot {
                    object_id: "context-denied".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(denied_root.candidates.is_empty());
    assert_eq!(denied_root.denied_objects, 0);
    assert_eq!(denied_root.unresolved_roots, 1);

    // #1087: the promoted expand and explain paths inherit the same
    // visibility. A hidden object never appears, and a path to it is not
    // explained, so its existence is not disclosed.
    let expanded = svc
        .expand_relations(with_named_principal(
            ExpandRelationsRequest {
                namespace: "widgets".into(),
                root: Some(ContextRoot {
                    object_id: "context-root".into(),
                    ..Default::default()
                }),
                relations: vec!["contains".into()],
                direction: "outgoing".into(),
                max_depth: 3,
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    let expanded_ids = expanded
        .candidates
        .iter()
        .map(|candidate| candidate.object.as_ref().unwrap().id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(expanded_ids, vec!["context-root", "context-allowed"]);
    assert!(
        expanded
            .links
            .iter()
            .all(|link| link.id == "context-visible-link")
    );
    for (target, visible) in [("context-allowed", true), ("context-denied", false)] {
        let explained = svc
            .explain_derivation(with_named_principal(
                ExplainDerivationRequest {
                    namespace: "widgets".into(),
                    from: Some(ContextRoot {
                        object_id: "context-root".into(),
                        ..Default::default()
                    }),
                    to: Some(ContextRoot {
                        object_id: target.into(),
                        ..Default::default()
                    }),
                    relations: vec!["contains".into()],
                    direction: "outgoing".into(),
                    ..Default::default()
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(explained.found, visible, "{target}");
        if !visible {
            assert!(explained.explanation.is_none());
            assert!(explained.evidence_refs.is_empty());
        }
    }
}

#[tokio::test]
async fn property_level_reads_omit_hidden_values_across_query_surfaces() {
    let svc = service();
    let namespace = "column-reads";
    for (id, secret) in [("visible-a", "classified"), ("visible-b", "other")] {
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: id.into(),
                kind: "document".into(),
                name: id.into(),
                namespace: namespace.into(),
                external_id: format!("{namespace}:{id}"),
                properties: HashMap::from([
                    ("owner".into(), "alice".into()),
                    ("state".into(), "open".into()),
                    ("note".into(), "visible".into()),
                    ("secret".into(), secret.into()),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
    }
    svc.db
        .runtime()
        .create_link(&domain::Link {
            id: "column-reads-link".into(),
            from_id: "visible-a".into(),
            to_id: "visible-b".into(),
            relation: "contains".into(),
            created: 1,
        })
        .unwrap();
    let grants = crate::sekai::object_security::ObjectSecurityPolicy {
        contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "document".into(),
        rules: vec![crate::sekai::object_security::ObjectSecurityRule {
            operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
            predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: Some(vec![
            crate::sekai::object_security::PropertyGrant {
                property: "owner".into(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            },
            crate::sekai::object_security::PropertyGrant {
                property: "state".into(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            },
            crate::sekai::object_security::PropertyGrant {
                property: "note".into(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            },
        ]),
        value_instance_grants: None,
        required_purpose: None,
    };
    let revision = svc
        .db
        .runtime()
        .put_object_security_policy(&grants, "root", "put-column-reads", 1)
        .unwrap();
    svc.db
        .runtime()
        .activate_object_security_policies(
            namespace,
            &BTreeMap::from([("document".into(), revision.revision_digest)]),
            "root",
            "activate-column-reads",
            2,
        )
        .unwrap();

    let loaded = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "visible-a".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert_eq!(
        loaded.properties.get("note").map(String::as_str),
        Some("visible")
    );
    assert!(!loaded.properties.contains_key("secret"));

    let listed = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: "document".into(),
                    property_filters: vec![PropertyFilter {
                        key: "note".into(),
                        op: "eq".into(),
                        value: "visible".into(),
                    }],
                    order_by: "property:state".into(),
                    limit: 10,
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.total, 2);
    assert!(
        listed
            .objects
            .iter()
            .all(|object| !object.properties.contains_key("secret")
                && object.properties.get("note").map(String::as_str) == Some("visible"))
    );

    let hidden_filter = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: "document".into(),
                    property_filters: vec![PropertyFilter {
                        key: "secret".into(),
                        op: "eq".into(),
                        value: "classified".into(),
                    }],
                    limit: 10,
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap_err();
    let unknown_filter = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: "document".into(),
                    property_filters: vec![PropertyFilter {
                        key: "unknown".into(),
                        op: "eq".into(),
                        value: "missing".into(),
                    }],
                    limit: 10,
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden_filter.code(), tonic::Code::PermissionDenied);
    assert_eq!(hidden_filter.message(), unknown_filter.message());
    assert_eq!(hidden_filter.message(), "access denied");

    let hidden_sort = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: namespace.into(),
                    kind: "document".into(),
                    order_by: "property:secret".into(),
                    limit: 10,
                    ..Default::default()
                }),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden_sort.code(), tonic::Code::PermissionDenied);
    assert_eq!(hidden_sort.message(), "access denied");

    let hidden_find = svc
        .find_by_property(with_named_principal(
            FindByPropertyRequest {
                kind: "document".into(),
                key: "secret".into(),
                value: "classified".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden_find.code(), tonic::Code::PermissionDenied);
    assert_eq!(hidden_find.message(), "access denied");

    let found = svc
        .find_by_property(with_named_principal(
            FindByPropertyRequest {
                kind: "document".into(),
                key: "state".into(),
                value: "open".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .objects;
    assert!(
        found
            .iter()
            .filter(|object| object.namespace == namespace)
            .all(|object| !object.properties.contains_key("secret"))
    );

    let hidden_traverse = svc
        .traverse(with_named_principal(
            TraverseRequest {
                query: Some(GraphQuery {
                    start_id: "visible-a".into(),
                    relations: vec!["contains".into()],
                    direction: "outgoing".into(),
                    max_depth: 1,
                    property_filter: HashMap::from([("secret".into(), "classified".into())]),
                    ..Default::default()
                }),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden_traverse.code(), tonic::Code::PermissionDenied);
    assert_eq!(hidden_traverse.message(), "access denied");

    let traversed = svc
        .traverse(with_named_principal(
            TraverseRequest {
                query: Some(GraphQuery {
                    start_id: "visible-a".into(),
                    relations: vec!["contains".into()],
                    direction: "outgoing".into(),
                    max_depth: 1,
                    ..Default::default()
                }),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(traversed.objects.len(), 1);
    assert!(!traversed.objects[0].properties.contains_key("secret"));

    let lineage = svc
        .get_lineage(with_named_principal(
            GetLineageRequest {
                object_id: "visible-a".into(),
                max_nodes: 20,
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert!(
        lineage
            .nodes
            .iter()
            .filter_map(|node| node.object.as_ref())
            .all(|object| !object.properties.contains_key("secret"))
    );

    let retrieved = svc
        .retrieve_context(with_named_principal(
            RetrieveContextRequest {
                roots: vec![ContextRoot {
                    object_id: "visible-a".into(),
                    ..Default::default()
                }],
                relations: vec!["contains".into()],
                direction: "outgoing".into(),
                max_depth: 1,
                max_objects: 20,
                max_links: 20,
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(
        retrieved
            .candidates
            .iter()
            .filter_map(|candidate| candidate.object.as_ref())
            .all(|object| !object.properties.contains_key("secret"))
    );

    let mut revoked = grants;
    revoked.property_grants = Some(vec![
        crate::sekai::object_security::PropertyGrant {
            property: "owner".into(),
            access: crate::sekai::object_security::PropertyGrantAccess::Read,
        },
        crate::sekai::object_security::PropertyGrant {
            property: "state".into(),
            access: crate::sekai::object_security::PropertyGrantAccess::Read,
        },
    ]);
    let revoked_revision = svc
        .db
        .runtime()
        .put_object_security_policy(&revoked, "root", "put-column-revoke", 3)
        .unwrap();
    svc.db
        .runtime()
        .activate_object_security_policies(
            namespace,
            &BTreeMap::from([("document".into(), revoked_revision.revision_digest)]),
            "root",
            "activate-column-revoke",
            4,
        )
        .unwrap();
    let after_revoke = svc
        .get_object(with_named_principal(
            GetObjectRequest {
                id: "visible-a".into(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert!(!after_revoke.properties.contains_key("note"));
    assert!(!after_revoke.properties.contains_key("secret"));
}

#[tokio::test]
async fn retrieve_context_rejects_ambiguous_roots() {
    let err = service()
        .retrieve_context(with_principal(RetrieveContextRequest {
            roots: vec![ContextRoot {
                object_id: "one".into(),
                external_id: "two".into(),
                link_id: String::new(),
            }],
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn retrieve_context_requires_an_authenticated_principal() {
    let err = service()
        .retrieve_context(Request::new(RetrieveContextRequest {
            roots: vec![ContextRoot {
                object_id: "one".into(),
                ..Default::default()
            }],
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

async fn seed_semantic_catalog_graph(svc: &SekaiServiceImpl) {
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        },
        "local",
    ))
    .await
    .unwrap();
    for (id, external_id, namespace) in [
        ("sem-root", "widget:sem-root", "acme"),
        ("sem-allowed", "widget:sem-allowed", "acme"),
        ("sem-denied", "widget:sem-denied", "acme"),
    ] {
        let mut object = widget_object(
            id,
            HashMap::from([("name".into(), id.into()), ("color".into(), "red".into())]),
        );
        object.external_id = external_id.into();
        object.namespace = namespace.into();
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(object),
                lease_precondition: None,
            },
            "local",
        ))
        .await
        .unwrap();
    }
    for link in [
        domain::Link {
            id: "sem-visible-link".into(),
            from_id: "sem-root".into(),
            to_id: "sem-allowed".into(),
            relation: "contains".into(),
            created: 0,
        },
        domain::Link {
            id: "sem-denied-link".into(),
            from_id: "sem-root".into(),
            to_id: "sem-denied".into(),
            relation: "contains".into(),
            created: 0,
        },
    ] {
        svc.db.runtime().create_link(&link).unwrap();
    }
    let denied_grant = security::Grant {
        id: "sem-denied-grant".into(),
        object_id: "sem-denied".into(),
        principal: "bob".into(),
        role: security::Role::Viewer,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&denied_grant).unwrap();
    svc.security.add_grant(&denied_grant);

    grant_ontology_admin(svc);
    svc.create_ontology_class(with_named_principal(
        CreateOntologyClassRequest {
            class: Some(OntologyClass {
                name: "WidgetClass".into(),
                description: "semantic widget".into(),
                mapped_kind: "widget".into(),
                ..Default::default()
            }),
        },
        "tester",
    ))
    .await
    .unwrap();
}

/// #1149: community PostgreSQL advertises no query-time entailment, serves
/// the asserted-only mode, and fails the entailment mode closed.
#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_semantic_discovery_is_honest_about_entailment() {
    let scratch = crate::db::ScratchDatabase::create();
    let db = Arc::new(RuntimeDb::Postgres(Arc::new(scratch.connect())));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
                db.clone(),
            ));
            seed_semantic_catalog_graph(&svc).await;
            let discovered = svc
                .discover_capabilities(with_named_principal(
                    DiscoverCapabilitiesRequest {
                        namespace: "acme".into(),
                        page_size: 200,
                        product_tier_filter: "all".into(),
                        ..Default::default()
                    },
                    "alice",
                ))
                .await
                .unwrap()
                .into_inner();
            for name in [
                semantic::CAPABILITY_EXPAND_RELATIONS,
                semantic::CAPABILITY_RETRIEVE_CONTEXT,
                semantic::CAPABILITY_EXPLAIN_DERIVATION,
            ] {
                let entry = discovered
                    .capabilities
                    .iter()
                    .find(|entry| entry.name == name)
                    .unwrap_or_else(|| panic!("missing semantic capability {name}"));
                let limits = entry
                    .limits
                    .iter()
                    .map(|limit| (limit.name.as_str(), limit.value))
                    .collect::<HashMap<_, _>>();
                assert_eq!(limits.get("supports_entailment"), Some(&0), "{name}");
                assert_eq!(limits.get("supports_asserted_only"), Some(&1), "{name}");
            }
            let expand = |mode: &str| ExpandRelationsRequest {
                namespace: "acme".into(),
                root: Some(ContextRoot {
                    object_id: "sem-root".into(),
                    ..Default::default()
                }),
                relations: vec!["contains".into()],
                direction: "outgoing".into(),
                max_depth: 2,
                reasoning_mode: mode.into(),
                ..Default::default()
            };
            let asserted = svc
                .expand_relations(with_named_principal(expand("asserted_only"), "alice"))
                .await
                .unwrap()
                .into_inner();
            assert!(
                asserted
                    .candidates
                    .iter()
                    .any(|candidate| candidate.object.as_ref().unwrap().id == "sem-root")
            );
            let entailment = svc
                .expand_relations(with_named_principal(expand("entailment"), "alice"))
                .await
                .unwrap_err();
            assert_eq!(entailment.code(), tonic::Code::FailedPrecondition);
        });
    drop(db);
}

#[tokio::test]
async fn semantic_capabilities_are_discoverable_with_bounds_and_versions() {
    let svc = service();
    seed_semantic_catalog_graph(&svc).await;
    let discovered = svc
        .discover_capabilities(with_named_principal(
            DiscoverCapabilitiesRequest {
                namespace: "acme".into(),
                page_size: 200,
                product_tier_filter: "all".into(),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    let by_name = discovered
        .capabilities
        .into_iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect::<HashMap<_, _>>();
    for name in [
        semantic::CAPABILITY_EXPAND_RELATIONS,
        semantic::CAPABILITY_RETRIEVE_CONTEXT,
        semantic::CAPABILITY_EXPLAIN_DERIVATION,
    ] {
        let entry = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing semantic capability {name}"));
        assert_eq!(entry.contract_version, capability::CONTRACT_VERSION);
        assert!(
            entry
                .policy_decision_points
                .iter()
                .any(|point| point == "namespace_access")
        );
        let limits = entry
            .limits
            .iter()
            .map(|limit| (limit.name.as_str(), limit.value))
            .collect::<HashMap<_, _>>();
        assert_eq!(
            limits.get("reasoning_profile_version"),
            Some(&semantic::REASONING_PROFILE_VERSION)
        );
        assert_eq!(
            limits.get("ontology_contract_version"),
            Some(&semantic::ONTOLOGY_CONTRACT_VERSION)
        );
        assert_eq!(
            limits.get("max_depth"),
            Some(&(u64::from(retrieval::MAX_DEPTH)))
        );
        assert_eq!(limits.get("supports_entailment"), Some(&1));
    }
}

#[tokio::test]
async fn credential_rpcs_manage_credentials_without_exposing_hashes() {
    let svc = service();
    let created = svc
        .create_credential(with_named_principal(
            CreateCredentialRequest {
                principal: "agent-a".into(),
                managed_team_principal: false,
                tenant_id: String::new(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(created.token.starts_with("sekai_"));
    assert_eq!(created.credential.unwrap().principal, "agent-a");

    let rotated = svc
        .rotate_credential(with_named_principal(
            RotateCredentialRequest {
                principal: "agent-a".into(),
                managed_team_principal: false,
                tenant_id: String::new(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(rotated.token, created.token);

    let listed = svc
        .list_credentials(with_named_principal(
            ListCredentialsRequest {
                tenant_id: String::new(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.credentials.len(), 2);
    assert_eq!(
        listed
            .credentials
            .iter()
            .filter(|credential| credential.status == "active")
            .count(),
        1
    );

    let revoked = svc
        .revoke_credential(with_named_principal(
            RevokeCredentialRequest {
                principal: "agent-a".into(),
                tenant_id: String::new(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .credential
        .unwrap();
    assert_eq!(revoked.status, "revoked");
}

#[tokio::test]
async fn credential_rpcs_require_control_plane_admin() {
    let error = service()
        .list_credentials(with_named_principal(
            ListCredentialsRequest {
                tenant_id: String::new(),
            },
            "tester",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn managed_team_classification_is_atomic_with_credential_rotation() {
    let svc = service();
    svc.create_credential(with_named_principal(
        CreateCredentialRequest {
            principal: "team-agent".into(),
            managed_team_principal: false,
            tenant_id: String::new(),
        },
        "local",
    ))
    .await
    .unwrap();
    assert!(!svc.db.runtime().is_team_principal("team-agent").unwrap());

    svc.rotate_credential(with_named_principal(
        RotateCredentialRequest {
            principal: "team-agent".into(),
            managed_team_principal: true,
            tenant_id: String::new(),
        },
        "local",
    ))
    .await
    .unwrap();
    assert!(svc.db.runtime().is_team_principal("team-agent").unwrap());
    assert_eq!(
        svc.db
            .runtime()
            .list_credentials(Some("team-agent"), Some("active"))
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn credential_rpcs_reject_privileged_principal_names() {
    for principal in ["root", "local", "anonymous"] {
        let error = service()
            .create_credential(with_named_principal(
                CreateCredentialRequest {
                    principal: principal.into(),
                    managed_team_principal: false,
                    tenant_id: String::new(),
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}

#[tokio::test]
async fn managed_credentials_reject_reserved_gateway_principal() {
    let error = service()
        .create_credential(with_named_principal(
            CreateCredentialRequest {
                principal: "chisei-gateway".into(),
                managed_team_principal: true,
                tenant_id: String::new(),
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn provenance_report_is_served_without_direct_database_access() {
    let svc = service();
    svc.create_contention_scope(with_named_principal(
        CreateContentionScopeRequest {
            request_id: "provenance-scope".into(),
            scope: Some(ContentionScope {
                id: "provenance-scope".into(),
                name: "provenance".into(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                ..Default::default()
            }),
        },
        "local",
    ))
    .await
    .unwrap();
    svc.create_work_unit(with_named_principal(
        CreateWorkUnitRequest {
            request_id: "work-unit-1".into(),
            work_unit: Some(WorkUnit {
                id: "work-unit-1".into(),
                kind: "analysis".into(),
                actor: "local".into(),
                requested_spec: "assemble provenance".into(),
                scope_id: "provenance-scope".into(),
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at: 1,
                idempotency_key: "work-unit-1".into(),
                ..Default::default()
            }),
        },
        "local",
    ))
    .await
    .unwrap();
    let response = svc
        .get_provenance_report(with_named_principal(
            GetProvenanceReportRequest {
                work_unit_id: "work-unit-1".into(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(response.report.contains("work-unit-1"));
}

async fn configured_evidence_service(with_target: bool) -> SekaiServiceImpl {
    let svc = service();
    svc.db
        .runtime()
        .upsert_evidence_producer(
            &DomainEvidenceProducerCapability {
                producer_identity: "producer:checks".into(),
                config_version: 1,
                source_types: vec!["verification_system".into()],
                source_instances: vec!["checks-primary".into()],
                namespaces: vec!["acme".into()],
                evidence_types: vec!["verification.result".into()],
                target_kinds: vec!["service".into()],
                classification_ceiling: evidence_domain::EvidenceClassification::Confidential,
                allowed_intents: vec![
                    evidence_domain::EvidenceIntent::Upsert,
                    evidence_domain::EvidenceIntent::Retract,
                    evidence_domain::EvidenceIntent::MarkStale,
                ],
                allow_operation_attachment: false,
                replay_window_ms: 60_000,
                max_clock_skew_ms: 1_000,
                max_payload_bytes: 4_096,
                max_relationships: 8,
                rate_limit_per_minute: 100,
                max_retained_submissions: 100_000,
                revoked: false,
            },
            now_millis(),
        )
        .unwrap();
    svc.register_evidence_schema(with_named_principal(
        RegisterEvidenceSchemaRequest {
            definition: Some(EvidenceSchemaDefinition {
                schema_id: "verification.result".into(),
                schema_version: "1.0.0".into(),
                evidence_type: "verification.result".into(),
                compatible_versions: vec![],
            }),
        },
        "local",
    ))
    .await
    .unwrap();
    if with_target {
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: "service-1".into(),
                kind: "service".into(),
                name: "payments".into(),
                namespace: "acme".into(),
                external_id: "service:payments".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
    }
    svc
}

fn proto_evidence(record: &str, sequence: i64) -> EvidenceEnvelope {
    let content = serde_json::json!({"result": "passed", "sequence": sequence});
    EvidenceEnvelope {
        contract_version: evidence_domain::EVIDENCE_ENVELOPE_VERSION.into(),
        source_type: "verification_system".into(),
        source_instance: "checks-primary".into(),
        source_record_id: record.into(),
        source_version: format!("v{sequence}"),
        source_sequence: sequence,
        namespace: "acme".into(),
        target_external_id: "service:payments".into(),
        target_kind: "service".into(),
        evidence_type: "verification.result".into(),
        signal: "verification".into(),
        schema_id: "verification.result".into(),
        schema_version: "1.0.0".into(),
        schema_compatibility: "exact".into(),
        observed_at_ms: now_millis(),
        collected_at_ms: now_millis(),
        expires_at_ms: None,
        content_json: serde_json::to_vec(&content).unwrap(),
        relationships: vec![],
        producer_identity: "producer:checks".into(),
        confidence_bps: 9_000,
        classification: "internal".into(),
        provenance: HashMap::new(),
        idempotency_key: format!("delivery-{record}-{sequence}"),
        content_digest: crate::sekai::evidence_store::canonical_content_digest(&content).unwrap(),
        intent: "upsert".into(),
        causality: None,
    }
}

#[tokio::test]
async fn evidence_admission_lifecycle_projects_and_resolves_domain_outcome() {
    let svc = configured_evidence_service(true).await;
    let envelope = from_proto_evidence_envelope(proto_evidence("lifecycle-run", 1)).unwrap();

    let outcome = EvidenceAdmissionLifecycle::new(svc.db.runtime())
        .admit(&envelope, "producer:checks", now_millis())
        .unwrap();

    assert!(outcome.admitted);
    assert!(!outcome.deduplicated);
    assert!(
        outcome
            .projection
            .as_ref()
            .is_some_and(|value| value.projected)
    );
    assert_eq!(outcome.submission.lifecycle_state.as_str(), "available");
    assert!(!outcome.execution_recorded);
}

#[tokio::test]
async fn evidence_control_plane_authenticates_and_filters_inspection() {
    let svc = configured_evidence_service(true).await;
    let submitted = svc
        .submit_evidence(with_named_principal(
            SubmitEvidenceRequest {
                envelope: Some(proto_evidence("run-1", 1)),
            },
            "producer:checks",
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert!(submitted.admitted);
    assert!(submitted.projected);
    let submission = submitted.submission.unwrap();
    assert_eq!(submission.lifecycle_state, "available");
    let descriptor = submission.descriptor.as_ref().unwrap();
    assert_eq!(
        descriptor.origin_class,
        crate::chisei::epistemic_descriptor::OriginClass::Asserted.as_str()
    );
    assert_eq!(
        descriptor.evidence_status,
        crate::chisei::epistemic_descriptor::EvidenceStatus::Unknown.as_str()
    );
    assert_eq!(
        descriptor.lifecycle_status,
        crate::chisei::epistemic_descriptor::LifecycleStatus::Current.as_str()
    );
    assert_eq!(
        descriptor.source_digests,
        vec![submission.content_digest.clone()]
    );

    let inspected = svc
        .get_evidence_submission(with_named_principal(
            GetEvidenceSubmissionRequest {
                submission_id: submission.id.clone(),
            },
            "producer:checks",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(inspected.lifecycle_history.last().unwrap(), "available");
    assert_eq!(
        inspected
            .submission
            .unwrap()
            .descriptor
            .unwrap()
            .lifecycle_status,
        crate::chisei::epistemic_descriptor::LifecycleStatus::Current.as_str()
    );
    let denied = svc
        .get_evidence_submission(with_named_principal(
            GetEvidenceSubmissionRequest {
                submission_id: submission.id,
            },
            "producer:other",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    let listed = svc
        .list_evidence_submissions(with_named_principal(
            ListEvidenceSubmissionsRequest {
                producer_identity: String::new(),
                source_instance: "checks-primary".into(),
                namespace: "acme".into(),
                lifecycle_state: "available".into(),
                target_external_id: "service:payments".into(),
                evidence_type: "verification.result".into(),
                limit: 10,
                offset: 0,
            },
            "producer:checks",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.submissions.len(), 1);
}

#[test]
fn evidence_content_lifecycle_is_fail_closed() {
    use evidence_domain::EvidenceLifecycleState::*;

    for state in [Available, Superseded, Retracted, Stale] {
        assert!(evidence_content_is_readable(state), "{state:?}");
    }
    for state in [
        Received,
        Validated,
        Deduplicated,
        Authorized,
        Projected,
        Rejected,
        Quarantined,
    ] {
        assert!(!evidence_content_is_readable(state), "{state:?}");
    }
}

#[test]
fn reserved_governance_kinds_are_exclusion_safe() {
    // Every reserved kind must be ASCII alphanumeric/underscore so the
    // static SQL exclusion covers it; a kind with special characters would
    // fail the query closed rather than silently re-opening the leak.
    for kind in RESERVED_GOVERNANCE_KINDS {
        assert!(
            !kind.is_empty() && kind.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "reserved governance kind {kind:?} is not exclusion-safe"
        );
    }
}

#[tokio::test]
async fn capability_discovery_requires_authentication_and_stable_version() {
    let svc = service();
    let unauthenticated = svc
        .discover_capabilities(Request::new(DiscoverCapabilitiesRequest {
            namespace: "acme".into(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(unauthenticated.code(), tonic::Code::Unauthenticated);

    let blank_principal = svc
        .discover_capabilities(with_named_principal(
            DiscoverCapabilitiesRequest {
                namespace: "acme".into(),
                ..Default::default()
            },
            ",",
        ))
        .await
        .unwrap_err();
    assert_eq!(blank_principal.code(), tonic::Code::Unauthenticated);

    let unsupported = svc
        .discover_capabilities(with_named_principal(
            DiscoverCapabilitiesRequest {
                namespace: "acme".into(),
                contract_version: "2.0".into(),
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(unsupported.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        unsupported.message(),
        "unsupported capability catalog contract version"
    );
}

#[tokio::test]
async fn capability_discovery_defaults_to_core_and_requires_explicit_expansion() {
    let svc = service();
    let core = svc
        .discover_capabilities(with_named_principal(
            DiscoverCapabilitiesRequest {
                namespace: "acme".into(),
                page_size: 200,
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!core.capabilities.is_empty());
    assert!(
        core.capabilities
            .iter()
            .all(|entry| entry.product_tier == "core")
    );

    let all = svc
        .discover_capabilities(with_named_principal(
            DiscoverCapabilitiesRequest {
                namespace: "acme".into(),
                page_size: 200,
                product_tier_filter: "all".into(),
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(all.total_size > core.total_size);
    assert!(
        all.capabilities
            .iter()
            .any(|entry| entry.product_tier != "core")
    );

    let experimental = core
        .capabilities
        .iter()
        .find(|entry| entry.name == crate::rpc_maturity::EXPERIMENTAL_CAPABILITY)
        .expect("core catalog reports the experimental RPC gate");
    let enabled = crate::rpc_maturity::experimental_rpcs_enabled();
    assert_eq!(experimental.product_tier, "core");
    assert_eq!(
        experimental.lifecycle_state,
        if enabled { "active" } else { "disabled" }
    );
    assert_eq!(
        experimental
            .limits
            .iter()
            .find(|limit| limit.name == "enabled")
            .map(|limit| limit.value),
        Some(u64::from(enabled))
    );

    let transform = core
        .capabilities
        .iter()
        .find(|entry| entry.name == crate::sekai::governed_transform::HOSTED_COMPUTE_CAPABILITY)
        .expect("core catalog reports the in-process transform host");
    assert_eq!(transform.product_tier, "core");
    assert_eq!(
        transform.lifecycle_state,
        if enabled { "active" } else { "disabled" }
    );
    assert!(transform.description.contains("dataset transform host"));
    let analytical = core
        .capabilities
        .iter()
        .find(|entry| entry.name == crate::sekai::governed_transform::ANALYTICAL_COMPUTE_CAPABILITY)
        .expect("core catalog reports the analytical transform profile");
    assert_eq!(analytical.product_tier, "core");
    assert_eq!(
        analytical.lifecycle_state,
        if enabled { "active" } else { "disabled" }
    );
    let isolated = core
        .capabilities
        .iter()
        .find(|entry| entry.name == crate::sekai::governed_transform::ISOLATED_COMPUTE_CAPABILITY)
        .expect("core catalog reports the isolated-process transform profile");
    assert_eq!(isolated.product_tier, "core");
    assert_eq!(
        isolated.lifecycle_state,
        if enabled { "active" } else { "disabled" }
    );
}

#[tokio::test]
async fn capability_discovery_rejects_a_stale_pinned_snapshot_without_metadata() {
    let svc = service();
    let first = svc
        .discover_capabilities(with_named_principal(
            DiscoverCapabilitiesRequest {
                namespace: "acme".into(),
                page_size: 1,
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        },
        "local",
    ))
    .await
    .unwrap();

    let stale = svc
        .discover_capabilities(with_named_principal(
            DiscoverCapabilitiesRequest {
                namespace: "acme".into(),
                catalog_version: first.catalog_version,
                page_size: 1,
                page_token: first.next_page_token,
                product_tier_filter: String::new(),
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::Aborted);
    assert_eq!(stale.message(), "capability catalog version unavailable");
    assert!(!stale.message().contains("widget"));
}

fn intake_action_type(object_kind: &str) -> GovernedActionType {
    let parameter_schema_json = if object_kind.is_empty() {
        r#"{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}"#
    } else {
        r#"{"type":"object","properties":{"object_id":{"type":"string"},"summary":{"type":"string"}},"required":["object_id","summary"],"additionalProperties":false}"#
    };
    GovernedActionType {
        approvers: Vec::new(),
        namespace: "acme".into(),
        type_id: "review.intake".into(),
        version: "1.0.0".into(),
        description: "Admit review".into(),
        parameter_schema_json: parameter_schema_json.into(),
        allowed_effect_kinds: vec!["runtime_dispatch".into()],
        policy_scope: String::new(),
        budget_scope: String::new(),
        enabled: true,
        created_by: String::new(),
        created_at_ms: 0,
        updated_at_ms: 0,
        disabled_at_ms: 0,
        object_kind: object_kind.into(),
        object_mutation: if object_kind.is_empty() {
            String::new()
        } else {
            "create".into()
        },
        submission_criteria: vec![],
        declared_effect_kinds: vec![],
        system_one_json: String::new(),
        review_queue_id: String::new(),
        review_sla_ms: 0,
        review_escalate: String::new(),
        review_escalate_to: String::new(),
        review_threshold_param: String::new(),
        review_threshold: 0,
        review_pool: vec![],
        review_agent_reviewers: vec![],
    }
}

async fn discover_acme(
    svc: &SekaiServiceImpl,
    principal: &str,
) -> crate::grpc::pb::sekai::DiscoverCapabilitiesResponse {
    svc.discover_capabilities(with_named_principal(
        DiscoverCapabilitiesRequest {
            namespace: "acme".into(),
            page_size: 200,
            ..Default::default()
        },
        principal,
    ))
    .await
    .unwrap()
    .into_inner()
}

/// #1459: a published enabled Action type is a core catalog entry for a
/// permitted principal, with the type's schema, description, and markings.
#[tokio::test]
async fn capability_discovery_lists_published_action_types_for_permitted_principals() {
    let svc = service();
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        },
        "local",
    ))
    .await
    .unwrap();
    let before = discover_acme(&svc, "tester").await;
    let action_name = capability::action_capability_name("review.intake");
    assert!(
        before
            .capabilities
            .iter()
            .all(|entry| entry.name != action_name)
    );

    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(intake_action_type("widget")),
            request_id: "put-intake".into(),
        },
        "local",
    ))
    .await
    .unwrap();

    let discovered = discover_acme(&svc, "tester").await;
    assert_ne!(discovered.catalog_version, before.catalog_version);
    assert!(discovered.ontology_revision.is_empty());
    let entry = discovered
        .capabilities
        .iter()
        .find(|entry| entry.name == action_name)
        .expect("published action type is discoverable");
    assert_eq!(entry.product_tier, "core");
    assert_eq!(entry.kind, "action");
    assert_eq!(entry.description, "Admit review");
    assert_eq!(
        entry.parameter_schema_json,
        r#"{"type":"object","properties":{"object_id":{"type":"string"},"summary":{"type":"string"}},"required":["object_id","summary"],"additionalProperties":false}"#
    );
    assert_eq!(entry.approval_behavior, "none");
    assert_eq!(entry.action_version, "1.0.0");
    assert_eq!(
        entry.tool_effect, "mutating",
        "derived from runtime_dispatch"
    );
    assert_eq!(entry.input_type, "sekai.SubmitActionInstanceRequest");
    assert_eq!(entry.output_type, "sekai.SubmitActionInstanceResponse");
    assert!(
        entry
            .required_scopes
            .iter()
            .any(|scope| scope == "action:submit")
    );
    assert!(
        entry
            .policy_decision_points
            .iter()
            .any(|point| point == "action_policy")
    );
    assert!(
        entry
            .policy_decision_points
            .iter()
            .any(|point| point == "schema_visibility")
    );
    assert!(entry.markings.iter().any(|marking| marking == "public"));

    let mut later = intake_action_type("widget");
    later.version = "2.0.0".into();
    later.description = "Admit review v2".into();
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(later),
            request_id: "put-intake-v2".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    let latest = discover_acme(&svc, "tester").await;
    let latest_entries: Vec<_> = latest
        .capabilities
        .iter()
        .filter(|entry| entry.name == action_name)
        .collect();
    assert_eq!(latest_entries.len(), 1);
    assert_eq!(latest_entries[0].action_version, "2.0.0");
    assert_eq!(latest_entries[0].description, "Admit review v2");

    let mut require_approval = action_policy::ActionPolicy::allow_all("agent:tester");
    require_approval.action_overrides.insert(
        crate::sekai::action_instance::SUBMIT_POLICY_ACTION.into(),
        action_policy::ActionDecision::RequireApproval,
    );
    svc.db
        .runtime()
        .upsert_action_policy(&require_approval)
        .unwrap();
    let approved = discover_acme(&svc, "tester").await;
    let approved_entry = approved
        .capabilities
        .iter()
        .find(|entry| entry.name == action_name)
        .expect("approval policy still lists the action");
    assert_eq!(approved_entry.approval_behavior, "required");

    let mut deny_submit = action_policy::ActionPolicy::allow_all("agent:tester");
    deny_submit.action_overrides.insert(
        crate::sekai::action_instance::SUBMIT_POLICY_ACTION.into(),
        action_policy::ActionDecision::Deny,
    );
    deny_submit
        .action_overrides
        .insert("review.intake".into(), action_policy::ActionDecision::Allow);
    svc.db.runtime().upsert_action_policy(&deny_submit).unwrap();
    let submit_denied = discover_acme(&svc, "tester").await;
    assert!(
        submit_denied
            .capabilities
            .iter()
            .all(|entry| entry.name != action_name)
    );
}

/// #1459: a type-level deny drops the catalog entry; catalog-bound submit
/// then fails closed. Direct submit without catalog headers is unchanged.
#[tokio::test]
async fn capability_discovery_omits_denied_action_and_catalog_submit_fails_closed() {
    use crate::sekai::action_instance::STATUS_ADMITTED;

    let svc = service();
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(intake_action_type("")),
            request_id: "put-intake".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    let action_name = capability::action_capability_name("review.intake");
    let listed = discover_acme(&svc, "tester").await;
    assert!(
        listed
            .capabilities
            .iter()
            .any(|entry| entry.name == action_name)
    );

    let mut later = intake_action_type("");
    later.version = "2.0.0".into();
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(later),
            request_id: "put-intake-v2-submit".into(),
        },
        "local",
    ))
    .await
    .unwrap();

    let submit = SubmitActionInstanceRequest {
        namespace: "acme".into(),
        type_id: "review.intake".into(),
        version: "2.0.0".into(),
        parameters_json: r#"{"summary":"ship it"}"#.into(),
        idempotency_key: "idem-catalog".into(),
        evidence_submission_ids: vec![],
        request_id: "req-catalog".into(),
        ontology_digest: String::new(),
    };
    let stale_version = svc
        .submit_action_instance(with_catalog_action(
            SubmitActionInstanceRequest {
                version: "1.0.0".into(),
                idempotency_key: "idem-old-version".into(),
                request_id: "req-old-version".into(),
                ..submit.clone()
            },
            "tester",
            &action_name,
            "acme",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale_version.code(), tonic::Code::FailedPrecondition);
    assert_eq!(stale_version.message(), "capability unavailable");

    let admitted = svc
        .submit_action_instance(with_catalog_action(
            submit.clone(),
            "tester",
            &action_name,
            "acme",
        ))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(admitted.status, STATUS_ADMITTED);

    let mut deny = action_policy::ActionPolicy::allow_all("agent:tester");
    deny.action_overrides
        .insert("review.intake".into(), action_policy::ActionDecision::Deny);
    svc.db.runtime().upsert_action_policy(&deny).unwrap();

    let omitted = discover_acme(&svc, "tester").await;
    assert!(
        omitted
            .capabilities
            .iter()
            .all(|entry| entry.name != action_name)
    );
    assert_ne!(omitted.catalog_version, listed.catalog_version);

    let stale = svc
        .submit_action_instance(with_catalog_action(
            SubmitActionInstanceRequest {
                idempotency_key: "idem-stale".into(),
                request_id: "req-stale".into(),
                ..submit.clone()
            },
            "tester",
            &action_name,
            "acme",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    assert_eq!(stale.message(), "capability unavailable");
    assert!(!stale.message().contains("review.intake"));

    let direct = svc
        .submit_action_instance(with_named_principal(
            SubmitActionInstanceRequest {
                idempotency_key: "idem-direct".into(),
                request_id: "req-direct".into(),
                ..submit.clone()
            },
            "tester",
        ))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(direct.status, STATUS_ADMITTED);

    let mcp = svc
        .submit_action_instance(with_catalog_action(
            SubmitActionInstanceRequest {
                idempotency_key: "idem-mcp".into(),
                request_id: "req-mcp".into(),
                ..submit
            },
            "tester",
            "sekai.actions.submit",
            "acme",
        ))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(mcp.status, STATUS_ADMITTED);
}

/// #1459: team-managed Viewers keep object queries and lose Action entries.
#[tokio::test]
async fn capability_discovery_omits_actions_without_namespace_write() {
    let svc = service();
    grant_source_namespace(&svc, "acme", "alice", security::Role::Viewer);
    grant_source_namespace(&svc, "acme", "tester", security::Role::Editor);
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(intake_action_type("")),
            request_id: "put-intake".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    let action_name = capability::action_capability_name("review.intake");
    let viewer = discover_acme(&svc, "alice").await;
    assert!(
        viewer
            .capabilities
            .iter()
            .all(|entry| entry.name != action_name)
    );
    let editor = discover_acme(&svc, "tester").await;
    assert!(
        editor
            .capabilities
            .iter()
            .any(|entry| entry.name == action_name)
    );
    assert_ne!(viewer.catalog_version, editor.catalog_version);
}

/// #1459: discover-only enterprise sessions keep queries and lose Actions.
#[tokio::test]
async fn capability_discovery_omits_actions_without_enterprise_write() {
    let svc = service();
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(intake_action_type("")),
            request_id: "put-intake".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    let action_name = capability::action_capability_name("review.intake");
    let discoverer = svc
        .discover_capabilities(with_discoverer(
            DiscoverCapabilitiesRequest {
                namespace: "acme".into(),
                page_size: 200,
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(
        discoverer
            .capabilities
            .iter()
            .all(|entry| entry.name != action_name)
    );
    let writer = discover_acme(&svc, "tester").await;
    assert!(
        writer
            .capabilities
            .iter()
            .any(|entry| entry.name == action_name)
    );
}

/// #1459: type_id `submit` publishes as `sekai.actions.submit` and still
/// rechecks the live catalog. The MCP allowlist skip does not apply.
#[tokio::test]
async fn capability_discovery_rechecks_native_submit_type_id() {
    use crate::sekai::action_instance::STATUS_ADMITTED;

    let svc = service();
    let mut native_submit = intake_action_type("");
    native_submit.type_id = "submit".into();
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(native_submit),
            request_id: "put-submit-type".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    let action_name = capability::action_capability_name("submit");
    assert_eq!(action_name, "sekai.actions.submit");
    let listed = discover_acme(&svc, "tester").await;
    assert!(
        listed
            .capabilities
            .iter()
            .any(|entry| entry.name == action_name)
    );

    let submit = SubmitActionInstanceRequest {
        namespace: "acme".into(),
        type_id: "submit".into(),
        version: "1.0.0".into(),
        parameters_json: r#"{"summary":"ship it"}"#.into(),
        idempotency_key: "idem-native-submit".into(),
        evidence_submission_ids: vec![],
        request_id: "req-native-submit".into(),
        ontology_digest: String::new(),
    };
    let admitted = svc
        .submit_action_instance(with_catalog_action(
            submit.clone(),
            "tester",
            &action_name,
            "acme",
        ))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(admitted.status, STATUS_ADMITTED);

    let mut deny = action_policy::ActionPolicy::allow_all("agent:tester");
    deny.action_overrides
        .insert("submit".into(), action_policy::ActionDecision::Deny);
    svc.db.runtime().upsert_action_policy(&deny).unwrap();
    let omitted = discover_acme(&svc, "tester").await;
    assert!(
        omitted
            .capabilities
            .iter()
            .all(|entry| entry.name != action_name)
    );
    let stale = svc
        .submit_action_instance(with_catalog_action(
            SubmitActionInstanceRequest {
                idempotency_key: "idem-native-submit-stale".into(),
                request_id: "req-native-submit-stale".into(),
                ..submit
            },
            "tester",
            &action_name,
            "acme",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    assert_eq!(stale.message(), "capability unavailable");
}

/// #1459: schema ACL hides types from ungranted principals; restricted
/// properties and markings stay off the catalog unless the caller may query
/// them.
#[tokio::test]
async fn capability_discovery_hides_restricted_schema_and_markings() {
    let svc = service();
    let mut widget = widget_schema_type();
    widget.properties.push(PropertyDef {
        name: "secret_note".into(),
        r#type: "string".into(),
        required: false,
        description: "".into(),
        enum_values: vec![],
        link_kind: "".into(),
        compute_expr: "".into(),
        classification: "internal".into(),
        struct_fields: vec![],
    });
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(widget),
        },
        "local",
    ))
    .await
    .unwrap();
    let mut classified = widget_schema_type();
    classified.kind = "classified_widget".into();
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(classified),
        },
        "local",
    ))
    .await
    .unwrap();
    grant_object_role(
        &svc,
        &schema_object_id("classified_widget"),
        "tester",
        security::Role::Viewer,
    );

    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(intake_action_type("widget")),
            request_id: "put-widget-action".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    let mut secret_action = intake_action_type("widget");
    secret_action.type_id = "review.secret".into();
    secret_action.description = "Admit review with note".into();
    secret_action.parameter_schema_json = r#"{"type":"object","properties":{"object_id":{"type":"string"},"summary":{"type":"string"},"secret_note":{"type":"string"}},"required":["object_id","summary"],"additionalProperties":false}"#.into();
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(secret_action),
            request_id: "put-secret-action".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    let mut classified_action = intake_action_type("classified_widget");
    classified_action.type_id = "classified.dispatch".into();
    classified_action.description = "Classified dispatch".into();
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(classified_action),
            request_id: "put-classified-action".into(),
        },
        "local",
    ))
    .await
    .unwrap();

    let widget_action = capability::action_capability_name("review.intake");
    let secret_action_name = capability::action_capability_name("review.secret");
    let classified_action_name = capability::action_capability_name("classified.dispatch");
    let alice = discover_acme(&svc, "alice").await;
    let alice_names: Vec<&str> = alice
        .capabilities
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    assert!(alice_names.contains(&widget_action.as_str()));
    assert!(!alice_names.contains(&secret_action_name.as_str()));
    assert!(!alice_names.contains(&classified_action_name.as_str()));
    assert!(!alice_names.contains(&"sekai.objects.query.classified_widget"));
    let alice_widget = alice
        .capabilities
        .iter()
        .find(|entry| entry.name == widget_action)
        .unwrap();
    assert!(
        !alice_widget
            .markings
            .iter()
            .any(|marking| marking == "internal")
    );
    let alice_query = alice
        .capabilities
        .iter()
        .find(|entry| entry.name == "sekai.objects.query.widget")
        .expect("world-readable widget query stays visible");
    assert!(
        alice_query
            .object_type
            .as_ref()
            .unwrap()
            .properties
            .iter()
            .all(|property| property.name != "secret_note")
    );
    assert!(!format!("{alice:?}").contains("classified_widget"));
    assert!(!format!("{alice:?}").contains("secret_note"));

    let tester = discover_acme(&svc, "tester").await;
    assert!(
        tester
            .capabilities
            .iter()
            .any(|entry| entry.name == classified_action_name)
    );
    assert!(
        tester
            .capabilities
            .iter()
            .any(|entry| entry.name == "sekai.objects.query.classified_widget")
    );

    let local = discover_acme(&svc, "local").await;
    let local_secret = local
        .capabilities
        .iter()
        .find(|entry| entry.name == secret_action_name)
        .expect("restricted callers still see parameter schemas they may use");
    assert!(local_secret.parameter_schema_json.contains("secret_note"));
    let local_widget = local
        .capabilities
        .iter()
        .find(|entry| entry.name == widget_action)
        .unwrap();
    assert!(
        local_widget
            .markings
            .iter()
            .any(|marking| marking == "internal")
    );
    let local_query = local
        .capabilities
        .iter()
        .find(|entry| entry.name == "sekai.objects.query.widget")
        .unwrap();
    assert!(
        local_query
            .object_type
            .as_ref()
            .unwrap()
            .properties
            .iter()
            .any(|property| property.name == "secret_note")
    );
}

/// Real transport regression: client extensions cannot cross the wire.
#[cfg(unix)]
#[tokio::test]
async fn scoped_published_definition_read_crosses_the_server_transport() {
    use crate::identity_assertion::{
        AssertionAuthority, IDENTITY_ASSERTION_VERSION, IdentityAssertion,
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::service::Interceptor;
    for (local_mode, unix_mode) in [(false, false), (true, false), (false, true), (true, true)] {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(TestEnterpriseExtension)),
            )
            .unwrap(),
        )));
        let store = crate::db::store::SekaiStore::from_shared_runtime(db.clone());
        let svc = SekaiServiceImpl::new(store.clone());
        let revision = seed_definition_parent(&svc, "allowed");
        let authority = Arc::new(AssertionAuthority::new(
            "https://issuer.test",
            "https://sekai.test",
            b"synthetic-test-key",
        ));
        let credentials = Arc::new(crate::sekai::credentials::PrincipalCredentialStore::new());
        let mut token = crate::grpc::TokenAuthInterceptor::from_runtime(
            credentials.clone(),
            store,
            Some(authority.clone()),
        );
        let mut local =
            crate::grpc::local_or_token_interceptor(credentials, db, Some(authority.clone()));
        let interceptor = move |req| {
            if local_mode {
                local.call(req)
            } else {
                token.call(req)
            }
        };
        let service = crate::grpc::rpc_identity::RpcIdentityService::new(
            crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer::with_interceptor(
                svc,
                interceptor,
            ),
        );
        let socket_dir = tempfile::tempdir().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (server, channel) = if unix_mode {
            let socket = socket_dir.path().join("grpc.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let server = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming_shutdown(
                        tokio_stream::wrappers::UnixListenerStream::new(listener),
                        async {
                            let _ = stopped.await;
                        },
                    )
                    .await
                    .unwrap()
            });
            let channel = tonic::transport::Endpoint::from_static("http://localhost")
                .connect_with_connector(tower::service_fn(move |_| {
                    let socket = socket.clone();
                    async move {
                        tokio::net::UnixStream::connect(socket)
                            .await
                            .map(hyper_util::rt::TokioIo::new)
                    }
                }))
                .await
                .unwrap();
            (server, channel)
        } else {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap()
            });
            (
                server,
                tonic::transport::Endpoint::from_shared(endpoint)
                    .unwrap()
                    .connect()
                    .await
                    .unwrap(),
            )
        };
        let mut client =
            crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient::new(channel);
        let claims = |nonce: &str| IdentityAssertion {
            contract_version: IDENTITY_ASSERTION_VERSION.into(),
            issuer: "https://issuer.test".into(),
            audience: "https://sekai.test".into(),
            subject: "subject-a".into(),
            credential_id: "credential-a".into(),
            credential_kind: "human_session".into(),
            space: None,
            space_role: None,
            act: None,
            tenant_id: Some("tenant-test".into()),
            scopes: vec!["sekai.read".into()],
            expires_at: chrono::Utc::now().timestamp() + 30,
            nonce: nonce.into(),
        };
        let bearer = authority.sign(&claims("transport-read")).unwrap();
        let mut request = Request::new(GetPublishedDefinitionRevisionRequest {
            namespace: "allowed".into(),
        });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
        let response = client.get_published_definition_revision(request).await;
        assert_eq!(
            response
                .unwrap()
                .into_inner()
                .revision
                .unwrap()
                .revision_digest,
            revision.revision_digest
        );
        let read_request = |bearer: &str, namespace: &str| {
            let mut request = Request::new(GetPublishedDefinitionRevisionRequest {
                namespace: namespace.into(),
            });
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
            request
        };
        assert_eq!(
            client
                .get_published_definition_revision(read_request(&bearer, "allowed"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated,
            "replay"
        );
        let token = authority.sign(&claims("foreign-namespace")).unwrap();
        assert_eq!(
            client
                .get_published_definition_revision(read_request(&token, "foreign"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        for (nonce, audience, expiry) in [
            (
                "wrong-audience",
                "https://other.test",
                chrono::Utc::now().timestamp() + 30,
            ),
            (
                "expired",
                "https://sekai.test",
                chrono::Utc::now().timestamp() - 120,
            ),
        ] {
            let mut assertion = claims(nonce);
            assertion.audience = audience.into();
            assertion.expires_at = expiry;
            let token = authority.sign(&assertion).unwrap();
            assert_eq!(
                client
                    .get_published_definition_revision(read_request(&token, "allowed"))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Unauthenticated
            );
        }
        let token = authority.sign(&claims("disallowed-rpc")).unwrap();
        let mut request = Request::new(CloseDefinitionProposalRequest {
            namespace: "allowed".into(),
            proposal_id: "fixture".into(),
            ..Default::default()
        });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request.metadata_mut().insert(
            "x-rpc-method",
            "GetPublishedDefinitionRevision".parse().unwrap(),
        );
        assert_eq!(
            client
                .close_definition_proposal(request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        stop.send(()).unwrap();
        server.await.unwrap();
    }
}
/// Exact-revision document reads retain transport scopes, grants, and integrity checks.
#[tokio::test]
async fn agent_definition_member_read_crosses_server_transport() {
    use crate::identity_assertion::{
        AssertionAuthority, IDENTITY_ASSERTION_VERSION, IdentityAssertion,
    };
    use tower::Layer;
    let sqlite = Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(TestEnterpriseExtension)))
            .unwrap(),
    );
    let store = crate::db::store::SekaiStore::from_shared_runtime(Arc::new(RuntimeDb::Sqlite(
        sqlite.clone(),
    )));
    let svc = SekaiServiceImpl::new(store.clone());
    let parent = seed_definition_parent(&svc, "allowed");
    sqlite
        .create_definition_branch(
            &definition_branch_domain::CreateDefinitionBranch {
                namespace: "allowed".into(),
                branch_id: "agent-draft".into(),
                parent_revision_digest: parent.revision_digest.clone(),
                idempotency_key: "create".into(),
            },
            "author",
            2,
        )
        .unwrap();
    let agent = definition_branch_domain::DefinitionMemberInput {
        member_kind: "agent".into(), member_id: "triage".into(), member_digest: String::new(),
        definition_json: serde_json::json!({"contract_version":"sekai.agent-definition/v1","name":"Triage","task_class":"lookup","instructions":"Inspect records.","allowed_action_types":["Ticket.inspect"]}).to_string()
    };
    let definition_branch_domain::DefinitionWriteResult::ApplyEdit { result } = sqlite
        .apply_definition_branch_edit(
            &definition_branch_domain::ApplyDefinitionBranchEdit {
                namespace: "allowed".into(),
                branch_id: "agent-draft".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![agent.clone()],
                removals: Vec::new(),
                idempotency_key: "edit".into(),
            },
            "author",
            3,
        )
        .unwrap()
    else {
        panic!("expected draft")
    };
    let revision = result.revision.revision_digest.clone();
    let security = svc.security.clone();
    let authority = Arc::new(AssertionAuthority::new(
        "https://issuer.test",
        "https://sekai.test",
        b"synthetic-test-key",
    ));
    let interceptor = crate::grpc::TokenAuthInterceptor::from_runtime(
        Arc::new(crate::sekai::credentials::PrincipalCredentialStore::new()),
        store,
        Some(authority.clone()),
    );
    let service = crate::grpc::rpc_identity::RpcIdentityService::new(
        tonic::service::interceptor::InterceptedService::new(
            crate::rpc_maturity::RpcMaturityLayer::new(true)
                .layer(crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer::new(svc)),
            interceptor,
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stopped.await;
                },
            )
            .await
            .unwrap()
    });
    let mut client =
        crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient::connect(endpoint)
            .await
            .unwrap();
    let claims = || IdentityAssertion {
        contract_version: IDENTITY_ASSERTION_VERSION.into(),
        issuer: "https://issuer.test".into(),
        audience: "https://sekai.test".into(),
        subject: "subject-a".into(),
        credential_id: "credential-a".into(),
        credential_kind: "human_session".into(),
        space: None,
        space_role: None,
        act: None,
        tenant_id: Some("tenant-test".into()),
        scopes: vec!["sekai.read".into()],
        expires_at: chrono::Utc::now().timestamp() + 30,
        nonce: uuid::Uuid::new_v4().to_string(),
    };
    let request = |assertion: &IdentityAssertion, namespace: &str, digest: &str, id: &str| {
        let mut request = Request::new(GetDefinitionMemberRequest {
            namespace: namespace.into(),
            revision_digest: digest.into(),
            member_kind: "agent".into(),
            member_id: id.into(),
        });
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", authority.sign(assertion).unwrap())
                .parse()
                .unwrap(),
        );
        request
    };
    let assertion = claims();
    let response = client
        .get_definition_member(request(&assertion, "allowed", &revision, "triage"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.revision_digest, revision);
    let member = response.member.unwrap();
    assert_eq!(
        member.definition_json,
        agent.prepare("allowed").unwrap().definition_json
    );
    assert_eq!(
        member.member_digest,
        agent.prepare("allowed").unwrap().member_digest
    );
    assert_eq!(
        client
            .get_definition_member(request(&assertion, "allowed", &revision, "triage"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        client
            .get_definition_member(request(&claims(), "foreign", &revision, "triage"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let missing = client
        .get_definition_member(request(&claims(), "allowed", &revision, "absent"))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
    let mut no_scope = claims();
    no_scope.scopes.clear();
    assert_eq!(
        client
            .get_definition_member(request(&no_scope, "allowed", &revision, "triage"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut expired = claims();
    expired.expires_at -= 150;
    assert_eq!(
        client
            .get_definition_member(request(&expired, "allowed", &revision, "triage"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    let mut wrong_audience = claims();
    wrong_audience.audience = "https://other.test".into();
    assert_eq!(
        client
            .get_definition_member(request(&wrong_audience, "allowed", &revision, "triage"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        client
            .get_definition_member(request(&claims(), "allowed", "invalid", "triage"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    for (index, object_id) in ["schema:agent:triage", "schema:Ticket"]
        .into_iter()
        .enumerate()
    {
        let grant = security::Grant {
            id: format!("deny-{index}"),
            object_id: object_id.into(),
            principal: "other-reader".into(),
            role: security::Role::Viewer,
            created: 1,
            ..Default::default()
        };
        security.add_grant(&grant);
        let denied = client
            .get_definition_member(request(&claims(), "allowed", &revision, "triage"))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), missing.code());
        assert_eq!(denied.message(), missing.message());
        security.remove_grant(&grant.object_id, &grant.principal);
    }
    // Valid documents must still match their storage lookup identity.
    let original_body = serde_json::to_string(&result.revision).unwrap();
    for substituted in [
        parent.clone(),
        definition_branch_domain::prepare_revision("foreign", "", Vec::new(), false, "author", 4)
            .unwrap(),
    ] {
        let body = serde_json::to_string(&substituted).unwrap();
        sqlite
            .conn()
            .execute(
                "UPDATE sekai_definition_revisions SET body_json = ?1 WHERE namespace = 'allowed' AND revision_digest = ?2",
                [body.as_str(), revision.as_str()],
            )
            .unwrap();
        let corrupt = client
            .get_definition_member(request(&claims(), "allowed", &revision, "triage"))
            .await
            .unwrap_err();
        assert_eq!(corrupt.code(), tonic::Code::Internal);
        assert_eq!(corrupt.message(), "definition member unavailable");
    }
    sqlite
        .conn()
        .execute(
            "UPDATE sekai_definition_revisions SET body_json = ?1 WHERE namespace = 'allowed' AND revision_digest = ?2",
            [original_body.as_str(), revision.as_str()],
        )
        .unwrap();
    sqlite
        .conn()
        .execute(
            "UPDATE sekai_definition_members SET body_json = '{}' WHERE member_kind = 'agent'",
            [],
        )
        .unwrap();
    let corrupt = client
        .get_definition_member(request(&claims(), "allowed", &revision, "triage"))
        .await
        .unwrap_err();
    assert_eq!(corrupt.code(), tonic::Code::Internal);
    assert_eq!(corrupt.message(), "definition member unavailable");
    stop.send(()).unwrap();
    server.await.unwrap();
}

#[test]
fn agent_certification_refusal_has_public_precondition_status() {
    for reason in [
        "agent_promotion_requires_certification",
        "agent_promotion_certification_revoked",
        "agent_promotion_certification_stale",
        "agent_promotion_certification_failed",
    ] {
        let error = map_definition_write_error(reason.into());
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(error.message(), reason);
    }
}

#[tokio::test]
async fn definition_certification_gate_rpc_reports_bound_states() {
    let svc = service();
    let namespace = "definition-cert";
    let parent = seed_definition_parent(&svc, namespace);
    grant_source_namespace(&svc, namespace, "root", security::Role::Admin);
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-cert".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: "feature".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "agent".into(),
                    member_id: "triage".into(),
                    member_digest: String::new(),
                    definition_json: serde_json::json!({
                        "contract_version": "sekai.agent-definition/v1",
                        "name": "Triage",
                        "task_class": "lookup",
                        "instructions": "Inspect records.",
                        "allowed_action_types": ["Ticket.inspect"]
                    })
                    .to_string(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-agent".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let digest = applied.revision.unwrap().revision_digest;
    let missing = svc
        .get_definition_certification_gate(with_named_principal(
            GetDefinitionCertificationGateRequest {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(!missing.admitted);
    assert_eq!(missing.certification_status, "missing");
    assert_eq!(missing.refusal, "agent_promotion_requires_certification");
    grant_source_namespace(&svc, namespace, "reviewer", security::Role::Admin);
    for principal in ["root", "reviewer"] {
        svc.security.add_grant(&security::Grant {
            id: format!("{namespace}-{principal}-agent-admin"),
            object_id: "schema:agent:triage".into(),
            principal: principal.into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        });
    }
    seed_agent_eval_run(&svc, "agent-cert", "agent-suite", true);
    seed_agent_eval_run(&svc, "agent-cert-fail", "agent-suite", false);
    let expires = now_millis() + 86_400_000;
    let put = |cert_id: &str, baseline: &str, latest: &str, expires: i64, revoked: i64| {
        PutDefinitionCertificationRequest {
            namespace: namespace.into(),
            revision_digest: digest.clone(),
            suite_id: "agent-suite".into(),
            certification_id: cert_id.into(),
            baseline_status: baseline.into(),
            latest_status: latest.into(),
            expires_at_ms: expires,
            revoked_at_ms: revoked,
        }
    };
    let failed = svc
        .put_definition_certification(with_named_principal(
            put("agent-cert-fail", "fail", "fail", expires, 0),
            "reviewer",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(!failed.admitted);
    assert_eq!(failed.certification_status, "fail");
    assert_eq!(failed.refusal, "agent_promotion_certification_failed");
    let stale = svc
        .put_definition_certification(with_named_principal(
            put("agent-cert", "pass", "pass", 1, 0),
            "reviewer",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(!stale.admitted);
    assert_eq!(stale.certification_status, "stale");
    assert_eq!(stale.refusal, "agent_promotion_certification_stale");
    let admitted = svc
        .put_definition_certification(with_named_principal(
            put("agent-cert", "pass", "pass", expires, 0),
            "reviewer",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(admitted.admitted);
    assert_eq!(admitted.certification_status, "admitted");
    assert!(admitted.refusal.is_empty());
    // #1640: the published revision's scored certification (twice the
    // candidate's mean score of 100) turns the same binding into a regression.
    svc.db
        .runtime()
        .put_agent_definition_certification(
            &crate::sekai::agent_promotion::AgentDefinitionCertification {
                namespace: namespace.into(),
                revision_digest: parent.revision_digest.clone(),
                suite_id: "agent-suite".into(),
                certification_id: "agent-cert-published".into(),
                baseline_status: "pass".into(),
                latest_status: "pass".into(),
                expires_at_ms: expires,
                revoked_at_ms: 0,
                bound_by: "reviewer".into(),
                bound_at_ms: now_millis(),
                mean_score_milli: Some(200_000),
            },
        )
        .unwrap();
    let regressed = svc
        .put_definition_certification(with_named_principal(
            put("agent-cert", "pass", "pass", expires, 0),
            "reviewer",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(!regressed.admitted);
    assert_eq!(regressed.certification_status, "regressed");
    assert_eq!(regressed.refusal, "agent_promotion_eval_regression");
    let reported = svc
        .get_definition_certification_gate(with_named_principal(
            GetDefinitionCertificationGateRequest {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert_eq!(reported, regressed);
    let revoked = svc
        .put_definition_certification(with_named_principal(
            put("agent-cert", "pass", "pass", expires, 4),
            "reviewer",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(!revoked.admitted);
    assert_eq!(revoked.certification_status, "revoked");
    assert_eq!(revoked.refusal, "agent_promotion_certification_revoked");
    let reported = svc
        .get_definition_certification_gate(with_named_principal(
            GetDefinitionCertificationGateRequest {
                namespace: namespace.into(),
                revision_digest: digest,
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert_eq!(reported, revoked);
}

#[tokio::test]
async fn certification_gate_refuses_a_tool_that_changes_things_without_a_policy() {
    let svc = service();
    let namespace = "definition-tools";
    let parent = seed_definition_parent(&svc, namespace);
    grant_source_namespace(&svc, namespace, "root", security::Role::Admin);
    grant_source_namespace(&svc, namespace, "reviewer", security::Role::Admin);
    for principal in ["root", "reviewer"] {
        svc.security.add_grant(&security::Grant {
            id: format!("{namespace}-{principal}-agent-admin"),
            object_id: "schema:agent:triage".into(),
            principal: principal.into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        });
    }
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-tools".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let edit =
        |tools: serde_json::Value, expected: String, key: &str| ApplyDefinitionBranchEditRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            expected_head_digest: expected,
            upserts: vec![DefinitionMemberInput {
                member_kind: "agent".into(),
                member_id: "triage".into(),
                member_digest: String::new(),
                definition_json: serde_json::json!({
                    "contract_version": "sekai.agent-definition/v1",
                    "name": "Triage",
                    "task_class": "lookup",
                    "instructions": "Inspect records.",
                    "allowed_action_types": [],
                    "tools": tools
                })
                .to_string(),
            }],
            removals: Vec::new(),
            idempotency_key: key.into(),
        };
    let unapproved = svc
        .apply_definition_branch_edit(with_named_principal(
            edit(
                serde_json::json!([{"kind": "query", "name": "open_tickets"}, {"kind": "action", "name": "Ticket.close"}]),
                parent.revision_digest.clone(),
                "edit-unapproved",
            ),
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .revision_digest;
    seed_agent_eval_run(&svc, "tools-cert", "agent-suite", true);
    let expires = now_millis() + 86_400_000;
    let certify = |digest: &str| PutDefinitionCertificationRequest {
        namespace: namespace.into(),
        revision_digest: digest.into(),
        suite_id: "agent-suite".into(),
        certification_id: "tools-cert".into(),
        baseline_status: "pass".into(),
        latest_status: "pass".into(),
        expires_at_ms: expires,
        revoked_at_ms: 0,
    };
    svc.put_definition_certification(with_named_principal(certify(&unapproved), "reviewer"))
        .await
        .unwrap();
    let gate = |digest: String| GetDefinitionCertificationGateRequest {
        namespace: namespace.into(),
        revision_digest: digest,
    };
    let refused = svc
        .get_definition_certification_gate(with_named_principal(gate(unapproved.clone()), "root"))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(!refused.admitted);
    assert_eq!(refused.refusal, "agent_tool_approval_required:Ticket.close");
    let effects: Vec<(&str, &str, bool)> = refused
        .tools
        .iter()
        .map(|tool| {
            (
                tool.name.as_str(),
                tool.effect.as_str(),
                tool.blocks_publish,
            )
        })
        .collect();
    assert_eq!(
        effects,
        [
            ("open_tickets", "read", false),
            ("Ticket.close", "destructive", true)
        ],
        "the gate reports each tool's derived effect"
    );

    let approved = svc
        .apply_definition_branch_edit(with_named_principal(
            edit(
                serde_json::json!([{"kind": "query", "name": "open_tickets"}, {"kind": "action", "name": "Ticket.close", "approval_policy": "owner"}]),
                unapproved,
                "edit-approved",
            ),
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .revision_digest;
    svc.put_definition_certification(with_named_principal(certify(&approved), "reviewer"))
        .await
        .unwrap();
    let admitted = svc
        .get_definition_certification_gate(with_named_principal(gate(approved), "root"))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(admitted.admitted, "{}", admitted.refusal);
}

#[tokio::test]
async fn definition_certification_refuses_self_certify_revoke_undo_and_caller_statuses() {
    let svc = service();
    let namespace = "definition-cert-guard";
    let parent = seed_definition_parent(&svc, namespace);
    grant_source_namespace(&svc, namespace, "root", security::Role::Admin);
    grant_source_namespace(&svc, namespace, "reviewer", security::Role::Admin);
    for principal in ["root", "reviewer"] {
        svc.security.add_grant(&security::Grant {
            id: format!("{namespace}-{principal}-agent-admin"),
            object_id: "schema:agent:triage".into(),
            principal: principal.into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        });
    }
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-cert-guard".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: "feature".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "agent".into(),
                    member_id: "triage".into(),
                    member_digest: String::new(),
                    definition_json: serde_json::json!({
                        "contract_version": "sekai.agent-definition/v1",
                        "name": "Triage",
                        "task_class": "lookup",
                        "instructions": "Inspect records.",
                        "allowed_action_types": ["Ticket.inspect"]
                    })
                    .to_string(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-agent-guard".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let digest = applied.revision.unwrap().revision_digest;
    seed_agent_eval_run(&svc, "agent-cert", "agent-suite", true);
    let expires = now_millis() + 86_400_000;
    let put = |baseline: &str, latest: &str, expires: i64, revoked: i64, cert_id: &str| {
        PutDefinitionCertificationRequest {
            namespace: namespace.into(),
            revision_digest: digest.clone(),
            suite_id: "agent-suite".into(),
            certification_id: cert_id.into(),
            baseline_status: baseline.into(),
            latest_status: latest.into(),
            expires_at_ms: expires,
            revoked_at_ms: revoked,
        }
    };
    let self_certify = svc
        .put_definition_certification(with_named_principal(
            put("pass", "pass", expires, 0, "agent-cert"),
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(self_certify.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        self_certify.message(),
        "agent_promotion_self_certification_forbidden"
    );
    let hidden_author = svc
        .put_definition_certification(with_named_principal(
            put("pass", "pass", expires, 0, "agent-cert"),
            "reviewer,root",
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden_author.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        hidden_author.message(),
        "agent_promotion_self_certification_forbidden"
    );
    let missing_suite = svc
        .put_definition_certification(with_named_principal(
            put("pass", "pass", expires, 0, "missing-cert"),
            "reviewer",
        ))
        .await
        .unwrap_err();
    assert_eq!(missing_suite.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        missing_suite.message(),
        "agent_promotion_certification_suite_result_missing"
    );
    let caller_status = svc
        .put_definition_certification(with_named_principal(
            put("pass", "fail", expires, 0, "agent-cert"),
            "reviewer",
        ))
        .await
        .unwrap_err();
    assert_eq!(caller_status.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        caller_status.message(),
        "agent_promotion_certification_status_mismatch"
    );
    let forever = svc
        .put_definition_certification(with_named_principal(
            put("pass", "pass", i64::MAX, 0, "agent-cert"),
            "reviewer",
        ))
        .await
        .unwrap_err();
    assert_eq!(forever.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        forever.message(),
        "agent_promotion_certification_expiry_exceeds_ttl"
    );
    svc.put_definition_certification(with_named_principal(
        put("pass", "pass", expires, 4, "agent-cert"),
        "reviewer",
    ))
    .await
    .unwrap();
    let undo = svc
        .put_definition_certification(with_named_principal(
            put("pass", "pass", expires, 0, "agent-cert"),
            "reviewer",
        ))
        .await
        .unwrap_err();
    assert_eq!(undo.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        undo.message(),
        "agent_promotion_certification_revoke_is_final"
    );
}

#[tokio::test]
async fn definition_certification_refuses_author_after_unrelated_edit() {
    let svc = service();
    let namespace = "definition-cert-author-lineage";
    let parent = seed_definition_parent(&svc, namespace);
    grant_source_namespace(&svc, namespace, "root", security::Role::Admin);
    grant_source_namespace(&svc, namespace, "editor", security::Role::Admin);
    grant_source_namespace(&svc, namespace, "reviewer", security::Role::Admin);
    for principal in ["root", "editor", "reviewer"] {
        for object_id in ["schema:agent:triage", "schema:Ticket"] {
            svc.security.add_grant(&security::Grant {
                id: format!("{namespace}-{principal}-{object_id}"),
                object_id: object_id.into(),
                principal: principal.into(),
                role: security::Role::Admin,
                created: 1,
                ..Default::default()
            });
        }
    }
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-cert-author-lineage".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let agent_edit = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: "feature".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "agent".into(),
                    member_id: "triage".into(),
                    member_digest: String::new(),
                    definition_json: serde_json::json!({
                        "contract_version": "sekai.agent-definition/v1",
                        "name": "Triage",
                        "task_class": "lookup",
                        "instructions": "Inspect records.",
                        "allowed_action_types": ["Ticket.inspect"]
                    })
                    .to_string(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-agent-author-lineage".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let unrelated = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: "feature".into(),
                expected_head_digest: agent_edit.revision.unwrap().revision_digest,
                upserts: vec![DefinitionMemberInput {
                    member_kind: "object_type".into(),
                    member_id: "Ticket".into(),
                    member_digest: String::new(),
                    definition_json: r#"{"name":"Ticket","title":"Queue"}"#.into(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-ticket-author-lineage".into(),
            },
            "editor",
        ))
        .await
        .unwrap()
        .into_inner();
    let digest = unrelated.revision.unwrap().revision_digest;
    seed_agent_eval_run(&svc, "agent-cert", "agent-suite", true);
    let expires = now_millis() + 86_400_000;
    let put = PutDefinitionCertificationRequest {
        namespace: namespace.into(),
        revision_digest: digest.clone(),
        suite_id: "agent-suite".into(),
        certification_id: "agent-cert".into(),
        baseline_status: "pass".into(),
        latest_status: "pass".into(),
        expires_at_ms: expires,
        revoked_at_ms: 0,
    };
    let self_certify = svc
        .put_definition_certification(with_named_principal(put.clone(), "root"))
        .await
        .unwrap_err();
    assert_eq!(self_certify.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        self_certify.message(),
        "agent_promotion_self_certification_forbidden"
    );
    let admitted = svc
        .put_definition_certification(with_named_principal(put, "reviewer"))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(admitted.admitted);
}

#[tokio::test]
async fn definition_certification_revokes_when_the_suite_run_is_gone() {
    let svc = service();
    let namespace = "definition-cert-revoke-missing-suite";
    let parent = seed_definition_parent(&svc, namespace);
    grant_source_namespace(&svc, namespace, "root", security::Role::Admin);
    grant_source_namespace(&svc, namespace, "reviewer", security::Role::Admin);
    for principal in ["root", "reviewer"] {
        svc.security.add_grant(&security::Grant {
            id: format!("{namespace}-{principal}-agent-admin"),
            object_id: "schema:agent:triage".into(),
            principal: principal.into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        });
    }
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-cert-revoke-missing".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let applied = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: "feature".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "agent".into(),
                    member_id: "triage".into(),
                    member_digest: String::new(),
                    definition_json: serde_json::json!({
                        "contract_version": "sekai.agent-definition/v1",
                        "name": "Triage",
                        "task_class": "lookup",
                        "instructions": "Inspect records.",
                        "allowed_action_types": ["Ticket.inspect"]
                    })
                    .to_string(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-agent-revoke-missing".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let digest = applied.revision.unwrap().revision_digest;
    let expires = now_millis() + 86_400_000;
    svc.db
        .runtime()
        .put_agent_definition_certification(
            &crate::sekai::agent_promotion::AgentDefinitionCertification {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
                suite_id: "agent-suite".into(),
                certification_id: "missing-run".into(),
                baseline_status: crate::sekai::agent_promotion::STATUS_PASS.into(),
                latest_status: crate::sekai::agent_promotion::STATUS_PASS.into(),
                expires_at_ms: expires,
                revoked_at_ms: 0,
                bound_by: "reviewer".into(),
                bound_at_ms: now_millis(),
                mean_score_milli: None,
            },
        )
        .unwrap();
    let revoked = svc
        .put_definition_certification(with_named_principal(
            PutDefinitionCertificationRequest {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
                suite_id: "agent-suite".into(),
                certification_id: "missing-run".into(),
                baseline_status: crate::sekai::agent_promotion::STATUS_PASS.into(),
                latest_status: crate::sekai::agent_promotion::STATUS_PASS.into(),
                expires_at_ms: expires,
                revoked_at_ms: 4,
            },
            "reviewer",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert!(!revoked.admitted);
    assert_eq!(revoked.certification_status, "revoked");
    assert_eq!(revoked.refusal, "agent_promotion_certification_revoked");
}

/// Scoped draft transport retains store retry/conflict authority and never admits promotion.
#[tokio::test]
async fn scoped_definition_draft_authoring_crosses_server_transport() {
    use crate::identity_assertion::{
        AssertionAuthority, IDENTITY_ASSERTION_VERSION, IdentityAssertion,
    };
    use tower::Layer;
    fn signed<T>(
        authority: &AssertionAuthority,
        claims: &IdentityAssertion,
        body: T,
    ) -> Request<T> {
        let mut request = Request::new(body);
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", authority.sign(claims).unwrap())
                .parse()
                .unwrap(),
        );
        request
    }
    let sqlite = Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(TestEnterpriseExtension)))
            .unwrap(),
    );
    let store = crate::db::store::SekaiStore::from_shared_runtime(Arc::new(RuntimeDb::Sqlite(
        sqlite.clone(),
    )));
    let svc = SekaiServiceImpl::new(store.clone());
    let parent = seed_definition_parent(&svc, "allowed");
    let security = svc.security.clone();
    let authority = Arc::new(AssertionAuthority::new(
        "https://issuer.test",
        "https://sekai.test",
        b"synthetic-draft-test-key",
    ));
    let interceptor = crate::grpc::TokenAuthInterceptor::from_runtime(
        Arc::new(crate::sekai::credentials::PrincipalCredentialStore::new()),
        store,
        Some(authority.clone()),
    );
    let service = crate::grpc::rpc_identity::RpcIdentityService::new(
        tonic::service::interceptor::InterceptedService::new(
            crate::rpc_maturity::RpcMaturityLayer::new(true)
                .layer(crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer::new(svc)),
            interceptor,
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stopped.await;
                },
            )
            .await
            .unwrap();
    });
    let mut client =
        crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient::connect(endpoint)
            .await
            .unwrap();
    let assertion = |subject: &str| IdentityAssertion {
        contract_version: IDENTITY_ASSERTION_VERSION.into(),
        issuer: "https://issuer.test".into(),
        audience: "https://sekai.test".into(),
        subject: subject.into(),
        credential_id: "credential-a".into(),
        credential_kind: "human_session".into(),
        space: None,
        space_role: None,
        act: None,
        tenant_id: Some("tenant-test".into()),
        scopes: vec!["sekai.read".into(), "sekai.write".into()],
        expires_at: chrono::Utc::now().timestamp() + 30,
        nonce: uuid::Uuid::new_v4().to_string(),
    };
    let claims = || assertion("subject-a");
    let reviewer = || assertion("reviewer");
    let create = CreateDefinitionBranchRequest {
        namespace: "allowed".into(),
        branch_id: "agent-save".into(),
        parent_revision_digest: parent.revision_digest.clone(),
        idempotency_key: "create-agent-save".into(),
    };
    let mut read_only = claims();
    read_only.scopes = vec!["sekai.read".into()];
    assert_eq!(
        client
            .create_definition_branch(signed(&authority, &read_only, create.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut foreign = create.clone();
    foreign.namespace = "foreign".into();
    assert_eq!(
        client
            .create_definition_branch(signed(&authority, &claims(), foreign))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    for (audience, expiry) in [
        ("https://other.test", chrono::Utc::now().timestamp() + 30),
        ("https://sekai.test", chrono::Utc::now().timestamp() - 120),
    ] {
        let mut invalid = claims();
        invalid.audience = audience.into();
        invalid.expires_at = expiry;
        assert_eq!(
            client
                .create_definition_branch(signed(&authority, &invalid, create.clone()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }
    let first_claims = claims();
    let first = client
        .create_definition_branch(signed(&authority, &first_claims, create.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.branch.as_ref().unwrap().created_by, "subject-a");
    assert_eq!(
        client
            .create_definition_branch(signed(&authority, &first_claims, create.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        first,
        client
            .create_definition_branch(signed(&authority, &claims(), create.clone()))
            .await
            .unwrap()
            .into_inner()
    );
    let mut changed_create = create.clone();
    changed_create.branch_id = "another-branch".into();
    assert_eq!(
        client
            .create_definition_branch(signed(&authority, &claims(), changed_create))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::AlreadyExists
    );
    let agent = DefinitionMemberInput { member_kind: "agent".into(), member_id: "triage".into(), member_digest: String::new(), definition_json: serde_json::json!({"contract_version":"sekai.agent-definition/v1","name":"Triage","task_class":"lookup","instructions":"Inspect records.","allowed_action_types":[]}).to_string() };
    let edit = ApplyDefinitionBranchEditRequest {
        namespace: "allowed".into(),
        branch_id: create.branch_id.clone(),
        expected_head_digest: parent.revision_digest.clone(),
        upserts: vec![agent.clone()],
        removals: vec![],
        idempotency_key: "save-agent-1".into(),
    };
    read_only.nonce = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        client
            .apply_definition_branch_edit(signed(&authority, &read_only, edit.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    for object_id in ["namespace:allowed", "schema:agent:triage", "schema:Ticket"] {
        let grant = security::Grant {
            id: uuid::Uuid::new_v4().to_string(),
            object_id: object_id.into(),
            principal: "other-author".into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        };
        security.add_grant(&grant);
        let denied = client
            .apply_definition_branch_edit(signed(&authority, &claims(), edit.clone()))
            .await
            .unwrap_err();
        assert!(
            matches!(
                denied.code(),
                tonic::Code::PermissionDenied | tonic::Code::NotFound
            ),
            "{denied}"
        );
        security.remove_grant(object_id, "other-author");
    }
    security.add_grant(&security::Grant {
        id: "author-agent-admin".into(),
        object_id: "schema:agent:triage".into(),
        principal: "subject-a".into(),
        role: security::Role::Admin,
        created: 1,
        ..Default::default()
    });
    let saved = client
        .apply_definition_branch_edit(signed(&authority, &claims(), edit.clone()))
        .await
        .unwrap()
        .into_inner();
    let revision = saved.revision.as_ref().unwrap();
    assert!(!revision.published);
    assert_eq!(revision.created_by, "subject-a");
    assert_eq!(saved.previous_head_digest, parent.revision_digest);
    assert_eq!(
        saved,
        client
            .apply_definition_branch_edit(signed(&authority, &claims(), edit.clone()))
            .await
            .unwrap()
            .into_inner()
    );
    let mut changed = edit.clone();
    changed.upserts[0].definition_json = agent
        .definition_json
        .replace("Inspect records.", "Inspect updated records.");
    assert_eq!(
        client
            .apply_definition_branch_edit(signed(&authority, &claims(), changed.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::AlreadyExists
    );
    changed.idempotency_key = "stale-edit".into();
    assert_eq!(
        client
            .apply_definition_branch_edit(signed(&authority, &claims(), changed.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let get = GetDefinitionBranchRequest {
        namespace: "allowed".into(),
        branch_id: create.branch_id.clone(),
    };
    let head = client
        .get_definition_branch(signed(&authority, &claims(), get))
        .await
        .unwrap()
        .into_inner()
        .branch
        .unwrap();
    assert_eq!(head.head_revision_digest, revision.revision_digest);
    changed.expected_head_digest = head.head_revision_digest.clone();
    changed.idempotency_key = "save-agent-2".into();
    let second = client
        .apply_definition_branch_edit(signed(&authority, &claims(), changed))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(
        second.revision.unwrap().revision_digest,
        revision.revision_digest
    );
    assert_eq!(
        saved,
        client
            .apply_definition_branch_edit(signed(&authority, &claims(), edit))
            .await
            .unwrap()
            .into_inner(),
        "an old retry returns its receipt even after the head advances"
    );
    let historical = client
        .get_definition_member(signed(
            &authority,
            &claims(),
            GetDefinitionMemberRequest {
                namespace: "allowed".into(),
                revision_digest: revision.revision_digest.clone(),
                member_kind: "agent".into(),
                member_id: "triage".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .member
        .unwrap();
    assert!(historical.definition_json.contains("Inspect records."));
    assert_eq!(
        sqlite
            .get_published_definition_revision("allowed")
            .unwrap()
            .unwrap()
            .revision_digest,
        parent.revision_digest
    );
    // ADR 0111: the scoped author publishes through a proposal under the
    // same grants and the ADR 0079 certification gate.
    let candidate = head.head_revision_digest.clone();
    let head = client
        .get_definition_branch(signed(
            &authority,
            &claims(),
            GetDefinitionBranchRequest {
                namespace: "allowed".into(),
                branch_id: create.branch_id.clone(),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .branch
        .unwrap()
        .head_revision_digest;
    assert_ne!(head, candidate, "the second save moved the head");
    let propose = CreateDefinitionProposalRequest {
        namespace: "allowed".into(),
        branch_id: create.branch_id.clone(),
        proposal_id: "publish-triage".into(),
        base_digest: parent.revision_digest.clone(),
        candidate_digest: head.clone(),
        eval_plan_digests: vec![],
        named_foreign_digests: vec![],
        idempotency_key: "publish-proposal".into(),
        major_revision: false,
    };
    read_only.nonce = uuid::Uuid::new_v4().to_string();
    let mut foreign_proposal = propose.clone();
    foreign_proposal.namespace = "foreign".into();
    let mut ungranted = claims();
    ungranted.subject = "subject-b".into();
    for (claims, request) in [
        (read_only.clone(), propose.clone()),
        (claims(), foreign_proposal),
        (ungranted, propose.clone()),
    ] {
        let denied = client
            .create_definition_proposal(signed(&authority, &claims, request))
            .await
            .unwrap_err();
        assert!(
            matches!(
                denied.code(),
                tonic::Code::PermissionDenied | tonic::Code::NotFound
            ),
            "{denied}"
        );
    }
    let opened = client
        .create_definition_proposal(signed(&authority, &claims(), propose))
        .await
        .unwrap()
        .into_inner()
        .proposal
        .unwrap();
    assert_eq!(
        (opened.status.as_str(), opened.created_by.as_str()),
        ("open", "subject-a")
    );
    let fetched = client
        .get_definition_proposal(signed(
            &authority,
            &claims(),
            GetDefinitionProposalRequest {
                namespace: "allowed".into(),
                proposal_id: "publish-triage".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .proposal
        .unwrap();
    assert_eq!(fetched, opened);
    let self_approve = client
        .approve_definition_proposal(signed(
            &authority,
            &claims(),
            ApproveDefinitionProposalRequest {
                namespace: "allowed".into(),
                proposal_id: "publish-triage".into(),
                idempotency_key: "publish-approve-self".into(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(self_approve.code(), tonic::Code::PermissionDenied);
    assert_eq!(self_approve.message(), "proposal creator cannot approve");
    security.add_grant(&security::Grant {
        id: "reviewer-agent-admin".into(),
        object_id: "schema:agent:triage".into(),
        principal: "reviewer".into(),
        role: security::Role::Admin,
        created: 1,
        ..Default::default()
    });
    let approved = client
        .approve_definition_proposal(signed(
            &authority,
            &reviewer(),
            ApproveDefinitionProposalRequest {
                namespace: "allowed".into(),
                proposal_id: "publish-triage".into(),
                idempotency_key: "publish-approve".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .proposal
        .unwrap();
    assert_eq!(approved.approvals[0].actor, "reviewer");
    // Administering the changed member is not enough: approve and merge also
    // need read access to every member of both revisions.
    security.add_grant(&security::Grant {
        id: "reader-c-agent-admin".into(),
        object_id: "schema:agent:triage".into(),
        principal: "subject-c".into(),
        role: security::Role::Admin,
        created: 1,
        ..Default::default()
    });
    security.add_grant(&security::Grant {
        id: "ticket-restricted".into(),
        object_id: "schema:Ticket".into(),
        principal: "subject-a".into(),
        role: security::Role::Admin,
        created: 1,
        ..Default::default()
    });
    let mut unreadable = claims();
    unreadable.subject = "subject-c".into();
    let approve_denied = client
        .approve_definition_proposal(signed(
            &authority,
            &unreadable,
            ApproveDefinitionProposalRequest {
                namespace: "allowed".into(),
                proposal_id: "publish-triage".into(),
                idempotency_key: "approve-unreadable".into(),
            },
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(
            approve_denied.code(),
            tonic::Code::PermissionDenied | tonic::Code::NotFound
        ),
        "{approve_denied}"
    );
    unreadable.nonce = uuid::Uuid::new_v4().to_string();
    let merge_denied = client
        .merge_definition_proposal(signed(
            &authority,
            &unreadable,
            MergeDefinitionProposalRequest {
                namespace: "allowed".into(),
                proposal_id: "publish-triage".into(),
                idempotency_key: "merge-unreadable".into(),
                expected_published_digest: parent.revision_digest.clone(),
            },
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(
            merge_denied.code(),
            tonic::Code::PermissionDenied | tonic::Code::NotFound
        ),
        "{merge_denied}"
    );
    security.remove_grant("schema:Ticket", "subject-a");
    security.remove_grant("schema:agent:triage", "subject-c");
    let merge = |key: &str| MergeDefinitionProposalRequest {
        namespace: "allowed".into(),
        proposal_id: "publish-triage".into(),
        idempotency_key: key.into(),
        expected_published_digest: parent.revision_digest.clone(),
    };
    let refused = client
        .merge_definition_proposal(signed(
            &authority,
            &reviewer(),
            merge("publish-uncertified"),
        ))
        .await
        .unwrap_err();
    assert_eq!(
        (refused.code(), refused.message()),
        (
            tonic::Code::FailedPrecondition,
            "agent_promotion_requires_certification"
        )
    );
    sqlite
        .put_agent_definition_certification(
            &crate::sekai::agent_promotion::AgentDefinitionCertification {
                namespace: "allowed".into(),
                revision_digest: head.clone(),
                suite_id: "triage-suite".into(),
                certification_id: "triage-cert".into(),
                baseline_status: "pass".into(),
                latest_status: "pass".into(),
                expires_at_ms: chrono::Utc::now().timestamp_millis() + 30 * 86_400_000,
                revoked_at_ms: 0,
                bound_by: "reviewer".into(),
                bound_at_ms: chrono::Utc::now().timestamp_millis(),
                mean_score_milli: None,
            },
        )
        .unwrap();
    let merged = client
        .merge_definition_proposal(signed(&authority, &reviewer(), merge("publish-merge")))
        .await
        .unwrap()
        .into_inner();
    assert!(!merged.receipt_id.is_empty());
    assert_eq!(merged.previous_published_digest, parent.revision_digest);
    let published = merged.published_revision.clone().unwrap();
    assert!(published.published);
    assert_eq!(
        merged,
        client
            .merge_definition_proposal(signed(&authority, &reviewer(), merge("publish-merge")))
            .await
            .unwrap()
            .into_inner(),
        "a replayed merge returns the same receipt"
    );
    assert_eq!(
        sqlite
            .get_published_definition_revision("allowed")
            .unwrap()
            .unwrap()
            .revision_digest,
        published.revision_digest
    );
    // Close stays unadmitted, even behind a spoofed method header.
    let mut close = signed(
        &authority,
        &claims(),
        CloseDefinitionProposalRequest {
            namespace: "allowed".into(),
            ..Default::default()
        },
    );
    close
        .metadata_mut()
        .insert("x-rpc-method", "CreateDefinitionProposal".parse().unwrap());
    assert_eq!(
        client
            .close_definition_proposal(close)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    for method in [
        "GetDefinitionBranch",
        "CreateDefinitionBranch",
        "ApplyDefinitionBranchEdit",
    ] {
        assert!(crate::rpc_maturity::require_invokable(method, false).is_err());
    }
    stop.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn scoped_transform_preview_and_reads_cross_server_transport() {
    use crate::identity_assertion::{
        AssertionAuthority, IDENTITY_ASSERTION_VERSION, IdentityAssertion,
    };
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{ANALYTICAL_CLASS, CONTRACT_VERSION};
    use tower::Layer;
    let sqlite = Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(TestEnterpriseExtension)))
            .unwrap(),
    );
    let runtime = Arc::new(RuntimeDb::Sqlite(sqlite));
    let store = crate::db::store::SekaiStore::from_shared_runtime(runtime.clone());
    for id in ["scoped-in", "scoped-out"] {
        runtime
            .create_dataset(&Dataset {
                id: id.into(),
                name: id.into(),
                columns: vec![ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
    }
    runtime
        .append_rows("scoped-in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    // A run in a namespace the tenant cannot read.
    let foreign_transform = crate::sekai::governed_transform::GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "foreign".into(),
        transform_id: "foreign-t".into(),
        input_dataset_id: "scoped-in".into(),
        output_dataset_id: "scoped-out".into(),
        steps: vec![crate::sekai::governed_transform::TransformStep {
            kind: "project".into(),
            column: String::new(),
            op: String::new(),
            value: String::new(),
            columns: vec!["id".into()],
        }],
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: None,
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    runtime
        .put_governed_transform(&foreign_transform, 10)
        .unwrap();
    let foreign_run = runtime
        .run_governed_transform("foreign", "foreign-t", false, 20)
        .unwrap()
        .run_id;
    let authority = Arc::new(AssertionAuthority::new(
        "https://issuer.test",
        "https://sekai.test",
        b"synthetic-transform-test-key",
    ));
    let interceptor = crate::grpc::TokenAuthInterceptor::from_runtime(
        Arc::new(crate::sekai::credentials::PrincipalCredentialStore::new()),
        store.clone(),
        Some(authority.clone()),
    );
    let service = crate::grpc::rpc_identity::RpcIdentityService::new(
        tonic::service::interceptor::InterceptedService::new(
            crate::rpc_maturity::RpcMaturityLayer::new(true).layer(
                crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer::new(
                    SekaiServiceImpl::new(store),
                ),
            ),
            interceptor,
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stopped.await;
                },
            )
            .await
            .unwrap();
    });
    let mut client =
        crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient::connect(endpoint)
            .await
            .unwrap();
    /// A tenant session with `scopes`.
    fn scoped<T>(authority: &AssertionAuthority, scopes: &[&str], body: T) -> Request<T> {
        let claims = IdentityAssertion {
            contract_version: IDENTITY_ASSERTION_VERSION.into(),
            issuer: "https://issuer.test".into(),
            audience: "https://sekai.test".into(),
            subject: "subject-a".into(),
            credential_id: "credential-a".into(),
            credential_kind: "human_session".into(),
            space: None,
            space_role: None,
            act: None,
            tenant_id: Some("tenant-test".into()),
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            expires_at: chrono::Utc::now().timestamp() + 30,
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        let mut request = Request::new(body);
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", authority.sign(&claims).unwrap())
                .parse()
                .unwrap(),
        );
        request
    }
    // Every admitted RPC here is a read; a read-only session suffices.
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "allowed".into(),
        transform_id: "scoped-preview".into(),
        input_dataset_id: "scoped-in".into(),
        output_dataset_id: "scoped-out".into(),
        profile: ANALYTICAL_CLASS.into(),
        sql: "SELECT id FROM input".into(),
        ..GovernedTransform::default()
    };
    let preview = client
        .preview_governed_transform(scoped(
            &authority,
            &["sekai.read"],
            PreviewGovernedTransformRequest {
                transform: Some(transform.clone()),
                row_cap: 0,
                preview_id: String::new(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(preview.inputs[0].rows_read, 1, "{}", preview.error);
    assert_eq!(preview.rows.len(), 1);
    let listed = client
        .list_governed_transforms(scoped(
            &authority,
            &["sekai.read"],
            ListGovernedTransformsRequest {
                namespace: "allowed".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(
        listed.transforms.is_empty(),
        "preview never puts a definition"
    );
    let runs = client
        .list_governed_transform_runs(scoped(
            &authority,
            &["sekai.read"],
            ListGovernedTransformRunsRequest {
                namespace: "allowed".into(),
                limit: 10,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(runs.runs.is_empty(), "preview never records a run");
    // Admitted past the interceptor; a preview identity is not a run.
    let run = client
        .get_governed_transform_run(scoped(
            &authority,
            &["sekai.read"],
            GetGovernedTransformRunRequest {
                run_id: preview.preview_id,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(run.code(), tonic::Code::NotFound);
    // Another tenant's namespace is refused for every admitted read.
    let foreign_list = client
        .list_governed_transforms(scoped(
            &authority,
            &["sekai.read"],
            ListGovernedTransformsRequest {
                namespace: "foreign".into(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(foreign_list.code(), tonic::Code::PermissionDenied);
    let foreign_runs = client
        .list_governed_transform_runs(scoped(
            &authority,
            &["sekai.read"],
            ListGovernedTransformRunsRequest {
                namespace: "foreign".into(),
                limit: 10,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(foreign_runs.code(), tonic::Code::PermissionDenied);
    let hidden_run = client
        .get_governed_transform_run(scoped(
            &authority,
            &["sekai.read"],
            GetGovernedTransformRunRequest {
                run_id: foreign_run,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden_run.code(), tonic::Code::NotFound, "{hidden_run:?}");
    let mut foreign = transform.clone();
    foreign.namespace = "foreign".into();
    let foreign = client
        .preview_governed_transform(scoped(
            &authority,
            &["sekai.read"],
            PreviewGovernedTransformRequest {
                transform: Some(foreign),
                row_cap: 0,
                preview_id: String::new(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), tonic::Code::PermissionDenied);
    let put = client
        .put_governed_transform(scoped(
            &authority,
            &["sekai.read", "sekai.write"],
            PutGovernedTransformRequest {
                transform: Some(transform.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(put.transform.unwrap().transform_id, "scoped-preview");
    let run = client
        .run_governed_transform(scoped(
            &authority,
            &["sekai.read", "sekai.write"],
            RunGovernedTransformRequest {
                namespace: "allowed".into(),
                transform_id: "scoped-preview".into(),
                incremental: false,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(
        (run.code(), run.message()),
        (
            tonic::Code::PermissionDenied,
            "RPC is not available to enterprise-scoped credentials"
        )
    );
    stop.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn scoped_put_governed_transform_requires_namespace_write_and_readable_datasets() {
    use crate::identity_assertion::{
        AssertionAuthority, IDENTITY_ASSERTION_VERSION, IdentityAssertion,
    };
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{ANALYTICAL_CLASS, CONTRACT_VERSION};
    use tower::Layer;
    let sqlite = Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(Arc::new(TestEnterpriseExtension)))
            .unwrap(),
    );
    let runtime = Arc::new(RuntimeDb::Sqlite(sqlite));
    let store = crate::db::store::SekaiStore::from_shared_runtime(runtime.clone());
    for id in ["scoped-in", "scoped-out", "hidden-in"] {
        runtime
            .create_dataset(&Dataset {
                id: id.into(),
                name: id.into(),
                columns: vec![ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: if id == "hidden-in" {
                    "hidden-object".into()
                } else {
                    String::new()
                },
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
    }
    runtime
        .create_object(&crate::domain::Object {
            id: "hidden-object".into(),
            kind: "widget".into(),
            name: "hidden-object".into(),
            namespace: "foreign".into(),
            external_id: "widget:hidden-object".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let authority = Arc::new(AssertionAuthority::new(
        "https://issuer.test",
        "https://sekai.test",
        b"synthetic-transform-put-test-key",
    ));
    let interceptor = crate::grpc::TokenAuthInterceptor::from_runtime(
        Arc::new(crate::sekai::credentials::PrincipalCredentialStore::new()),
        store.clone(),
        Some(authority.clone()),
    );
    let service = crate::grpc::rpc_identity::RpcIdentityService::new(
        tonic::service::interceptor::InterceptedService::new(
            crate::rpc_maturity::RpcMaturityLayer::new(true).layer(
                crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer::new(
                    SekaiServiceImpl::new(store),
                ),
            ),
            interceptor,
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stopped.await;
                },
            )
            .await
            .unwrap();
    });
    let mut client =
        crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient::connect(endpoint)
            .await
            .unwrap();
    fn scoped<T>(authority: &AssertionAuthority, scopes: &[&str], body: T) -> Request<T> {
        let claims = IdentityAssertion {
            contract_version: IDENTITY_ASSERTION_VERSION.into(),
            issuer: "https://issuer.test".into(),
            audience: "https://sekai.test".into(),
            subject: "subject-a".into(),
            credential_id: "credential-a".into(),
            credential_kind: "human_session".into(),
            space: None,
            space_role: None,
            act: None,
            tenant_id: Some("tenant-test".into()),
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            expires_at: chrono::Utc::now().timestamp() + 30,
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        let mut request = Request::new(body);
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", authority.sign(&claims).unwrap())
                .parse()
                .unwrap(),
        );
        request
    }
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "allowed".into(),
        transform_id: "scoped-put".into(),
        input_dataset_id: "scoped-in".into(),
        output_dataset_id: "scoped-out".into(),
        profile: ANALYTICAL_CLASS.into(),
        sql: "SELECT id FROM input".into(),
        ..GovernedTransform::default()
    };
    let put = client
        .put_governed_transform(scoped(
            &authority,
            &["sekai.read", "sekai.write"],
            PutGovernedTransformRequest {
                transform: Some(transform.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(put.transform.unwrap().transform_id, "scoped-put");
    let listed = client
        .list_governed_transforms(scoped(
            &authority,
            &["sekai.read"],
            ListGovernedTransformsRequest {
                namespace: "allowed".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.transforms.len(), 1);
    let read_only = client
        .put_governed_transform(scoped(
            &authority,
            &["sekai.read"],
            PutGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    transform_id: "scoped-put-ro".into(),
                    ..transform.clone()
                }),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(read_only.code(), tonic::Code::PermissionDenied);
    let mut foreign = transform.clone();
    foreign.namespace = "foreign".into();
    foreign.transform_id = "scoped-put-foreign".into();
    let foreign = client
        .put_governed_transform(scoped(
            &authority,
            &["sekai.read", "sekai.write"],
            PutGovernedTransformRequest {
                transform: Some(foreign),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), tonic::Code::PermissionDenied);
    let hidden = client
        .put_governed_transform(scoped(
            &authority,
            &["sekai.read", "sekai.write"],
            PutGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    transform_id: "scoped-put-hidden".into(),
                    input_dataset_id: "hidden-in".into(),
                    ..transform.clone()
                }),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(hidden.code(), tonic::Code::PermissionDenied);
    let scheduled = client
        .put_governed_transform(scoped(
            &authority,
            &["sekai.read", "sekai.write"],
            PutGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    transform_id: "scoped-put-scheduled".into(),
                    schedule_every_ms: 60_000,
                    ..transform.clone()
                }),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(
        (scheduled.code(), scheduled.message()),
        (
            tonic::Code::PermissionDenied,
            "scoped put cannot schedule or trigger execution"
        )
    );
    stop.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn community_put_governed_transform_still_requires_credential_admin() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::CONTRACT_VERSION;
    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    let request = PutGovernedTransformRequest {
        transform: Some(GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "community-put".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: vec![TransformStep {
                kind: "project".into(),
                columns: vec!["id".into()],
                ..Default::default()
            }],
            ..Default::default()
        }),
    };
    let denied = svc
        .put_governed_transform(with_principal(request.clone()))
        .await
        .unwrap_err();
    assert_eq!(
        (denied.code(), denied.message()),
        (tonic::Code::PermissionDenied, "credential admin required")
    );
    svc.put_governed_transform(with_named_principal(request, "local"))
        .await
        .unwrap();
}

#[tokio::test]
async fn community_human_session_put_still_requires_credential_admin() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::CONTRACT_VERSION;
    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    let mut req = with_principal(PutGovernedTransformRequest {
        transform: Some(GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "community-session-put".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: vec![TransformStep {
                kind: "project".into(),
                columns: vec!["id".into()],
                ..Default::default()
            }],
            ..Default::default()
        }),
    });
    req.extensions_mut()
        .insert(crate::enterprise::AuthenticatedContext {
            contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
            home_tenant: None,
            principal: crate::enterprise::AuthenticatedPrincipal {
                subject: "subject-a".into(),
                credential_id: "credential-a".into(),
            },
            credential_kind: crate::enterprise::CredentialKind::HumanSession,
            space: None,
            space_role: None,
            act: None,
            tenant: None,
            scopes: vec!["sekai.read".into(), "sekai.write".into()],
            issuer: "https://issuer.test".into(),
            resource: "https://sekai.test".into(),
            expires_at: 100,
        });
    let denied = svc.put_governed_transform(req).await.unwrap_err();
    assert_eq!(
        (denied.code(), denied.message()),
        (tonic::Code::PermissionDenied, "credential admin required")
    );
}

#[tokio::test]
async fn legacy_pipeline_round_trips_through_create_and_list() {
    use prost::Message;
    let svc = service();
    // filter/customer, encoded by the old flat PipelineStep schema.
    let bytes = b"\x0a\x06filter\x12\x08customer";
    let step = PipelineStep::decode(bytes.as_slice()).unwrap();
    let created = svc
        .create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "legacy-filter".into(),
                pipeline: vec![step],
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .function
        .unwrap();
    let projected = &created.pipeline[0];
    assert_eq!(projected.op, "filter");
    assert_eq!(projected.kind, "customer");
    assert!(matches!(
        projected.step,
        Some(pipeline_step::Step::Operator(_))
    ));
    svc.create_function(with_principal(CreateFunctionRequest {
        function: Some(Function {
            name: "legacy-round-trip".into(),
            ..created.clone()
        }),
    }))
    .await
    .unwrap();
    let listed = svc
        .list_functions(with_principal(ListFunctionsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        listed
            .functions
            .iter()
            .find(|f| f.name == created.name)
            .unwrap()
            .pipeline,
        created.pipeline
    );
}

#[tokio::test]
async fn create_function_rejects_conflicting_pipeline_representations() {
    let svc = service();
    for variant in [
        pipeline_step::Step::Operator(OperatorStep {
            op: "aggregate".into(),
            func: "count".into(),
            ..Default::default()
        }),
        pipeline_step::Step::Llm(LlmStep::default()),
    ] {
        let error = svc
            .create_function(with_principal(CreateFunctionRequest {
                function: Some(Function {
                    name: "conflicting".into(),
                    pipeline: vec![PipelineStep {
                        op: "filter".into(),
                        step: Some(variant),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("conflicting pipeline step"));
    }
}

#[tokio::test]
async fn action_instance_reads_enforce_authenticated_tenant() {
    let svc = enterprise_service();
    let instance = action_read_fixture("other-tenant");
    svc.db.runtime().put_action_instance(&instance).unwrap();
    let get = svc
        .get_action_instance(with_tenant_context(GetActionInstanceRequest {
            instance_id: instance.instance_id.clone(),
            ..Default::default()
        }))
        .await;
    assert_eq!(get.unwrap_err().code(), tonic::Code::PermissionDenied);
    let list = svc
        .list_action_instances(with_tenant_context(ListActionInstancesRequest {
            namespace: instance.namespace,
            ..Default::default()
        }))
        .await;
    assert_eq!(list.unwrap_err().code(), tonic::Code::PermissionDenied);
}

fn action_read_fixture(namespace: &str) -> crate::sekai::action_instance::ActionInstance {
    crate::sekai::action_instance::ActionInstance {
        instance_id: "private-instance".into(),
        namespace: namespace.into(),
        type_id: "review".into(),
        version: "1".into(),
        delegating_actor: None,
        principal: "owner".into(),
        parameters_json: r#"{"summary":"private payload"}"#.into(),
        request_digest: "digest".into(),
        idempotency_key: "private-key".into(),
        operation_id: "private-operation".into(),
        status: "parked".into(),
        deny_reason: String::new(),
        evidence_submission_ids: vec![],
        policy_decision: "require_approval".into(),
        budget_decision: "allow".into(),
        created_at_ms: 1,
        decided_at_ms: 0,
        system_one_fill_json: String::new(),
        parked_object_digest: String::new(),
        decided_by: String::new(),
        approval_decision: String::new(),
        autonomous_envelope_id: String::new(),
        review: Default::default(),
        agent_action: false,
        admission_tenant: String::new(),
        resource_tenant: String::new(),
    }
}

#[tokio::test]
async fn action_instance_reads_require_entitlement_and_target_visibility() {
    let svc = service();
    seed_lineage_object(&svc, "restricted-target", "acme");
    grant_object_role(&svc, "restricted-target", "owner", security::Role::Viewer);
    let mut instance = action_read_fixture("acme");
    instance.parameters_json = r#"{"object_id":"restricted-target","title":"pending"}"#.into();
    svc.db.runtime().put_action_instance(&instance).unwrap();

    for principal in ["owner", "outsider"] {
        let get = svc
            .get_action_instance(with_named_principal(
                GetActionInstanceRequest {
                    instance_id: instance.instance_id.clone(),
                    ..Default::default()
                },
                principal,
            ))
            .await;
        let list = svc
            .list_action_instances(with_named_principal(
                ListActionInstancesRequest {
                    namespace: "acme".into(),
                    ..Default::default()
                },
                principal,
            ))
            .await
            .unwrap()
            .into_inner();
        if principal == "owner" {
            assert_eq!(
                get.unwrap().into_inner().instance.unwrap().parameters_json,
                instance.parameters_json
            );
            assert_eq!(list.instances.len(), 1);
        } else {
            assert_eq!(get.unwrap_err().code(), tonic::Code::PermissionDenied);
            assert!(list.instances.is_empty());
        }
    }
    // Entitlement alone cannot disclose a target whose grant was revoked.
    instance.principal = "outsider".into();
    svc.db.runtime().put_action_instance(&instance).unwrap();
    let denied = svc
        .get_action_instance(with_named_principal(
            GetActionInstanceRequest {
                instance_id: instance.instance_id,
                ..Default::default()
            },
            "outsider",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn delegated_service_intersects_acl_properties_and_marking_clearance() {
    let svc = service();
    let mut schema_type = widget_schema_type();
    schema_type.properties.push(PropertyDef {
        name: "secret_note".into(),
        r#type: "string".into(),
        classification: "sensitive".into(),
        ..Default::default()
    });
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        },
        "root",
    ))
    .await
    .unwrap();
    let mut object = widget_object(
        "delegated-widget",
        HashMap::from([
            ("name".into(), "widget".into()),
            ("secret_note".into(), "private value".into()),
        ]),
    );
    object.namespace = "delegated-read".into();
    svc.db
        .runtime()
        .create_object(&from_proto_obj(&object))
        .unwrap();
    grant_object_role(&svc, &object.id, "service-a", security::Role::Admin);
    grant_object_role(&svc, &object.id, "human-a", security::Role::Editor);
    let context = crate::enterprise::AuthenticatedContext::machine(
        crate::enterprise::AuthenticatedPrincipal {
            subject: "service-a".into(),
            credential_id: "service-credential".into(),
        },
    );
    let mut denied_service = context.clone();
    denied_service.principal.subject = "service-b".into();
    denied_service.act = Some("human-a".into());
    let mut request = Request::new(GetObjectRequest {
        id: object.id.clone(),
    });
    request.extensions_mut().insert(denied_service);
    assert!(svc.get_object(request).await.is_err());
    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            actor: Some("service-b".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        decisions
            .iter()
            .any(|decision| decision.target_id == object.id
                && decision.outcome == "deny"
                && decision.evidence.get("act").map(String::as_str) == Some("human-a"))
    );
    for (actor, expected_secret) in [(None, "private value"), (Some("human-a"), REDACTED_VALUE)] {
        let mut request = Request::new(GetObjectRequest {
            id: object.id.clone(),
        });
        let mut delegated = context.clone();
        delegated.act = actor.map(str::to_string);
        request.extensions_mut().insert(delegated);
        // Metadata cannot substitute another user's grants.
        request
            .metadata_mut()
            .insert("x-principal", "root".parse().unwrap());
        let response = svc
            .get_object(request)
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(response.properties["secret_note"], expected_secret);
    }
    svc.db
        .runtime()
        .record_object_change(&audit::ObjectChange {
            id: "delegated-secret-change".into(),
            object_id: object.id.clone(),
            field: "properties.secret_note".into(),
            old_value: "old private value".into(),
            new_value: "private value".into(),
            changed_by: "service-a".into(),
            timestamp: 1,
        })
        .unwrap();
    for (actor, expected_value) in [(None, "private value"), (Some("human-a"), REDACTED_VALUE)] {
        let mut delegated = context.clone();
        delegated.act = actor.map(str::to_string);
        let mut request = Request::new(ListObjectChangesRequest {
            object_id: object.id.clone(),
            limit: 10,
            offset: 0,
        });
        request.extensions_mut().insert(delegated);
        let response = svc.list_object_changes(request).await.unwrap().into_inner();
        let change = response
            .changes
            .iter()
            .find(|change| change.field == "properties.secret_note")
            .unwrap();
        assert_eq!(change.new_value, expected_value);
    }
    grant_object_role(&svc, &object.id, "root", security::Role::Admin);
    for (actor, allowed) in [(None, true), (Some("human-a"), false)] {
        let mut delegated = context.clone();
        delegated.principal.subject = "root".into();
        delegated.act = actor.map(str::to_string);
        let mut request = Request::new(FindByPropertyRequest {
            kind: "widget".into(),
            key: "secret_note".into(),
            value: "private value".into(),
        });
        request.extensions_mut().insert(delegated);
        assert_eq!(svc.find_by_property(request).await.is_ok(), allowed);
    }

    let mut updated = object.clone();
    updated
        .properties
        .insert("secret_note".into(), "overwritten".into());
    let mut request = Request::new(UpdateObjectRequest {
        object: Some(updated),
        lease_precondition: None,
    });
    let mut delegated = context.clone();
    delegated.act = Some("human-a".into());
    request.extensions_mut().insert(delegated);
    svc.update_object(request).await.unwrap();
    assert_eq!(
        svc.db
            .runtime()
            .get_object(&object.id)
            .unwrap()
            .unwrap()
            .properties["secret_note"],
        "private value"
    );

    let mut denied = context.clone();
    denied.act = Some("human-without-grants".into());
    let mut request = Request::new(GetObjectRequest {
        id: object.id.clone(),
    });
    request.extensions_mut().insert(denied);
    assert!(svc.get_object(request).await.is_err());

    for (actor, ceiling) in [("service-a", "restricted"), ("human-a", "public")] {
        let profile = domain::Object {
            id: format!("profile-{actor}"),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: actor.into(),
            namespace: String::new(),
            external_id: markings::principal_profile_external_id(actor),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    ceiling.into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 1,
            updated: 1,
        };
        svc.db.runtime().create_object(&profile).unwrap();
        grant_object_role(&svc, &profile.id, "root", security::Role::Admin);
    }
    object.properties.insert(
        markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
        "restricted".into(),
    );
    svc.db
        .runtime()
        .update_object(&from_proto_obj(&object))
        .unwrap();
    for (actor, allowed) in [(None, true), (Some("human-a"), false)] {
        let mut request = Request::new(GetObjectRequest {
            id: object.id.clone(),
        });
        let mut delegated = context.clone();
        delegated.act = actor.map(str::to_string);
        request.extensions_mut().insert(delegated);
        assert_eq!(svc.get_object(request).await.is_ok(), allowed);
        let mut request = Request::new(ListObjectsRequest {
            filter: Some(ListFilter {
                namespace: object.namespace.clone(),
                kind: "widget".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        let mut delegated = context.clone();
        delegated.act = actor.map(str::to_string);
        request.extensions_mut().insert(delegated);
        let response = svc.list_objects(request).await.unwrap().into_inner();
        assert_eq!(response.total, i32::from(allowed));
        assert_eq!(response.objects.len(), usize::from(allowed));
    }
    let audit = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            actor: Some("service-a".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        audit
            .iter()
            .any(|decision| decision.action == "policy.delegated"
                && decision.actor == "service-a"
                && decision.evidence.get("act").map(String::as_str) == Some("human-a"))
    );
}

#[tokio::test]
async fn delegated_service_requires_human_namespace_membership() {
    let svc = service();
    grant_source_namespace(&svc, "delegated-team", "service-a", security::Role::Admin);
    let mut object = from_proto_obj(&widget_object("team-widget", HashMap::new()));
    object.namespace = "delegated-team".into();
    svc.db.runtime().create_object(&object).unwrap();
    let mut context = crate::enterprise::AuthenticatedContext::machine(
        crate::enterprise::AuthenticatedPrincipal {
            subject: "service-a".into(),
            credential_id: "service-credential".into(),
        },
    );
    for (actor, allowed) in [(None, true), (Some("human-a"), false)] {
        context.act = actor.map(str::to_string);
        let mut request = Request::new(GetObjectRequest {
            id: object.id.clone(),
        });
        request.extensions_mut().insert(context.clone());
        assert_eq!(svc.get_object(request).await.is_ok(), allowed);
    }
    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            actor: Some("service-a".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        decisions
            .iter()
            .any(|decision| decision.target_id == "delegated-team"
                && decision.outcome == "deny"
                && decision.evidence.get("act").map(String::as_str) == Some("human-a"))
    );
    grant_source_namespace(&svc, "delegated-team", "human-a", security::Role::Viewer);
    context.act = Some("human-a".into());
    let mut request = Request::new(GetObjectRequest {
        id: object.id.clone(),
    });
    request.extensions_mut().insert(context.clone());
    assert!(svc.get_object(request).await.is_ok());
    let mut denied_service = context.clone();
    denied_service.principal.subject = "service-b".into();
    let mut request = Request::new(GetObjectRequest {
        id: object.id.clone(),
    });
    request.extensions_mut().insert(denied_service);
    assert!(svc.get_object(request).await.is_err());
    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            actor: Some("service-b".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        decisions
            .iter()
            .any(|decision| decision.target_id == "delegated-team"
                && decision.outcome == "deny"
                && decision.evidence.get("act").map(String::as_str) == Some("human-a"))
    );
    let decision = decide_object_access(
        svc.db.runtime(),
        &object,
        &["service-a".into()],
        Some(&context),
        crate::sekai::object_security::ObjectSecurityOperation::Update,
        None,
    )
    .unwrap();
    assert_eq!(
        decision.outcome,
        crate::sekai::policy_decision::PolicyOutcome::Deny
    );
}

#[tokio::test]
async fn delegated_service_requires_human_admin_for_policy_input_changes() {
    let svc = service();
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        },
        "root",
    ))
    .await
    .unwrap();
    let mut object = widget_object(
        "policy-widget",
        HashMap::from([("name".into(), "widget".into())]),
    );
    object.namespace = "delegated-policy".into();
    svc.db
        .runtime()
        .create_object(&from_proto_obj(&object))
        .unwrap();
    grant_object_role(&svc, &object.id, "service-a", security::Role::Admin);
    grant_object_role(&svc, &object.id, "human-a", security::Role::Editor);
    let policy = crate::sekai::object_security::ObjectSecurityPolicy::from_canonical_input(&serde_json::to_vec(&serde_json::json!({
        "contract_version":"sekai.object-security-policy/v1", "namespace":"delegated-policy", "kind":"widget",
        "rules":[
            {"operation":"read","predicates":[{"kind":"subject_equals_property","property":"name"}]},
            {"operation":"update","predicates":[{"kind":"allow_all"}]}
        ]
    })).unwrap()).unwrap();
    let revision = svc
        .db
        .runtime()
        .put_object_security_policy(&policy, "root", "put-admin-policy", 1)
        .unwrap();
    svc.db
        .runtime()
        .activate_object_security_policies(
            "delegated-policy",
            &std::collections::BTreeMap::from([("widget".into(), revision.revision_digest)]),
            "root",
            "activate-admin-policy",
            2,
        )
        .unwrap();
    let mut context = crate::enterprise::AuthenticatedContext::machine(
        crate::enterprise::AuthenticatedPrincipal {
            subject: "service-a".into(),
            credential_id: "service-credential".into(),
        },
    );
    for (actor, allowed) in [(Some("human-a"), false), (None, true)] {
        let mut updated = object.clone();
        updated.properties.insert("name".into(), "changed".into());
        context.act = actor.map(str::to_string);
        let mut request = Request::new(UpdateObjectRequest {
            object: Some(updated),
            lease_precondition: None,
        });
        request.extensions_mut().insert(context.clone());
        assert_eq!(svc.update_object(request).await.is_ok(), allowed);
    }
    context.act = Some("human-a".into());
    let mut request = Request::new(GetObjectRequest {
        id: object.id.clone(),
    });
    request.extensions_mut().insert(context);
    assert_eq!(
        svc.get_object(request).await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    let audit = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            actor: Some("service-a".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(audit.iter().any(|decision| decision.outcome == "deny"
        && decision.evidence.get("operation").map(String::as_str) == Some("read")
        && decision.evidence.get("act").map(String::as_str) == Some("human-a")));
}

/// Guest of `tenant-test` whose home tenant is `tenant-home` (#1432).
fn guest_context() -> crate::enterprise::AuthenticatedContext {
    crate::enterprise::AuthenticatedContext {
        home_tenant: Some("tenant-home".into()),
        scopes: vec!["sekai.read".into(), "sekai.write".into()],
        ..test_tenant_context()
    }
}

/// Host grant for guests on namespace `shared` only; `None` revokes it.
struct GuestSharedExtension(std::sync::Mutex<Option<crate::enterprise::GuestGrant>>);

impl GuestSharedExtension {
    fn granting(role: crate::enterprise::SpaceRole, ceiling: &str) -> Self {
        Self(std::sync::Mutex::new(Some(crate::enterprise::GuestGrant {
            role,
            marking_ceiling: ceiling.into(),
        })))
    }

    fn editor() -> Self {
        Self::granting(crate::enterprise::SpaceRole::Editor, "restricted")
    }
}

impl crate::enterprise::EnterpriseExtension for GuestSharedExtension {
    fn authenticate_bearer(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.authenticate_bearer(bearer_token)
    }

    fn authenticate_context(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError> {
        let issued = TestEnterpriseExtension.authenticate_context(bearer_token)?;
        Ok(crate::enterprise::AuthenticatedContext {
            expires_at: i64::MAX,
            issuer: issued.issuer,
            resource: issued.resource,
            ..guest_context()
        })
    }

    fn tenant_context(
        &self,
        principal: &crate::enterprise::AuthenticatedPrincipal,
    ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.tenant_context(principal)
    }

    fn authorize_namespace(
        &self,
        context: &crate::enterprise::TenantContext,
        namespace: &str,
        action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.authorize_namespace(context, namespace, action)
    }

    fn authorize_guest_namespace(
        &self,
        context: &crate::enterprise::AuthenticatedContext,
        namespace: &str,
        _action: crate::enterprise::NamespaceAction,
    ) -> Result<crate::enterprise::GuestGrant, crate::enterprise::ExtensionError> {
        let grant = self.0.lock().unwrap().clone();
        grant
            .filter(|_| context.guest_home_tenant() == Some("tenant-home") && namespace == "shared")
            .ok_or(crate::enterprise::ExtensionError::PermissionDenied)
    }

    fn authorize_unscoped_namespace(
        &self,
        principal: &crate::enterprise::AuthenticatedPrincipal,
        namespace: &str,
        action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.authorize_unscoped_namespace(principal, namespace, action)
    }
}

fn guest_decisions(db: &RuntimeDb) -> Vec<crate::sekai::audit::Decision> {
    db.list_decisions(&crate::sekai::decision_ledger::DecisionFilter {
        action: Some("tenant.guest_access".into()),
        limit: 100,
        ..Default::default()
    })
    .unwrap()
}

#[tokio::test]
async fn guest_contexts_are_denied_by_default_and_look_missing() {
    let svc = enterprise_service();
    seed_lineage_object(&svc, "tenant-object", "allowed");
    let get = |id: &str| {
        let mut req = with_named_principal(GetObjectRequest { id: id.into() }, "subject-a");
        req.extensions_mut().insert(guest_context());
        req
    };
    let existing = svc.get_object(get("tenant-object")).await.unwrap_err();
    let missing = svc.get_object(get("no-such-object")).await.unwrap_err();
    assert_eq!(existing.code(), missing.code());
    assert_eq!(existing.code(), tonic::Code::NotFound);

    let mut list = with_named_principal(
        ListObjectsRequest {
            filter: Some(ListFilter {
                namespace: "allowed".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
        "subject-a",
    );
    list.extensions_mut().insert(guest_context());
    let listed = svc.list_objects(list).await;
    assert!(
        listed.as_ref().map_or(true, |response| {
            response.get_ref().objects.is_empty() && response.get_ref().total == 0
        }),
        "{listed:?}"
    );

    let db = svc.db.runtime();
    for action in [
        crate::enterprise::NamespaceAction::Discover,
        crate::enterprise::NamespaceAction::Read,
        crate::enterprise::NamespaceAction::Write,
    ] {
        assert!(
            enforce_namespace_tenant_context_for(db, Some(&guest_context()), "allowed", action)
                .is_err()
        );
    }
    // The same principal acting in its own tenant is unaffected.
    assert!(
        enforce_namespace_tenant_context(db, Some(&test_tenant_context()), "allowed", false)
            .is_ok()
    );

    let decisions = guest_decisions(db);
    assert!(!decisions.is_empty());
    assert!(decisions.iter().all(|decision| decision.outcome == "denied"
        && decision.evidence["home_tenant"] == "tenant-home"
        && decision.evidence["acting_tenant"] == "tenant-test"));
}

#[test]
fn guest_access_needs_explicit_extension_opt_in() {
    let community = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    assert!(
        enforce_namespace_tenant_context(&community, Some(&guest_context()), "shared", false)
            .is_err()
    );

    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(
            ":memory:",
            Some(Arc::new(GuestSharedExtension::editor())),
        )
        .unwrap(),
    ));
    assert!(enforce_namespace_tenant_context(&db, Some(&guest_context()), "shared", false).is_ok());
    assert!(enforce_namespace_tenant_context(&db, Some(&guest_context()), "shared", true).is_ok());
    assert!(
        enforce_namespace_tenant_context(&db, Some(&guest_context()), "allowed", false).is_err()
    );

    // A denial from the space check before the guest hook is audited too.
    let viewer = crate::enterprise::AuthenticatedContext {
        space: Some("space-a".into()),
        space_role: Some(crate::enterprise::SpaceRole::Viewer),
        ..guest_context()
    };
    assert!(enforce_namespace_tenant_context(&db, Some(&viewer), "shared", true).is_err());

    let decisions = guest_decisions(&db);
    let outcome = |namespace: &str| {
        decisions
            .iter()
            .filter(|decision| decision.target_id == namespace)
            .map(|decision| decision.outcome.as_str())
            .collect::<Vec<_>>()
    };
    let mut shared = outcome("shared");
    shared.sort_unstable();
    assert_eq!(shared, ["allowed", "allowed", "denied"]);
    assert_eq!(outcome("allowed"), ["denied"]);
    assert!(decisions.iter().any(|decision| decision.evidence["space"] == "space-a"
        && decision.outcome == "denied"));
    assert!(
        decisions
            .iter()
            .all(|decision| decision.actor == "subject-a"
                && decision.evidence["home_tenant"] == "tenant-home"
                && decision.evidence["acting_tenant"] == "tenant-test")
    );
}

#[test]
fn guest_credentials_reach_only_namespace_checked_rpcs() {
    use tonic::service::Interceptor;
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(
            ":memory:",
            Some(Arc::new(GuestSharedExtension::editor())),
        )
        .unwrap(),
    )));
    let mut interceptor = crate::grpc::TokenAuthInterceptor::new(
        Arc::new(crate::sekai::credentials::PrincipalCredentialStore::new()),
        crate::db::store::SekaiStore::from_shared_runtime(db.clone()),
    );
    let guest_rpcs = [
        "GetObject",
        "ListObjects",
        "CreateObject",
        "UpdateObject",
        "DeleteObject",
        "DiscoverCapabilities",
    ];
    for (service, protocol) in [
        (
            "sekai.SekaiService",
            include_str!("../../proto/sekai.proto"),
        ),
        (
            "chisei.ChiseiService",
            include_str!("../../proto/chisei.proto"),
        ),
    ] {
        for method in protocol.lines().filter_map(|line| {
            line.trim()
                .strip_prefix("rpc ")
                .and_then(|rpc| rpc.split_once('(').map(|(name, _)| name.trim()))
        }) {
            if service == "sekai.SekaiService" && method == "IssueServicePrincipalToken" {
                // Client-credentials issuance authenticates from the request body.
                continue;
            }
            let mut request = Request::new(());
            request.metadata_mut().insert(
                "authorization",
                MetadataValue::from_static("Bearer enterprise-token"),
            );
            request
                .extensions_mut()
                .insert(tonic::GrpcMethod::new(service, method));
            let result = interceptor.call(request);
            let denied_rpc = format!("{service}/{method}");
            if service == "sekai.SekaiService" && guest_rpcs.contains(&method) {
                assert!(result.is_ok(), "{denied_rpc}: {result:?}");
            } else {
                assert!(result.is_err(), "{denied_rpc}");
                assert!(
                    guest_decisions(&db)
                        .iter()
                        .any(|decision| decision.target_id == denied_rpc
                            && decision.outcome == "denied"
                            && decision.evidence["home_tenant"] == "tenant-home"
                            && decision.evidence["acting_tenant"] == "tenant-test"),
                    "unaudited {denied_rpc}"
                );
            }
        }
    }
}

fn guest_service(extension: Arc<GuestSharedExtension>) -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(extension)).unwrap(),
    )));
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
}

fn seed_marked(svc: &SekaiServiceImpl, id: &str, marking: &str) {
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: id.into(),
            kind: "widget".into(),
            name: id.into(),
            namespace: "shared".into(),
            external_id: format!("widget:{id}"),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                marking.into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();
}

fn pin_guest_profile(svc: &SekaiServiceImpl, ceiling: &str) {
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "profile-subject-a".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "subject-a".into(),
            namespace: "shared".into(),
            external_id: markings::principal_profile_external_id("subject-a"),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    ceiling.into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    grant_object_role(svc, "profile-subject-a", "root", security::Role::Admin);
}

fn guest_get(id: &str) -> Request<GetObjectRequest> {
    let mut req = with_named_principal(GetObjectRequest { id: id.into() }, "subject-a");
    req.extensions_mut().insert(guest_context());
    req
}

#[test]
fn guest_role_bounds_the_namespace_action() {
    let viewer = Arc::new(GuestSharedExtension::granting(
        crate::enterprise::SpaceRole::Viewer,
        "restricted",
    ));
    let svc = guest_service(viewer.clone());
    let db = svc.db.runtime();
    let guest = guest_context();
    assert!(enforce_namespace_tenant_context(db, Some(&guest), "shared", false).is_ok());
    assert!(enforce_namespace_tenant_context(db, Some(&guest), "shared", true).is_err());
    let discoverer =
        GuestSharedExtension::granting(crate::enterprise::SpaceRole::Discoverer, "restricted");
    *viewer.0.lock().unwrap() = discoverer.0.lock().unwrap().clone();
    assert!(
        enforce_namespace_tenant_context_for(
            db,
            Some(&guest),
            "shared",
            crate::enterprise::NamespaceAction::Discover
        )
        .is_ok()
    );
    assert!(enforce_namespace_tenant_context(db, Some(&guest), "shared", false).is_err());
}

#[tokio::test]
async fn guest_is_capped_by_the_host_ceiling_and_revocation_is_next_request() {
    let extension = Arc::new(GuestSharedExtension::granting(
        crate::enterprise::SpaceRole::Viewer,
        "internal",
    ));
    let svc = guest_service(extension.clone());
    seed_marked(&svc, "w-internal", "internal");
    seed_marked(&svc, "w-confidential", "confidential");
    // The guest's own profile would allow restricted; the host grant caps it.
    pin_guest_profile(&svc, "restricted");

    assert_eq!(
        svc.get_object(guest_get("w-internal"))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap()
            .id,
        "w-internal"
    );
    let above = svc
        .get_object(guest_get("w-confidential"))
        .await
        .unwrap_err();
    let missing = svc
        .get_object(guest_get("no-such-object"))
        .await
        .unwrap_err();
    assert_eq!(above.code(), tonic::Code::NotFound);
    assert_eq!(above.code(), missing.code());

    let mut list = with_named_principal(
        ListObjectsRequest {
            filter: Some(ListFilter {
                namespace: "shared".into(),
                kind: "widget".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
        "subject-a",
    );
    list.extensions_mut().insert(guest_context());
    let listed = svc.list_objects(list).await.unwrap().into_inner();
    let ids: Vec<_> = listed
        .objects
        .iter()
        .map(|object| object.id.as_str())
        .collect();
    assert_eq!(ids, ["w-internal"]);
    assert_eq!(listed.total, 1);

    let decisions = guest_decisions(svc.db.runtime());
    assert!(
        decisions
            .iter()
            .any(|decision| decision.target_id == "w-confidential"
                && decision.outcome == "denied"
                && decision.evidence["operation"] == "ceiling"
                && decision.evidence["home_tenant"] == "tenant-home"
                && decision.evidence["acting_tenant"] == "tenant-test"),
        "{decisions:?}"
    );

    *extension.0.lock().unwrap() = None;
    assert_eq!(
        svc.get_object(guest_get("w-internal"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
}

#[test]
fn guest_writes_stay_under_role_and_ceiling() {
    let svc = guest_service(Arc::new(GuestSharedExtension::granting(
        crate::enterprise::SpaceRole::Editor,
        "internal",
    )));
    let db = svc.db.runtime();
    let guest = guest_context();
    let object = |marking: &str| domain::Object {
        id: "w".into(),
        kind: "widget".into(),
        name: "w".into(),
        namespace: "shared".into(),
        external_id: String::new(),
        properties: HashMap::from([(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            marking.into(),
        )]),
        created: 0,
        updated: 0,
    };
    let write = crate::enterprise::NamespaceAction::Write;
    assert!(guest_object_permitted(db, Some(&guest), &object("internal"), write).unwrap());
    assert!(!guest_object_permitted(db, Some(&guest), &object("confidential"), write).unwrap());
    // Unknown markings fail closed for guests.
    assert!(!guest_object_permitted(db, Some(&guest), &object("secret-ish"), write).unwrap());
    // Non-guests are not affected by guest grants.
    assert!(
        guest_object_permitted(
            db,
            Some(&test_tenant_context()),
            &object("restricted"),
            write
        )
        .unwrap()
    );
}

fn shared_health_lattice() -> crate::sekai::classification_lattice::ClassificationLattice {
    crate::sekai::classification_lattice::ClassificationLattice {
        contract_version: crate::sekai::classification_lattice::CLASSIFICATION_LATTICE_VERSION
            .into(),
        namespace: "shared".into(),
        tokens: vec![
            "public".into(),
            "internal".into(),
            "confidential".into(),
            "secret".into(),
            "health".into(),
        ],
        parents: BTreeMap::from([
            ("public".into(), vec!["internal".into()]),
            ("internal".into(), vec!["confidential".into()]),
            ("confidential".into(), vec!["secret".into()]),
            ("health".into(), vec!["secret".into()]),
        ]),
        incomparable: vec![("confidential".into(), "health".into())],
    }
}

#[tokio::test]
async fn guest_ceiling_follows_activated_lattice() {
    let extension = Arc::new(GuestSharedExtension::granting(
        crate::enterprise::SpaceRole::Editor,
        "secret",
    ));
    let svc = guest_service(extension.clone());
    seed_marked(&svc, "w-health", "health");
    pin_guest_profile(&svc, "secret");
    // Custom tokens are unknown on the default ordinal.
    assert_eq!(
        svc.get_object(guest_get("w-health"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );

    svc.db
        .runtime()
        .put_classification_lattice(&shared_health_lattice(), "root", 10)
        .unwrap();
    assert_eq!(
        svc.get_object(guest_get("w-health"))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap()
            .id,
        "w-health"
    );

    *extension.0.lock().unwrap() = Some(crate::enterprise::GuestGrant {
        role: crate::enterprise::SpaceRole::Editor,
        marking_ceiling: "confidential".into(),
    });
    assert_eq!(
        svc.get_object(guest_get("w-health"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    let write = crate::enterprise::NamespaceAction::Write;
    let health = domain::Object {
        id: "w-health".into(),
        kind: "widget".into(),
        name: "w-health".into(),
        namespace: "shared".into(),
        external_id: String::new(),
        properties: HashMap::from([(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "health".into(),
        )]),
        created: 0,
        updated: 0,
    };
    assert!(
        !guest_object_permitted(svc.db.runtime(), Some(&guest_context()), &health, write).unwrap()
    );
    *extension.0.lock().unwrap() = Some(crate::enterprise::GuestGrant {
        role: crate::enterprise::SpaceRole::Editor,
        marking_ceiling: "secret".into(),
    });
    assert!(
        guest_object_permitted(svc.db.runtime(), Some(&guest_context()), &health, write).unwrap()
    );

    let decisions = guest_decisions(svc.db.runtime());
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| decision.target_id == "w-health"
                && decision.outcome == "denied"
                && decision.evidence["operation"] == "ceiling")
            .count(),
        3,
        "{decisions:?}"
    );
}

struct DiscoveryRuleExtension(std::sync::Mutex<Option<crate::enterprise::DiscoveryRule>>);

impl DiscoveryRuleExtension {
    fn naming(namespaces: &[&str]) -> Self {
        Self(std::sync::Mutex::new(Some(
            crate::enterprise::DiscoveryRule {
                owner_tenant: "tenant-test".into(),
                tenants: vec!["tenant-test".into()],
                principals: vec!["subject-a".into()],
                spaces: vec!["collab".into()],
                namespaces: namespaces
                    .iter()
                    .map(|namespace| (*namespace).into())
                    .collect(),
            },
        )))
    }

    fn none() -> Self {
        Self(std::sync::Mutex::new(None))
    }
}

impl crate::enterprise::EnterpriseExtension for DiscoveryRuleExtension {
    fn authenticate_bearer(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.authenticate_bearer(bearer_token)
    }

    fn authenticate_context(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError> {
        let issued = TestEnterpriseExtension.authenticate_context(bearer_token)?;
        Ok(crate::enterprise::AuthenticatedContext {
            expires_at: i64::MAX,
            issuer: issued.issuer,
            resource: issued.resource,
            ..guest_context()
        })
    }

    fn tenant_context(
        &self,
        principal: &crate::enterprise::AuthenticatedPrincipal,
    ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.tenant_context(principal)
    }

    fn authorize_namespace(
        &self,
        context: &crate::enterprise::TenantContext,
        namespace: &str,
        action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.authorize_namespace(context, namespace, action)
    }

    fn authorize_discovery(
        &self,
        _context: &crate::enterprise::AuthenticatedContext,
        owner_tenant: &str,
    ) -> Result<Option<crate::enterprise::DiscoveryRule>, crate::enterprise::ExtensionError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .clone()
            .filter(|rule| rule.owner_tenant == owner_tenant))
    }

    fn authorize_unscoped_namespace(
        &self,
        principal: &crate::enterprise::AuthenticatedPrincipal,
        namespace: &str,
        action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.authorize_unscoped_namespace(principal, namespace, action)
    }
}

fn discovery_service(extension: Arc<DiscoveryRuleExtension>) -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(extension)).unwrap(),
    )));
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
}

fn discovery_decisions(db: &RuntimeDb) -> Vec<crate::sekai::audit::Decision> {
    db.list_decisions(&crate::sekai::decision_ledger::DecisionFilter {
        action: Some("tenant.discovery".into()),
        limit: 100,
        ..Default::default()
    })
    .unwrap()
}

fn guest_discover(namespace: &str) -> Request<DiscoverCapabilitiesRequest> {
    let mut req = with_named_principal(
        DiscoverCapabilitiesRequest {
            namespace: namespace.into(),
            ..Default::default()
        },
        "subject-a",
    );
    req.extensions_mut().insert(guest_context());
    req
}

#[tokio::test]
async fn discovery_without_a_rule_looks_missing() {
    let svc = discovery_service(Arc::new(DiscoveryRuleExtension::none()));
    seed_lineage_object(&svc, "shared-object", "shared");
    let hidden = svc
        .discover_capabilities(guest_discover("shared"))
        .await
        .unwrap_err();
    assert_eq!(hidden.code(), tonic::Code::NotFound);
    assert_eq!(hidden.message(), "not found");
    let existing = svc
        .get_object(guest_get("shared-object"))
        .await
        .unwrap_err();
    let missing = svc
        .get_object(guest_get("no-such-object"))
        .await
        .unwrap_err();
    assert_eq!(existing.code(), missing.code());
    assert_eq!(existing.code(), tonic::Code::NotFound);
    let mut list = with_named_principal(
        ListObjectsRequest {
            filter: Some(ListFilter {
                namespace: "shared".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
        "subject-a",
    );
    list.extensions_mut().insert(guest_context());
    let listed = svc.list_objects(list).await.unwrap();
    assert!(listed.get_ref().objects.is_empty());
    assert_eq!(listed.get_ref().total, 0);
}

#[test]
fn discovery_is_off_until_a_rule_names_the_namespace() {
    let extension = Arc::new(DiscoveryRuleExtension::none());
    let svc = discovery_service(extension);
    let db = svc.db.runtime();
    for action in [
        crate::enterprise::NamespaceAction::Discover,
        crate::enterprise::NamespaceAction::Read,
        crate::enterprise::NamespaceAction::Write,
    ] {
        assert!(
            enforce_namespace_tenant_context_for(db, Some(&guest_context()), "shared", action)
                .is_err()
        );
    }
    let decisions = discovery_decisions(db);
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "denied");
    assert_eq!(decisions[0].target_id, "shared");
    assert_eq!(decisions[0].evidence["home_tenant"], "tenant-home");
    assert_eq!(decisions[0].evidence["owner_tenant"], "tenant-test");
    assert_eq!(decisions[0].evidence["operation"], "namespace");
}

#[test]
fn guest_grant_discover_is_still_audited_as_discovery() {
    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(
            ":memory:",
            Some(Arc::new(GuestSharedExtension::granting(
                crate::enterprise::SpaceRole::Discoverer,
                "restricted",
            ))),
        )
        .unwrap(),
    ));
    assert!(
        enforce_namespace_tenant_context_for(
            &db,
            Some(&guest_context()),
            "shared",
            crate::enterprise::NamespaceAction::Discover,
        )
        .is_ok()
    );
    let decisions = discovery_decisions(&db);
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "allowed");
    assert_eq!(decisions[0].target_id, "shared");
    assert_eq!(decisions[0].evidence["owner_tenant"], "tenant-test");
    assert_eq!(decisions[0].evidence["home_tenant"], "tenant-home");
}

#[tokio::test]
async fn discovery_rule_names_exact_targets_at_discover_only() {
    let extension = Arc::new(DiscoveryRuleExtension::naming(&["shared"]));
    let svc = discovery_service(extension);
    seed_lineage_object(&svc, "shared-object", "shared");
    let db = svc.db.runtime();
    assert!(
        enforce_namespace_tenant_context_for(
            db,
            Some(&guest_context()),
            "shared",
            crate::enterprise::NamespaceAction::Discover,
        )
        .is_ok()
    );
    assert!(
        enforce_namespace_tenant_context_for(
            db,
            Some(&guest_context()),
            "allowed",
            crate::enterprise::NamespaceAction::Discover,
        )
        .is_err()
    );
    assert!(
        enforce_namespace_tenant_context_for(
            db,
            Some(&guest_context()),
            "shared",
            crate::enterprise::NamespaceAction::Read,
        )
        .is_err()
    );
    assert!(
        enforce_namespace_tenant_context_for(
            db,
            Some(&guest_context()),
            "shared",
            crate::enterprise::NamespaceAction::Write,
        )
        .is_err()
    );

    let found = svc
        .discover_capabilities(guest_discover("shared"))
        .await
        .unwrap();
    assert_eq!(found.get_ref().cache_scope, "authorization_context");
    let hidden = svc
        .discover_capabilities(guest_discover("allowed"))
        .await
        .unwrap_err();
    assert_eq!(hidden.code(), tonic::Code::NotFound);
    assert_eq!(hidden.message(), "not found");

    let existing = svc
        .get_object(guest_get("shared-object"))
        .await
        .unwrap_err();
    let missing = svc
        .get_object(guest_get("no-such-object"))
        .await
        .unwrap_err();
    assert_eq!(existing.code(), missing.code());
    assert_eq!(existing.code(), tonic::Code::NotFound);
    let mut list = with_named_principal(
        ListObjectsRequest {
            filter: Some(ListFilter {
                namespace: "shared".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
        "subject-a",
    );
    list.extensions_mut().insert(guest_context());
    let listed = svc.list_objects(list).await.unwrap();
    assert!(listed.get_ref().objects.is_empty());
    assert_eq!(listed.get_ref().total, 0);

    let decisions = discovery_decisions(db);
    assert!(decisions.iter().any(|decision| {
        decision.target_id == "shared"
            && decision.outcome == "allowed"
            && decision.evidence["owner_tenant"] == "tenant-test"
            && decision.evidence["home_tenant"] == "tenant-home"
            && decision.evidence["operation"] == "namespace"
    }));
    assert!(
        decisions
            .iter()
            .any(|decision| { decision.target_id == "allowed" && decision.outcome == "denied" })
    );
}

#[test]
fn discovery_withdrawal_is_next_request_and_audited() {
    let extension = Arc::new(DiscoveryRuleExtension::naming(&["shared"]));
    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(extension.clone())).unwrap(),
    ));
    assert!(
        enforce_namespace_tenant_context_for(
            &db,
            Some(&guest_context()),
            "shared",
            crate::enterprise::NamespaceAction::Discover,
        )
        .is_ok()
    );
    *extension.0.lock().unwrap() = None;
    assert!(
        enforce_namespace_tenant_context_for(
            &db,
            Some(&guest_context()),
            "shared",
            crate::enterprise::NamespaceAction::Discover,
        )
        .is_err()
    );
    let outcomes: Vec<_> = discovery_decisions(&db)
        .into_iter()
        .map(|decision| decision.outcome)
        .collect();
    assert_eq!(outcomes, ["denied", "allowed"]);
}

/// Member of `tenant-home` acting at home through shared space `collab` (#1434).
fn shared_space_member() -> crate::enterprise::AuthenticatedContext {
    crate::enterprise::AuthenticatedContext {
        tenant: Some(crate::enterprise::TenantContext {
            tenant_id: "tenant-home".into(),
            subject: "subject-a".into(),
        }),
        space: Some("collab".into()),
        space_role: Some(crate::enterprise::SpaceRole::Viewer),
        scopes: vec!["sekai.read".into(), "sekai.write".into()],
        ..test_tenant_context()
    }
}

#[derive(Clone)]
struct SharedSpaceState {
    owner_approved: bool,
    member_approved: bool,
    grant: Option<crate::enterprise::SharedSpaceGrant>,
}

/// Dual-approval shared space on `ops`; `None` grant or a false side withdraws it.
struct SharedSpaceExtension(std::sync::Mutex<SharedSpaceState>);

impl SharedSpaceExtension {
    fn granting() -> Self {
        Self(std::sync::Mutex::new(SharedSpaceState {
            owner_approved: true,
            member_approved: true,
            grant: Some(crate::enterprise::SharedSpaceGrant {
                owner_tenant: "tenant-test".into(),
                namespaces: vec!["ops".into()],
                kinds: vec!["widget".into()],
                marking_ceiling: "internal".into(),
            }),
        }))
    }
}

impl crate::enterprise::EnterpriseExtension for SharedSpaceExtension {
    fn authenticate_bearer(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.authenticate_bearer(bearer_token)
    }

    fn authenticate_context(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError> {
        let issued = TestEnterpriseExtension.authenticate_context(bearer_token)?;
        Ok(crate::enterprise::AuthenticatedContext {
            expires_at: i64::MAX,
            issuer: issued.issuer,
            resource: issued.resource,
            ..shared_space_member()
        })
    }

    fn tenant_context(
        &self,
        principal: &crate::enterprise::AuthenticatedPrincipal,
    ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
        Ok(crate::enterprise::TenantContext {
            tenant_id: "tenant-home".into(),
            subject: principal.subject.clone(),
        })
    }

    fn authorize_namespace(
        &self,
        context: &crate::enterprise::TenantContext,
        namespace: &str,
        action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.authorize_namespace(context, namespace, action)
    }

    fn authorize_shared_space(
        &self,
        context: &crate::enterprise::AuthenticatedContext,
        namespace: &str,
        _action: crate::enterprise::NamespaceAction,
    ) -> Result<crate::enterprise::SharedSpaceAuthorization, crate::enterprise::ExtensionError>
    {
        if context.named_space() != Some("collab") {
            return Ok(crate::enterprise::SharedSpaceAuthorization::Unshared);
        }
        let state = self.0.lock().unwrap();
        let owner_tenant = state
            .grant
            .as_ref()
            .map(|grant| grant.owner_tenant.clone())
            .unwrap_or_else(|| "tenant-test".into());
        if !(state.owner_approved && state.member_approved) {
            return Ok(crate::enterprise::SharedSpaceAuthorization::Denied { owner_tenant });
        }
        let Some(grant) = state.grant.clone() else {
            return Ok(crate::enterprise::SharedSpaceAuthorization::Denied { owner_tenant });
        };
        if grant.exposes_namespace(namespace) {
            Ok(crate::enterprise::SharedSpaceAuthorization::Granted(grant))
        } else {
            Ok(crate::enterprise::SharedSpaceAuthorization::Denied {
                owner_tenant: grant.owner_tenant,
            })
        }
    }

    fn authorize_unscoped_namespace(
        &self,
        principal: &crate::enterprise::AuthenticatedPrincipal,
        namespace: &str,
        action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        TestEnterpriseExtension.authorize_unscoped_namespace(principal, namespace, action)
    }
}

fn shared_space_service(extension: Arc<SharedSpaceExtension>) -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(extension)).unwrap(),
    )));
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
}

fn shared_space_decisions(db: &RuntimeDb) -> Vec<crate::sekai::audit::Decision> {
    db.list_decisions(&crate::sekai::decision_ledger::DecisionFilter {
        action: Some("tenant.shared_space_access".into()),
        limit: 100,
        ..Default::default()
    })
    .unwrap()
}

fn seed_ops(svc: &SekaiServiceImpl, id: &str, kind: &str, marking: &str) {
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: "ops".into(),
            external_id: format!("{kind}:{id}"),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                marking.into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();
}

fn pin_shared_space_profile(svc: &SekaiServiceImpl, ceiling: &str) {
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "profile-subject-a".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "subject-a".into(),
            namespace: "ops".into(),
            external_id: markings::principal_profile_external_id("subject-a"),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    ceiling.into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    grant_object_role(svc, "profile-subject-a", "root", security::Role::Admin);
}

fn shared_space_get(id: &str) -> Request<GetObjectRequest> {
    let mut req = with_named_principal(GetObjectRequest { id: id.into() }, "subject-a");
    req.extensions_mut().insert(shared_space_member());
    req
}

fn shared_space_list(namespace: &str, kind: &str) -> Request<ListObjectsRequest> {
    let mut req = with_named_principal(
        ListObjectsRequest {
            filter: Some(ListFilter {
                namespace: namespace.into(),
                kind: kind.into(),
                ..Default::default()
            }),
            ..Default::default()
        },
        "subject-a",
    );
    req.extensions_mut().insert(shared_space_member());
    req
}

#[test]
fn shared_space_membership_needs_approval_from_both_sides() {
    let extension = Arc::new(SharedSpaceExtension::granting());
    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(extension.clone())).unwrap(),
    ));
    let member = shared_space_member();
    assert!(enforce_collaboration_namespace(&db, Some(&member), "ops", false).is_ok());
    // Non-object RPCs must not inherit the grant.
    assert!(enforce_namespace_tenant_context(&db, Some(&member), "ops", false).is_err());
    let discoverer = crate::enterprise::AuthenticatedContext {
        space_role: Some(crate::enterprise::SpaceRole::Discoverer),
        ..member.clone()
    };
    assert!(enforce_collaboration_namespace(&db, Some(&discoverer), "ops", false).is_err());

    for (owner, participant) in [(true, false), (false, true), (false, false)] {
        let grant = extension.0.lock().unwrap().grant.clone();
        *extension.0.lock().unwrap() = SharedSpaceState {
            owner_approved: owner,
            member_approved: participant,
            grant,
        };
        assert!(
            enforce_collaboration_namespace(&db, Some(&member), "ops", false).is_err(),
            "owner={owner} member={participant}"
        );
    }

    let decisions = shared_space_decisions(&db);
    assert!(
        decisions
            .iter()
            .any(|decision| decision.outcome == "allowed"
                && decision.target_id == "ops"
                && decision.evidence["home_tenant"] == "tenant-home"
                && decision.evidence["resource_tenant"] == "tenant-test"
                && decision.evidence["space"] == "collab")
    );
    assert!(
        decisions
            .iter()
            .filter(|decision| decision.outcome == "denied" && decision.target_id == "ops")
            .count()
            >= 3
    );
    assert!(
        decisions
            .iter()
            .filter(|decision| decision.outcome == "denied" && decision.target_id == "ops")
            .all(|decision| decision.evidence["resource_tenant"] == "tenant-test")
    );
}

#[tokio::test]
async fn shared_space_exposes_only_named_namespaces_kinds_and_markings() {
    let svc = shared_space_service(Arc::new(SharedSpaceExtension::granting()));
    pin_shared_space_profile(&svc, "restricted");
    seed_ops(&svc, "w-internal", "widget", "internal");
    seed_ops(&svc, "w-confidential", "widget", "confidential");
    seed_ops(&svc, "note-internal", "note", "internal");
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "other-ns".into(),
            kind: "widget".into(),
            name: "other-ns".into(),
            namespace: "secrets".into(),
            external_id: "widget:other-ns".into(),
            properties: HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "internal".into(),
            )]),
            created: 0,
            updated: 0,
        })
        .unwrap();

    assert_eq!(
        svc.get_object(shared_space_get("w-internal"))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap()
            .id,
        "w-internal"
    );
    for missing in [
        "w-confidential",
        "note-internal",
        "other-ns",
        "no-such-object",
    ] {
        let denied = svc.get_object(shared_space_get(missing)).await.unwrap_err();
        assert_eq!(denied.code(), tonic::Code::NotFound, "{missing}");
    }

    let listed = svc
        .list_objects(shared_space_list("ops", "widget"))
        .await
        .unwrap()
        .into_inner();
    let ids: Vec<_> = listed
        .objects
        .iter()
        .map(|object| object.id.as_str())
        .collect();
    assert_eq!(ids, ["w-internal"]);
    assert_eq!(listed.total, 1);

    let secrets = svc
        .list_objects(shared_space_list("secrets", "widget"))
        .await;
    assert!(
        secrets.as_ref().map_or(true, |response| {
            response.get_ref().objects.is_empty() && response.get_ref().total == 0
        }),
        "{secrets:?}"
    );

    let decisions = shared_space_decisions(svc.db.runtime());
    assert!(decisions.iter().any(|decision| {
        decision.target_id == "w-internal"
            && decision.outcome == "allowed"
            && decision.evidence["resource_tenant"] == "tenant-test"
            && decision.evidence["operation"] == "read"
    }));
    assert!(
        decisions
            .iter()
            .any(|decision| decision.target_id == "w-confidential"
                && decision.outcome == "denied"
                && decision.evidence["operation"] == "ceiling"
                && decision.evidence["home_tenant"] == "tenant-home"
                && decision.evidence["resource_tenant"] == "tenant-test"
                && decision.evidence["space"] == "collab")
    );
    assert!(
        decisions
            .iter()
            .any(|decision| decision.target_id == "note-internal"
                && decision.outcome == "denied"
                && decision.evidence["operation"] == "kind")
    );
    assert!(
        decisions
            .iter()
            .any(|decision| decision.target_id == "secrets" && decision.outcome == "denied")
    );
}

#[tokio::test]
async fn shared_space_does_not_admit_link_reads() {
    let svc = shared_space_service(Arc::new(SharedSpaceExtension::granting()));
    pin_shared_space_profile(&svc, "restricted");
    seed_ops(&svc, "w-internal", "widget", "internal");
    assert!(svc.get_object(shared_space_get("w-internal")).await.is_ok());
    let mut req = with_named_principal(
        GetLinksRequest {
            object_id: "w-internal".into(),
            relation: String::new(),
            direction: String::new(),
        },
        "subject-a",
    );
    req.extensions_mut().insert(shared_space_member());
    let denied = svc.get_links(req).await.unwrap_err();
    assert_eq!(denied.code(), tonic::Code::NotFound, "{denied}");
}

#[tokio::test]
async fn shared_space_withdrawal_denies_the_next_request() {
    let extension = Arc::new(SharedSpaceExtension::granting());
    let svc = shared_space_service(extension.clone());
    pin_shared_space_profile(&svc, "restricted");
    seed_ops(&svc, "w-internal", "widget", "internal");
    assert_eq!(
        svc.get_object(shared_space_get("w-internal"))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap()
            .id,
        "w-internal"
    );

    extension.0.lock().unwrap().member_approved = false;
    assert_eq!(
        svc.get_object(shared_space_get("w-internal"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );

    extension.0.lock().unwrap().member_approved = true;
    extension.0.lock().unwrap().owner_approved = false;
    assert_eq!(
        svc.get_object(shared_space_get("w-internal"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );

    let decisions = shared_space_decisions(svc.db.runtime());
    assert!(
        decisions
            .iter()
            .any(|decision| decision.outcome == "allowed"
                && decision.target_id == "ops"
                && decision.evidence["home_tenant"] == "tenant-home"
                && decision.evidence["resource_tenant"] == "tenant-test"
                && decision.evidence["space"] == "collab"
                && decision.actor == "subject-a")
    );
    assert!(
        decisions
            .iter()
            .filter(|decision| decision.outcome == "denied" && decision.target_id == "ops")
            .count()
            >= 2
    );
    assert!(
        decisions
            .iter()
            .filter(|decision| decision.outcome == "denied" && decision.target_id == "ops")
            .all(|decision| decision.evidence["resource_tenant"] == "tenant-test")
    );
}

#[tokio::test]
async fn shared_space_history_hides_unexposed_kinds_and_markings() {
    let svc = shared_space_service(Arc::new(SharedSpaceExtension::granting()));
    pin_shared_space_profile(&svc, "restricted");
    seed_ops(&svc, "w-internal", "widget", "internal");
    seed_ops(&svc, "w-confidential", "widget", "confidential");
    seed_ops(&svc, "note-internal", "note", "internal");

    let history = |id: &str| {
        let mut req = with_named_principal(
            ListObjectChangesRequest {
                object_id: id.into(),
                limit: 10,
                offset: 0,
            },
            "subject-a",
        );
        req.extensions_mut().insert(shared_space_member());
        req
    };
    assert!(svc.list_object_changes(history("w-internal")).await.is_ok());
    for hidden in ["w-confidential", "note-internal"] {
        assert_eq!(
            svc.list_object_changes(history(hidden))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound,
            "{hidden}"
        );
    }
}

#[tokio::test]
async fn shared_space_history_omits_values_written_under_a_higher_marking() {
    let svc = shared_space_service(Arc::new(SharedSpaceExtension::granting()));
    pin_shared_space_profile(&svc, "restricted");
    seed_ops(&svc, "w-internal", "widget", "internal");
    let runtime = svc.db.runtime();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "secret-while-confidential".into(),
            object_id: "w-internal".into(),
            field: "properties.secret_note".into(),
            old_value: String::new(),
            new_value: "classified note".into(),
            changed_by: "owner".into(),
            timestamp: 1,
        })
        .unwrap();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "downgrade-marking".into(),
            object_id: "w-internal".into(),
            field: format!("properties.{}", markings::OBJECT_CLASSIFICATION_PROPERTY),
            old_value: "confidential".into(),
            new_value: "internal".into(),
            changed_by: "owner".into(),
            timestamp: 2,
        })
        .unwrap();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "note-after-downgrade".into(),
            object_id: "w-internal".into(),
            field: "properties.secret_note".into(),
            old_value: "classified note".into(),
            new_value: "public note".into(),
            changed_by: "owner".into(),
            timestamp: 3,
        })
        .unwrap();

    let history = |limit: i32, offset: i32| {
        let mut req = with_named_principal(
            ListObjectChangesRequest {
                object_id: "w-internal".into(),
                limit,
                offset,
            },
            "subject-a",
        );
        req.extensions_mut().insert(shared_space_member());
        req
    };
    let changes = svc
        .list_object_changes(history(10, 0))
        .await
        .unwrap()
        .into_inner()
        .changes;
    assert!(
        changes.iter().all(|change| {
            change.old_value != "classified note"
                && change.new_value != "classified note"
                && change.old_value != "confidential"
        }),
        "{changes:?}"
    );
    assert!(
        changes.iter().any(|change| {
            change.field == "properties.secret_note" && change.new_value == "public note"
        }),
        "{changes:?}"
    );
    let newest = svc
        .list_object_changes(history(1, 0))
        .await
        .unwrap()
        .into_inner()
        .changes;
    assert_eq!(newest.len(), 1, "{newest:?}");
    assert_eq!(newest[0].new_value, "public note");
    assert_ne!(newest[0].old_value, "classified note");

    runtime
        .record_object_change(&audit::ObjectChange {
            id: "raise-marking".into(),
            object_id: "w-internal".into(),
            field: format!("properties.{}", markings::OBJECT_CLASSIFICATION_PROPERTY),
            old_value: "internal".into(),
            new_value: "confidential".into(),
            changed_by: "owner".into(),
            timestamp: 4,
        })
        .unwrap();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "secret-after-raise".into(),
            object_id: "w-internal".into(),
            field: "properties.secret_note".into(),
            old_value: "public note".into(),
            new_value: "later classified".into(),
            changed_by: "owner".into(),
            timestamp: 5,
        })
        .unwrap();
    let after_raise = svc
        .list_object_changes(history(1, 0))
        .await
        .unwrap()
        .into_inner()
        .changes;
    assert_eq!(after_raise.len(), 1, "{after_raise:?}");
    assert_eq!(after_raise[0].new_value, "public note", "{after_raise:?}");

    runtime
        .record_object_change(&audit::ObjectChange {
            id: "same-ms-raise".into(),
            object_id: "w-internal".into(),
            field: format!("properties.{}", markings::OBJECT_CLASSIFICATION_PROPERTY),
            old_value: "internal".into(),
            new_value: "confidential".into(),
            changed_by: "owner".into(),
            timestamp: 6,
        })
        .unwrap();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "same-ms-secret".into(),
            object_id: "w-internal".into(),
            field: "properties.secret_note".into(),
            old_value: "public note".into(),
            new_value: "same-ms classified".into(),
            changed_by: "owner".into(),
            timestamp: 6,
        })
        .unwrap();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "same-ms-downgrade".into(),
            object_id: "w-internal".into(),
            field: format!("properties.{}", markings::OBJECT_CLASSIFICATION_PROPERTY),
            old_value: "confidential".into(),
            new_value: "internal".into(),
            changed_by: "owner".into(),
            timestamp: 6,
        })
        .unwrap();
    let same_ms = svc
        .list_object_changes(history(10, 0))
        .await
        .unwrap()
        .into_inner()
        .changes;
    assert!(
        same_ms
            .iter()
            .all(|change| change.new_value != "same-ms classified"
                && change.old_value != "same-ms classified"),
        "{same_ms:?}"
    );
}

#[test]
fn unshared_space_history_stays_on_the_store_path() {
    let extension = Arc::new(SharedSpaceExtension::granting());
    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(extension)).unwrap(),
    ));
    let local = crate::enterprise::AuthenticatedContext {
        space: Some("local".into()),
        space_role: Some(crate::enterprise::SpaceRole::Viewer),
        ..test_tenant_context()
    };
    let object = domain::Object {
        id: "local-widget".into(),
        kind: "widget".into(),
        name: "local-widget".into(),
        namespace: "allowed".into(),
        external_id: "widget:local-widget".into(),
        properties: HashMap::new(),
        created: 0,
        updated: 0,
    };
    assert!(
        visible_collaboration_history_page(&db, Some(&local), Some(&object), 10, 0)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn shared_space_history_redacts_create_time_values_above_the_ceiling() {
    let svc = shared_space_service(Arc::new(SharedSpaceExtension::granting()));
    pin_shared_space_profile(&svc, "restricted");
    seed_ops(&svc, "w-internal", "widget", "internal");
    let runtime = svc.db.runtime();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "created-confidential".into(),
            object_id: "w-internal".into(),
            field: format!("properties.{}", markings::OBJECT_CLASSIFICATION_PROPERTY),
            old_value: "confidential".into(),
            new_value: "internal".into(),
            changed_by: "owner".into(),
            timestamp: 1,
        })
        .unwrap();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "first-note-after-create".into(),
            object_id: "w-internal".into(),
            field: "properties.secret_note".into(),
            old_value: "created classified".into(),
            new_value: "public note".into(),
            changed_by: "owner".into(),
            timestamp: 2,
        })
        .unwrap();
    let mut req = with_named_principal(
        ListObjectChangesRequest {
            object_id: "w-internal".into(),
            limit: 10,
            offset: 0,
        },
        "subject-a",
    );
    req.extensions_mut().insert(shared_space_member());
    let changes = svc
        .list_object_changes(req)
        .await
        .unwrap()
        .into_inner()
        .changes;
    let note = changes
        .iter()
        .find(|change| change.field == "properties.secret_note")
        .expect("visible post-downgrade note");
    assert_eq!(note.new_value, "public note");
    assert_ne!(note.old_value, "created classified");
}

#[tokio::test]
async fn shared_space_history_redacts_old_values_when_retention_removes_exposure() {
    let svc = shared_space_service(Arc::new(SharedSpaceExtension::granting()));
    pin_shared_space_profile(&svc, "restricted");
    seed_ops(&svc, "w-internal", "widget", "internal");
    let runtime = svc.db.runtime();
    // Retention deleted the confidential write and its downgrade. This
    // retained update still carries the classified text in old_value.
    // Later internal→confidential→internal marking events must not be
    // treated as creation-time evidence that the old value was internal.
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "retained-after-purge".into(),
            object_id: "w-internal".into(),
            field: "properties.secret_note".into(),
            old_value: "classified note".into(),
            new_value: "public note".into(),
            changed_by: "owner".into(),
            timestamp: 3,
        })
        .unwrap();
    let marking = format!("properties.{}", markings::OBJECT_CLASSIFICATION_PROPERTY);
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "later-raise".into(),
            object_id: "w-internal".into(),
            field: marking.clone(),
            old_value: "internal".into(),
            new_value: "confidential".into(),
            changed_by: "owner".into(),
            timestamp: 4,
        })
        .unwrap();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "later-downgrade".into(),
            object_id: "w-internal".into(),
            field: marking,
            old_value: "confidential".into(),
            new_value: "internal".into(),
            changed_by: "owner".into(),
            timestamp: 5,
        })
        .unwrap();
    let mut req = with_named_principal(
        ListObjectChangesRequest {
            object_id: "w-internal".into(),
            limit: 10,
            offset: 0,
        },
        "subject-a",
    );
    req.extensions_mut().insert(shared_space_member());
    let changes = svc
        .list_object_changes(req)
        .await
        .unwrap()
        .into_inner()
        .changes;
    let note = changes
        .iter()
        .find(|change| change.field == "properties.secret_note")
        .expect("visible post-retention note");
    assert_eq!(note.new_value, "public note");
    assert_ne!(note.old_value, "classified note");
    assert!(note.old_value.is_empty(), "{note:?}");
}

#[tokio::test]
async fn shared_space_history_uses_store_order_for_same_millisecond_markings() {
    let svc = shared_space_service(Arc::new(SharedSpaceExtension::granting()));
    pin_shared_space_profile(&svc, "restricted");
    seed_ops(&svc, "w-internal", "widget", "internal");
    let runtime = svc.db.runtime();
    let marking = |id: &str, old: &str, new: &str, timestamp: i64| audit::ObjectChange {
        id: id.into(),
        object_id: "w-internal".into(),
        field: format!("properties.{}", markings::OBJECT_CLASSIFICATION_PROPERTY),
        old_value: old.into(),
        new_value: new.into(),
        changed_by: "owner".into(),
        timestamp,
    };
    runtime
        .record_object_change(&marking("ms-downgrade", "confidential", "internal", 1))
        .unwrap();
    runtime
        .record_object_change(&marking("ms-raise", "internal", "confidential", 1))
        .unwrap();
    runtime
        .record_object_change(&audit::ObjectChange {
            id: "secret-after-same-ms-raise".into(),
            object_id: "w-internal".into(),
            field: "properties.secret_note".into(),
            old_value: String::new(),
            new_value: "secret after raise".into(),
            changed_by: "owner".into(),
            timestamp: 2,
        })
        .unwrap();
    runtime
        .record_object_change(&marking("later-downgrade", "confidential", "internal", 3))
        .unwrap();
    let mut req = with_named_principal(
        ListObjectChangesRequest {
            object_id: "w-internal".into(),
            limit: 10,
            offset: 0,
        },
        "subject-a",
    );
    req.extensions_mut().insert(shared_space_member());
    let changes = svc
        .list_object_changes(req)
        .await
        .unwrap()
        .into_inner()
        .changes;
    assert!(
        changes
            .iter()
            .all(|change| change.new_value != "secret after raise"
                && change.old_value != "secret after raise"),
        "{changes:?}"
    );
}

#[test]
fn unshared_spaces_keep_the_same_tenant_path() {
    let extension = Arc::new(SharedSpaceExtension::granting());
    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(extension)).unwrap(),
    ));
    let local = crate::enterprise::AuthenticatedContext {
        space: Some("local".into()),
        space_role: Some(crate::enterprise::SpaceRole::Viewer),
        ..test_tenant_context()
    };
    assert!(enforce_namespace_tenant_context(&db, Some(&local), "allowed", false).is_ok());
    assert!(enforce_namespace_tenant_context(&db, Some(&local), "ops", false).is_err());
    assert!(shared_space_decisions(&db).is_empty());
}

#[tokio::test]
async fn list_governed_transforms_returns_definitions_and_runs_for_authorized_principal() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform, TransformStep};

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: "t1".into(),
        input_dataset_id: "in".into(),
        output_dataset_id: "out".into(),
        steps: vec![TransformStep {
            kind: "project".into(),
            column: String::new(),
            op: String::new(),
            value: String::new(),
            columns: vec!["id".into()],
        }],
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: None,
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    runtime.put_governed_transform(&transform, 10).unwrap();
    runtime
        .run_governed_transform("ops", "t1", false, 20)
        .unwrap();

    let listed = svc
        .list_governed_transforms(with_principal(ListGovernedTransformsRequest {
            namespace: "ops".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .transforms;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].transform_id, "t1");

    let runs = svc
        .list_governed_transform_runs(with_principal(ListGovernedTransformRunsRequest {
            namespace: "ops".into(),
            limit: 10,
        }))
        .await
        .unwrap()
        .into_inner()
        .runs;
    assert_eq!(runs.len(), 1);
    let over_max = svc
        .list_governed_transform_runs(with_principal(ListGovernedTransformRunsRequest {
            namespace: "ops".into(),
            limit: crate::domain::MAX_LIST_LIMIT + 1,
        }))
        .await
        .unwrap()
        .into_inner()
        .runs;
    assert_eq!(over_max.len(), 1);

    let denied = svc
        .list_governed_transforms(Request::new(ListGovernedTransformsRequest {
            namespace: "ops".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::Unauthenticated);

    svc.ensure_team_namespace(with_named_principal(
        EnsureTeamNamespaceRequest {
            namespace: "ops".into(),
            principal: "bob".into(),
            role: "viewer".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    let member = svc
        .list_governed_transforms(with_named_principal(
            ListGovernedTransformsRequest {
                namespace: "ops".into(),
            },
            "bob",
        ))
        .await
        .unwrap()
        .into_inner()
        .transforms;
    assert_eq!(member.len(), 1);
    let outsider = svc
        .list_governed_transforms(with_principal(ListGovernedTransformsRequest {
            namespace: "ops".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(outsider.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn get_transform_run_redacts_partition_keys_without_dataset_read() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, REDACTED_PARTITION_IDENTITY, TransformStep,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    runtime
        .create_object(&domain::Object {
            id: "secret-in".into(),
            kind: "artifact".into(),
            name: "in".into(),
            namespace: "ops".into(),
            external_id: "artifact:secret-in".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    runtime
        .create_object(&domain::Object {
            id: "secret-out".into(),
            kind: "artifact".into(),
            name: "out".into(),
            namespace: "ops".into(),
            external_id: "artifact:secret-out".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let dataset = |id: &str, object_id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![
            ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
            ColumnDef {
                name: "region".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
        ],
        object_id: object_id.into(),
        created: 1,
        partition_keys: vec!["region".into()],
    };
    runtime.create_dataset(&dataset("in", "secret-in")).unwrap();
    runtime
        .create_dataset(&dataset("out", "secret-out"))
        .unwrap();
    runtime
        .append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("region".into(), "east".into()),
            ])],
        )
        .unwrap();
    let owner_in = security::Grant {
        id: "owner-in".into(),
        object_id: "secret-in".into(),
        principal: "alice".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    let owner_out = security::Grant {
        id: "owner-out".into(),
        object_id: "secret-out".into(),
        principal: "alice".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    runtime.create_grant(&owner_in).unwrap();
    runtime.create_grant(&owner_out).unwrap();
    svc.security.add_grant(&owner_in);
    svc.security.add_grant(&owner_out);
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: "t1".into(),
        input_dataset_id: "in".into(),
        output_dataset_id: "out".into(),
        steps: vec![TransformStep {
            kind: "project".into(),
            column: String::new(),
            op: String::new(),
            value: String::new(),
            columns: vec!["id".into(), "region".into()],
        }],
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: None,
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    runtime.put_governed_transform(&transform, 10).unwrap();
    let stored = runtime
        .run_governed_transform("ops", "t1", false, 20)
        .unwrap();
    let request = GetGovernedTransformRunRequest {
        run_id: stored.run_id.clone(),
    };
    let revealed = svc
        .get_governed_transform_run(with_named_principal(request.clone(), "alice"))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    assert_eq!(revealed.output_partitions[0].partition_key, "east");
    let redacted = svc
        .get_governed_transform_run(with_named_principal(request.clone(), "bob"))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    assert_eq!(
        redacted.output_partitions[0].partition_key,
        REDACTED_PARTITION_IDENTITY
    );
    assert_eq!(
        redacted.output_partitions[0].digest,
        REDACTED_PARTITION_IDENTITY
    );
    assert_ne!(
        redacted.output_partitions[0].digest,
        revealed.output_partitions[0].digest
    );
    let mut updated = transform;
    updated.steps[0].columns = vec!["id".into()];
    updated.definition_digest.clear();
    runtime
        .put_governed_transform(&updated.prepare().unwrap(), 30)
        .unwrap();
    let stale = svc
        .get_governed_transform_run(with_named_principal(request.clone(), "alice"))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    assert_eq!(
        stale.output_partitions[0].partition_key,
        REDACTED_PARTITION_IDENTITY
    );
    let denied = svc
        .get_governed_transform_run(Request::new(request))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn isolated_process_claim_and_write_back_are_namespace_authorized() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, rows_digest,
    };
    use futures_util::StreamExt;

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: "iso1".into(),
        input_dataset_id: "in".into(),
        output_dataset_id: "out".into(),
        steps: Vec::new(),
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: Some(IsolatedProcessSpec {
            engine: "python".into(),
            runtime_image: "runner:1".into(),
            inputs: Vec::new(),
        }),
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    runtime.put_governed_transform(&transform, 10).unwrap();
    runtime
        .run_governed_transform("ops", "iso1", false, 20)
        .unwrap();

    let editor_denied = svc
        .list_claimable_transform_work(with_principal(ListClaimableTransformWorkRequest {
            namespace: "ops".into(),
            runtime_id: "runner-a".into(),
            limit: 10,
        }))
        .await
        .unwrap_err();
    assert_eq!(editor_denied.code(), tonic::Code::PermissionDenied);
    let listed = svc
        .list_claimable_transform_work(with_named_principal(
            ListClaimableTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                limit: 10,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .work;
    assert_eq!(listed.len(), 1);
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let mut stream = svc
        .read_transform_run_inputs(with_named_principal(
            ReadTransformRunInputsRequest {
                run_id: work.run_id.clone(),
                runtime_id: work.claim_owner.clone(),
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token.clone(),
                alias: String::new(),
                after_row_id: 0,
                limit: 100,
                after_alias: String::new(),
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let mut rows = Vec::new();
    while let Some(item) = stream.next().await {
        rows.push(item.unwrap().row.unwrap());
    }
    assert_eq!(rows.len(), 1);
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    let written = svc
        .write_transform_run_result(with_named_principal(
            WriteTransformRunResultRequest {
                run_id: work.run_id,
                runtime_id: work.claim_owner,
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token,
                rows: output
                    .iter()
                    .map(|values| TransformRunInputRow {
                        alias: String::new(),
                        dataset_id: "out".into(),
                        row_id: 0,
                        values: values.clone(),
                        ..Default::default()
                    })
                    .collect(),
                output_digest: rows_digest(&output),
                quarantined: false,
                quality_rule: String::new(),
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    assert_eq!(written.dispatch_status, "completed");
    let denied = svc
        .list_claimable_transform_work(Request::new(ListClaimableTransformWorkRequest {
            namespace: "ops".into(),
            runtime_id: "runner-a".into(),
            limit: 10,
        }))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn isolated_process_input_stream_requires_dataset_read() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, rows_digest,
    };
    use futures_util::StreamExt;

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str, object_id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: object_id.into(),
        created: 1,
        partition_keys: Vec::new(),
    };
    for (id, name) in [("secret-in", "in"), ("secret-out", "out")] {
        runtime
            .create_object(&domain::Object {
                id: id.into(),
                kind: "artifact".into(),
                name: name.into(),
                namespace: "ops".into(),
                external_id: format!("artifact:{id}"),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
    }
    runtime.create_dataset(&dataset("in", "secret-in")).unwrap();
    runtime
        .create_dataset(&dataset("out", "secret-out"))
        .unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let owner_in = security::Grant {
        id: "owner-in".into(),
        object_id: "secret-in".into(),
        principal: "alice".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    let owner_out = security::Grant {
        id: "owner-out".into(),
        object_id: "secret-out".into(),
        principal: "alice".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    runtime.create_grant(&owner_in).unwrap();
    runtime.create_grant(&owner_out).unwrap();
    svc.security.add_grant(&owner_in);
    svc.security.add_grant(&owner_out);
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: "iso-acl".into(),
        input_dataset_id: "in".into(),
        output_dataset_id: "out".into(),
        steps: Vec::new(),
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: Some(IsolatedProcessSpec {
            engine: "python".into(),
            runtime_image: "runner:1".into(),
            inputs: Vec::new(),
        }),
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    runtime.put_governed_transform(&transform, 10).unwrap();
    runtime
        .run_governed_transform("ops", "iso-acl", false, 20)
        .unwrap();
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let read_req = || ReadTransformRunInputsRequest {
        run_id: work.run_id.clone(),
        runtime_id: work.claim_owner.clone(),
        claim_generation: work.claim_generation,
        fencing_token: work.fencing_token.clone(),
        alias: String::new(),
        after_row_id: 0,
        limit: 100,
        after_alias: String::new(),
        ..Default::default()
    };
    let denied_read = match svc
        .read_transform_run_inputs(with_named_principal(read_req(), "local"))
        .await
    {
        Err(status) => status,
        Ok(_) => panic!("expected dataset read to be denied"),
    };
    assert_eq!(denied_read.code(), tonic::Code::PermissionDenied);

    let reader = security::Grant {
        id: "reader".into(),
        object_id: "secret-in".into(),
        principal: "local".into(),
        role: security::Role::Viewer,
        created: 0,
        ..Default::default()
    };
    runtime.create_grant(&reader).unwrap();
    svc.security.add_grant(&reader);
    let mut stream = svc
        .read_transform_run_inputs(with_named_principal(read_req(), "local"))
        .await
        .unwrap()
        .into_inner();
    let mut rows = Vec::new();
    while let Some(item) = stream.next().await {
        rows.push(item.unwrap().row.unwrap());
    }
    assert_eq!(rows.len(), 1);

    let output = vec![HashMap::from([("id".into(), "1".into())])];
    let write_req = || WriteTransformRunResultRequest {
        run_id: work.run_id.clone(),
        runtime_id: work.claim_owner.clone(),
        claim_generation: work.claim_generation,
        fencing_token: work.fencing_token.clone(),
        rows: output
            .iter()
            .map(|values| TransformRunInputRow {
                alias: String::new(),
                dataset_id: "out".into(),
                row_id: 0,
                values: values.clone(),
                ..Default::default()
            })
            .collect(),
        output_digest: rows_digest(&output),
        quarantined: false,
        quality_rule: String::new(),
        ..Default::default()
    };
    let denied_write = svc
        .write_transform_run_result(with_named_principal(write_req(), "local"))
        .await
        .unwrap_err();
    assert_eq!(denied_write.code(), tonic::Code::PermissionDenied);

    let writer = security::Grant {
        id: "writer".into(),
        object_id: "secret-out".into(),
        principal: "local".into(),
        role: security::Role::Editor,
        created: 0,
        ..Default::default()
    };
    runtime.create_grant(&writer).unwrap();
    svc.security.add_grant(&writer);
    let written = svc
        .write_transform_run_result(with_named_principal(write_req(), "local"))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    assert_eq!(written.dispatch_status, "completed");
}

fn with_tenant_admin<T>(payload: T, tenant_id: &str) -> Request<T> {
    let mut req = with_named_principal(payload, "local");
    req.extensions_mut()
        .insert(crate::provider_credentials::tenant_context(
            tenant_id, "local",
        ));
    req
}

#[tokio::test]
async fn run_governed_transform_applies_tenant_quota_and_records_usage() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform, TransformStep};

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-meter".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: vec![TransformStep {
                    kind: "project".into(),
                    column: String::new(),
                    op: String::new(),
                    value: String::new(),
                    columns: vec!["id".into()],
                }],
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: None,
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    let gate = crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc());
    let limits = TenantQuotaLimits {
        version: 1,
        max_requests_per_period: Some(1),
        max_tokens_per_period: None,
        max_concurrency: None,
        max_storage_bytes: None,
        period: PeriodType::Daily,
    };
    gate.configure("tenant-a", &limits).unwrap();

    let missing = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "missing".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    let first = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-meter".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    assert!(!first.run_id.is_empty());
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let usage = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);

    let denied = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-meter".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn split_plane_run_records_usage_on_the_chisei_dest() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::composition::cross_store_admission::CrossStoreAdmission;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform, TransformStep};

    let dir = tempfile::tempdir().unwrap();
    let sekai =
        crate::db::store::SekaiStore::open_sqlite(dir.path().join("sekai.db").to_str().unwrap());
    let chisei = crate::chisei_store::ChiseiStore::open_sqlite(
        dir.path().join("chisei.db").to_str().unwrap(),
    );
    let svc = SekaiServiceImpl::new(sekai.clone()).with_cross_store_admission(Arc::new(
        CrossStoreAdmission::new(chisei.clone(), sekai.clone(), None),
    ));
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-split".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: vec![TransformStep {
                    kind: "project".into(),
                    column: String::new(),
                    op: String::new(),
                    value: String::new(),
                    columns: vec!["id".into()],
                }],
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: None,
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    let gate = crate::composition::transform_run_admission::quota_gate(chisei.runtime_arc());
    let limits = TenantQuotaLimits {
        version: 1,
        max_requests_per_period: Some(1),
        max_tokens_per_period: None,
        max_concurrency: None,
        max_storage_bytes: None,
        period: PeriodType::Daily,
    };
    gate.configure("tenant-a", &limits).unwrap();

    let first = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-split".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    assert!(!first.run_id.is_empty());

    let quota = svc.quota_runtime();
    let RuntimeDb::Sqlite(chisei_sqlite) = quota.as_ref() else {
        panic!("sqlite");
    };
    let usage = chisei_sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);

    let RuntimeDb::Sqlite(sekai_sqlite) = runtime else {
        panic!("sqlite");
    };
    assert!(
        sekai_sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .is_err(),
        "Sekai plane must not host usage events"
    );

    let denied = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-split".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn in_process_run_without_tenant_meters_the_put_owner() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::CONTRACT_VERSION;

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(1),
                max_tokens_per_period: None,
                max_concurrency: None,
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    svc.put_governed_transform(with_tenant_admin(
        PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-meter-owner".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: vec![TransformStep {
                    kind: "project".into(),
                    columns: vec!["id".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    svc.run_governed_transform(with_named_principal(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-meter-owner".into(),
            incremental: false,
        },
        "local",
    ))
    .await
    .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let usage = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);
    let denied = svc
        .run_governed_transform(with_named_principal(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-meter-owner".into(),
                incremental: false,
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn in_process_run_with_tenant_meters_the_caller_not_the_put_owner() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::CONTRACT_VERSION;

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let limits = TenantQuotaLimits {
        version: 1,
        max_requests_per_period: Some(1),
        max_tokens_per_period: None,
        max_concurrency: None,
        max_storage_bytes: None,
        period: PeriodType::Daily,
    };
    let gate = crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc());
    gate.configure("tenant-a", &limits).unwrap();
    gate.configure("tenant-b", &limits).unwrap();
    svc.put_governed_transform(with_tenant_admin(
        PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-meter-caller".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: vec![TransformStep {
                    kind: "project".into(),
                    columns: vec!["id".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-meter-caller".into(),
            incremental: false,
        },
        "tenant-b",
    ))
    .await
    .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    assert_eq!(
        sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap()
            .measured,
        0
    );
    assert_eq!(
        sqlite
            .aggregate_usage_for_tenant("tenant-b", UsageUnit::Requests, 0, i64::MAX)
            .unwrap()
            .measured,
        1
    );
    let denied = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-meter-caller".into(),
                incremental: false,
            },
            "tenant-b",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-meter-caller".into(),
            incremental: false,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    assert_eq!(
        sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap()
            .measured,
        1
    );
}

#[tokio::test]
async fn isolated_run_without_tenant_stamps_the_put_owner() {
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, ISOLATED_CLASS, rows_digest};

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    svc.put_governed_transform(with_tenant_admin(
        PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-put-owner".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                profile: ISOLATED_CLASS.into(),
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                ..Default::default()
            }),
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let run = svc
        .run_governed_transform(with_named_principal(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-iso-put-owner".into(),
                incremental: false,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: run.run_id,
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    assert_eq!(work.tenant_id, "tenant-a");
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    svc.write_transform_run_result(with_named_principal(
        WriteTransformRunResultRequest {
            run_id: work.run_id,
            runtime_id: work.claim_owner,
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token,
            rows: output
                .iter()
                .map(|values| TransformRunInputRow {
                    alias: String::new(),
                    dataset_id: "out".into(),
                    row_id: 0,
                    values: values.clone(),
                    ..Default::default()
                })
                .collect(),
            output_digest: rows_digest(&output),
            quarantined: false,
            quality_rule: String::new(),
            ..Default::default()
        },
        "local",
    ))
    .await
    .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let usage = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);
}

#[tokio::test]
async fn isolated_write_retry_after_complete_records_usage_once() {
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, ISOLATED_CLASS, rows_digest};

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    svc.put_governed_transform(with_tenant_admin(
        PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-usage-retry".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                profile: ISOLATED_CLASS.into(),
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                ..Default::default()
            }),
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let run = svc
        .run_governed_transform(with_named_principal(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-iso-usage-retry".into(),
                incremental: false,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: run.run_id,
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    let write = WriteTransformRunResultRequest {
        run_id: work.run_id.clone(),
        runtime_id: work.claim_owner.clone(),
        claim_generation: work.claim_generation,
        fencing_token: work.fencing_token.clone(),
        rows: output
            .iter()
            .map(|values| TransformRunInputRow {
                alias: String::new(),
                dataset_id: "out".into(),
                row_id: 0,
                values: values.clone(),
                ..Default::default()
            })
            .collect(),
        output_digest: rows_digest(&output),
        quarantined: false,
        quality_rule: String::new(),
        ..Default::default()
    };
    runtime
        .write_transform_run(
            crate::sekai::governed_transform::WriteTransformRunCommand {
                run_id: write.run_id.clone(),
                runtime_id: write.runtime_id.clone(),
                claim_generation: write.claim_generation,
                fencing_token: write.fencing_token.clone(),
                rows: output.clone(),
                output_digest: write.output_digest.clone(),
                quarantined: false,
                quality_rule: String::new(),
                ..crate::sekai::governed_transform::WriteTransformRunCommand::default()
            },
            40,
        )
        .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    assert_eq!(
        sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap()
            .measured,
        0
    );
    svc.write_transform_run_result(with_named_principal(write.clone(), "local"))
        .await
        .unwrap();
    assert_eq!(
        sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap()
            .measured,
        1
    );
    svc.write_transform_run_result(with_named_principal(write, "local"))
        .await
        .unwrap();
    assert_eq!(
        sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap()
            .measured,
        1
    );
}

#[tokio::test]
async fn isolated_claim_admits_quota_and_write_records_usage() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, rows_digest,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-meter".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    let gate = crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc());
    gate.configure(
        "tenant-a",
        &TenantQuotaLimits {
            version: 1,
            max_requests_per_period: Some(1),
            max_tokens_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        },
    )
    .unwrap();

    let queued = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-iso-meter".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let before_claim = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(before_claim.measured, 0);

    let claimed = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: queued.run_id.clone(),
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    let written = svc
        .write_transform_run_result(with_tenant_admin(
            WriteTransformRunResultRequest {
                run_id: work.run_id,
                runtime_id: work.claim_owner,
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token,
                rows: output
                    .iter()
                    .map(|values| TransformRunInputRow {
                        alias: String::new(),
                        dataset_id: "out".into(),
                        row_id: 0,
                        values: values.clone(),
                        ..Default::default()
                    })
                    .collect(),
                output_digest: rows_digest(&output),
                quarantined: false,
                quality_rule: String::new(),
                ..Default::default()
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    assert_eq!(written.dispatch_status, "completed");
    let usage = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);

    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-iso-meter".into(),
            incremental: false,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let denied = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn isolated_write_records_usage_for_the_claiming_tenant() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, rows_digest,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-owner".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(1),
                max_tokens_per_period: None,
                max_concurrency: None,
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    let queued = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-iso-owner".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    let claimed = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: queued.run_id,
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    svc.write_transform_run_result(with_tenant_admin(
        WriteTransformRunResultRequest {
            run_id: work.run_id,
            runtime_id: work.claim_owner,
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token,
            rows: output
                .iter()
                .map(|values| TransformRunInputRow {
                    alias: String::new(),
                    dataset_id: "out".into(),
                    row_id: 0,
                    values: values.clone(),
                    ..Default::default()
                })
                .collect(),
            output_digest: rows_digest(&output),
            quarantined: false,
            quality_rule: String::new(),
            ..Default::default()
        },
        "tenant-b",
    ))
    .await
    .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let owner = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    let writer = sqlite
        .aggregate_usage_for_tenant("tenant-b", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(owner.measured, 1);
    assert_eq!(writer.measured, 0);
}

#[tokio::test]
async fn isolated_claim_without_tenant_context_meters_the_owner() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, rows_digest,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-runner".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(1),
                max_tokens_per_period: None,
                max_concurrency: None,
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    let queued = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-iso-runner".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: queued.run_id,
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    svc.write_transform_run_result(with_named_principal(
        WriteTransformRunResultRequest {
            run_id: work.run_id,
            runtime_id: work.claim_owner,
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token,
            rows: output
                .iter()
                .map(|values| TransformRunInputRow {
                    alias: String::new(),
                    dataset_id: "out".into(),
                    row_id: 0,
                    values: values.clone(),
                    ..Default::default()
                })
                .collect(),
            output_digest: rows_digest(&output),
            quarantined: false,
            quality_rule: String::new(),
            ..Default::default()
        },
        "local",
    ))
    .await
    .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let usage = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);
    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-iso-runner".into(),
            incremental: false,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let denied = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn isolated_write_records_owner_usage_without_quota_limits() {
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, rows_digest,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-noleak".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    let queued = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-iso-noleak".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: queued.run_id,
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    svc.write_transform_run_result(with_named_principal(
        WriteTransformRunResultRequest {
            run_id: work.run_id,
            runtime_id: work.claim_owner,
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token,
            rows: output
                .iter()
                .map(|values| TransformRunInputRow {
                    alias: String::new(),
                    dataset_id: "out".into(),
                    row_id: 0,
                    values: values.clone(),
                    ..Default::default()
                })
                .collect(),
            output_digest: rows_digest(&output),
            quarantined: false,
            quality_rule: String::new(),
            ..Default::default()
        },
        "local",
    ))
    .await
    .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let usage = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);
}

#[tokio::test]
async fn scheduled_isolated_tick_meters_the_put_owner() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, ISOLATED_CLASS, rows_digest};

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(1),
                max_tokens_per_period: None,
                max_concurrency: None,
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    svc.put_governed_transform(with_tenant_admin(
        PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-sched".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                profile: ISOLATED_CLASS.into(),
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                schedule_every_ms: 1_000,
                ..Default::default()
            }),
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let ticked = svc
        .tick_governed_transforms(with_named_principal(
            TickGovernedTransformsRequest { now_ms: 1_500 },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .runs;
    assert_eq!(ticked.len(), 1);
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: ticked[0].run_id.clone(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    svc.write_transform_run_result(with_named_principal(
        WriteTransformRunResultRequest {
            run_id: work.run_id,
            runtime_id: work.claim_owner,
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token,
            rows: output
                .iter()
                .map(|values| TransformRunInputRow {
                    alias: String::new(),
                    dataset_id: "out".into(),
                    row_id: 0,
                    values: values.clone(),
                    ..Default::default()
                })
                .collect(),
            output_digest: rows_digest(&output),
            quarantined: false,
            quality_rule: String::new(),
            ..Default::default()
        },
        "local",
    ))
    .await
    .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let usage = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);
}

#[tokio::test]
async fn scheduled_in_process_tick_admits_owner_quota_before_run() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::CONTRACT_VERSION;

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(1),
                max_tokens_per_period: None,
                max_concurrency: None,
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    svc.put_governed_transform(with_tenant_admin(
        PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-inproc-sched".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: vec![TransformStep {
                    kind: "project".into(),
                    columns: vec!["id".into()],
                    ..Default::default()
                }],
                schedule_every_ms: 1_000,
                ..Default::default()
            }),
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let first = svc
        .tick_governed_transforms(with_named_principal(
            TickGovernedTransformsRequest { now_ms: 1_500 },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .runs;
    assert_eq!(first.len(), 1);
    let second = svc
        .tick_governed_transforms(with_named_principal(
            TickGovernedTransformsRequest { now_ms: 2_500 },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .runs;
    assert!(second.is_empty());
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let usage = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);
}

#[tokio::test]
async fn in_process_tick_retries_usage_after_commit() {
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::CONTRACT_VERSION;

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    svc.put_governed_transform(with_tenant_admin(
        PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-inproc-usage-retry".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: vec![TransformStep {
                    kind: "project".into(),
                    columns: vec!["id".into()],
                    ..Default::default()
                }],
                schedule_every_ms: 1_000,
                ..Default::default()
            }),
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let committed = runtime
        .commit_due_owned_in_process_transform("ops", "t-inproc-usage-retry", 1_500, "tenant-a")
        .unwrap()
        .expect("due owned in-process run");
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    assert_eq!(
        sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap()
            .measured,
        0
    );
    assert_eq!(
        runtime.list_transform_usage_pending().unwrap(),
        vec![(committed.run_id.clone(), "tenant-a".into(), 1_500)]
    );
    let ran = svc
        .tick_governed_transforms(with_named_principal(
            TickGovernedTransformsRequest { now_ms: 1_600 },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .runs;
    assert!(ran.is_empty());
    assert_eq!(
        sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap()
            .measured,
        1
    );
    let events = sqlite
        .list_usage_events_for_tenant("tenant-a", 0, i64::MAX, 10)
        .unwrap();
    assert_eq!(events[0].event_time_ms, 1_500);
    assert!(runtime.list_transform_usage_pending().unwrap().is_empty());
    svc.tick_governed_transforms(with_named_principal(
        TickGovernedTransformsRequest { now_ms: 1_700 },
        "local",
    ))
    .await
    .unwrap();
    assert_eq!(
        sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap()
            .measured,
        1
    );
}

#[tokio::test]
async fn triggered_in_process_defers_until_quota_tick() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::CONTRACT_VERSION;

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("mid")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(1),
                max_tokens_per_period: None,
                max_concurrency: None,
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    let project = |id: &str, input: &str, output: &str, trigger: bool| GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: id.into(),
        input_dataset_id: input.into(),
        output_dataset_id: output.into(),
        steps: vec![TransformStep {
            kind: "project".into(),
            columns: vec!["id".into()],
            ..Default::default()
        }],
        trigger_on_input_commit: trigger,
        ..Default::default()
    };
    svc.put_governed_transform(with_tenant_admin(
        PutGovernedTransformRequest {
            transform: Some(project("t-up", "in", "mid", false)),
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    svc.put_governed_transform(with_tenant_admin(
        PutGovernedTransformRequest {
            transform: Some(project("t-down", "mid", "out", true)),
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-up".into(),
            incremental: false,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let listed = svc
        .list_governed_transform_runs(with_principal(ListGovernedTransformRunsRequest {
            namespace: "ops".into(),
            limit: 10,
        }))
        .await
        .unwrap()
        .into_inner()
        .runs;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].transform_id, "t-up");
    let ticked = svc
        .tick_governed_transforms(with_named_principal(
            TickGovernedTransformsRequest { now_ms: 1_500 },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .runs;
    assert!(ticked.is_empty());
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let usage = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(usage.measured, 1);
}

#[tokio::test]
async fn isolated_claim_without_limits_binds_the_claiming_tenant() {
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, rows_digest,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-bind".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    let queued = runtime
        .run_governed_transform("ops", "t-iso-bind", false, 20)
        .unwrap();
    let claimed = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: queued.run_id.clone(),
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        runtime
            .transform_work_tenant(&queued.run_id)
            .unwrap()
            .as_deref(),
        Some("tenant-a")
    );
    let work = claimed.work.unwrap();
    assert_eq!(work.tenant_id, "tenant-a");
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    svc.write_transform_run_result(with_named_principal(
        WriteTransformRunResultRequest {
            run_id: work.run_id,
            runtime_id: work.claim_owner,
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token,
            rows: output
                .iter()
                .map(|values| TransformRunInputRow {
                    alias: String::new(),
                    dataset_id: "out".into(),
                    row_id: 0,
                    values: values.clone(),
                    ..Default::default()
                })
                .collect(),
            output_digest: rows_digest(&output),
            quarantined: false,
            quality_rule: String::new(),
            ..Default::default()
        },
        "local",
    ))
    .await
    .unwrap();
    let RuntimeDb::Sqlite(sqlite) = runtime else {
        panic!("sqlite");
    };
    let owner = sqlite
        .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
        .unwrap();
    assert_eq!(owner.measured, 1);
}

#[tokio::test]
async fn isolated_quota_exhaustion_leaves_work_claimable() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-deny".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(0),
                max_tokens_per_period: None,
                max_concurrency: None,
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-iso-deny".into(),
            incremental: false,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let denied = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
    let listed = svc
        .list_claimable_transform_work(with_named_principal(
            ListClaimableTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                limit: 10,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .work;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].tenant_id, "tenant-a");
}

#[tokio::test]
async fn untargeted_claim_skips_quota_denied_work_for_another_owner() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out-a")).unwrap();
    runtime.create_dataset(&dataset("out-b")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let isolated = |id: &str, output: &str| {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: id.into(),
            input_dataset_id: "in".into(),
            output_dataset_id: output.into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                inputs: Vec::new(),
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    };
    runtime
        .put_governed_transform_owned(&isolated("t-iso-a", "out-a"), 10, "tenant-a")
        .unwrap();
    runtime
        .put_governed_transform_owned(&isolated("t-iso-b", "out-b"), 11, "tenant-b")
        .unwrap();
    let gate = crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc());
    gate.configure(
        "tenant-a",
        &TenantQuotaLimits {
            version: 1,
            max_requests_per_period: Some(0),
            max_tokens_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        },
    )
    .unwrap();
    gate.configure(
        "tenant-b",
        &TenantQuotaLimits {
            version: 1,
            max_requests_per_period: Some(1),
            max_tokens_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        },
    )
    .unwrap();
    runtime
        .run_governed_transform_owned("ops", "t-iso-a", false, 20, "tenant-a", "")
        .unwrap();
    runtime
        .run_governed_transform_owned("ops", "t-iso-b", false, 21, "tenant-b", "")
        .unwrap();
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .work
        .unwrap();
    assert_eq!(claimed.transform_id, "t-iso-b");
    assert_eq!(claimed.tenant_id, "tenant-b");
}

struct IsolatedClaimExtension {
    deny: bool,
}

impl crate::enterprise::EnterpriseExtension for IsolatedClaimExtension {
    fn authenticate_bearer(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError> {
        (bearer_token == "enterprise-token")
            .then(|| crate::enterprise::AuthenticatedPrincipal {
                subject: "subject-a".into(),
                credential_id: "credential-a".into(),
            })
            .ok_or(crate::enterprise::ExtensionError::CredentialNotFound)
    }

    fn authenticate_context(
        &self,
        bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError> {
        let principal = self.authenticate_bearer(bearer_token)?;
        Ok(crate::enterprise::AuthenticatedContext {
            contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
            home_tenant: None,
            tenant: Some(self.tenant_context(&principal)?),
            principal,
            credential_kind: crate::enterprise::CredentialKind::HumanSession,
            space: None,
            space_role: None,
            act: None,
            scopes: vec!["sekai.read".into(), "sekai.write".into()],
            issuer: "https://issuer.test".into(),
            resource: "https://sekai.test".into(),
            expires_at: i64::MAX,
        })
    }

    fn tenant_context(
        &self,
        principal: &crate::enterprise::AuthenticatedPrincipal,
    ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
        Ok(crate::enterprise::TenantContext {
            tenant_id: "tenant-a".into(),
            subject: principal.subject.clone(),
        })
    }

    fn authorize_namespace(
        &self,
        _context: &crate::enterprise::TenantContext,
        _namespace: &str,
        _action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        Ok(())
    }

    fn authorize_unscoped_namespace(
        &self,
        _principal: &crate::enterprise::AuthenticatedPrincipal,
        _namespace: &str,
        _action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        Ok(())
    }

    fn admit_isolated_process_job(
        &self,
        _context: &crate::enterprise::AuthenticatedContext,
        _job: &crate::enterprise::IsolatedProcessJob,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        if self.deny {
            Err(crate::enterprise::ExtensionError::PermissionDenied)
        } else {
            Ok(())
        }
    }
}

fn isolated_claim_service(deny: bool) -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new_with_enterprise_extension(
            ":memory:",
            Some(Arc::new(IsolatedClaimExtension { deny })),
        )
        .unwrap(),
    )));
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
}

async fn enqueue_isolated_claim(svc: &SekaiServiceImpl, transform_id: &str) {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec,
    };

    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: transform_id.into(),
        input_dataset_id: "in".into(),
        output_dataset_id: "out".into(),
        steps: Vec::new(),
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: Some(IsolatedProcessSpec {
            engine: "python".into(),
            runtime_image: "runner:1".into(),
            inputs: Vec::new(),
        }),
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    runtime
        .put_governed_transform_owned(&transform, 10, "tenant-a")
        .unwrap();
    runtime
        .run_governed_transform_owned("ops", transform_id, false, 20, "tenant-a", "")
        .unwrap();
}

#[tokio::test]
async fn isolated_process_claim_is_admitted_by_the_enterprise_extension() {
    let svc = isolated_claim_service(false);
    enqueue_isolated_claim(&svc, "t-iso-admit").await;
    let claimed = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .work
        .unwrap();
    assert_eq!(claimed.transform_id, "t-iso-admit");
}

#[tokio::test]
async fn isolated_process_claim_skips_work_the_extension_denies() {
    let svc = isolated_claim_service(true);
    enqueue_isolated_claim(&svc, "t-iso-deny").await;
    let denied = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
    let listed = svc
        .list_claimable_transform_work(with_tenant_admin(
            ListClaimableTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                limit: 10,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .work;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].transform_id, "t-iso-deny");
}

#[tokio::test]
async fn scheduled_isolated_tick_claims_against_the_put_owner() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, TransformSchedule,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform_owned(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-sched".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: Some(TransformSchedule { every_ms: 1_000 }),
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
            "tenant-a",
        )
        .unwrap();
    let gate = crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc());
    gate.configure(
        "tenant-a",
        &TenantQuotaLimits {
            version: 1,
            max_requests_per_period: Some(0),
            max_tokens_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        },
    )
    .unwrap();
    svc.tick_governed_transforms(with_named_principal(
        TickGovernedTransformsRequest { now_ms: 1_500 },
        "local",
    ))
    .await
    .unwrap();
    let listed = svc
        .list_claimable_transform_work(with_named_principal(
            ListClaimableTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                limit: 10,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .work;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].tenant_id, "tenant-a");
    let denied = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn triggered_isolated_claim_uses_the_put_owner() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, TransformTrigger,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("mid")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform_owned(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-up".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "mid".into(),
                steps: vec![crate::sekai::governed_transform::TransformStep {
                    kind: "project".into(),
                    columns: vec!["id".into()],
                    ..Default::default()
                }],
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: None,
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
            "tenant-a",
        )
        .unwrap();
    runtime
        .put_governed_transform_owned(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-down".into(),
                input_dataset_id: "mid".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: Some(TransformTrigger {
                    on_input_commit: true,
                    debounce_ms: 0,
                }),
            }
            .prepare()
            .unwrap(),
            11,
            "tenant-a",
        )
        .unwrap();
    runtime
        .run_governed_transform_owned("ops", "t-up", false, 20, "tenant-a", "")
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(0),
                max_tokens_per_period: None,
                max_concurrency: None,
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    let listed = svc
        .list_claimable_transform_work(with_named_principal(
            ListClaimableTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                limit: 10,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .work;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].transform_id, "t-iso-down");
    assert_eq!(listed[0].tenant_id, "tenant-a");
    let denied = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn isolated_expired_claim_releases_concurrency_for_reclaim() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-conc".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: None,
                max_tokens_per_period: None,
                max_concurrency: Some(1),
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-iso-conc".into(),
            incremental: false,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    svc.claim_transform_work(with_tenant_admin(
        ClaimTransformWorkRequest {
            namespace: "ops".into(),
            runtime_id: "runner-a".into(),
            run_id: String::new(),
            ttl_ms: 1,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let reclaimed = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-b".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .work
        .unwrap();
    assert_eq!(reclaimed.claim_owner, "runner-b");
}

#[tokio::test]
async fn isolated_terminal_lease_failure_releases_concurrency() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, MAX_TRANSFORM_LEASE_EXPIRIES,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-term".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: None,
                max_tokens_per_period: None,
                max_concurrency: Some(1),
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-iso-term".into(),
            incremental: false,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    for attempt in 0..MAX_TRANSFORM_LEASE_EXPIRIES {
        svc.claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: format!("runner-{attempt}"),
                run_id: String::new(),
                ttl_ms: 1,
            },
            "tenant-a",
        ))
        .await
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let terminal = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-final".into(),
                run_id: String::new(),
                ttl_ms: 1,
            },
            "tenant-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(terminal.code(), tonic::Code::NotFound);
    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-iso-term".into(),
            incremental: false,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let next = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-next".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .work
        .unwrap();
    assert_eq!(next.claim_owner, "runner-next");
}

#[tokio::test]
async fn isolated_cancel_releases_concurrency_for_next_claim() {
    use crate::chisei::budget::PeriodType;
    use crate::chisei::tenant_quota::TenantQuotaLimits;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-iso-cancel".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    crate::composition::transform_run_admission::quota_gate(svc.db.runtime_arc())
        .configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: None,
                max_tokens_per_period: None,
                max_concurrency: Some(1),
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
    let queued = svc
        .run_governed_transform(with_tenant_admin(
            RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "t-iso-cancel".into(),
                incremental: false,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    svc.claim_transform_work(with_tenant_admin(
        ClaimTransformWorkRequest {
            namespace: "ops".into(),
            runtime_id: "runner-a".into(),
            run_id: queued.run_id.clone(),
            ttl_ms: 60_000,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    svc.cancel_governed_transform_run(with_tenant_admin(
        CancelGovernedTransformRunRequest {
            run_id: queued.run_id,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    svc.run_governed_transform(with_tenant_admin(
        RunGovernedTransformRequest {
            namespace: "ops".into(),
            transform_id: "t-iso-cancel".into(),
            incremental: false,
        },
        "tenant-a",
    ))
    .await
    .unwrap();
    let next = svc
        .claim_transform_work(with_tenant_admin(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-b".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "tenant-a",
        ))
        .await
        .unwrap()
        .into_inner()
        .work
        .unwrap();
    assert_eq!(next.claim_owner, "runner-b");
}

#[tokio::test]
async fn preview_governed_transform_returns_rows_without_committing() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        ANALYTICAL_CLASS, CONTRACT_VERSION, DEFAULT_PREVIEW_ROW_CAP, PREVIEW_ID_PREFIX,
        PREVIEW_ROW_CAP,
    };

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![
            ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
            ColumnDef {
                name: "keep".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
        ],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows(
            "in",
            &[
                HashMap::from([("id".into(), "1".into()), ("keep".into(), "yes".into())]),
                HashMap::from([("id".into(), "2".into()), ("keep".into(), "no".into())]),
            ],
        )
        .unwrap();
    let versions_before = runtime.list_dataset_versions("out").unwrap();
    let proto = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: "preview-t1".into(),
        input_dataset_id: "in".into(),
        output_dataset_id: "out".into(),
        steps: vec![TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }],
        profile: ANALYTICAL_CLASS.into(),
        ..GovernedTransform::default()
    };
    let preview = svc
        .preview_governed_transform(with_principal(PreviewGovernedTransformRequest {
            transform: Some(proto.clone()),
            row_cap: 0,
            preview_id: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(preview.preview_id.starts_with(PREVIEW_ID_PREFIX));
    assert_eq!(preview.rows.len(), 1);
    assert_eq!(
        preview.rows[0].values.get("id").map(String::as_str),
        Some("1")
    );
    assert_eq!(preview.inputs[0].rows_read, 2);
    assert!(preview.error.is_empty());
    assert_eq!(
        runtime.list_dataset_versions("out").unwrap(),
        versions_before
    );
    assert!(
        runtime
            .list_governed_transform_runs("ops", 10)
            .unwrap()
            .is_empty()
    );
    let missing = svc
        .get_governed_transform_run(with_principal(GetGovernedTransformRunRequest {
            run_id: preview.preview_id,
        }))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    let over_cap = svc
        .preview_governed_transform(with_principal(PreviewGovernedTransformRequest {
            transform: Some(proto),
            row_cap: (DEFAULT_PREVIEW_ROW_CAP as u32) + 2000,
            preview_id: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(over_cap.code(), tonic::Code::FailedPrecondition);
    assert_eq!(over_cap.message(), PREVIEW_ROW_CAP);
}

#[tokio::test]
async fn preview_governed_transform_denies_unreadable_input() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::CONTRACT_VERSION;

    let svc = service();
    let runtime = svc.db.runtime();
    runtime
        .create_object(&domain::Object {
            id: "secret-in".into(),
            kind: "artifact".into(),
            name: "in".into(),
            namespace: "ops".into(),
            external_id: "artifact:secret-in".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    runtime
        .create_dataset(&Dataset {
            id: "in".into(),
            name: "in".into(),
            columns: vec![ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: "secret-in".into(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    runtime
        .create_dataset(&Dataset {
            id: "out".into(),
            name: "out".into(),
            columns: vec![ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    let owner = security::Grant {
        id: "owner-in".into(),
        object_id: "secret-in".into(),
        principal: "bob".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    runtime.create_grant(&owner).unwrap();
    svc.security.add_grant(&owner);
    let denied = svc
        .preview_governed_transform(with_named_principal(
            PreviewGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    contract_version: CONTRACT_VERSION.into(),
                    namespace: "ops".into(),
                    transform_id: "preview-acl".into(),
                    input_dataset_id: "in".into(),
                    output_dataset_id: "out".into(),
                    steps: vec![TransformStep {
                        kind: "project".into(),
                        column: String::new(),
                        op: String::new(),
                        value: String::new(),
                        columns: vec!["id".into()],
                    }],
                    ..GovernedTransform::default()
                }),
                row_cap: 0,
                preview_id: String::new(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    let query = svc
        .query_rows(with_named_principal(
            QueryRowsRequest {
                dataset_id: "in".into(),
                query: None,
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(query.code(), denied.code());
}

#[tokio::test]
async fn preview_governed_transform_omits_ungranted_columns() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::CONTRACT_VERSION;
    use std::collections::BTreeMap;

    let svc = service();
    let runtime = svc.db.runtime();
    runtime
        .create_object(&domain::Object {
            id: "bound-in".into(),
            kind: "artifact".into(),
            name: "in".into(),
            namespace: "ops".into(),
            external_id: "artifact:bound-in".into(),
            properties: HashMap::from([("id".into(), "1".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    runtime
        .create_dataset(&Dataset {
            id: "in".into(),
            name: "in".into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "note".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
            ],
            object_id: "bound-in".into(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    runtime
        .create_dataset(&Dataset {
            id: "out".into(),
            name: "out".into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "note".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
            ],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    runtime
        .append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("note".into(), "hidden".into()),
            ])],
        )
        .unwrap();
    let owner = security::Grant {
        id: "owner-in".into(),
        object_id: "bound-in".into(),
        principal: "alice".into(),
        role: security::Role::Viewer,
        created: 0,
        ..Default::default()
    };
    runtime.create_grant(&owner).unwrap();
    svc.security.add_grant(&owner);
    let grants = crate::sekai::object_security::ObjectSecurityPolicy {
        contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: "ops".into(),
        kind: "artifact".into(),
        rules: vec![crate::sekai::object_security::ObjectSecurityRule {
            operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
            predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: Some(vec![crate::sekai::object_security::PropertyGrant {
            property: "id".into(),
            access: crate::sekai::object_security::PropertyGrantAccess::Read,
        }]),
        value_instance_grants: None,
        required_purpose: None,
    };
    let revision = runtime
        .put_object_security_policy(&grants, "root", "put-preview-cols", 1)
        .unwrap();
    runtime
        .activate_object_security_policies(
            "ops",
            &BTreeMap::from([("artifact".into(), revision.revision_digest)]),
            "root",
            "activate-preview-cols",
            2,
        )
        .unwrap();
    let preview = svc
        .preview_governed_transform(with_named_principal(
            PreviewGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    contract_version: CONTRACT_VERSION.into(),
                    namespace: "ops".into(),
                    transform_id: "preview-cols".into(),
                    input_dataset_id: "in".into(),
                    output_dataset_id: "out".into(),
                    steps: vec![TransformStep {
                        kind: "project".into(),
                        column: String::new(),
                        op: String::new(),
                        value: String::new(),
                        columns: vec!["id".into(), "note".into()],
                    }],
                    ..GovernedTransform::default()
                }),
                row_cap: 0,
                preview_id: String::new(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(preview.rows.len(), 1);
    assert_eq!(
        preview.rows[0].values.get("id").map(String::as_str),
        Some("1")
    );
    assert!(!preview.rows[0].values.contains_key("note"));
}

#[tokio::test]
async fn preview_isolated_process_is_claimed_without_commit() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, ISOLATED_CLASS, PREVIEW_ID_PREFIX, rows_digest,
    };
    use futures_util::StreamExt;

    let svc = service();
    let runtime = svc.db.runtime();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let preview = svc
        .preview_governed_transform(with_named_principal(
            PreviewGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    contract_version: CONTRACT_VERSION.into(),
                    namespace: "ops".into(),
                    transform_id: "iso-preview".into(),
                    input_dataset_id: "in".into(),
                    output_dataset_id: "out".into(),
                    profile: ISOLATED_CLASS.into(),
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    ..GovernedTransform::default()
                }),
                row_cap: 256,
                preview_id: String::new(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(preview.preview_id.starts_with(PREVIEW_ID_PREFIX));
    assert!(preview.rows.is_empty());
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: preview.preview_id.clone(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let mut stream = svc
        .read_transform_run_inputs(with_named_principal(
            ReadTransformRunInputsRequest {
                run_id: work.run_id.clone(),
                runtime_id: work.claim_owner.clone(),
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token.clone(),
                alias: String::new(),
                after_row_id: 0,
                limit: 100,
                after_alias: String::new(),
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let mut rows = Vec::new();
    while let Some(item) = stream.next().await {
        rows.push(item.unwrap().row.unwrap());
    }
    assert_eq!(rows.len(), 1);
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    let written = svc
        .write_transform_run_result(with_named_principal(
            WriteTransformRunResultRequest {
                run_id: work.run_id.clone(),
                runtime_id: work.claim_owner.clone(),
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token.clone(),
                rows: output
                    .iter()
                    .map(|values| TransformRunInputRow {
                        alias: String::new(),
                        dataset_id: "out".into(),
                        row_id: 0,
                        values: values.clone(),
                        ..Default::default()
                    })
                    .collect(),
                output_digest: rows_digest(&output),
                quarantined: false,
                quality_rule: String::new(),
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap();
    assert_eq!(written.dispatch_status, "completed");
    let retrieved = svc
        .preview_governed_transform(with_named_principal(
            PreviewGovernedTransformRequest {
                preview_id: preview.preview_id.clone(),
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(retrieved.preview_id, preview.preview_id);
    assert_eq!(retrieved.rows.len(), 1);
    assert_eq!(
        retrieved.rows[0].values.get("id").map(String::as_str),
        Some("1")
    );
    assert!(
        runtime
            .query_rows("out", &crate::sekai::dataset::RowQuery::default())
            .unwrap()
            .is_empty()
    );
    assert!(
        runtime
            .list_governed_transform_runs("ops", 10)
            .unwrap()
            .is_empty()
    );
    let stale = svc
        .write_transform_run_result(with_named_principal(
            WriteTransformRunResultRequest {
                run_id: work.run_id,
                runtime_id: "other".into(),
                claim_generation: work.claim_generation,
                fencing_token: "stale".into(),
                rows: output
                    .iter()
                    .map(|values| TransformRunInputRow {
                        alias: String::new(),
                        dataset_id: "out".into(),
                        row_id: 0,
                        values: values.clone(),
                        ..Default::default()
                    })
                    .collect(),
                output_digest: rows_digest(&output),
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    assert!(
        runtime
            .query_rows("out", &crate::sekai::dataset::RowQuery::default())
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn preview_retrieve_denies_unreadable_input() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, ISOLATED_CLASS, rows_digest};
    use crate::sekai::security;

    let svc = service();
    let runtime = svc.db.runtime();
    runtime
        .create_object(&domain::Object {
            id: "secret-in".into(),
            kind: "artifact".into(),
            name: "in".into(),
            namespace: "ops".into(),
            external_id: "artifact:secret-in".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    runtime
        .create_dataset(&Dataset {
            id: "in".into(),
            name: "in".into(),
            columns: vec![ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: "secret-in".into(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    runtime
        .create_dataset(&Dataset {
            id: "out".into(),
            name: "out".into(),
            columns: vec![ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let owner = security::Grant {
        id: "owner-in".into(),
        object_id: "secret-in".into(),
        principal: "local".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    runtime.create_grant(&owner).unwrap();
    svc.security.add_grant(&owner);
    let preview = svc
        .preview_governed_transform(with_named_principal(
            PreviewGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    contract_version: CONTRACT_VERSION.into(),
                    namespace: "ops".into(),
                    transform_id: "iso-preview-acl".into(),
                    input_dataset_id: "in".into(),
                    output_dataset_id: "out".into(),
                    profile: ISOLATED_CLASS.into(),
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    ..GovernedTransform::default()
                }),
                row_cap: 256,
                preview_id: String::new(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let claimed = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: preview.preview_id.clone(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    let work = claimed.work.unwrap();
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    svc.write_transform_run_result(with_named_principal(
        WriteTransformRunResultRequest {
            run_id: work.run_id.clone(),
            runtime_id: work.claim_owner.clone(),
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token.clone(),
            rows: output
                .iter()
                .map(|values| TransformRunInputRow {
                    alias: String::new(),
                    dataset_id: "out".into(),
                    row_id: 0,
                    values: values.clone(),
                    ..Default::default()
                })
                .collect(),
            output_digest: rows_digest(&output),
            ..Default::default()
        },
        "local",
    ))
    .await
    .unwrap();
    let denied = svc
        .preview_governed_transform(with_named_principal(
            PreviewGovernedTransformRequest {
                preview_id: preview.preview_id.clone(),
                ..Default::default()
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
}

fn seed_inspect_action_type(svc: &SekaiServiceImpl, namespace: &str) {
    svc.db
        .runtime()
        .put_governed_action_type(
            crate::sekai::governed_action_type::GovernedActionType {
                namespace: namespace.into(),
                type_id: "Ticket.inspect".into(),
                version: "1".into(),
                description: "inspect one ticket".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![
                    crate::sekai::governed_action_type::EFFECT_KIND_NOTIFY.into(),
                ],
                enabled: true,
                ..Default::default()
            },
            "root",
            1,
        )
        .unwrap();
}

async fn seed_agent_draft(svc: &SekaiServiceImpl, namespace: &str) -> String {
    let parent = seed_definition_parent(svc, namespace);
    grant_source_namespace(svc, namespace, "root", security::Role::Admin);
    grant_source_namespace(svc, namespace, "reviewer", security::Role::Admin);
    for principal in ["root", "reviewer"] {
        svc.security.add_grant(&security::Grant {
            id: format!("{namespace}-{principal}-agent-admin"),
            object_id: "schema:agent:triage".into(),
            principal: principal.into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        });
    }
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: format!("create-{namespace}"),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.apply_definition_branch_edit(with_named_principal(
        ApplyDefinitionBranchEditRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            expected_head_digest: parent.revision_digest.clone(),
            upserts: vec![DefinitionMemberInput {
                member_kind: "agent".into(),
                member_id: "triage".into(),
                member_digest: String::new(),
                definition_json: serde_json::json!({
                    "contract_version": "sekai.agent-definition/v1",
                    "name": "Triage",
                    "task_class": "lookup",
                    "instructions": "Inspect records.",
                    "allowed_action_types": ["Ticket.inspect"]
                })
                .to_string(),
            }],
            removals: Vec::new(),
            idempotency_key: format!("edit-{namespace}"),
        },
        "root",
    ))
    .await
    .unwrap()
    .into_inner()
    .revision
    .unwrap()
    .revision_digest
}

#[tokio::test]
async fn agent_dry_run_proposes_actions_without_submitting_and_refuses_disallowed_types() {
    let mut svc = service();
    let namespace = "agent-dry-run-submit";
    let digest = seed_agent_draft(&svc, namespace).await;
    seed_inspect_action_type(&svc, namespace);
    let host = std::sync::Arc::new(crate::sekai::agent_dry_run::ScriptedHost {
        route: Ok("native/scripted".into()),
        budget: Ok(()),
        reply: crate::sekai::agent_dry_run::DryRunModelReply {
            route: "native/scripted".into(),
            output: "scripted".into(),
            tool_calls: vec![crate::sekai::agent_dry_run::ToolCall {
                name: "lookup".into(),
                arguments_json: r#"{"id":"1"}"#.into(),
            }],
            proposed_actions: vec![
                crate::sekai::agent_dry_run::ProposedAction {
                    action_type: "Ticket.inspect".into(),
                    parameters_json: r#"{"id":"1"}"#.into(),
                },
                crate::sekai::agent_dry_run::ProposedAction {
                    action_type: "Ticket.close".into(),
                    parameters_json: "{}".into(),
                },
            ],
        },
        attempts: std::sync::atomic::AtomicUsize::new(0),
    });
    svc.dry_run_host = Some(host);
    let response = svc
        .dry_run_agent(with_named_principal(
            DryRunAgentRequest {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
                member_id: "triage".into(),
                input: "inspect ticket 1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.actions.len(), 2);
    assert_eq!(response.actions[0].disposition, "would_submit");
    assert_eq!(response.actions[0].action_type, "Ticket.inspect");
    assert_eq!(response.actions[1].disposition, "refused");
    assert_eq!(response.actions[1].reason, "action_type_not_allowed");
    assert_eq!(response.model_steps[0].route, "native/scripted");
    assert_eq!(response.tool_calls[0].name, "lookup");
    let instances = svc
        .list_action_instances(with_named_principal(
            ListActionInstancesRequest {
                namespace: namespace.into(),
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(instances.instances.is_empty());
    let effects = svc
        .list_action_effects(with_named_principal(
            ListActionEffectsRequest {
                namespace: namespace.into(),
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(effects.effects.is_empty());
    let run = svc
        .db
        .runtime()
        .get_eval_run_record(&response.record_id)
        .unwrap()
        .expect("dry-run record");
    assert!(crate::sekai::agent_dry_run::run_is_dry_run(
        &run.config_ref,
        &run.suite_id
    ));
}

#[tokio::test]
async fn agent_dry_run_matches_definition_member_unavailable_and_cannot_certify() {
    let mut svc = service();
    let namespace = "agent-dry-run-auth";
    let digest = seed_agent_draft(&svc, namespace).await;
    let host = std::sync::Arc::new(crate::sekai::agent_dry_run::ScriptedHost::proposing(vec![
        crate::sekai::agent_dry_run::ProposedAction {
            action_type: "Ticket.inspect".into(),
            parameters_json: "{}".into(),
        },
    ]));
    svc.dry_run_host = Some(host);
    let denied_member = svc
        .get_definition_member(with_named_principal(
            GetDefinitionMemberRequest {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
                member_kind: "agent".into(),
                member_id: "triage".into(),
            },
            "stranger",
        ))
        .await
        .unwrap_err();
    let denied_dry_run = svc
        .dry_run_agent(with_named_principal(
            DryRunAgentRequest {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
                member_id: "triage".into(),
                input: "inspect".into(),
            },
            "stranger",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied_dry_run.code(), denied_member.code());
    assert_eq!(denied_dry_run.message(), denied_member.message());
    let published = svc
        .dry_run_agent(with_named_principal(
            DryRunAgentRequest {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
                member_id: "triage".into(),
                input: "inspect".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let expires = now_millis() + 86_400_000;
    let refused = svc
        .put_definition_certification(with_named_principal(
            PutDefinitionCertificationRequest {
                namespace: namespace.into(),
                revision_digest: digest,
                suite_id: format!("dry_run:{namespace}:triage"),
                certification_id: published.record_id,
                baseline_status: "pass".into(),
                latest_status: "pass".into(),
                expires_at_ms: expires,
                revoked_at_ms: 0,
            },
            "reviewer",
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        refused.message(),
        crate::sekai::agent_dry_run::REFUSAL_DRY_RUN
    );
}

#[tokio::test]
async fn agent_dry_run_reports_admission_and_budget_failures_once() {
    let mut svc = service();
    let namespace = "agent-dry-run-guards";
    let digest = seed_agent_draft(&svc, namespace).await;
    let admission = std::sync::Arc::new(crate::sekai::agent_dry_run::ScriptedHost {
        route: Err("model_review.not_enabled".into()),
        budget: Ok(()),
        reply: crate::sekai::agent_dry_run::DryRunModelReply {
            route: String::new(),
            output: String::new(),
            tool_calls: Vec::new(),
            proposed_actions: Vec::new(),
        },
        attempts: std::sync::atomic::AtomicUsize::new(0),
    });
    svc.dry_run_host = Some(admission.clone());
    let denied = svc
        .dry_run_agent(with_named_principal(
            DryRunAgentRequest {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
                member_id: "triage".into(),
                input: "inspect".into(),
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::FailedPrecondition);
    assert_eq!(denied.message(), "model_review.not_enabled");
    assert_eq!(admission.attempts(), 1);
    let budget = std::sync::Arc::new(crate::sekai::agent_dry_run::ScriptedHost {
        route: Ok("native/scripted".into()),
        budget: Err("budget exceeded".into()),
        reply: crate::sekai::agent_dry_run::DryRunModelReply {
            route: String::new(),
            output: String::new(),
            tool_calls: Vec::new(),
            proposed_actions: Vec::new(),
        },
        attempts: std::sync::atomic::AtomicUsize::new(0),
    });
    svc.dry_run_host = Some(budget.clone());
    let limited = svc
        .dry_run_agent(with_named_principal(
            DryRunAgentRequest {
                namespace: namespace.into(),
                revision_digest: digest,
                member_id: "triage".into(),
                input: "inspect".into(),
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(limited.code(), tonic::Code::FailedPrecondition);
    assert_eq!(limited.message(), "budget exceeded");
    assert_eq!(budget.attempts(), 1);
}

#[tokio::test]
async fn agent_dry_run_default_host_checks_admission_then_refuses_without_a_completion_host() {
    let svc = service();
    let namespace = "agent-dry-run-default-host";
    let digest = seed_agent_draft(&svc, namespace).await;
    let missing_route = svc
        .dry_run_agent(with_named_principal(
            DryRunAgentRequest {
                namespace: namespace.into(),
                revision_digest: digest.clone(),
                member_id: "triage".into(),
                input: "inspect".into(),
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(missing_route.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        missing_route.message(),
        crate::chisei::model_review::REFUSAL_NOT_ENABLED
    );
    svc.db
        .runtime()
        .insert_family_enablement_record_if_absent(
            &crate::chisei::model_review::FamilyEnablementRecord {
                namespace: namespace.into(),
                region_label: String::new(),
                family_id: "native".into(),
                status: crate::chisei::model_review::ModelReviewStatus::Enabled,
                actor: "root".into(),
                reason: "admit dry run".into(),
                updated_at_ms: 1,
            },
        )
        .unwrap();
    let no_host = svc
        .dry_run_agent(with_named_principal(
            DryRunAgentRequest {
                namespace: namespace.into(),
                revision_digest: digest,
                member_id: "triage".into(),
                input: "inspect".into(),
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(no_host.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        no_host.message(),
        crate::sekai::agent_dry_run::REFUSAL_MODEL_UNAVAILABLE
    );
}

#[tokio::test]
async fn agent_dry_run_namespace_revocation_overrides_global_enablement() {
    let svc = service();
    let namespace = "agent-dry-run-revoked-family";
    let digest = seed_agent_draft(&svc, namespace).await;
    svc.db
        .runtime()
        .insert_family_enablement_record_if_absent(
            &crate::chisei::model_review::FamilyEnablementRecord {
                namespace: String::new(),
                region_label: String::new(),
                family_id: "native".into(),
                status: crate::chisei::model_review::ModelReviewStatus::Enabled,
                actor: "root".into(),
                reason: "global enable".into(),
                updated_at_ms: 1,
            },
        )
        .unwrap();
    svc.db
        .runtime()
        .insert_family_enablement_record_if_absent(
            &crate::chisei::model_review::FamilyEnablementRecord {
                namespace: namespace.into(),
                region_label: String::new(),
                family_id: "native".into(),
                status: crate::chisei::model_review::ModelReviewStatus::Revoked,
                actor: "root".into(),
                reason: "namespace revoke".into(),
                updated_at_ms: 2,
            },
        )
        .unwrap();
    let denied = svc
        .dry_run_agent(with_named_principal(
            DryRunAgentRequest {
                namespace: namespace.into(),
                revision_digest: digest,
                member_id: "triage".into(),
                input: "inspect".into(),
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        denied.message(),
        crate::chisei::model_review::REFUSAL_NOT_ENABLED
    );
}

#[tokio::test]
async fn agent_dry_run_refuses_allowed_actions_that_fail_the_type_schema() {
    let mut svc = service();
    let namespace = "agent-dry-run-schema";
    let digest = seed_agent_draft(&svc, namespace).await;
    seed_inspect_action_type(&svc, namespace);
    svc.dry_run_host = Some(std::sync::Arc::new(
        crate::sekai::agent_dry_run::ScriptedHost::proposing(vec![
            crate::sekai::agent_dry_run::ProposedAction {
                action_type: "Ticket.inspect".into(),
                parameters_json: "{}".into(),
            },
        ]),
    ));
    let response = svc
        .dry_run_agent(with_named_principal(
            DryRunAgentRequest {
                namespace: namespace.into(),
                revision_digest: digest,
                member_id: "triage".into(),
                input: "inspect".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.actions[0].disposition, "refused");
    assert_eq!(
        response.actions[0].reason,
        crate::sekai::agent_dry_run::REFUSAL_INVALID_PARAMETERS
    );
}

#[tokio::test]
async fn write_freeze_refuses_in_scope_writes_and_records_receipts() {
    let svc = service();
    svc.set_write_freeze(with_named_principal(
        SetWriteFreezeRequest {
            freeze: Some(WriteFreeze {
                scope_kind: "namespace".into(),
                scope_value: "ops".into(),
                mode: "block_writes".into(),
                reason: "incident".into(),
                enabled: true,
                updated_ms: 0,
            }),
        },
        "local",
    ))
    .await
    .unwrap();

    let listed = svc
        .list_write_freezes(with_named_principal(ListWriteFreezesRequest {}, "local"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.freezes.len(), 1);
    assert!(listed.freezes[0].enabled);

    let mut frozen = widget_object(
        "frozen-widget",
        HashMap::from([("name".into(), "frozen".into())]),
    );
    frozen.namespace = "ops".into();
    let refused = svc
        .create_object(with_principal(CreateObjectRequest {
            object: Some(frozen),
            lease_precondition: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused
            .message()
            .contains("write freeze (namespace/ops/block_writes)")
    );

    let mut outside = widget_object(
        "live-widget",
        HashMap::from([("name".into(), "live".into())]),
    );
    outside.namespace = "other".into();
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(outside),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    svc.set_write_freeze(with_named_principal(
        SetWriteFreezeRequest {
            freeze: Some(WriteFreeze {
                scope_kind: "namespace".into(),
                scope_value: "ops".into(),
                mode: "block_writes".into(),
                reason: "lifted".into(),
                enabled: false,
                updated_ms: 0,
            }),
        },
        "local",
    ))
    .await
    .unwrap();

    let mut thawed = widget_object(
        "thawed-widget",
        HashMap::from([("name".into(), "thawed".into())]),
    );
    thawed.namespace = "ops".into();
    svc.create_object(with_principal(CreateObjectRequest {
        object: Some(thawed),
        lease_precondition: None,
    }))
    .await
    .unwrap();

    let receipts = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            action: Some("write_freeze".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    let outcomes: Vec<&str> = receipts
        .iter()
        .map(|decision| decision.outcome.as_str())
        .collect();
    assert!(outcomes.contains(&"enabled"), "{outcomes:?}");
    assert!(outcomes.contains(&"disabled"), "{outcomes:?}");
}

#[tokio::test]
async fn write_freeze_refuses_source_batch_in_scope() {
    let svc = service();
    let namespace = "sync-frozen";
    let producer = "connector/github-primary";
    grant_source_namespace(&svc, namespace, producer, security::Role::Editor);
    svc.set_write_freeze(with_named_principal(
        SetWriteFreezeRequest {
            freeze: Some(WriteFreeze {
                scope_kind: "namespace".into(),
                scope_value: namespace.into(),
                mode: "block_writes".into(),
                reason: "incident".into(),
                enabled: true,
                updated_ms: 0,
            }),
        },
        "local",
    ))
    .await
    .unwrap();

    let refused = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(source_batch(
                    namespace,
                    producer,
                    "",
                    "cursor:1",
                    "batch-frozen",
                )),
            },
            producer,
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused
            .message()
            .contains("write freeze (namespace/sync-frozen/block_writes)")
    );

    svc.set_write_freeze(with_named_principal(
        SetWriteFreezeRequest {
            freeze: Some(WriteFreeze {
                scope_kind: "namespace".into(),
                scope_value: namespace.into(),
                mode: "block_writes".into(),
                reason: "lifted".into(),
                enabled: false,
                updated_ms: 0,
            }),
        },
        "local",
    ))
    .await
    .unwrap();

    let admitted = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(source_batch(
                    namespace,
                    producer,
                    "",
                    "cursor:1",
                    "batch-frozen",
                )),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(admitted.transaction.as_ref().unwrap().status, "COMMITTED");
}

#[tokio::test]
async fn write_freeze_blocks_source_batch_when_registered_tenant_is_frozen() {
    let svc = service();
    let namespace = "sync-tenant-frozen";
    let producer = "github-primary";
    grant_source_namespace(&svc, namespace, producer, security::Role::Editor);
    svc.db
        .runtime()
        .put_service_principal(
            &crate::sekai::service_principal::ServicePrincipalRegistration {
                principal: producer.into(),
                tenant_id: "acme-tenant".into(),
                namespaces: vec![namespace.into()],
                action_types: vec!["dispatch".into()],
                registered_by: "local".into(),
                created_at_ms: 1,
                updated_at_ms: 1,
            },
        )
        .unwrap();
    svc.set_write_freeze(with_named_principal(
        SetWriteFreezeRequest {
            freeze: Some(WriteFreeze {
                scope_kind: "tenant".into(),
                scope_value: "acme-tenant".into(),
                mode: "block_writes".into(),
                reason: "incident".into(),
                enabled: true,
                updated_ms: 0,
            }),
        },
        "local",
    ))
    .await
    .unwrap();

    let refused = svc
        .apply_source_batch(with_named_principal(
            ApplySourceBatchRequest {
                batch: Some(source_batch(
                    namespace,
                    producer,
                    "",
                    "cursor:1",
                    "batch-tenant-frozen",
                )),
            },
            producer,
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused
            .message()
            .contains("write freeze (tenant/acme-tenant/block_writes)")
    );
}

#[tokio::test]
async fn write_freeze_blocks_machine_action_submit() {
    let svc = service();
    grant_action_admin(&svc);
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            approvers: Vec::new(),
            namespace: "acme".into(),
            type_id: "dispatch".into(),
            version: "1".into(),
            description: "dispatch work".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["runtime_dispatch".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            object_kind: String::new(),
            object_mutation: String::new(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
            system_one_json: String::new(),
            review_queue_id: String::new(),
            review_sla_ms: 0,
            review_escalate: String::new(),
            review_escalate_to: String::new(),
            review_threshold_param: String::new(),
            review_threshold: 0,
            review_pool: vec![],
            review_agent_reviewers: vec![],
        }),
        request_id: "put-freeze-dispatch".into(),
    }))
    .await
    .unwrap();
    svc.set_write_freeze(with_named_principal(
        SetWriteFreezeRequest {
            freeze: Some(WriteFreeze {
                scope_kind: "namespace".into(),
                scope_value: "acme".into(),
                mode: "block_agent_actions".into(),
                reason: "incident".into(),
                enabled: true,
                updated_ms: 0,
            }),
        },
        "local",
    ))
    .await
    .unwrap();

    svc.submit_action_instance(with_principal(SubmitActionInstanceRequest {
        namespace: "acme".into(),
        type_id: "dispatch".into(),
        version: "1".into(),
        parameters_json: r#"{"runtime":"shikigami"}"#.into(),
        idempotency_key: "freeze-human".into(),
        evidence_submission_ids: Vec::new(),
        request_id: "req-freeze-human".into(),
        ontology_digest: String::new(),
    }))
    .await
    .unwrap();

    let mut machine = with_named_principal(
        SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "dispatch".into(),
            version: "1".into(),
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            idempotency_key: "freeze-machine".into(),
            evidence_submission_ids: Vec::new(),
            request_id: "req-freeze-machine".into(),
            ontology_digest: String::new(),
        },
        "tester",
    );
    machine
        .extensions_mut()
        .insert(crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: "tester".into(),
                credential_id: "community-credential".into(),
            },
        ));
    let refused = svc.submit_action_instance(machine).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused
            .message()
            .contains("write freeze (namespace/acme/block_agent_actions)")
    );
}

#[test]
fn write_freeze_blocks_shared_space_write_when_owner_tenant_is_frozen() {
    let extension = Arc::new(SharedSpaceExtension::granting());
    let db = RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(":memory:", Some(extension)).unwrap(),
    ));
    db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
        scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
        scope_value: "tenant-test".into(),
        mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
        reason: "incident".into(),
        enabled: true,
        updated_ms: 1,
    })
    .unwrap();
    let object = domain::Object {
        id: "w-owner-freeze".into(),
        kind: "widget".into(),
        name: "w-owner-freeze".into(),
        namespace: "ops".into(),
        external_id: String::new(),
        properties: HashMap::from([(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "internal".into(),
        )]),
        created: 0,
        updated: 0,
    };
    let member = crate::enterprise::AuthenticatedContext {
        space_role: Some(crate::enterprise::SpaceRole::Editor),
        ..shared_space_member()
    };
    let refused = enforce_object_operation_access(
        &db,
        &object,
        &["subject-a".into()],
        Some(&member),
        crate::sekai::object_security::ObjectSecurityOperation::Update,
        "op-owner-freeze",
        None,
    )
    .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused
            .message()
            .contains("write freeze (tenant/tenant-test/block_writes)")
    );
}

#[test]
fn write_freeze_blocks_object_write_when_registered_tenant_is_frozen() {
    let db = RuntimeDb::memory();
    db.put_service_principal(
        &crate::sekai::service_principal::ServicePrincipalRegistration {
            principal: "worker-a".into(),
            tenant_id: "acme-tenant".into(),
            namespaces: vec!["ops".into()],
            action_types: vec!["dispatch".into()],
            registered_by: "local".into(),
            created_at_ms: 1,
            updated_at_ms: 1,
        },
    )
    .unwrap();
    db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
        scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
        scope_value: "acme-tenant".into(),
        mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
        reason: "incident".into(),
        enabled: true,
        updated_ms: 1,
    })
    .unwrap();
    let object = domain::Object {
        id: "w-registered-tenant-freeze".into(),
        kind: "widget".into(),
        name: "w-registered-tenant-freeze".into(),
        namespace: "ops".into(),
        external_id: String::new(),
        properties: HashMap::from([(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "internal".into(),
        )]),
        created: 0,
        updated: 0,
    };
    let refused = enforce_object_operation_access(
        &db,
        &object,
        &["worker-a".into()],
        None,
        crate::sekai::object_security::ObjectSecurityOperation::Update,
        "op-registered-tenant-freeze",
        None,
    )
    .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused
            .message()
            .contains("write freeze (tenant/acme-tenant/block_writes)")
    );
}

#[tokio::test]
async fn apply_streaming_transform_batch_is_fenced_and_idempotent() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec,
    };
    use crate::sekai::schema::{ObjectType, PropertyDef, PropertyType};

    let svc = service();
    let runtime = svc.db.runtime();
    runtime
        .upsert_object_type(&ObjectType {
            kind: "stream_record".into(),
            description: "fixture".into(),
            properties: vec![PropertyDef {
                name: "n".into(),
                prop_type: PropertyType::String,
                required: false,
                description: String::new(),
                enum_values: vec![],
                link_kind: String::new(),
                compute_expr: String::new(),
                classification: "public".into(),
                struct_fields: vec![],
            }],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
    runtime
        .put_governed_action_type(
            GovernedActionType {
                namespace: "ops".into(),
                type_id: "stream.record.create".into(),
                version: "1".into(),
                description: "create".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"n":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
                object_kind: "stream_record".into(),
                object_mutation: crate::sekai::governed_action_type::OBJECT_MUTATION_CREATE.into(),
                enabled: true,
                created_by: "alice".into(),
                created_at_ms: 1,
                updated_at_ms: 1,
                ..Default::default()
            },
            "alice",
            5,
        )
        .unwrap();
    let dataset = |id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in")).unwrap();
    runtime.create_dataset(&dataset("out")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "iso-stream".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    runtime
        .run_governed_transform("ops", "iso-stream", false, 20)
        .unwrap();
    let work = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .work
        .unwrap();
    let apply_req = || ApplyStreamingTransformBatchRequest {
        run_id: work.run_id.clone(),
        runtime_id: work.claim_owner.clone(),
        claim_generation: work.claim_generation,
        fencing_token: work.fencing_token.clone(),
        checkpoint: "c0".into(),
        action_type_id: "stream.record.create".into(),
        action_type_version: "1".into(),
        edits: vec![StreamingTransformObjectEdit {
            object_id: "rec-0".into(),
            name: "rec-0".into(),
            properties: HashMap::from([("n".into(), "0".into())]),
        }],
        input_positions: vec![StreamingTransformInputPosition {
            source: "src".into(),
            position: "c0".into(),
        }],
    };
    let first = svc
        .apply_streaming_transform_batch(with_named_principal(apply_req(), "local"))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert!(!first.replay);
    assert_eq!(first.objects[0].object_id, "rec-0");
    let replay = svc
        .apply_streaming_transform_batch(with_named_principal(apply_req(), "local"))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert!(replay.replay);
    assert_eq!(replay.objects, first.objects);
    let mut stale = apply_req();
    stale.checkpoint = "c1".into();
    stale.claim_generation = work.claim_generation.saturating_sub(1);
    stale.edits[0].object_id = "rec-1".into();
    let fenced = svc
        .apply_streaming_transform_batch(with_named_principal(stale, "local"))
        .await
        .unwrap_err();
    assert_eq!(fenced.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        fenced.message(),
        crate::sekai::governed_transform::STALE_TRANSFORM_CLAIM
    );
    assert!(runtime.get_object("rec-1").unwrap().is_none());
}

#[tokio::test]
async fn apply_streaming_transform_batch_stamps_markings_and_refuses_declassify() {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec,
    };
    use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
    use crate::sekai::schema::{ObjectType, PropertyDef, PropertyType};

    let svc = service();
    let runtime = svc.db.runtime();
    runtime
        .upsert_object_type(&ObjectType {
            kind: "stream_record".into(),
            description: "fixture".into(),
            properties: vec![PropertyDef {
                name: "n".into(),
                prop_type: PropertyType::String,
                required: false,
                description: String::new(),
                enum_values: vec![],
                link_kind: String::new(),
                compute_expr: String::new(),
                classification: "public".into(),
                struct_fields: vec![],
            }],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
    let marked_schema = r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"n":{"type":"string"},"access_marking":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#;
    runtime
        .put_governed_action_type(
            GovernedActionType {
                namespace: "ops".into(),
                type_id: "stream.record.create".into(),
                version: "1".into(),
                description: "create".into(),
                parameter_schema_json: marked_schema.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
                object_kind: "stream_record".into(),
                object_mutation: crate::sekai::governed_action_type::OBJECT_MUTATION_CREATE.into(),
                enabled: true,
                created_by: "alice".into(),
                created_at_ms: 1,
                updated_at_ms: 1,
                ..Default::default()
            },
            "alice",
            5,
        )
        .unwrap();
    runtime
        .put_governed_action_type(
            GovernedActionType {
                namespace: "ops".into(),
                type_id: "stream.record.update".into(),
                version: "1".into(),
                description: "update".into(),
                parameter_schema_json: marked_schema.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
                object_kind: "stream_record".into(),
                object_mutation: crate::sekai::governed_action_type::OBJECT_MUTATION_UPDATE.into(),
                enabled: true,
                created_by: "alice".into(),
                created_at_ms: 1,
                updated_at_ms: 1,
                ..Default::default()
            },
            "alice",
            6,
        )
        .unwrap();
    runtime
        .create_object(&crate::domain::Object {
            id: "in-obj".into(),
            kind: "stream_record".into(),
            name: "in-obj".into(),
            namespace: "ops".into(),
            external_id: String::new(),
            properties: HashMap::from([(
                OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            )]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    let dataset = |id: &str, object_id: &str| Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: object_id.into(),
        created: 1,
        partition_keys: Vec::new(),
    };
    runtime.create_dataset(&dataset("in", "in-obj")).unwrap();
    runtime.create_dataset(&dataset("out", "")).unwrap();
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    runtime
        .put_governed_transform(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "iso-stream".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    inputs: Vec::new(),
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
        )
        .unwrap();
    runtime
        .run_governed_transform("ops", "iso-stream", false, 20)
        .unwrap();
    let work = svc
        .claim_transform_work(with_named_principal(
            ClaimTransformWorkRequest {
                namespace: "ops".into(),
                runtime_id: "runner-a".into(),
                run_id: String::new(),
                ttl_ms: 60_000,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .work
        .unwrap();
    let created = svc
        .apply_streaming_transform_batch(with_named_principal(
            ApplyStreamingTransformBatchRequest {
                run_id: work.run_id.clone(),
                runtime_id: work.claim_owner.clone(),
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token.clone(),
                checkpoint: "c0".into(),
                action_type_id: "stream.record.create".into(),
                action_type_version: "1".into(),
                edits: vec![StreamingTransformObjectEdit {
                    object_id: "rec-0".into(),
                    name: "rec-0".into(),
                    properties: HashMap::from([
                        ("n".into(), "0".into()),
                        (OBJECT_CLASSIFICATION_PROPERTY.into(), "public".into()),
                    ]),
                }],
                input_positions: vec![StreamingTransformInputPosition {
                    source: "src".into(),
                    position: "c0".into(),
                }],
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert!(!created.replay);
    let stored = runtime.get_object("rec-0").unwrap().expect("created");
    assert_eq!(
        stored
            .properties
            .get(OBJECT_CLASSIFICATION_PROPERTY)
            .map(String::as_str),
        Some("confidential")
    );
    svc.apply_streaming_transform_batch(with_named_principal(
        ApplyStreamingTransformBatchRequest {
            run_id: work.run_id.clone(),
            runtime_id: work.claim_owner.clone(),
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token.clone(),
            checkpoint: "c1".into(),
            action_type_id: "stream.record.update".into(),
            action_type_version: "1".into(),
            edits: vec![StreamingTransformObjectEdit {
                object_id: "rec-0".into(),
                name: "rec-0".into(),
                properties: HashMap::from([
                    ("n".into(), "1".into()),
                    (OBJECT_CLASSIFICATION_PROPERTY.into(), "public".into()),
                ]),
            }],
            input_positions: vec![StreamingTransformInputPosition {
                source: "src".into(),
                position: "c1".into(),
            }],
        },
        "local",
    ))
    .await
    .unwrap();
    let stored = runtime.get_object("rec-0").unwrap().expect("updated");
    assert_eq!(stored.properties.get("n").map(String::as_str), Some("1"));
    assert_eq!(
        stored
            .properties
            .get(OBJECT_CLASSIFICATION_PROPERTY)
            .map(String::as_str),
        Some("confidential")
    );
}

/// #1615: two generated tenants answer the same read checks as real ones.
/// A viewer reads a part with its restricted `unit_cost` redacted, the
/// tenant admin reads it, the other tenant reads nothing, and an object
/// marked above the viewer's clearance is refused.
#[tokio::test]
async fn synthetic_tenants_pass_the_real_read_checks() {
    use crate::sekai::synthetic::{SizePreset, Spec, SupplyChain, apply, generate};
    let db = Arc::new(RuntimeDb::memory());
    let tenant = |namespace: &str, seed| {
        generate(
            &SupplyChain,
            &Spec {
                namespace: namespace.into(),
                seed,
                preset: SizePreset::Demo,
            },
        )
        .unwrap()
    };
    let north = tenant("synthetic-north", 1);
    let south = tenant("synthetic-south", 2);
    apply(&db, &north).unwrap();
    apply(&db, &south).unwrap();
    let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db));

    let rank = |token: &str| {
        ["public", "internal", "confidential", "restricted"]
            .iter()
            .position(|level| *level == token)
            .unwrap()
    };
    let principal = |plan: &crate::sekai::synthetic::SyntheticPlan, role: &str| {
        plan.principals
            .iter()
            .find(|principal| principal.role == role)
            .unwrap()
            .clone()
    };
    let viewer = principal(&north, "viewer");
    let admin = principal(&north, "admin");
    let outsider = principal(&south, "admin");
    let marking = |object: &crate::domain::Object| {
        rank(&object.properties[markings::OBJECT_CLASSIFICATION_PROPERTY])
    };
    let part = north
        .objects
        .iter()
        .find(|object| object.kind == "synthetic_part" && marking(object) == 0)
        .unwrap();
    let read = |id: &str, principal: &str| {
        svc.get_object(with_named_principal(
            GetObjectRequest { id: id.into() },
            principal,
        ))
    };

    let seen = read(&part.id, &viewer.id).await.unwrap().into_inner();
    assert_eq!(seen.object.unwrap().properties["unit_cost"], REDACTED_VALUE);
    let seen = read(&part.id, &admin.id).await.unwrap().into_inner();
    assert_eq!(
        seen.object.unwrap().properties["unit_cost"],
        part.properties["unit_cost"]
    );
    let refused = read(&part.id, &outsider.id).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);

    let above_clearance = north
        .objects
        .iter()
        .find(|object| marking(object) > rank(&viewer.clearance))
        .unwrap();
    let refused = read(&above_clearance.id, &viewer.id).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    read(&above_clearance.id, &admin.id).await.unwrap();
}

#[path = "isolation_probes.rs"]
mod isolation_probes;

#[tokio::test]
async fn dataset_branch_rpcs_isolate_then_merge_once_by_another_principal() {
    let svc = service();
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "branched".into(),
            name: "branched".into(),
            columns: vec![ColumnDef {
                name: "kind".into(),
                r#type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    svc.append_rows(with_principal(AppendRowsRequest {
        dataset_id: "branched".into(),
        rows: vec![Row {
            values: [("kind".into(), "v1".into())].into(),
        }],
    }))
    .await
    .unwrap();
    let branch = svc
        .create_dataset_branch(with_principal(CreateDatasetBranchRequest {
            dataset_id: "branched".into(),
            name: "dev".into(),
            from_version_id: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
        .branch
        .unwrap();
    assert!(!branch.written);
    svc.db
        .runtime()
        .write_dataset_branch_rows(
            "branched",
            "dev",
            &[[("kind".to_string(), "v2".to_string())].into()],
            false,
        )
        .unwrap();
    let diff = svc
        .compare_dataset_branch(with_principal(CompareDatasetBranchRequest {
            dataset_id: "branched".into(),
            name: "dev".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((diff.parent_rows, diff.branch_rows), (1, 2));
    let proposal = svc
        .propose_dataset_branch_merge(with_principal(ProposeDatasetBranchMergeRequest {
            dataset_id: "branched".into(),
            name: "dev".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .proposal
        .unwrap();
    let merge = |principal: &str| {
        with_named_principal(
            MergeDatasetBranchRequest {
                dataset_id: "branched".into(),
                proposal_id: proposal.id.clone(),
                reason: String::new(),
            },
            principal,
        )
    };
    let own = svc.merge_dataset_branch(merge("tester")).await.unwrap_err();
    assert_eq!(own.code(), tonic::Code::PermissionDenied);
    let merged = svc
        .merge_dataset_branch(merge("reviewer"))
        .await
        .unwrap()
        .into_inner()
        .proposal
        .unwrap();
    assert_eq!(merged.status, "merged");
    assert!(merged.receipt_id.starts_with("sha256:"));
    let versions = svc
        .list_dataset_versions(with_principal(ListDatasetVersionsRequest {
            dataset_id: "branched".into(),
            as_of_ms: 0,
        }))
        .await
        .unwrap()
        .into_inner()
        .versions;
    assert_eq!(versions.len(), 2);
    assert_eq!(
        versions.last().unwrap().version_id,
        merged.merged_version_id
    );
    let listed = svc
        .list_dataset_branches(with_principal(ListDatasetBranchesRequest {
            dataset_id: "branched".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(listed.branches.is_empty());
    let missing = svc
        .delete_dataset_branch(with_principal(DeleteDatasetBranchRequest {
            dataset_id: "branched".into(),
            name: "dev".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
}

fn gate_binding(namespace: &str, blocking: bool) -> domain::Object {
    use crate::sekai::definition_consumer_impact::{
        BINDING_CONTRACT, BINDING_KIND, DefinitionConsumerBinding, binding_digest,
    };
    let mut binding = DefinitionConsumerBinding {
        contract_version: BINDING_CONTRACT.into(),
        owner: "billing-team".into(),
        resource_identity: "app:invoices".into(),
        namespace: namespace.into(),
        member_kind: "object_type".into(),
        member_id: "Ticket".into(),
        property: "title".into(),
        declaration_digest: String::new(),
        source_locator: "invoices/src/ticket.rs".into(),
        blocking,
    };
    binding.declaration_digest = binding_digest(&binding);
    let mut properties = HashMap::from([
        ("contract_version".into(), binding.contract_version),
        ("owner".into(), binding.owner),
        ("resource_identity".into(), binding.resource_identity),
        ("member_kind".into(), binding.member_kind),
        ("member_id".into(), binding.member_id),
        ("property".into(), binding.property),
        ("declaration_digest".into(), binding.declaration_digest),
        ("source_locator".into(), binding.source_locator),
    ]);
    if blocking {
        properties.insert("blocking".into(), "true".into());
    }
    domain::Object {
        id: "binding-invoices".into(),
        kind: BINDING_KIND.into(),
        name: "binding-invoices".into(),
        namespace: namespace.into(),
        external_id: format!("{namespace}:binding-invoices"),
        properties,
        created: 1,
        updated: 1,
    }
}

/// Branch, edit, propose, approve and merge; the merge result is returned.
async fn try_publish(
    svc: &SekaiServiceImpl,
    namespace: &str,
    parent: &str,
    branch_id: &str,
    proposal_id: &str,
    properties: &str,
    major_revision: bool,
) -> Result<String, Status> {
    let _ = svc
        .create_definition_branch(with_named_principal(
            CreateDefinitionBranchRequest {
                namespace: namespace.into(),
                branch_id: branch_id.into(),
                parent_revision_digest: parent.into(),
                idempotency_key: format!("{branch_id}-create"),
            },
            "root",
        ))
        .await;
    let candidate = match svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: branch_id.into(),
                expected_head_digest: parent.into(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "object_type".into(),
                    member_id: "Ticket".into(),
                    definition_json: format!(r#"{{"name":"Ticket","properties":{properties}}}"#),
                    member_digest: String::new(),
                }],
                removals: Vec::new(),
                idempotency_key: format!("{branch_id}-edit"),
            },
            "root",
        ))
        .await
    {
        Ok(applied) => applied.into_inner().revision.unwrap().revision_digest,
        Err(_) => {
            svc.get_definition_branch(with_named_principal(
                GetDefinitionBranchRequest {
                    namespace: namespace.into(),
                    branch_id: branch_id.into(),
                },
                "root",
            ))
            .await
            .unwrap()
            .into_inner()
            .branch
            .unwrap()
            .head_revision_digest
        }
    };
    svc.create_definition_proposal(with_named_principal(
        CreateDefinitionProposalRequest {
            namespace: namespace.into(),
            branch_id: branch_id.into(),
            proposal_id: proposal_id.into(),
            base_digest: parent.into(),
            candidate_digest: candidate,
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: format!("{proposal_id}-propose"),
            major_revision,
        },
        "root",
    ))
    .await?;
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: namespace.into(),
            proposal_id: proposal_id.into(),
            idempotency_key: format!("{proposal_id}-approve"),
        },
        "root",
    ))
    .await?;
    let merged = svc
        .merge_definition_proposal(with_named_principal(
            MergeDefinitionProposalRequest {
                namespace: namespace.into(),
                proposal_id: proposal_id.into(),
                expected_published_digest: parent.into(),
                idempotency_key: format!("{proposal_id}-merge"),
            },
            "root",
        ))
        .await?
        .into_inner();
    Ok(merged.published_revision.unwrap().revision_digest)
}

#[tokio::test]
async fn blocking_consumer_bindings_gate_breaking_publishes() {
    let svc = service();
    let namespace = "gate-team";
    let parent = seed_definition_parent(&svc, namespace);
    let with_title = try_publish(
        &svc,
        namespace,
        &parent.revision_digest,
        "g-1",
        "g-cs-1",
        r#"["title"]"#,
        false,
    )
    .await
    .unwrap();
    svc.db
        .runtime()
        .create_object(&gate_binding(namespace, true))
        .unwrap();

    // Making `title` required is breaking too, though no property is removed.
    let tightened = try_publish(
        &svc,
        namespace,
        &with_title,
        "g-req",
        "g-cs-req",
        r#"["title"],"required":["title"]"#,
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(
        tightened.code(),
        tonic::Code::FailedPrecondition,
        "{tightened:?}"
    );
    assert!(
        tightened.message().contains("app:invoices"),
        "{tightened:?}"
    );

    // Dropping `title` breaks the blocking binding: refused, naming it.
    let blocked = try_publish(
        &svc,
        namespace,
        &with_title,
        "g-2",
        "g-cs-2",
        r#"["body"]"#,
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(blocked.code(), tonic::Code::FailedPrecondition);
    assert!(blocked.message().contains("app:invoices"), "{blocked:?}");
    assert!(blocked.message().contains("Ticket.title"), "{blocked:?}");

    // The same change as an approved major revision publishes past the gate.
    let major = try_publish(
        &svc,
        namespace,
        &with_title,
        "g-2",
        "g-cs-2-major",
        r#"["body"]"#,
        true,
    )
    .await
    .unwrap();
    assert_ne!(major, with_title);

    // An advisory binding never blocks and is not disclosed.
    let restored = try_publish(
        &svc,
        namespace,
        &major,
        "g-3",
        "g-cs-3",
        r#"["title"]"#,
        false,
    )
    .await
    .unwrap();
    svc.db
        .runtime()
        .update_object(&gate_binding(namespace, false))
        .unwrap();
    try_publish(
        &svc,
        namespace,
        &restored,
        "g-4",
        "g-cs-4",
        r#"["body"]"#,
        false,
    )
    .await
    .unwrap();
}

fn changelog_binding(namespace: &str) -> domain::Object {
    use crate::sekai::definition_consumer_impact::{
        BINDING_CONTRACT, BINDING_KIND, DefinitionConsumerBinding, binding_digest,
    };
    let mut binding = DefinitionConsumerBinding {
        contract_version: BINDING_CONTRACT.into(),
        owner: "billing-team".into(),
        resource_identity: "app:invoices".into(),
        namespace: namespace.into(),
        member_kind: "object_type".into(),
        member_id: "Ticket".into(),
        property: "title".into(),
        declaration_digest: String::new(),
        source_locator: "invoices/src/ticket.rs".into(),
        blocking: false,
    };
    binding.declaration_digest = binding_digest(&binding);
    domain::Object {
        id: "binding-invoices".into(),
        kind: BINDING_KIND.into(),
        name: "binding-invoices".into(),
        namespace: namespace.into(),
        external_id: format!("{namespace}:binding-invoices"),
        properties: HashMap::from([
            ("contract_version".into(), binding.contract_version),
            ("owner".into(), binding.owner),
            ("resource_identity".into(), binding.resource_identity),
            ("member_kind".into(), binding.member_kind),
            ("member_id".into(), binding.member_id),
            ("property".into(), binding.property),
            ("declaration_digest".into(), binding.declaration_digest),
            ("source_locator".into(), binding.source_locator),
        ]),
        created: 1,
        updated: 1,
    }
}

async fn changelog(
    svc: &SekaiServiceImpl,
    caller: &str,
    reader: &str,
) -> GetOntologyChangelogResponse {
    svc.get_ontology_changelog(with_named_principal(
        GetOntologyChangelogRequest {
            namespaces: vec!["orders".into()],
            since_ms: now_millis() - 7 * 24 * 60 * 60 * 1000,
            until_ms: now_millis() + 1_000,
            reader: reader.into(),
        },
        caller,
    ))
    .await
    .unwrap()
    .into_inner()
}

#[tokio::test]
async fn ontology_changelog_lists_the_week_with_authors_approvers_and_consumers() {
    let svc = service();
    let namespace = "orders";
    let parent = seed_definition_parent(&svc, namespace);
    svc.db
        .runtime()
        .create_object(&changelog_binding(namespace))
        .unwrap();
    let ticket = |properties: &str| DefinitionMemberInput {
        member_kind: "object_type".into(),
        member_id: "Ticket".into(),
        definition_json: format!(r#"{{"name":"Ticket","properties":{properties}}}"#),
        member_digest: String::new(),
    };
    let (added, _) = publish_definition_history_entry(
        &svc,
        namespace,
        &parent.revision_digest,
        "log-1",
        "log-cs-1",
        vec![ticket(r#"["title"]"#)],
    )
    .await;
    // Dropping `title` breaks the invoices app bound to it.
    let (revision, receipt) = publish_definition_history_entry(
        &svc,
        namespace,
        &added,
        "log-2",
        "log-cs-2",
        vec![ticket(r#"["body"]"#)],
    )
    .await;
    let (_, grants) = svc
        .db
        .runtime()
        .ensure_team_namespace(namespace, "orders-team", security::Role::Admin, "local")
        .unwrap();
    for grant in grants {
        svc.security.add_grant(&grant);
    }

    let digest = changelog(&svc, "root", "orders-team").await;
    assert_eq!(digest.reader, "orders-team");
    let entries: Vec<_> = digest
        .entries
        .iter()
        .filter(|entry| entry.change_kind == "definition_revision")
        .collect();
    assert_eq!(entries.len(), 2, "{digest:?}");
    assert_eq!(
        entries[0].summary,
        ["changed object type Ticket: added properties title"]
    );
    assert!(entries[0].affected_consumers.is_empty());
    let entry = entries[1];
    assert_eq!(entry.revision_digest, revision);
    assert_eq!(entry.receipt_id, receipt);
    assert_eq!(entry.author, "root");
    assert_eq!(entry.approvers, ["root"]);
    assert_eq!(entry.published_by, "root");
    assert_eq!(
        entry.summary,
        ["changed object type Ticket: added properties body; removed properties title"]
    );
    assert!(
        entry
            .affected_consumers
            .iter()
            .any(|consumer| consumer.resource_identity == "app:invoices"),
        "{entry:?}"
    );

    // With no namespaces named, the team's own namespaces are covered.
    let by_role = svc
        .get_ontology_changelog(with_named_principal(
            GetOntologyChangelogRequest {
                namespaces: Vec::new(),
                since_ms: now_millis() - 7 * 24 * 60 * 60 * 1000,
                until_ms: now_millis() + 1_000,
                reader: "orders-team".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(by_role.entries, digest.entries);

    // A team without access to the namespace gets nothing for it.
    let outsider = changelog(&svc, "root", "outsider-team").await;
    assert!(outsider.entries.is_empty(), "{outsider:?}");
    // Building another reader's digest is for credential admins only.
    let denied = svc
        .get_ontology_changelog(with_named_principal(
            GetOntologyChangelogRequest {
                namespaces: vec![namespace.into()],
                since_ms: 0,
                until_ms: 1_000,
                reader: "orders-team".into(),
            },
            "outsider-team",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
}
