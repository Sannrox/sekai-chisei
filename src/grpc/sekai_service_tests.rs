use super::*;
use std::collections::HashMap;
use tonic::metadata::MetadataValue;

fn service() -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    SekaiServiceImpl::new(db)
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
            tenant: Some(self.tenant_context(&principal)?),
            principal,
            credential_kind: crate::enterprise::CredentialKind::HumanSession,
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
            principal: crate::enterprise::AuthenticatedPrincipal {
                subject: "subject-a".into(),
                credential_id: "credential-a".into(),
            },
            credential_kind: crate::enterprise::CredentialKind::HumanSession,
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
fn community_request_is_authorized_by_installed_enterprise_extension() {
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

    let context = request_tenant_context(&db, &request).unwrap().unwrap();
    assert!(context.tenant.is_none());
    assert!(enforce_namespace_tenant_context(&db, Some(&context), "community", true).is_ok());
    assert_eq!(
        enforce_namespace_tenant_context(&db, Some(&context), "tenant-private", false)
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
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
    SekaiServiceImpl::new(db)
}

fn test_tenant_context() -> crate::enterprise::AuthenticatedContext {
    crate::enterprise::AuthenticatedContext {
        contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
        principal: crate::enterprise::AuthenticatedPrincipal {
            subject: "subject-a".into(),
            credential_id: "credential-a".into(),
        },
        credential_kind: crate::enterprise::CredentialKind::HumanSession,
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

fn with_principal<T>(payload: T) -> Request<T> {
    with_named_principal(payload, "tester")
}

fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
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
    work().await;
    String::from_utf8(buf.0.lock().expect("log buffer").clone()).expect("utf8 logs")
}

const SOURCE_TYPE_DIGEST: &str = source_sync_domain::GITHUB_OBJECT_SYNC_TYPE_DIGEST;
const SOURCE_PAYLOAD_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn grant_source_namespace(
    svc: &SekaiServiceImpl,
    namespace: &str,
    principal: &str,
    role: security::Role,
) {
    let (_, grants) = svc
        .db
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
    let RuntimeDb::Sqlite(db) = svc.db.as_ref() else {
        panic!("test service must use SQLite");
    };
    db.seed_published_definition_revision(&revision, &[member])
        .unwrap();
    revision
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
    };
    svc.db.create_grant(&read_grant).unwrap();
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
    };
    svc.db.create_grant(&object_admin_grant).unwrap();
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
    };
    svc.db.create_grant(&ticket_admin).unwrap();
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
        };
        svc.db.create_grant(&grant).unwrap();
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
    };
    svc.db.create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

fn grant_ontology_admin(svc: &SekaiServiceImpl) {
    let grant = security::Grant {
        id: format!("ontology-admin-{}", uuid::Uuid::new_v4().simple()),
        object_id: "ontology".into(),
        principal: "tester".into(),
        role: security::Role::Admin,
        created: 0,
    };
    svc.db.create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

fn grant_ontology_reader(svc: &SekaiServiceImpl, object_id: &str) {
    let grant = security::Grant {
        id: format!("ontology-reader-{}", uuid::Uuid::new_v4().simple()),
        object_id: object_id.into(),
        principal: "tester".into(),
        role: security::Role::Viewer,
        created: 0,
    };
    svc.db.create_grant(&grant).unwrap();
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
    };
    svc.db.create_grant(&grant).unwrap();
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
    };
    svc.db.create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

fn seed_scoring_namespace(svc: &SekaiServiceImpl, namespace: &str) -> String {
    let id = format!("namespace-{namespace}");
    svc.db
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
            .put_object_security_policy(&policy, "root", &format!("put-{id}"), 1)
            .unwrap();
        svc.db
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
        .put_object_security_policy(&policy, "root", "put-purpose-bound", 1)
        .unwrap();
    let activation = svc
        .db
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
        .create_link(&domain::Link {
            id: "lattice-hop".into(),
            from_id: "lattice-confidential".into(),
            to_id: "lattice-health".into(),
            relation: "contains".into(),
            created: 1,
        })
        .unwrap();
    svc.db
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
        .put_object_security_policy(&policy, "root", "put-find-activated", 1)
        .unwrap();
    svc.db
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
    let stored = svc.db.get_decision(&recorded.id).unwrap().unwrap();
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
    let stored = svc.db.get_object("widget-ai").unwrap().unwrap();
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
async fn query_rows_reports_corrupt_storage_as_internal() {
    let svc = service();
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "corrupt-dataset".into(),
            name: "corrupt".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
        }),
    }))
    .await
    .unwrap();
    svc.db
        .with_sqlite_conn(|connection| {
            connection.execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data) VALUES (?1, ?2)",
                rusqlite::params!["corrupt-dataset", "not-json"],
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
    };
    svc.db.create_grant(&grant).unwrap();
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
                }),
            },
            "intruder",
        ))
        .await
        .unwrap_err();

    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    let stored = svc.db.get_dataset("protected-dataset").unwrap().unwrap();
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
                }),
            },
            "gateway-prod",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
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
                PipelineStep {
                    op: "self".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    r#as: "".into(),
                },
                PipelineStep {
                    op: "traverse".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "contains".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    r#as: "".into(),
                },
                PipelineStep {
                    op: "aggregate".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "count".into(),
                    field: "".into(),
                    r#as: "child_count".into(),
                },
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

    let stored = svc.db.get_object("cluster-1").unwrap().unwrap();
    assert!(!stored.properties.contains_key("child_count"));
}

#[tokio::test]
async fn computed_aggregates_exclude_objects_denied_by_active_policy() {
    let svc = service();
    grant_schema_admin(&svc);
    svc.create_function(with_principal(CreateFunctionRequest {
        function: Some(Function {
            name: "count_policy_children".into(),
            pipeline: vec![
                PipelineStep {
                    op: "self".into(),
                    ..Default::default()
                },
                PipelineStep {
                    op: "traverse".into(),
                    relation: "contains".into(),
                    ..Default::default()
                },
                PipelineStep {
                    op: "aggregate".into(),
                    func: "count".into(),
                    r#as: "child_count".into(),
                    ..Default::default()
                },
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
        .put_object_security_policy(&allow_cluster, "root", "put-computed-cluster", 1)
        .unwrap();
    let component_revision = svc
        .db
        .put_object_security_policy(&owned_component, "root", "put-computed-component", 2)
        .unwrap();
    svc.db
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
                    PipelineStep {
                        op: "self".into(),
                        ..Default::default()
                    },
                    PipelineStep {
                        op: "traverse".into(),
                        relation: "contains".into(),
                        ..Default::default()
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        func: "count".into(),
                        r#as: "child_count".into(),
                        ..Default::default()
                    },
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
                PipelineStep {
                    op: "self".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    r#as: "".into(),
                },
                PipelineStep {
                    op: "aggregate".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "count".into(),
                    field: "".into(),
                    r#as: "first".into(),
                },
                PipelineStep {
                    op: "aggregate".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "count".into(),
                    field: "".into(),
                    r#as: "second".into(),
                },
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

    let stored = svc.db.get_object("cluster-spoofed").unwrap().unwrap();
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
    assert!(svc.db.get_object("audit-fail-closed").unwrap().is_none());
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
    assert!(svc.db.get_object("delete-audit-fail").unwrap().is_some());
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
        svc.db.get_object("guarded-auth").unwrap().unwrap().name,
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
        svc.db.get_object("unified-guarded").unwrap().unwrap().name,
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
        svc.db.get_object("unified-guarded").unwrap().unwrap().name,
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
    let budget = Arc::new(BudgetTracker::new(db.clone()));
    budget
        .set_limit("action:governed", 1, PeriodType::Daily)
        .unwrap();
    let svc = SekaiServiceImpl::with_budget(db, budget.clone());
    grant_action_admin(&svc);

    let type_def = GovernedActionType {
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
            request_id: "req-2".into(),
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
            request_id: "req-3".into(),
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

    // Budget deny (limit was 1; second distinct admit exhausts)
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
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(budget_denied.status, STATUS_DENIED);
    assert_eq!(budget_denied.budget_decision, "budget_exceeded");
    assert!(budget_denied.deny_reason.contains("budget"));

    // Policy deny
    svc.db
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
    };
    svc.db.create_grant(&hidden_grant).unwrap();
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
        .get_object("rec-grpc-1")
        .unwrap()
        .expect("created record");
    assert_eq!(stored.kind, "customer_record");
    assert_eq!(stored.namespace, "acme");
    assert_eq!(stored.name, "Northwind");
    let receipt = svc
        .db
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
    svc.db.create_object(&object).unwrap();
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
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
            .list_action_instances("acme", None, None, 10)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        svc.db.get_object("cust-preview").unwrap().unwrap().name,
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
    svc.db.create_object(&object).unwrap();
}

#[tokio::test]
async fn preview_does_not_fill_system_one_when_stale_or_denied() {
    let svc = service();
    grant_action_admin(&svc);
    put_system_one_ticket_type(&svc);
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
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
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("preview_object_action".into()),
                ..Default::default()
            })
            .unwrap()
            .is_empty()
    );

    svc.db
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
            axum::Json(sekai_provider::system_one::SystemOneResponse {
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
        std::env::set_var(sekai_provider::system_one::API_KEY_ENV, "test-key");
        std::env::set_var(
            sekai_provider::system_one::BASE_URL_ENV,
            format!("http://{addr}/v1/systemone"),
        );
    }

    let svc = service();
    grant_action_admin(&svc);
    put_system_one_ticket_type(&svc);
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
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
            .list_action_instances("acme", None, None, 10)
            .unwrap()
            .len(),
        0
    );
    unsafe {
        std::env::remove_var(sekai_provider::system_one::API_KEY_ENV);
        std::env::remove_var(sekai_provider::system_one::BASE_URL_ENV);
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
            axum::Json(sekai_provider::system_one::SystemOneResponse {
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
        std::env::set_var(sekai_provider::system_one::API_KEY_ENV, "test-key");
        std::env::set_var(
            sekai_provider::system_one::BASE_URL_ENV,
            format!("http://{addr}/v1/systemone"),
        );
    }

    let svc = service();
    grant_action_admin(&svc);
    put_system_one_ticket_type(&svc);
    svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
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
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("preview_object_action".into()),
                ..Default::default()
            })
            .unwrap()
            .is_empty()
    );
    unsafe {
        std::env::remove_var(sekai_provider::system_one::API_KEY_ENV);
        std::env::remove_var(sekai_provider::system_one::BASE_URL_ENV);
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
        assert!(svc.db.list_grants(object_id).unwrap().is_empty());
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
            .list_grants("ontology:class:Restricted")
            .unwrap()
            .is_empty()
    );
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
    svc.db.upsert_interface(&interface).unwrap();
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
    let svc = SekaiServiceImpl::new(db.clone());
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
    let svc = SekaiServiceImpl::new(db.clone());

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
        let conn = svc.db.conn();
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
    };
    svc.db.create_grant(&admin_grant).unwrap();
    svc.security.add_grant(&admin_grant);
    svc.db
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
    assert_eq!(listed.decisions.len(), 2);

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
    };
    svc.db.create_grant(&member_grant).unwrap();
    svc.security.add_grant(&member_grant);

    svc.create_grant(with_named_principal(
        CreateGrantRequest {
            grant: Some(Grant {
                id: "recovery".into(),
                object_id: "namespace:acme".into(),
                principal: "root".into(),
                role: "admin".into(),
                created: 1,
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
    assert!(svc.db.find_namespace_boundary("acme").unwrap().is_none());

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
    assert!(svc.db.find_namespace_boundary("acme").unwrap().is_some());

    svc.db
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
                }),
            },
            "mallory",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::InvalidArgument);

    svc.db
        .create_grant(&security::Grant {
            id: "legacy-orphan".into(),
            object_id: "namespace:future".into(),
            principal: "mallory".into(),
            role: security::Role::Admin,
            created: 1,
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
    assert!(svc.db.find_namespace_boundary("future").unwrap().is_none());
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
    let mut stale_candidate = svc.db.get_work_unit("wu-f1").unwrap().unwrap();
    stale_candidate.started_at = 1;
    stale_candidate.last_heartbeat_at = 1;
    stale_candidate.updated_at = 1;
    svc.db.update_work_unit(&stale_candidate).unwrap();
    svc.db
        .conn()
        .execute(
            "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
            rusqlite::params!["wu-f1"],
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
    let mut stale_candidate = svc.db.get_work_unit("wu-other").unwrap().unwrap();
    stale_candidate.started_at = 1;
    stale_candidate.last_heartbeat_at = 1;
    stale_candidate.updated_at = 1;
    svc.db.update_work_unit(&stale_candidate).unwrap();
    svc.db
        .conn()
        .execute(
            "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
            rusqlite::params!["wu-other"],
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
    let mut stale_candidate = svc.db.get_work_unit("wu-mismatch").unwrap().unwrap();
    stale_candidate.started_at = 1;
    stale_candidate.last_heartbeat_at = 1;
    stale_candidate.updated_at = 1;
    svc.db.update_work_unit(&stale_candidate).unwrap();
    svc.db
        .conn()
        .execute(
            "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
            rusqlite::params!["wu-mismatch"],
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
        .put_object_security_policy(&policy, "root", "put-list-compat", 1)
        .unwrap();
    svc.db
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
        svc.db.create_object(&object).unwrap();
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
    let learning = svc.db.get_object(&learning_id).unwrap().unwrap();
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
        .get_link(&format!("{learning_id}->{namespace_id}"))
        .unwrap()
        .unwrap();
    assert_eq!(link.from_id, learning_id);
    assert_eq!(link.to_id, namespace_id);
    assert_eq!(link.relation, domain::REL_TOUCHES);

    let grants = svc.db.list_grants(&learning.id).unwrap();
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
        .list_objects(&domain::ListFilter {
            kind: Some(domain::KIND_LEARNING.into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(learnings.len(), 1);
    assert_eq!(svc.db.list_grants(&learning.id).unwrap().len(), 1);

    let decisions = svc
        .db
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
    assert!(svc.db.get_object(&learning_id).unwrap().is_some());
    assert!(
        svc.db
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
    assert!(denied_svc.db.get_object(&denied_id).unwrap().is_none());
    let denied_decisions = denied_svc
        .db
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
    assert!(approval_svc.db.get_object(&approval_id).unwrap().is_none());
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
    };
    svc.db.create_grant(&grant).unwrap();
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
        svc.db.insert_attestation(&attestation).unwrap();
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
        svc.db.create_link(&link).unwrap();
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
    svc.db.add_blast_radius("wu-1", 1, 0).unwrap();
    let counter_id = svc
        .db
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
    assert_eq!(svc.db.get_blast_radius("wu-1").unwrap(), (1, 0));
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
        svc.db.create_link(&link).unwrap();
    }
    let denied_grant = security::Grant {
        id: "context-denied-grant".into(),
        object_id: "context-denied".into(),
        principal: "bob".into(),
        role: security::Role::Viewer,
        created: 0,
    };
    svc.db.create_grant(&denied_grant).unwrap();
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
}

#[tokio::test]
async fn property_level_reads_omit_hidden_values_across_query_surfaces() {
    let svc = service();
    let namespace = "column-reads";
    for (id, secret) in [("visible-a", "classified"), ("visible-b", "other")] {
        svc.db
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
        .put_object_security_policy(&grants, "root", "put-column-reads", 1)
        .unwrap();
    svc.db
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
        .put_object_security_policy(&revoked, "root", "put-column-revoke", 3)
        .unwrap();
    svc.db
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
        svc.db.create_link(&link).unwrap();
    }
    let denied_grant = security::Grant {
        id: "sem-denied-grant".into(),
        object_id: "sem-denied".into(),
        principal: "bob".into(),
        role: security::Role::Viewer,
        created: 0,
    };
    svc.db.create_grant(&denied_grant).unwrap();
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
    assert!(!svc.db.is_team_principal("team-agent").unwrap());

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
    assert!(svc.db.is_team_principal("team-agent").unwrap());
    assert_eq!(
        svc.db
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

    let outcome = EvidenceAdmissionLifecycle::new(&svc.db)
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
