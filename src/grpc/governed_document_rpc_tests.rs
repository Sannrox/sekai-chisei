//! Governed-document RPCs (#2266): each of the seven runs the same lifecycle
//! and the same namespace and tenant refusals on SQLite and on PostgreSQL.

use super::*;
use crate::sekai::service_principal::ServicePrincipalRegistration;

const NAMESPACE: &str = "acme";
const DOCUMENT_ID: &str = "doc:brief";
const PURPOSE: &str = "case-review";

fn service_on(db: RuntimeDb) -> SekaiServiceImpl {
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
        db,
    )))
}

/// Run a document test on a scratch PostgreSQL database, on a multi-thread
/// runtime because the PostgreSQL store blocks in place. The store drops
/// after the runtime: closing its pool blocks.
fn on_postgres<F: std::future::Future<Output = ()>>(test: impl FnOnce(RuntimeDb) -> F) {
    let scratch = crate::db::ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test(db.clone()));
    drop(db);
}

fn admission(document_id: &str) -> GovernedDocumentAdmission {
    GovernedDocumentAdmission {
        contract_version: "sekai.governed-document/v1".into(),
        document_id: document_id.into(),
        namespace: NAMESPACE.into(),
        type_revision: "v1".into(),
        purpose: PURPOSE.into(),
        classification: "public".into(),
        title: "Brief".into(),
        content_ref: Some(ContentReference {
            scheme: "digest".into(),
            digest: format!("sha256:01{}", "ab".repeat(31)),
            media_type: "application/pdf".into(),
            byte_length: 128,
        }),
        ..Default::default()
    }
}

fn attachment(parent_content_digest: &str) -> DocumentRenditionAttachment {
    DocumentRenditionAttachment {
        namespace: NAMESPACE.into(),
        document_id: DOCUMENT_ID.into(),
        rendition_id: "rend:text".into(),
        class: "extracted_text".into(),
        parent_content_digest: parent_content_digest.into(),
        content_ref: Some(ContentReference {
            scheme: "digest".into(),
            digest: format!("sha256:02{}", "cd".repeat(31)),
            media_type: "text/plain".into(),
            byte_length: 32,
        }),
        extractor_id: "extractor:text".into(),
        extractor_profile_digest: format!("sha256:03{}", "ef".repeat(31)),
    }
}

/// Who calls: a named principal, or an authenticated tenant context.
#[derive(Clone)]
enum Caller {
    Named(&'static str),
    Context(Box<crate::enterprise::AuthenticatedContext>),
}

fn as_caller<T>(payload: T, caller: &Caller) -> Request<T> {
    match caller {
        Caller::Named(principal) => with_named_principal(payload, principal),
        Caller::Context(context) => {
            let mut req = Request::new(payload);
            req.extensions_mut().insert(context.as_ref().clone());
            req
        }
    }
}

async fn admit(
    svc: &SekaiServiceImpl,
    caller: &Caller,
    document: GovernedDocumentAdmission,
) -> Result<GovernedDocument, Status> {
    svc.admit_governed_document(as_caller(
        AdmitGovernedDocumentRequest {
            document: Some(document),
        },
        caller,
    ))
    .await
    .map(|response| response.into_inner().document.unwrap())
}

async fn attach(
    svc: &SekaiServiceImpl,
    caller: &Caller,
    rendition: DocumentRenditionAttachment,
) -> Result<DocumentRendition, Status> {
    svc.attach_governed_document_rendition(as_caller(
        AttachGovernedDocumentRenditionRequest {
            rendition: Some(rendition),
        },
        caller,
    ))
    .await
    .map(|response| response.into_inner().rendition.unwrap())
}

async fn get(
    svc: &SekaiServiceImpl,
    caller: &Caller,
    document_id: &str,
    purpose: &str,
) -> Result<DocumentView, Status> {
    svc.get_governed_document(as_caller(
        GetGovernedDocumentRequest {
            namespace: NAMESPACE.into(),
            document_id: document_id.into(),
            purpose: purpose.into(),
            fields: vec!["renditions".into()],
            ..Default::default()
        },
        caller,
    ))
    .await
    .map(|response| response.into_inner().view.unwrap())
}

async fn hold(svc: &SekaiServiceImpl, caller: &Caller) -> Result<GovernedDocument, Status> {
    svc.hold_governed_document(as_caller(
        HoldGovernedDocumentRequest {
            namespace: NAMESPACE.into(),
            document_id: DOCUMENT_ID.into(),
            hold_id: "hold:1".into(),
            reason: "litigation".into(),
        },
        caller,
    ))
    .await
    .map(|response| response.into_inner().document.unwrap())
}

async fn release(svc: &SekaiServiceImpl, caller: &Caller) -> Result<GovernedDocument, Status> {
    svc.release_governed_document_hold(as_caller(
        ReleaseGovernedDocumentHoldRequest {
            namespace: NAMESPACE.into(),
            document_id: DOCUMENT_ID.into(),
            hold_id: "hold:1".into(),
        },
        caller,
    ))
    .await
    .map(|response| response.into_inner().document.unwrap())
}

async fn expire(
    svc: &SekaiServiceImpl,
    caller: &Caller,
    document_id: &str,
) -> Result<GovernedDocument, Status> {
    svc.expire_governed_document(as_caller(
        ExpireGovernedDocumentRequest {
            namespace: NAMESPACE.into(),
            document_id: document_id.into(),
        },
        caller,
    ))
    .await
    .map(|response| response.into_inner().document.unwrap())
}

async fn delete(
    svc: &SekaiServiceImpl,
    caller: &Caller,
    document_id: &str,
) -> Result<GovernedDocument, Status> {
    svc.delete_governed_document(as_caller(
        DeleteGovernedDocumentRequest {
            namespace: NAMESPACE.into(),
            document_id: document_id.into(),
        },
        caller,
    ))
    .await
    .map(|response| response.into_inner().document.unwrap())
}

/// The six write RPCs and `GetGovernedDocument` as `caller`, against the
/// document `carol` admitted. Labels name the RPC.
async fn all_seven(svc: &SekaiServiceImpl, caller: &Caller) -> Vec<(&'static str, Status)> {
    fn refused<T>(result: Result<T, Status>) -> Status {
        result.err().unwrap_or_else(|| Status::ok(""))
    }
    vec![
        (
            "admit",
            refused(admit(svc, caller, admission("doc:other")).await),
        ),
        (
            "attach",
            refused(attach(svc, caller, attachment("sha256:00")).await),
        ),
        ("get", refused(get(svc, caller, DOCUMENT_ID, PURPOSE).await)),
        ("hold", refused(hold(svc, caller).await)),
        ("release", refused(release(svc, caller).await)),
        ("expire", refused(expire(svc, caller, DOCUMENT_ID).await)),
        ("delete", refused(delete(svc, caller, DOCUMENT_ID).await)),
    ]
}

fn assert_status(label: &str, status: &Status, code: tonic::Code, message: &str) {
    assert_eq!(status.code(), code, "{label}: {status}");
    assert_eq!(status.message(), message, "{label}");
}

/// Admit, attach, get, hold, release, expire and delete over the RPCs: the
/// server sets owner and attachment fields, retries are idempotent, a hold
/// blocks expiry and deletion, and a gone document reads as missing.
async fn exercise_document_lifecycle(db: RuntimeDb) {
    let svc = service_on(db);
    let carol = Caller::Named("carol");
    let unavailable = "governed document is unavailable";

    let admitted = admit(&svc, &carol, admission(DOCUMENT_ID)).await.unwrap();
    assert_eq!(
        (admitted.owner.as_str(), admitted.admitted_by.as_str()),
        ("carol", "carol")
    );
    assert!(admitted.admitted_at_ms > 0);
    assert_eq!(
        admit(&svc, &carol, admission(DOCUMENT_ID)).await.unwrap(),
        admitted
    );

    // An old client sends the stored rendition shape; the server-set fields
    // it carries decode as unknown fields and are dropped.
    let mut stored = DocumentRendition::decode(
        attachment(&admitted.content_digest)
            .encode_to_vec()
            .as_slice(),
    )
    .unwrap();
    stored.attached_by = "mallory".into();
    stored.attached_at_ms = 1;
    let from_old_client =
        DocumentRenditionAttachment::decode(stored.encode_to_vec().as_slice()).unwrap();
    assert_eq!(from_old_client, attachment(&admitted.content_digest));
    let attached = attach(&svc, &carol, from_old_client).await.unwrap();
    assert_eq!(attached.attached_by, "carol");
    assert!(attached.attached_at_ms > 1);
    assert_eq!(
        attach(&svc, &carol, attachment(&admitted.content_digest))
            .await
            .unwrap(),
        attached,
        "a retry returns the stored rendition"
    );
    let mut conflicting = attachment(&admitted.content_digest);
    conflicting.extractor_id = "extractor:other".into();
    assert_status(
        "conflicting attach",
        &attach(&svc, &carol, conflicting).await.unwrap_err(),
        tonic::Code::NotFound,
        unavailable,
    );

    let view = get(&svc, &carol, DOCUMENT_ID, PURPOSE).await.unwrap();
    assert_eq!(view.lifecycle, "admitted");
    assert_eq!(view.renditions, vec![attached]);
    for (label, caller, purpose) in [
        ("foreign owner", Caller::Named("dave"), PURPOSE),
        ("mismatched purpose", carol.clone(), "other-purpose"),
    ] {
        assert_status(
            label,
            &get(&svc, &caller, DOCUMENT_ID, purpose).await.unwrap_err(),
            tonic::Code::NotFound,
            unavailable,
        );
    }

    assert_eq!(hold(&svc, &carol).await.unwrap().hold_id, "hold:1");
    assert_eq!(
        get(&svc, &carol, DOCUMENT_ID, PURPOSE)
            .await
            .unwrap()
            .lifecycle,
        "held"
    );
    for (label, result) in [
        ("expire while held", expire(&svc, &carol, DOCUMENT_ID).await),
        ("delete while held", delete(&svc, &carol, DOCUMENT_ID).await),
    ] {
        assert_status(
            label,
            &result.unwrap_err(),
            tonic::Code::FailedPrecondition,
            "governed document is held",
        );
    }
    assert!(release(&svc, &carol).await.unwrap().hold_id.is_empty());
    expire(&svc, &carol, DOCUMENT_ID).await.unwrap();
    assert_status(
        "get after expire",
        &get(&svc, &carol, DOCUMENT_ID, PURPOSE).await.unwrap_err(),
        tonic::Code::NotFound,
        unavailable,
    );

    admit(&svc, &carol, admission("doc:second")).await.unwrap();
    assert!(
        delete(&svc, &carol, "doc:second")
            .await
            .unwrap()
            .deleted_at_ms
            > 0
    );
    for (label, result) in [
        (
            "get after delete",
            get(&svc, &carol, "doc:second", PURPOSE).await.map(drop),
        ),
        (
            "re-admit after delete",
            admit(&svc, &carol, admission("doc:second")).await.map(drop),
        ),
    ] {
        assert_status(
            label,
            &result.unwrap_err(),
            tonic::Code::NotFound,
            unavailable,
        );
    }
}

#[tokio::test]
async fn document_rpcs_run_the_lifecycle() {
    exercise_document_lifecycle(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_document_rpcs_run_the_lifecycle() {
    on_postgres(exercise_document_lifecycle);
}

fn tenant_context(credential_id: &str, scopes: &[&str]) -> crate::enterprise::AuthenticatedContext {
    crate::enterprise::AuthenticatedContext {
        contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
        home_tenant: None,
        principal: crate::enterprise::AuthenticatedPrincipal {
            subject: "worker".into(),
            credential_id: credential_id.into(),
        },
        credential_kind: if scopes.is_empty() {
            crate::enterprise::CredentialKind::Machine
        } else {
            crate::enterprise::CredentialKind::HumanSession
        },
        space: None,
        space_role: None,
        act: None,
        tenant: Some(crate::enterprise::TenantContext {
            tenant_id: "tenant-a".into(),
            subject: "worker".into(),
        }),
        scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
        issuer: "https://issuer.test".into(),
        resource: "https://sekai.test".into(),
        expires_at: 100,
        device: None,
    }
}

/// Namespace authorization runs before the store on all seven RPCs (#2248):
/// a non-member of a team-managed namespace is refused everywhere and a
/// viewer may only read; a service principal outside its registered
/// namespaces is refused everywhere; a read-only credential may only read.
async fn exercise_namespace_and_tenant_refusals(db: RuntimeDb) {
    db.put_service_principal(&ServicePrincipalRegistration {
        capabilities: Vec::new(),
        principal: "worker".into(),
        tenant_id: "tenant-a".into(),
        namespaces: vec!["elsewhere".into()],
        action_types: vec!["dispatch".into()],
        registered_by: "root".into(),
        created_at_ms: 1,
        updated_at_ms: 1,
    })
    .unwrap()
    .unwrap();
    let svc = service_on(db);
    for (principal, role) in [
        ("alice", "viewer"),
        ("carol", "editor"),
        ("worker", "viewer"),
    ] {
        svc.ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: NAMESPACE.into(),
                principal: principal.into(),
                role: role.into(),
            },
            "local",
        ))
        .await
        .unwrap();
    }
    admit(&svc, &Caller::Named("carol"), admission(DOCUMENT_ID))
        .await
        .unwrap();

    let team_denied = "namespace access denied";
    for (label, status) in all_seven(&svc, &Caller::Named("bob")).await {
        assert_status(label, &status, tonic::Code::PermissionDenied, team_denied);
    }
    let scoped = Caller::Context(Box::new(tenant_context(
        "service-principal:cred-worker",
        &[],
    )));
    for (label, status) in all_seven(&svc, &scoped).await {
        assert_status(
            label,
            &status,
            tonic::Code::PermissionDenied,
            "namespace outside the service principal scope",
        );
    }
    // A viewer, and a viewer's read-only credential, pass the namespace
    // check on Get and meet the owner-only read; every write is refused
    // before the store.
    let read_only = Caller::Context(Box::new(tenant_context("credential-a", &["sekai.read"])));
    for (caller, write_denied) in [
        (Caller::Named("alice"), team_denied),
        (read_only, "enterprise authorization denied"),
    ] {
        for (label, status) in all_seven(&svc, &caller).await {
            if label == "get" {
                assert_status(
                    label,
                    &status,
                    tonic::Code::NotFound,
                    "governed document is unavailable",
                );
            } else {
                assert_status(label, &status, tonic::Code::PermissionDenied, write_denied);
            }
        }
    }
    get(&svc, &Caller::Named("carol"), DOCUMENT_ID, PURPOSE)
        .await
        .expect("owner and editor reads");
}

#[tokio::test]
async fn document_rpcs_refuse_outside_the_namespace_and_tenant_scope() {
    exercise_namespace_and_tenant_refusals(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_document_rpcs_refuse_outside_the_namespace_and_tenant_scope() {
    on_postgres(exercise_namespace_and_tenant_refusals);
}
