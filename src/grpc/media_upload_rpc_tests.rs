//! Media delete and unfinished-upload expiry (#3042), on SQLite and on
//! PostgreSQL.

use super::*;
use crate::sekai::media_upload::{UNFINISHED_UPLOAD_TTL_MS, hex};
use sha2::{Digest, Sha256};

const NAMESPACE: &str = "field";

/// Run a media test on a scratch PostgreSQL database, on a multi-thread
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

fn service_on(db: RuntimeDb) -> SekaiServiceImpl {
    let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
        db,
    )));
    grant_source_namespace(&svc, NAMESPACE, "alice", security::Role::Admin);
    grant_source_namespace(&svc, NAMESPACE, "carol", security::Role::Viewer);
    svc
}

const FILE: &[u8] = b"field photo";

fn begin(key: &str) -> BeginMediaUploadRequest {
    BeginMediaUploadRequest {
        namespace: NAMESPACE.into(),
        idempotency_key: key.into(),
        size_bytes: FILE.len() as u64,
        sha256: hex(&Sha256::digest(FILE)),
        media_type: "image/jpeg".into(),
        file_name: "site.jpg".into(),
        access_marking: String::new(),
    }
}

/// Begin `key` as alice and send the whole file.
async fn upload(svc: &SekaiServiceImpl, key: &str) -> String {
    let upload_id = svc
        .begin_media_upload(with_named_principal(begin(key), "alice"))
        .await
        .unwrap()
        .into_inner()
        .upload_id;
    svc.upload_media_chunk(with_named_principal(
        UploadMediaChunkRequest {
            upload_id: upload_id.clone(),
            offset: 0,
            data: FILE.to_vec(),
        },
        "alice",
    ))
    .await
    .unwrap();
    upload_id
}

async fn complete(svc: &SekaiServiceImpl, upload_id: &str) -> Result<MediaUploadStatus, Status> {
    svc.complete_media_upload(with_named_principal(
        CompleteMediaUploadRequest {
            upload_id: upload_id.into(),
        },
        "alice",
    ))
    .await
    .map(Response::into_inner)
}

async fn read(
    svc: &SekaiServiceImpl,
    reference: &str,
    as_principal: &str,
) -> Result<Vec<u8>, Status> {
    svc.read_media(with_named_principal(
        ReadMediaRequest {
            media_reference: reference.into(),
            offset: 0,
            limit: 0,
        },
        as_principal,
    ))
    .await
    .map(|response| response.into_inner().data)
}

async fn delete(svc: &SekaiServiceImpl, reference: &str, as_principal: &str) -> Result<(), Status> {
    svc.delete_media(with_named_principal(
        DeleteMediaRequest {
            media_reference: reference.into(),
        },
        as_principal,
    ))
    .await
    .map(drop)
}

async fn exercise_delete(db: RuntimeDb) {
    let svc = service_on(db);
    let upload_id = upload(&svc, "p-1").await;
    let reference = complete(&svc, &upload_id).await.unwrap().media_reference;
    let object_id = reference.trim_start_matches("sekai-media:").to_string();

    // A reader who may not delete is refused, and the bytes stay.
    let refused = delete(&svc, &reference, "carol").await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{refused:?}");
    assert_eq!(read(&svc, &reference, "carol").await.unwrap(), FILE);

    delete(&svc, &reference, "alice").await.unwrap();
    let gone = read(&svc, &reference, "alice").await.unwrap_err();
    assert_eq!(gone.code(), tonic::Code::NotFound);
    assert!(svc.db.runtime().get_object(&object_id).unwrap().is_none());
    assert!(
        svc.db
            .runtime()
            .read_media_bytes(&upload_id, 0, FILE.len())
            .unwrap()
            .is_empty()
    );
    let session = svc
        .get_media_upload(with_named_principal(
            GetMediaUploadRequest {
                upload_id: upload_id.clone(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(session.code(), tonic::Code::NotFound);
    let decisions = svc
        .db
        .runtime()
        .list_decisions(&audit::DecisionFilter {
            actor: Some("alice".into()),
            target_id: Some(object_id.clone()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        decisions
            .iter()
            .any(|decision| decision.action == "media.delete" && decision.outcome == "allowed"),
        "{decisions:?}"
    );

    // Repeating the delete succeeds and changes nothing; the key is spent.
    delete(&svc, &reference, "alice").await.unwrap();
    let respent = svc
        .begin_media_upload(with_named_principal(begin("p-1"), "alice"))
        .await
        .unwrap_err();
    assert_eq!(
        respent.code(),
        tonic::Code::FailedPrecondition,
        "{respent:?}"
    );
    assert!(svc.db.runtime().get_object(&object_id).unwrap().is_none());
}

#[tokio::test]
async fn deleting_media_removes_object_bytes_and_session() {
    exercise_delete(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_deleting_media_removes_object_bytes_and_session() {
    on_postgres(exercise_delete);
}

/// An expiry pass as if the window had passed for every session now idle.
fn expire_all(db: &RuntimeDb) -> usize {
    let now = now_millis() + UNFINISHED_UPLOAD_TTL_MS + 1;
    db.expire_media_uploads(now - UNFINISHED_UPLOAD_TTL_MS, now, 100)
        .unwrap()
}

async fn exercise_expiry(db: RuntimeDb) {
    let svc = service_on(db);
    let db = svc.db.runtime();

    // An idle unfinished upload loses its bytes and starts over at 0.
    let idle = upload(&svc, "idle").await;
    assert_eq!(expire_all(db), 1);
    assert!(
        db.read_media_bytes(&idle, 0, FILE.len())
            .unwrap()
            .is_empty()
    );
    let restarted = svc
        .begin_media_upload(with_named_principal(begin("idle"), "alice"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((restarted.upload_id, restarted.received_bytes), (idle, 0));

    // Expiry that lands before a completion: the completion is refused and
    // the file can be sent again.
    let raced = upload(&svc, "raced").await;
    assert_eq!(expire_all(db), 1);
    let refused = complete(&svc, &raced).await.unwrap_err();
    assert_eq!(
        refused.code(),
        tonic::Code::FailedPrecondition,
        "{refused:?}"
    );
    let reference = upload(&svc, "raced").await;
    let reference = complete(&svc, &reference).await.unwrap().media_reference;
    assert_eq!(read(&svc, &reference, "alice").await.unwrap(), FILE);

    // A completed upload is never expired.
    assert_eq!(expire_all(db), 0);
    assert_eq!(read(&svc, &reference, "alice").await.unwrap(), FILE);
}

#[tokio::test]
async fn idle_unfinished_uploads_lose_their_bytes() {
    exercise_expiry(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_idle_unfinished_uploads_lose_their_bytes() {
    on_postgres(exercise_expiry);
}

const PURPOSE: &str = "case-review";

/// A `media` content reference over a completed upload of [`FILE`].
fn media_content(reference: &str) -> ContentReference {
    ContentReference {
        scheme: "media".into(),
        digest: format!("sha256:{}", hex(&Sha256::digest(FILE))),
        media_type: "image/jpeg".into(),
        byte_length: FILE.len() as u64,
        media_reference: reference.into(),
    }
}

async fn admit_media(
    svc: &SekaiServiceImpl,
    document_id: &str,
    content: ContentReference,
) -> Result<GovernedDocument, Status> {
    svc.admit_governed_document(with_named_principal(
        AdmitGovernedDocumentRequest {
            document: Some(GovernedDocumentAdmission {
                contract_version: "sekai.governed-document/v1".into(),
                document_id: document_id.into(),
                namespace: NAMESPACE.into(),
                type_revision: "v1".into(),
                purpose: PURPOSE.into(),
                classification: "public".into(),
                title: "Site photo".into(),
                content_ref: Some(content),
                ..Default::default()
            }),
        },
        "alice",
    ))
    .await
    .map(|response| response.into_inner().document.unwrap())
}

/// Read as `as_principal`, presenting the document purpose.
async fn read_for_purpose(
    svc: &SekaiServiceImpl,
    reference: &str,
    as_principal: &str,
) -> Result<Vec<u8>, Status> {
    let mut request = with_named_principal(
        ReadMediaRequest {
            media_reference: reference.into(),
            offset: 0,
            limit: 0,
        },
        as_principal,
    );
    request
        .metadata_mut()
        .insert("x-sekai-purpose", PURPOSE.parse().unwrap());
    svc.read_media(request)
        .await
        .map(|response| response.into_inner().data)
}

async fn completed(svc: &SekaiServiceImpl, key: &str) -> String {
    let upload_id = upload(svc, key).await;
    complete(svc, &upload_id).await.unwrap().media_reference
}

fn code<T: std::fmt::Debug>(result: Result<T, Status>) -> tonic::Code {
    result.unwrap_err().code()
}

/// Give `principal` a sealed profile cleared up to `ceiling`.
fn clear(svc: &SekaiServiceImpl, principal: &str, ceiling: &str) {
    let id = format!("profile-{principal}");
    svc.db
        .runtime()
        .create_object(&crate::domain::Object {
            id: id.clone(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: principal.into(),
            namespace: NAMESPACE.into(),
            external_id: markings::principal_profile_external_id(principal),
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
    let grant = crate::sekai::security::Grant {
        id: format!("grant-{id}"),
        object_id: id,
        principal: "root".into(),
        role: security::Role::Admin,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

/// ADR 0159: a document that binds media governs reading and removing it.
async fn exercise_document_media(db: RuntimeDb) {
    let svc = service_on(db);
    // Both may read the attachment under the document's marking; only alice
    // may read the document.
    clear(&svc, "alice", "internal");
    clear(&svc, "carol", "confidential");
    let reference = completed(&svc, "doc-photo").await;
    assert_eq!(read(&svc, &reference, "carol").await.unwrap(), FILE);

    // Declared content must be the attachment's.
    let mismatched = [
        ContentReference {
            digest: format!("sha256:{}", "0".repeat(64)),
            ..media_content(&reference)
        },
        ContentReference {
            byte_length: FILE.len() as u64 + 1,
            ..media_content(&reference)
        },
        ContentReference {
            media_type: "image/png".into(),
            ..media_content(&reference)
        },
    ];
    for content in mismatched {
        let refused = admit_media(&svc, "doc:photo", content).await;
        assert_eq!(code(refused), tonic::Code::InvalidArgument);
    }
    // Refusals bind nothing: the attachment still reads as before.
    assert_eq!(read(&svc, &reference, "carol").await.unwrap(), FILE);

    let admitted = admit_media(&svc, "doc:photo", media_content(&reference))
        .await
        .unwrap();
    // Re-admission is idempotent; a second document cannot bind it again.
    assert_eq!(
        admit_media(&svc, "doc:photo", media_content(&reference))
            .await
            .unwrap(),
        admitted
    );
    let second = admit_media(&svc, "doc:other", media_content(&reference)).await;
    assert_eq!(code(second), tonic::Code::FailedPrecondition);

    // Reading the bytes is reading the document: carol may read the
    // attachment's namespace but not the document, and alice must present
    // its purpose.
    assert_eq!(
        code(read(&svc, &reference, "carol").await),
        tonic::Code::NotFound
    );
    assert_eq!(
        code(read_for_purpose(&svc, &reference, "carol").await),
        tonic::Code::NotFound
    );
    assert_eq!(
        code(read(&svc, &reference, "alice").await),
        tonic::Code::NotFound
    );
    assert_eq!(
        read_for_purpose(&svc, &reference, "alice").await.unwrap(),
        FILE
    );

    // A rendition's bytes follow the parent.
    let thumb = completed(&svc, "doc-thumb").await;
    svc.attach_governed_document_rendition(with_named_principal(
        AttachGovernedDocumentRenditionRequest {
            rendition: Some(DocumentRenditionAttachment {
                namespace: NAMESPACE.into(),
                document_id: "doc:photo".into(),
                rendition_id: "rend:thumb".into(),
                class: "thumbnail".into(),
                parent_content_digest: admitted.content_digest.clone(),
                content_ref: Some(media_content(&thumb)),
                extractor_id: "extractor:thumb".into(),
                extractor_profile_digest: format!("sha256:{}", "e".repeat(64)),
            }),
        },
        "alice",
    ))
    .await
    .unwrap();
    assert_eq!(
        code(read(&svc, &thumb, "carol").await),
        tonic::Code::NotFound
    );
    assert_eq!(read_for_purpose(&svc, &thumb, "alice").await.unwrap(), FILE);

    // Live or held, the bytes stay.
    assert_eq!(
        code(delete(&svc, &reference, "alice").await),
        tonic::Code::FailedPrecondition
    );
    let hold = |hold_id: &str| HoldGovernedDocumentRequest {
        namespace: NAMESPACE.into(),
        document_id: "doc:photo".into(),
        hold_id: hold_id.into(),
        reason: "litigation".into(),
    };
    svc.hold_governed_document(with_named_principal(hold("hold-1"), "alice"))
        .await
        .unwrap();
    assert_eq!(
        code(delete(&svc, &thumb, "alice").await),
        tonic::Code::FailedPrecondition
    );
    svc.release_governed_document_hold(with_named_principal(
        ReleaseGovernedDocumentHoldRequest {
            namespace: NAMESPACE.into(),
            document_id: "doc:photo".into(),
            hold_id: "hold-1".into(),
        },
        "alice",
    ))
    .await
    .unwrap();

    // Deleting the document hides the bytes through the attachment too, and
    // makes them removable.
    svc.delete_governed_document(with_named_principal(
        DeleteGovernedDocumentRequest {
            namespace: NAMESPACE.into(),
            document_id: "doc:photo".into(),
        },
        "alice",
    ))
    .await
    .unwrap();
    for bytes in [&reference, &thumb] {
        assert_eq!(
            code(read_for_purpose(&svc, bytes, "alice").await),
            tonic::Code::NotFound
        );
        delete(&svc, bytes, "alice").await.unwrap();
    }

    // Expiry ends the read the same way.
    let expiring = completed(&svc, "doc-expiring").await;
    admit_media(&svc, "doc:expiring", media_content(&expiring))
        .await
        .unwrap();
    svc.expire_governed_document(with_named_principal(
        ExpireGovernedDocumentRequest {
            namespace: NAMESPACE.into(),
            document_id: "doc:expiring".into(),
        },
        "alice",
    ))
    .await
    .unwrap();
    assert_eq!(
        code(read_for_purpose(&svc, &expiring, "alice").await),
        tonic::Code::NotFound
    );
    delete(&svc, &expiring, "alice").await.unwrap();
}

#[tokio::test]
async fn a_document_governs_the_media_it_binds() {
    exercise_document_media(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_a_document_governs_the_media_it_binds() {
    on_postgres(exercise_document_media);
}
