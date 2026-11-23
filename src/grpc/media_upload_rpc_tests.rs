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
