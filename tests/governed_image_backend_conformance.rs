//! Shared SQLite/PostgreSQL conformance for governed images (#1479).

use std::collections::BTreeMap;
use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::image::{
    ANNOTATION_LABEL, CONTENT_SCHEME_DIGEST, ContentReference, FIELD_IDENTITY, GovernedImage,
    IMAGE_CONTRACT, IMAGE_UNAVAILABLE, ImageAnnotation, ImageRendition, RENDITION_THUMBNAIL,
    TYPE_REVISION_V1,
};

use crate::postgres_scratch::ScratchDatabase;

fn digest(tag: u8) -> String {
    format!("sha256:{tag:02x}{}", "ab".repeat(31))
}

fn content(tag: u8) -> ContentReference {
    ContentReference {
        scheme: CONTENT_SCHEME_DIGEST.into(),
        digest: digest(tag),
        media_type: "image/png".into(),
        byte_length: 32,
    }
}

fn image(owner: &str) -> GovernedImage {
    let content_ref = content(1);
    GovernedImage {
        contract_version: IMAGE_CONTRACT.into(),
        image_id: "img:site".into(),
        namespace: "records".into(),
        owner: owner.into(),
        type_revision: TYPE_REVISION_V1.into(),
        purpose: FIELD_IDENTITY.into(),
        classification: "internal".into(),
        title: "site".into(),
        metadata: BTreeMap::new(),
        content_digest: content_ref.digest.clone(),
        content_ref,
        expires_at_ms: 0,
        hold_id: String::new(),
        hold_reason: String::new(),
        admitted_by: owner.into(),
        admitted_at_ms: 1_000,
        deleted_at_ms: 0,
    }
}

fn rendition() -> ImageRendition {
    ImageRendition {
        namespace: "records".into(),
        image_id: "img:site".into(),
        rendition_id: "ren:thumb".into(),
        class: RENDITION_THUMBNAIL.into(),
        parent_content_digest: digest(1),
        content_ref: content(2),
        extractor_id: "extractor".into(),
        extractor_profile_digest: digest(3),
        attached_by: "analyst".into(),
        attached_at_ms: 2_000,
    }
}

fn annotation() -> ImageAnnotation {
    ImageAnnotation {
        namespace: "records".into(),
        image_id: "img:site".into(),
        annotation_id: "ann:label".into(),
        class: ANNOTATION_LABEL.into(),
        parent_content_digest: digest(1),
        payload: BTreeMap::from([("label".into(), "door".into())]),
        attached_by: "analyst".into(),
        attached_at_ms: 3_000,
    }
}

fn exercise(db: &RuntimeDb) {
    assert_eq!(
        db.put_governed_image_rendition(&rendition()).unwrap_err(),
        IMAGE_UNAVAILABLE
    );
    assert_eq!(
        db.put_governed_image_annotation(&annotation()).unwrap_err(),
        IMAGE_UNAVAILABLE
    );

    let first = image("analyst");
    db.put_governed_image(&first).unwrap();
    assert_eq!(
        db.get_governed_image("records", "img:site").unwrap(),
        Some(first.clone())
    );
    db.put_governed_image(&first).unwrap();

    let mut taken = first.clone();
    taken.owner = "other".into();
    taken.title = "takeover".into();
    assert_eq!(
        db.put_governed_image(&taken).unwrap_err(),
        IMAGE_UNAVAILABLE
    );
    assert_eq!(
        db.get_governed_image("records", "img:site")
            .unwrap()
            .unwrap()
            .title,
        "site"
    );

    db.put_governed_image_rendition(&rendition()).unwrap();
    assert_eq!(
        db.list_governed_image_renditions("records", "img:site")
            .unwrap(),
        vec![rendition()]
    );
    db.put_governed_image_annotation(&annotation()).unwrap();
    assert_eq!(
        db.list_governed_image_annotations("records", "img:site")
            .unwrap(),
        vec![annotation()]
    );

    let mut tombstoned = first.clone();
    tombstoned.deleted_at_ms = 4_000;
    db.tombstone_governed_image(&tombstoned).unwrap();
    assert_eq!(
        db.get_governed_image("records", "img:site").unwrap(),
        Some(tombstoned.clone())
    );
    assert!(
        db.list_governed_image_renditions("records", "img:site")
            .unwrap()
            .is_empty()
    );
    assert!(
        db.list_governed_image_annotations("records", "img:site")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.tombstone_governed_image(&taken).unwrap_err(),
        IMAGE_UNAVAILABLE
    );

    assert_eq!(
        db.put_governed_image_rendition(&ImageRendition {
            image_id: "img:missing".into(),
            ..rendition()
        })
        .unwrap_err(),
        IMAGE_UNAVAILABLE
    );
    assert_eq!(
        db.put_governed_image_annotation(&ImageAnnotation {
            image_id: "img:missing".into(),
            ..annotation()
        })
        .unwrap_err(),
        IMAGE_UNAVAILABLE
    );
}

#[test]
fn sqlite_governed_image_backend_conformance() {
    exercise(&RuntimeDb::memory());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_governed_image_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise(&db);
}
