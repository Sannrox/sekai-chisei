//! Governed image objects, digest-bound renditions, and annotations (#696).
//!
//! An image is an object that binds metadata, a content reference, purpose,
//! classification, retention, and hold. Renditions and annotations are
//! derived children. The plane does not store bytes or run a renderer.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::evidence::EvidenceClassification;
use crate::sekai::markings::{
    PRINCIPAL_PROFILE_KIND, PRINCIPAL_PROFILE_SEALED_PROPERTY, PrincipalAuthority,
    parse_classification, principal_authority_from_profile, principal_profile_external_id,
    trusted_service_authority,
};
use crate::sekai::security::Role;
use crate::shomei;

pub const IMAGE_CONTRACT: &str = "sekai.governed-image/v1";
pub const TYPE_REVISION_V1: &str = "v1";
pub const CONTENT_SCHEME_DIGEST: &str = "digest";
pub const FIELD_IDENTITY: &str = "identity";
pub const FIELD_CONTENT_REF: &str = "content_ref";
pub const FIELD_METADATA: &str = "metadata";
pub const FIELD_RENDITIONS: &str = "renditions";
pub const FIELD_ANNOTATIONS: &str = "annotations";
pub const FIELD_BYTES: &str = "bytes";
pub const FIELD_BINARY: &str = "binary";
pub const RENDITION_THUMBNAIL: &str = "thumbnail";
pub const RENDITION_DERIVED_METADATA: &str = "derived_metadata";
pub const ANNOTATION_REGION: &str = "region";
pub const ANNOTATION_LABEL: &str = "label";
pub const MAX_METADATA_KEYS: usize = 32;
pub const MAX_METADATA_BYTES: usize = 8 * 1024;
pub const MAX_ANNOTATION_KEYS: usize = 32;
pub const MAX_ANNOTATION_BYTES: usize = 8 * 1024;
pub const MAX_RENDITIONS: usize = 16;
pub const MAX_ANNOTATIONS: usize = 16;
pub const IMAGE_UNAVAILABLE: &str = "governed image is unavailable";
pub const IMAGE_HELD: &str = "governed image is held";
pub const REVISION_UNSUPPORTED: &str = "governed image revision is unsupported";
pub const FORMAT_UNSUPPORTED: &str = "governed image format is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "governed images are unavailable on the PostgreSQL community runtime";

const MEDIA_PNG: &str = "image/png";
const MEDIA_JPEG: &str = "image/jpeg";
const MEDIA_WEBP: &str = "image/webp";
const MEDIA_JSON: &str = "application/json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentReference {
    pub scheme: String,
    pub digest: String,
    pub media_type: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedImage {
    pub contract_version: String,
    pub image_id: String,
    pub namespace: String,
    pub owner: String,
    pub type_revision: String,
    pub purpose: String,
    pub classification: String,
    pub title: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub content_ref: ContentReference,
    pub content_digest: String,
    #[serde(default)]
    pub expires_at_ms: i64,
    #[serde(default)]
    pub hold_id: String,
    #[serde(default)]
    pub hold_reason: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
    #[serde(default)]
    pub deleted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRendition {
    pub namespace: String,
    pub image_id: String,
    pub rendition_id: String,
    pub class: String,
    pub parent_content_digest: String,
    pub content_ref: ContentReference,
    pub extractor_id: String,
    pub extractor_profile_digest: String,
    pub attached_by: String,
    pub attached_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageAnnotation {
    pub namespace: String,
    pub image_id: String,
    pub annotation_id: String,
    pub class: String,
    pub parent_content_digest: String,
    #[serde(default)]
    pub payload: BTreeMap<String, String>,
    pub attached_by: String,
    pub attached_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageRetrieve {
    pub namespace: String,
    pub image_id: String,
    pub purpose: Option<String>,
    pub fields: Vec<String>,
    pub classification_ceiling: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageView {
    pub contract_version: String,
    pub image_id: String,
    pub namespace: String,
    pub type_revision: String,
    pub lifecycle: String,
    pub definition_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<ContentReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renditions: Option<Vec<ImageRendition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<ImageAnnotation>>,
}

#[derive(Serialize)]
struct ContentPin<'a> {
    scheme: &'a str,
    digest: &'a str,
    media_type: &'a str,
    byte_length: u64,
}

#[derive(Serialize)]
struct DefinitionPin<'a> {
    contract_version: &'a str,
    image_id: &'a str,
    namespace: &'a str,
    owner: &'a str,
    type_revision: &'a str,
    purpose: &'a str,
    classification: &'a str,
    title: &'a str,
    metadata: &'a BTreeMap<String, String>,
    content_ref: &'a ContentReference,
}

pub fn content_digest_for(reference: &ContentReference) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&ContentPin {
            scheme: &reference.scheme,
            digest: &reference.digest,
            media_type: &reference.media_type,
            byte_length: reference.byte_length,
        })?
    ))
}

pub fn admit_image(
    db: &RuntimeDb,
    actor: &str,
    image: &GovernedImage,
    now_ms: i64,
) -> Result<GovernedImage, String> {
    required("actor", actor)?;
    require_positive_timestamp("admit", now_ms)?;
    let validated = validate_image(image, actor, now_ms)?;
    if let Some(existing) = db.get_governed_image(&validated.namespace, &validated.image_id)? {
        if existing.deleted_at_ms != 0 || existing.owner != actor || is_expired(&existing, now_ms) {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        if existing.content_digest == validated.content_digest
            && definition_digest(&existing)? == definition_digest(&validated)?
        {
            return Ok(existing);
        }
        return Err(IMAGE_UNAVAILABLE.into());
    }
    db.put_governed_image(&validated)?;
    Ok(validated)
}

pub fn attach_rendition(
    db: &RuntimeDb,
    actor: &str,
    rendition: &ImageRendition,
    now_ms: i64,
) -> Result<ImageRendition, String> {
    required("actor", actor)?;
    require_positive_timestamp("attach", now_ms)?;
    let image = live_image(db, &rendition.namespace, &rendition.image_id, actor, now_ms)?;
    let validated = validate_rendition(&image, rendition, actor, now_ms)?;
    let existing = db.list_governed_image_renditions(&image.namespace, &image.image_id)?;
    if existing.len() >= MAX_RENDITIONS
        && existing
            .iter()
            .all(|item| item.rendition_id != validated.rendition_id)
    {
        return Err("governed image rendition list is oversized".into());
    }
    if let Some(prior) = existing
        .iter()
        .find(|item| item.rendition_id == validated.rendition_id)
    {
        if prior == &validated {
            return Ok(prior.clone());
        }
        return Err(IMAGE_UNAVAILABLE.into());
    }
    db.put_governed_image_rendition(&validated)?;
    Ok(validated)
}

pub fn attach_annotation(
    db: &RuntimeDb,
    actor: &str,
    annotation: &ImageAnnotation,
    now_ms: i64,
) -> Result<ImageAnnotation, String> {
    required("actor", actor)?;
    require_positive_timestamp("attach", now_ms)?;
    let image = live_image(
        db,
        &annotation.namespace,
        &annotation.image_id,
        actor,
        now_ms,
    )?;
    let validated = validate_annotation(&image, annotation, actor, now_ms)?;
    let existing = db.list_governed_image_annotations(&image.namespace, &image.image_id)?;
    if existing.len() >= MAX_ANNOTATIONS
        && existing
            .iter()
            .all(|item| item.annotation_id != validated.annotation_id)
    {
        return Err("governed image annotation list is oversized".into());
    }
    if let Some(prior) = existing
        .iter()
        .find(|item| item.annotation_id == validated.annotation_id)
    {
        if prior == &validated {
            return Ok(prior.clone());
        }
        return Err(IMAGE_UNAVAILABLE.into());
    }
    db.put_governed_image_annotation(&validated)?;
    Ok(validated)
}

pub fn retrieve_image(
    db: &RuntimeDb,
    actor: &str,
    query: &ImageRetrieve,
    now_ms: i64,
) -> Result<ImageView, String> {
    required("actor", actor)?;
    required("namespace", &query.namespace)?;
    required("image id", &query.image_id)?;
    require_positive_timestamp("retrieve", now_ms)?;
    let fields = requested_fields(&query.fields)?;
    let image = live_image(db, &query.namespace, &query.image_id, actor, now_ms)?;
    let authority = retrieve_authority(db, actor, query)?;
    if !classification_visible(&image.classification, &authority) {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    if query.purpose.as_deref() != Some(image.purpose.as_str()) {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    if !authority.allowed_purposes.is_empty()
        && !authority.allowed_purposes.contains(&image.purpose)
    {
        return Err(IMAGE_UNAVAILABLE.into());
    }

    let wants_content = fields.contains(FIELD_CONTENT_REF);
    let wants_metadata = fields.contains(FIELD_METADATA);
    let wants_renditions = fields.contains(FIELD_RENDITIONS);
    let wants_annotations = fields.contains(FIELD_ANNOTATIONS);
    let renditions = if wants_renditions {
        Some(db.list_governed_image_renditions(&image.namespace, &image.image_id)?)
    } else {
        None
    };
    let annotations = if wants_annotations {
        Some(db.list_governed_image_annotations(&image.namespace, &image.image_id)?)
    } else {
        None
    };

    let lifecycle = lifecycle_of(&image, now_ms);
    let definition_digest = definition_digest(&image)?;
    Ok(ImageView {
        contract_version: image.contract_version,
        image_id: image.image_id,
        namespace: image.namespace,
        type_revision: image.type_revision,
        lifecycle,
        definition_digest,
        content_ref: wants_content.then_some(image.content_ref),
        title: wants_metadata.then_some(image.title),
        metadata: wants_metadata.then_some(image.metadata),
        purpose: wants_metadata.then_some(image.purpose),
        classification: wants_metadata.then_some(image.classification),
        expires_at_ms: wants_metadata.then_some(image.expires_at_ms),
        hold_id: wants_metadata.then(|| image.hold_id.clone()),
        renditions,
        annotations,
    })
}

pub fn place_hold(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    image_id: &str,
    hold_id: &str,
    reason: &str,
    now_ms: i64,
) -> Result<GovernedImage, String> {
    required("actor", actor)?;
    required("hold id", hold_id)?;
    required("hold reason", reason)?;
    require_positive_timestamp("hold", now_ms)?;
    let mut image = live_image(db, namespace, image_id, actor, now_ms)?;
    if !image.hold_id.is_empty() && image.hold_id != hold_id {
        return Err(IMAGE_HELD.into());
    }
    image.hold_id = hold_id.into();
    image.hold_reason = reason.into();
    db.put_governed_image(&image)?;
    Ok(image)
}

pub fn release_hold(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    image_id: &str,
    hold_id: &str,
    now_ms: i64,
) -> Result<GovernedImage, String> {
    required("actor", actor)?;
    required("hold id", hold_id)?;
    require_positive_timestamp("release", now_ms)?;
    let mut image = live_image(db, namespace, image_id, actor, now_ms)?;
    if image.hold_id != hold_id {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    image.hold_id.clear();
    image.hold_reason.clear();
    db.put_governed_image(&image)?;
    Ok(image)
}

pub fn expire_image(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    image_id: &str,
    now_ms: i64,
) -> Result<GovernedImage, String> {
    required("actor", actor)?;
    require_positive_timestamp("expire", now_ms)?;
    let mut image = owned_image(db, namespace, image_id, actor)?;
    if image.deleted_at_ms != 0 {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    if !image.hold_id.is_empty() {
        return Err(IMAGE_HELD.into());
    }
    if image.expires_at_ms == 0 || image.expires_at_ms > now_ms {
        image.expires_at_ms = now_ms;
    }
    db.put_governed_image(&image)?;
    Ok(image)
}

pub fn delete_image(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    image_id: &str,
    now_ms: i64,
) -> Result<GovernedImage, String> {
    required("actor", actor)?;
    require_positive_timestamp("delete", now_ms)?;
    let mut image = owned_image(db, namespace, image_id, actor)?;
    if image.deleted_at_ms != 0 {
        return Ok(image);
    }
    if !image.hold_id.is_empty() {
        return Err(IMAGE_HELD.into());
    }
    if is_expired(&image, now_ms) {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    image.deleted_at_ms = now_ms;
    db.tombstone_governed_image(&image)?;
    Ok(image)
}

fn live_image(
    db: &RuntimeDb,
    namespace: &str,
    image_id: &str,
    actor: &str,
    now_ms: i64,
) -> Result<GovernedImage, String> {
    let image = owned_image(db, namespace, image_id, actor)?;
    if image.deleted_at_ms != 0 || is_expired(&image, now_ms) {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    if image.contract_version != IMAGE_CONTRACT || image.type_revision != TYPE_REVISION_V1 {
        return Err(REVISION_UNSUPPORTED.into());
    }
    if content_digest_for(&image.content_ref)? != image.content_digest {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    Ok(image)
}

fn owned_image(
    db: &RuntimeDb,
    namespace: &str,
    image_id: &str,
    actor: &str,
) -> Result<GovernedImage, String> {
    required("namespace", namespace)?;
    required("image id", image_id)?;
    let image = db
        .get_governed_image(namespace, image_id)?
        .ok_or(IMAGE_UNAVAILABLE)?;
    if image.owner != actor {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    Ok(image)
}

fn validate_image(
    image: &GovernedImage,
    actor: &str,
    now_ms: i64,
) -> Result<GovernedImage, String> {
    if image.contract_version != IMAGE_CONTRACT || image.type_revision != TYPE_REVISION_V1 {
        return Err(REVISION_UNSUPPORTED.into());
    }
    required("image id", &image.image_id)?;
    required("namespace", &image.namespace)?;
    required("owner", &image.owner)?;
    required("purpose", &image.purpose)?;
    required("title", &image.title)?;
    if image.owner != actor {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    parse_classification(&image.classification)?;
    if image.expires_at_ms < 0 {
        return Err("image expiry must be non-negative".into());
    }
    if !image.hold_id.is_empty() {
        required("hold reason", &image.hold_reason)?;
    }
    validate_metadata(&image.metadata)?;
    validate_content_ref(&image.content_ref, None)?;
    let digest = content_digest_for(&image.content_ref)?;
    if !image.content_digest.is_empty() && image.content_digest != digest {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    if image.deleted_at_ms != 0 {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    Ok(GovernedImage {
        content_digest: digest,
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
        deleted_at_ms: 0,
        ..image.clone()
    })
}

fn validate_rendition(
    image: &GovernedImage,
    rendition: &ImageRendition,
    actor: &str,
    now_ms: i64,
) -> Result<ImageRendition, String> {
    if rendition.namespace != image.namespace || rendition.image_id != image.image_id {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    required("namespace", &rendition.namespace)?;
    required("rendition id", &rendition.rendition_id)?;
    required("extractor id", &rendition.extractor_id)?;
    required(
        "extractor profile digest",
        &rendition.extractor_profile_digest,
    )?;
    if !supported_rendition_class(&rendition.class) {
        return Err(REVISION_UNSUPPORTED.into());
    }
    if rendition.parent_content_digest != image.content_digest {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    if !digest_token(&rendition.extractor_profile_digest) {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    validate_content_ref(&rendition.content_ref, Some(&rendition.class))?;
    Ok(ImageRendition {
        attached_by: actor.into(),
        attached_at_ms: now_ms,
        ..rendition.clone()
    })
}

fn validate_annotation(
    image: &GovernedImage,
    annotation: &ImageAnnotation,
    actor: &str,
    now_ms: i64,
) -> Result<ImageAnnotation, String> {
    if annotation.namespace != image.namespace || annotation.image_id != image.image_id {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    required("namespace", &annotation.namespace)?;
    required("annotation id", &annotation.annotation_id)?;
    if !supported_annotation_class(&annotation.class) {
        return Err(REVISION_UNSUPPORTED.into());
    }
    if annotation.parent_content_digest != image.content_digest {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    validate_annotation_payload(&annotation.payload)?;
    Ok(ImageAnnotation {
        attached_by: actor.into(),
        attached_at_ms: now_ms,
        ..annotation.clone()
    })
}

fn validate_content_ref(reference: &ContentReference, class: Option<&str>) -> Result<(), String> {
    if reference.scheme != CONTENT_SCHEME_DIGEST {
        return Err(REVISION_UNSUPPORTED.into());
    }
    if !digest_token(&reference.digest) {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    if reference.byte_length == 0 || reference.byte_length > 32 * 1024 * 1024 {
        return Err("governed image content length is invalid".into());
    }
    if !supported_media_type(&reference.media_type, class) {
        return Err(FORMAT_UNSUPPORTED.into());
    }
    Ok(())
}

fn validate_metadata(metadata: &BTreeMap<String, String>) -> Result<(), String> {
    bound_string_map(
        metadata,
        MAX_METADATA_KEYS,
        MAX_METADATA_BYTES,
        "governed image metadata is oversized",
        "metadata",
    )
}

fn validate_annotation_payload(payload: &BTreeMap<String, String>) -> Result<(), String> {
    for key in payload.keys() {
        if key == FIELD_BYTES || key == FIELD_BINARY {
            return Err(IMAGE_UNAVAILABLE.into());
        }
    }
    bound_string_map(
        payload,
        MAX_ANNOTATION_KEYS,
        MAX_ANNOTATION_BYTES,
        "governed image annotation payload is oversized",
        "annotation payload",
    )
}

fn bound_string_map(
    values: &BTreeMap<String, String>,
    max_keys: usize,
    max_bytes: usize,
    oversized: &str,
    label: &str,
) -> Result<(), String> {
    if values.len() > max_keys {
        return Err(oversized.into());
    }
    let encoded = serde_json::to_vec(values).map_err(|error| error.to_string())?;
    if encoded.len() > max_bytes {
        return Err(oversized.into());
    }
    let mut seen = BTreeSet::new();
    for (key, value) in values {
        required(&format!("{label} key"), key)?;
        if !seen.insert(key) {
            return Err(format!("duplicate image {label} key {key}"));
        }
        required(&format!("{label} value"), value)?;
    }
    Ok(())
}

fn requested_fields(fields: &[String]) -> Result<BTreeSet<&str>, String> {
    let mut requested = BTreeSet::new();
    for field in fields {
        if matches!(field.as_str(), FIELD_BYTES | FIELD_BINARY)
            || !matches!(
                field.as_str(),
                FIELD_IDENTITY
                    | FIELD_CONTENT_REF
                    | FIELD_METADATA
                    | FIELD_RENDITIONS
                    | FIELD_ANNOTATIONS
            )
        {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        if !requested.insert(field.as_str()) {
            return Err(IMAGE_UNAVAILABLE.into());
        }
    }
    requested.insert(FIELD_IDENTITY);
    Ok(requested)
}

fn retrieve_authority(
    db: &RuntimeDb,
    actor: &str,
    query: &ImageRetrieve,
) -> Result<PrincipalAuthority, String> {
    let mut authority = if let Some(trusted) = trusted_service_authority(actor) {
        trusted
    } else {
        let candidates = db.find_all_by_external_id(&principal_profile_external_id(actor))?;
        let mut sealed = Vec::new();
        for object in &candidates {
            if object.kind != PRINCIPAL_PROFILE_KIND {
                continue;
            }
            if object
                .properties
                .get(PRINCIPAL_PROFILE_SEALED_PROPERTY)
                .is_none_or(|value| value != "true")
            {
                continue;
            }
            if db
                .list_grants(&object.id)?
                .iter()
                .any(|grant| matches!(grant.role, Role::Admin))
            {
                sealed.push(object);
            }
        }
        if sealed.len() > 1 {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        principal_authority_from_profile(actor, sealed.first().copied())?
    };
    if let Some(requested) = query.classification_ceiling.as_deref() {
        let requested = parse_classification(requested)?;
        if authority
            .classification_ceiling
            .is_some_and(|existing| requested < existing)
        {
            authority.classification_ceiling = Some(requested);
            authority.classification_token = Some(requested.as_str().into());
        }
    }
    Ok(authority)
}

fn classification_visible(classification: &str, authority: &PrincipalAuthority) -> bool {
    let Ok(marking) = parse_classification(classification) else {
        return false;
    };
    if marking == EvidenceClassification::Public {
        return true;
    }
    authority
        .classification_ceiling
        .is_some_and(|ceiling| ceiling >= marking)
}

fn supported_media_type(media_type: &str, class: Option<&str>) -> bool {
    match class {
        Some(RENDITION_THUMBNAIL) => matches!(media_type, MEDIA_PNG | MEDIA_JPEG),
        Some(RENDITION_DERIVED_METADATA) => media_type == MEDIA_JSON,
        None => matches!(media_type, MEDIA_PNG | MEDIA_JPEG | MEDIA_WEBP),
        Some(_) => false,
    }
}

fn supported_rendition_class(class: &str) -> bool {
    matches!(class, RENDITION_THUMBNAIL | RENDITION_DERIVED_METADATA)
}

fn supported_annotation_class(class: &str) -> bool {
    matches!(class, ANNOTATION_REGION | ANNOTATION_LABEL)
}

fn digest_token(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_expired(image: &GovernedImage, now_ms: i64) -> bool {
    image.hold_id.is_empty() && image.expires_at_ms > 0 && now_ms >= image.expires_at_ms
}

fn lifecycle_of(image: &GovernedImage, now_ms: i64) -> String {
    if image.deleted_at_ms != 0 {
        "deleted".into()
    } else if is_expired(image, now_ms) {
        "expired".into()
    } else if !image.hold_id.is_empty() {
        "held".into()
    } else {
        "admitted".into()
    }
}

fn definition_digest(image: &GovernedImage) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&DefinitionPin {
            contract_version: &image.contract_version,
            image_id: &image.image_id,
            namespace: &image.namespace,
            owner: &image.owner,
            type_revision: &image.type_revision,
            purpose: &image.purpose,
            classification: &image.classification,
            title: &image.title,
            metadata: &image.metadata,
            content_ref: &image.content_ref,
        })?
    ))
}

fn require_positive_timestamp(label: &str, now_ms: i64) -> Result<(), String> {
    if now_ms <= 0 {
        Err(format!("{label} timestamp must be positive"))
    } else {
        Ok(())
    }
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY;
    use crate::sekai::security::Grant;
    use std::collections::HashMap;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn pin_ceiling(runtime: &RuntimeDb, principal: &str, ceiling: &str) {
        let profile_id = format!("profile:{principal}");
        runtime
            .create_object(&Object {
                id: profile_id.clone(),
                kind: PRINCIPAL_PROFILE_KIND.into(),
                name: principal.into(),
                namespace: "records".into(),
                external_id: principal_profile_external_id(principal),
                properties: HashMap::from([
                    (
                        PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        ceiling.into(),
                    ),
                    (PRINCIPAL_PROFILE_SEALED_PROPERTY.into(), "true".into()),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        runtime
            .create_grant(&Grant {
                id: format!("grant:{principal}"),
                object_id: profile_id,
                principal: "root".into(),
                role: Role::Admin,
                created: 1,
            })
            .unwrap();
    }

    fn digest(tag: u8) -> String {
        format!("sha256:{tag:02x}{}", "ab".repeat(31))
    }

    fn content_ref(media: &str) -> ContentReference {
        ContentReference {
            scheme: CONTENT_SCHEME_DIGEST.into(),
            digest: digest(1),
            media_type: media.into(),
            byte_length: 128,
        }
    }

    fn image() -> GovernedImage {
        let content_ref = content_ref(MEDIA_PNG);
        GovernedImage {
            contract_version: IMAGE_CONTRACT.into(),
            image_id: "img:site".into(),
            namespace: "records".into(),
            owner: "analyst".into(),
            type_revision: TYPE_REVISION_V1.into(),
            purpose: "case-review".into(),
            classification: "internal".into(),
            title: "Site photo".into(),
            metadata: BTreeMap::from([("source".into(), "intake".into())]),
            content_digest: content_digest_for(&content_ref).unwrap(),
            content_ref,
            expires_at_ms: 10_000,
            hold_id: String::new(),
            hold_reason: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
            deleted_at_ms: 0,
        }
    }

    fn thumbnail() -> ImageRendition {
        ImageRendition {
            namespace: "records".into(),
            image_id: "img:site".into(),
            rendition_id: "rend:thumb".into(),
            class: RENDITION_THUMBNAIL.into(),
            parent_content_digest: content_digest_for(&content_ref(MEDIA_PNG)).unwrap(),
            content_ref: ContentReference {
                scheme: CONTENT_SCHEME_DIGEST.into(),
                digest: digest(2),
                media_type: MEDIA_JPEG.into(),
                byte_length: 32,
            },
            extractor_id: "extractor:thumb".into(),
            extractor_profile_digest: digest(3),
            attached_by: String::new(),
            attached_at_ms: 0,
        }
    }

    fn derived_metadata() -> ImageRendition {
        ImageRendition {
            namespace: "records".into(),
            image_id: "img:site".into(),
            rendition_id: "rend:meta".into(),
            class: RENDITION_DERIVED_METADATA.into(),
            parent_content_digest: content_digest_for(&content_ref(MEDIA_PNG)).unwrap(),
            content_ref: ContentReference {
                scheme: CONTENT_SCHEME_DIGEST.into(),
                digest: digest(4),
                media_type: MEDIA_JSON.into(),
                byte_length: 16,
            },
            extractor_id: "extractor:exif".into(),
            extractor_profile_digest: digest(5),
            attached_by: String::new(),
            attached_at_ms: 0,
        }
    }

    fn annotation() -> ImageAnnotation {
        ImageAnnotation {
            namespace: "records".into(),
            image_id: "img:site".into(),
            annotation_id: "ann:door".into(),
            class: ANNOTATION_REGION.into(),
            parent_content_digest: content_digest_for(&content_ref(MEDIA_PNG)).unwrap(),
            payload: BTreeMap::from([
                ("x".into(), "12".into()),
                ("y".into(), "8".into()),
                ("label".into(), "door".into()),
            ]),
            attached_by: String::new(),
            attached_at_ms: 0,
        }
    }

    fn admit(runtime: &RuntimeDb) -> GovernedImage {
        pin_ceiling(runtime, "analyst", "internal");
        admit_image(runtime, "analyst", &image(), 1_000).unwrap()
    }

    fn retrieve(
        runtime: &RuntimeDb,
        fields: &[&str],
        purpose: &str,
        ceiling: Option<&str>,
    ) -> Result<ImageView, String> {
        retrieve_image(
            runtime,
            "analyst",
            &ImageRetrieve {
                namespace: "records".into(),
                image_id: "img:site".into(),
                purpose: Some(purpose.into()),
                fields: fields.iter().map(|field| (*field).to_string()).collect(),
                classification_ceiling: ceiling.map(str::to_string),
            },
            2_000,
        )
    }

    #[test]
    fn authorized_admit_attaches_and_retrieves_original_thumbnail_metadata_and_annotation() {
        let runtime = db();
        let admitted = admit(&runtime);
        assert_eq!(admitted.contract_version, IMAGE_CONTRACT);
        assert_eq!(admitted.content_ref.media_type, MEDIA_PNG);
        let thumb = attach_rendition(&runtime, "analyst", &thumbnail(), 1_500).unwrap();
        let derived = attach_rendition(&runtime, "analyst", &derived_metadata(), 1_600).unwrap();
        let note = attach_annotation(&runtime, "analyst", &annotation(), 1_700).unwrap();
        let view = retrieve(
            &runtime,
            &[
                FIELD_CONTENT_REF,
                FIELD_METADATA,
                FIELD_RENDITIONS,
                FIELD_ANNOTATIONS,
            ],
            "case-review",
            Some("internal"),
        )
        .unwrap();
        assert_eq!(view.lifecycle, "admitted");
        assert_eq!(
            view.content_ref.unwrap().digest,
            admitted.content_ref.digest
        );
        assert_eq!(view.metadata.unwrap().get("source").unwrap(), "intake");
        assert_eq!(view.renditions.unwrap(), vec![derived, thumb]);
        assert_eq!(view.annotations.unwrap(), vec![note]);
        assert_eq!(
            retrieve(&runtime, &[], "case-review", Some("internal"))
                .unwrap()
                .content_ref,
            None
        );
    }

    #[test]
    fn binary_request_fails_unavailable_before_disclosure() {
        let runtime = db();
        admit(&runtime);
        attach_rendition(&runtime, "analyst", &thumbnail(), 1_500).unwrap();
        for fields in [
            &[FIELD_BYTES][..],
            &[FIELD_BINARY][..],
            &[FIELD_BYTES, FIELD_CONTENT_REF][..],
            &[FIELD_BINARY, FIELD_METADATA, FIELD_RENDITIONS][..],
        ] {
            assert_eq!(
                retrieve(&runtime, fields, "case-review", Some("internal")).unwrap_err(),
                IMAGE_UNAVAILABLE
            );
        }
        let view = retrieve(
            &runtime,
            &[FIELD_CONTENT_REF],
            "case-review",
            Some("internal"),
        )
        .unwrap();
        assert!(view.content_ref.is_some());
        assert!(view.metadata.is_none());
        assert!(view.renditions.is_none());
    }

    #[test]
    fn metadata_purpose_unknown_field_and_foreign_owner_fail_unavailable() {
        let runtime = db();
        admit(&runtime);
        assert_eq!(
            retrieve(
                &runtime,
                &[FIELD_METADATA],
                "other-purpose",
                Some("internal")
            )
            .unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert_eq!(
            retrieve(&runtime, &[FIELD_METADATA], "case-review", Some("public")).unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert_eq!(
            retrieve_image(
                &runtime,
                "intruder",
                &ImageRetrieve {
                    namespace: "records".into(),
                    image_id: "img:site".into(),
                    purpose: Some("case-review".into()),
                    fields: vec![FIELD_METADATA.into()],
                    classification_ceiling: Some("restricted".into()),
                },
                2_000,
            )
            .unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert_eq!(
            retrieve(&runtime, &["secret"], "case-review", Some("internal")).unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert_eq!(
            retrieve(&runtime, &["hidden"], "case-review", Some("internal")).unwrap_err(),
            IMAGE_UNAVAILABLE
        );
    }

    #[test]
    fn replay_identical_admit_is_idempotent() {
        let runtime = db();
        let first = admit(&runtime);
        let second = admit_image(&runtime, "analyst", &image(), 2_000).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.content_digest, second.content_digest);

        let mut changed = image();
        changed.content_ref.digest = digest(9);
        changed.content_digest.clear();
        assert_eq!(
            admit_image(&runtime, "analyst", &changed, 3_000).unwrap_err(),
            IMAGE_UNAVAILABLE
        );

        let mut unknown = serde_json::to_value(image()).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("hidden".into(), serde_json::json!("nope"));
        assert!(serde_json::from_value::<GovernedImage>(unknown).is_err());
    }

    #[test]
    fn unknown_format_unsupported_revision_and_corrupt_digest_fail_before_persist() {
        let runtime = db();
        pin_ceiling(&runtime, "analyst", "internal");
        let mut bad_media = image();
        bad_media.content_ref.media_type = "application/x-unknown".into();
        bad_media.content_digest.clear();
        assert_eq!(
            admit_image(&runtime, "analyst", &bad_media, 1_000).unwrap_err(),
            FORMAT_UNSUPPORTED
        );
        let mut bad_revision = image();
        bad_revision.type_revision = "v2".into();
        bad_revision.content_digest.clear();
        assert_eq!(
            admit_image(&runtime, "analyst", &bad_revision, 1_000).unwrap_err(),
            REVISION_UNSUPPORTED
        );
        let mut corrupt = image();
        corrupt.content_digest = digest(8);
        assert_eq!(
            admit_image(&runtime, "analyst", &corrupt, 1_000).unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert!(
            runtime
                .get_governed_image("records", "img:site")
                .unwrap()
                .is_none()
        );

        admit_image(&runtime, "analyst", &image(), 1_000).unwrap();
        let mut mismatch = thumbnail();
        mismatch.parent_content_digest = digest(8);
        assert_eq!(
            attach_rendition(&runtime, "analyst", &mismatch, 2_000).unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        let mut bad_class = thumbnail();
        bad_class.class = "ocr-box".into();
        assert_eq!(
            attach_rendition(&runtime, "analyst", &bad_class, 2_000).unwrap_err(),
            REVISION_UNSUPPORTED
        );
        let mut webp_thumb = thumbnail();
        webp_thumb.content_ref.media_type = MEDIA_WEBP.into();
        assert_eq!(
            attach_rendition(&runtime, "analyst", &webp_thumb, 2_000).unwrap_err(),
            FORMAT_UNSUPPORTED
        );
        let mut bad_note = annotation();
        bad_note.class = "mask".into();
        assert_eq!(
            attach_annotation(&runtime, "analyst", &bad_note, 2_000).unwrap_err(),
            REVISION_UNSUPPORTED
        );
        assert!(
            runtime
                .list_governed_image_renditions("records", "img:site")
                .unwrap()
                .is_empty()
        );
        assert!(
            runtime
                .list_governed_image_annotations("records", "img:site")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn hold_blocks_expire_and_delete_then_release_expire_and_terminal_delete() {
        let runtime = db();
        admit(&runtime);
        attach_rendition(&runtime, "analyst", &thumbnail(), 1_500).unwrap();
        attach_annotation(&runtime, "analyst", &annotation(), 1_600).unwrap();

        let held = place_hold(
            &runtime,
            "analyst",
            "records",
            "img:site",
            "hold:1",
            "litigation",
            3_000,
        )
        .unwrap();
        assert_eq!(held.hold_id, "hold:1");
        assert_eq!(
            retrieve(&runtime, &[FIELD_METADATA], "case-review", Some("internal"))
                .unwrap()
                .lifecycle,
            "held"
        );
        assert_eq!(
            delete_image(&runtime, "analyst", "records", "img:site", 4_000).unwrap_err(),
            IMAGE_HELD
        );
        assert_eq!(
            expire_image(&runtime, "analyst", "records", "img:site", 4_000).unwrap_err(),
            IMAGE_HELD
        );
        assert_eq!(
            retrieve_image(
                &runtime,
                "analyst",
                &ImageRetrieve {
                    namespace: "records".into(),
                    image_id: "img:site".into(),
                    purpose: Some("case-review".into()),
                    fields: vec![FIELD_METADATA.into()],
                    classification_ceiling: Some("internal".into()),
                },
                12_000,
            )
            .unwrap()
            .lifecycle,
            "held"
        );
        release_hold(&runtime, "analyst", "records", "img:site", "hold:1", 12_000).unwrap();
        expire_image(&runtime, "analyst", "records", "img:site", 9_000).unwrap();
        assert_eq!(
            retrieve_image(
                &runtime,
                "analyst",
                &ImageRetrieve {
                    namespace: "records".into(),
                    image_id: "img:site".into(),
                    purpose: Some("case-review".into()),
                    fields: Vec::new(),
                    classification_ceiling: Some("internal".into()),
                },
                9_000,
            )
            .unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert_eq!(
            admit_image(&runtime, "analyst", &image(), 9_000).unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert_eq!(
            attach_rendition(&runtime, "analyst", &thumbnail(), 9_100).unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert_eq!(
            delete_image(&runtime, "analyst", "records", "img:site", 9_200).unwrap_err(),
            IMAGE_UNAVAILABLE
        );

        let runtime = db();
        admit(&runtime);
        attach_rendition(&runtime, "analyst", &thumbnail(), 1_500).unwrap();
        attach_annotation(&runtime, "analyst", &annotation(), 1_600).unwrap();
        delete_image(&runtime, "analyst", "records", "img:site", 5_000).unwrap();
        assert_eq!(
            retrieve(&runtime, &[], "case-review", Some("internal")).unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert_eq!(
            admit_image(&runtime, "analyst", &image(), 6_000).unwrap_err(),
            IMAGE_UNAVAILABLE
        );
        assert!(
            runtime
                .list_governed_image_renditions("records", "img:site")
                .unwrap()
                .is_empty()
        );
        assert!(
            runtime
                .list_governed_image_annotations("records", "img:site")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn zero_and_negative_timestamps_fail_before_mutation() {
        let runtime = db();
        pin_ceiling(&runtime, "analyst", "internal");
        for now in [0, -1] {
            assert_eq!(
                admit_image(&runtime, "analyst", &image(), now).unwrap_err(),
                "admit timestamp must be positive"
            );
            assert_eq!(
                retrieve_image(
                    &runtime,
                    "analyst",
                    &ImageRetrieve {
                        namespace: "records".into(),
                        image_id: "img:site".into(),
                        purpose: Some("case-review".into()),
                        fields: vec![FIELD_METADATA.into()],
                        classification_ceiling: Some("internal".into()),
                    },
                    now,
                )
                .unwrap_err(),
                "retrieve timestamp must be positive"
            );
            assert_eq!(
                delete_image(&runtime, "analyst", "records", "img:site", now).unwrap_err(),
                "delete timestamp must be positive"
            );
        }
        assert!(
            runtime
                .get_governed_image("records", "img:site")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn postgres_surface_is_explicitly_unavailable() {
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "governed images are unavailable on the PostgreSQL community runtime"
        );
    }
}
