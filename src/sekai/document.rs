//! Governed document objects and digest-bound renditions (#688).
//!
//! A document is an object that binds metadata, a content reference, purpose,
//! classification, retention, and hold. Renditions are derived children. The
//! plane does not store bytes or run extractors.

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

pub const DOCUMENT_CONTRACT: &str = "sekai.governed-document/v1";
pub const TYPE_REVISION_V1: &str = "v1";
pub const CONTENT_SCHEME_DIGEST: &str = "digest";
pub const FIELD_IDENTITY: &str = "identity";
pub const FIELD_CONTENT_REF: &str = "content_ref";
pub const FIELD_METADATA: &str = "metadata";
pub const FIELD_RENDITIONS: &str = "renditions";
pub const RENDITION_EXTRACTED_TEXT: &str = "extracted_text";
pub const RENDITION_PREVIEW: &str = "preview";
pub const RENDITION_THUMBNAIL: &str = "thumbnail";
pub const MAX_METADATA_KEYS: usize = 32;
pub const MAX_METADATA_BYTES: usize = 8 * 1024;
pub const MAX_RENDITIONS: usize = 16;
pub const DOCUMENT_UNAVAILABLE: &str = "governed document is unavailable";
pub const DOCUMENT_HELD: &str = "governed document is held";
pub const REVISION_UNSUPPORTED: &str = "governed document revision is unsupported";
pub const FORMAT_UNSUPPORTED: &str = "governed document format is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "governed documents are unavailable on the PostgreSQL community runtime";

const MEDIA_TEXT_PLAIN: &str = "text/plain";
const MEDIA_PDF: &str = "application/pdf";
const MEDIA_JSON: &str = "application/json";
const MEDIA_PNG: &str = "image/png";
const MEDIA_JPEG: &str = "image/jpeg";

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
pub struct GovernedDocument {
    pub contract_version: String,
    pub document_id: String,
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
pub struct DocumentRendition {
    pub namespace: String,
    pub document_id: String,
    pub rendition_id: String,
    pub class: String,
    pub parent_content_digest: String,
    pub content_ref: ContentReference,
    pub extractor_id: String,
    pub extractor_profile_digest: String,
    pub attached_by: String,
    pub attached_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DocumentRetrieve {
    pub namespace: String,
    pub document_id: String,
    pub purpose: Option<String>,
    pub fields: Vec<String>,
    pub classification_ceiling: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentView {
    pub contract_version: String,
    pub document_id: String,
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
    pub renditions: Option<Vec<DocumentRendition>>,
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
    document_id: &'a str,
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

pub fn admit_document(
    db: &RuntimeDb,
    actor: &str,
    document: &GovernedDocument,
    now_ms: i64,
) -> Result<GovernedDocument, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("admit timestamp must be non-negative".into());
    }
    let validated = validate_document(document, actor, now_ms)?;
    if let Some(existing) =
        db.get_governed_document(&validated.namespace, &validated.document_id)?
    {
        if existing.deleted_at_ms != 0 || existing.owner != actor || is_expired(&existing, now_ms) {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
        if existing.content_digest == validated.content_digest
            && definition_digest(&existing)? == definition_digest(&validated)?
        {
            return Ok(existing);
        }
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    db.put_governed_document(&validated)?;
    Ok(validated)
}

pub fn attach_rendition(
    db: &RuntimeDb,
    actor: &str,
    rendition: &DocumentRendition,
    now_ms: i64,
) -> Result<DocumentRendition, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("attach timestamp must be non-negative".into());
    }
    let document = live_document(
        db,
        &rendition.namespace,
        &rendition.document_id,
        actor,
        now_ms,
    )?;
    let validated = validate_rendition(&document, rendition, actor, now_ms)?;
    let existing = db.list_governed_renditions(&document.namespace, &document.document_id)?;
    if existing.len() >= MAX_RENDITIONS
        && existing
            .iter()
            .all(|item| item.rendition_id != validated.rendition_id)
    {
        return Err("governed document rendition list is oversized".into());
    }
    if let Some(prior) = existing
        .iter()
        .find(|item| item.rendition_id == validated.rendition_id)
    {
        if prior == &validated {
            return Ok(prior.clone());
        }
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    db.put_governed_rendition(&validated)?;
    Ok(validated)
}

pub fn retrieve_document(
    db: &RuntimeDb,
    actor: &str,
    query: &DocumentRetrieve,
    now_ms: i64,
) -> Result<DocumentView, String> {
    required("actor", actor)?;
    required("namespace", &query.namespace)?;
    required("document id", &query.document_id)?;
    if now_ms < 0 {
        return Err("retrieve timestamp must be non-negative".into());
    }
    let document = live_document(db, &query.namespace, &query.document_id, actor, now_ms)?;
    let fields = requested_fields(&query.fields)?;
    let authority = retrieve_authority(db, actor, query)?;
    if !classification_visible(&document.classification, &authority) {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    if query.purpose.as_deref() != Some(document.purpose.as_str()) {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    if !authority.allowed_purposes.is_empty()
        && !authority.allowed_purposes.contains(&document.purpose)
    {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }

    let wants_content = fields.contains(FIELD_CONTENT_REF);
    let wants_metadata = fields.contains(FIELD_METADATA);
    let wants_renditions = fields.contains(FIELD_RENDITIONS);
    let renditions = if wants_renditions {
        Some(db.list_governed_renditions(&document.namespace, &document.document_id)?)
    } else {
        None
    };

    let lifecycle = lifecycle_of(&document, now_ms);
    let definition_digest = definition_digest(&document)?;
    Ok(DocumentView {
        contract_version: document.contract_version,
        document_id: document.document_id,
        namespace: document.namespace,
        type_revision: document.type_revision,
        lifecycle,
        definition_digest,
        content_ref: wants_content.then_some(document.content_ref),
        title: wants_metadata.then_some(document.title),
        metadata: wants_metadata.then_some(document.metadata),
        purpose: wants_metadata.then_some(document.purpose),
        classification: wants_metadata.then_some(document.classification),
        expires_at_ms: wants_metadata.then_some(document.expires_at_ms),
        hold_id: wants_metadata.then(|| document.hold_id.clone()),
        renditions,
    })
}

pub fn place_hold(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    document_id: &str,
    hold_id: &str,
    reason: &str,
    now_ms: i64,
) -> Result<GovernedDocument, String> {
    required("actor", actor)?;
    required("hold id", hold_id)?;
    required("hold reason", reason)?;
    if now_ms < 0 {
        return Err("hold timestamp must be non-negative".into());
    }
    let mut document = live_document(db, namespace, document_id, actor, now_ms)?;
    if !document.hold_id.is_empty() && document.hold_id != hold_id {
        return Err(DOCUMENT_HELD.into());
    }
    document.hold_id = hold_id.into();
    document.hold_reason = reason.into();
    db.put_governed_document(&document)?;
    Ok(document)
}

pub fn release_hold(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    document_id: &str,
    hold_id: &str,
    now_ms: i64,
) -> Result<GovernedDocument, String> {
    required("actor", actor)?;
    required("hold id", hold_id)?;
    if now_ms < 0 {
        return Err("release timestamp must be non-negative".into());
    }
    let mut document = live_document(db, namespace, document_id, actor, now_ms)?;
    if document.hold_id != hold_id {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    document.hold_id.clear();
    document.hold_reason.clear();
    db.put_governed_document(&document)?;
    Ok(document)
}

pub fn expire_document(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    document_id: &str,
    now_ms: i64,
) -> Result<GovernedDocument, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("expire timestamp must be non-negative".into());
    }
    let mut document = owned_document(db, namespace, document_id, actor)?;
    if document.deleted_at_ms != 0 {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    if !document.hold_id.is_empty() {
        return Err(DOCUMENT_HELD.into());
    }
    if document.expires_at_ms == 0 || document.expires_at_ms > now_ms {
        document.expires_at_ms = now_ms;
    }
    db.put_governed_document(&document)?;
    Ok(document)
}

pub fn delete_document(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    document_id: &str,
    now_ms: i64,
) -> Result<GovernedDocument, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("delete timestamp must be non-negative".into());
    }
    let mut document = owned_document(db, namespace, document_id, actor)?;
    if document.deleted_at_ms != 0 {
        return Ok(document);
    }
    if !document.hold_id.is_empty() {
        return Err(DOCUMENT_HELD.into());
    }
    if is_expired(&document, now_ms) {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    document.deleted_at_ms = now_ms;
    db.delete_governed_renditions(&document.namespace, &document.document_id)?;
    db.put_governed_document(&document)?;
    Ok(document)
}

fn live_document(
    db: &RuntimeDb,
    namespace: &str,
    document_id: &str,
    actor: &str,
    now_ms: i64,
) -> Result<GovernedDocument, String> {
    let document = owned_document(db, namespace, document_id, actor)?;
    if document.deleted_at_ms != 0 || is_expired(&document, now_ms) {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    if document.contract_version != DOCUMENT_CONTRACT || document.type_revision != TYPE_REVISION_V1
    {
        return Err(REVISION_UNSUPPORTED.into());
    }
    if content_digest_for(&document.content_ref)? != document.content_digest {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    Ok(document)
}

fn owned_document(
    db: &RuntimeDb,
    namespace: &str,
    document_id: &str,
    actor: &str,
) -> Result<GovernedDocument, String> {
    required("namespace", namespace)?;
    required("document id", document_id)?;
    let document = db
        .get_governed_document(namespace, document_id)?
        .ok_or(DOCUMENT_UNAVAILABLE)?;
    if document.owner != actor {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    Ok(document)
}

fn validate_document(
    document: &GovernedDocument,
    actor: &str,
    now_ms: i64,
) -> Result<GovernedDocument, String> {
    if document.contract_version != DOCUMENT_CONTRACT || document.type_revision != TYPE_REVISION_V1
    {
        return Err(REVISION_UNSUPPORTED.into());
    }
    required("document id", &document.document_id)?;
    required("namespace", &document.namespace)?;
    required("owner", &document.owner)?;
    required("purpose", &document.purpose)?;
    required("title", &document.title)?;
    if document.owner != actor {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    parse_classification(&document.classification)?;
    if document.expires_at_ms < 0 {
        return Err("document expiry must be non-negative".into());
    }
    if !document.hold_id.is_empty() {
        required("hold reason", &document.hold_reason)?;
    }
    validate_metadata(&document.metadata)?;
    validate_content_ref(&document.content_ref, None)?;
    let digest = content_digest_for(&document.content_ref)?;
    if !document.content_digest.is_empty() && document.content_digest != digest {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    if document.deleted_at_ms != 0 {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    Ok(GovernedDocument {
        content_digest: digest,
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
        deleted_at_ms: 0,
        ..document.clone()
    })
}

fn validate_rendition(
    document: &GovernedDocument,
    rendition: &DocumentRendition,
    actor: &str,
    now_ms: i64,
) -> Result<DocumentRendition, String> {
    if rendition.namespace != document.namespace || rendition.document_id != document.document_id {
        return Err(DOCUMENT_UNAVAILABLE.into());
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
    if rendition.parent_content_digest != document.content_digest {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    if !digest_token(&rendition.extractor_profile_digest) {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    validate_content_ref(&rendition.content_ref, Some(&rendition.class))?;
    Ok(DocumentRendition {
        attached_by: actor.into(),
        attached_at_ms: now_ms,
        ..rendition.clone()
    })
}

fn validate_content_ref(reference: &ContentReference, class: Option<&str>) -> Result<(), String> {
    if reference.scheme != CONTENT_SCHEME_DIGEST {
        return Err(REVISION_UNSUPPORTED.into());
    }
    if !digest_token(&reference.digest) {
        return Err(DOCUMENT_UNAVAILABLE.into());
    }
    if reference.byte_length == 0 || reference.byte_length > 32 * 1024 * 1024 {
        return Err("governed document content length is invalid".into());
    }
    if !supported_media_type(&reference.media_type, class) {
        return Err(FORMAT_UNSUPPORTED.into());
    }
    Ok(())
}

fn validate_metadata(metadata: &BTreeMap<String, String>) -> Result<(), String> {
    if metadata.len() > MAX_METADATA_KEYS {
        return Err("governed document metadata is oversized".into());
    }
    let encoded = serde_json::to_vec(metadata).map_err(|error| error.to_string())?;
    if encoded.len() > MAX_METADATA_BYTES {
        return Err("governed document metadata is oversized".into());
    }
    let mut seen = BTreeSet::new();
    for (key, value) in metadata {
        required("metadata key", key)?;
        if !seen.insert(key) {
            return Err(format!("duplicate document metadata key {key}"));
        }
        required("metadata value", value)?;
    }
    Ok(())
}

fn requested_fields(fields: &[String]) -> Result<BTreeSet<&str>, String> {
    let mut requested = BTreeSet::new();
    for field in fields {
        if !matches!(
            field.as_str(),
            FIELD_IDENTITY | FIELD_CONTENT_REF | FIELD_METADATA | FIELD_RENDITIONS
        ) {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
        if !requested.insert(field.as_str()) {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
    }
    requested.insert(FIELD_IDENTITY);
    Ok(requested)
}

fn retrieve_authority(
    db: &RuntimeDb,
    actor: &str,
    query: &DocumentRetrieve,
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
            return Err(DOCUMENT_UNAVAILABLE.into());
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
        Some(RENDITION_EXTRACTED_TEXT) => media_type == MEDIA_TEXT_PLAIN,
        Some(RENDITION_PREVIEW) => matches!(media_type, MEDIA_PDF | MEDIA_PNG),
        Some(RENDITION_THUMBNAIL) => matches!(media_type, MEDIA_PNG | MEDIA_JPEG),
        None => matches!(
            media_type,
            MEDIA_TEXT_PLAIN | MEDIA_PDF | MEDIA_JSON | MEDIA_PNG | MEDIA_JPEG
        ),
        Some(_) => false,
    }
}

fn supported_rendition_class(class: &str) -> bool {
    matches!(
        class,
        RENDITION_EXTRACTED_TEXT | RENDITION_PREVIEW | RENDITION_THUMBNAIL
    )
}

fn digest_token(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_expired(document: &GovernedDocument, now_ms: i64) -> bool {
    document.hold_id.is_empty() && document.expires_at_ms > 0 && now_ms >= document.expires_at_ms
}

fn lifecycle_of(document: &GovernedDocument, now_ms: i64) -> String {
    if document.deleted_at_ms != 0 {
        "deleted".into()
    } else if is_expired(document, now_ms) {
        "expired".into()
    } else if !document.hold_id.is_empty() {
        "held".into()
    } else {
        "admitted".into()
    }
}

fn definition_digest(document: &GovernedDocument) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&DefinitionPin {
            contract_version: &document.contract_version,
            document_id: &document.document_id,
            namespace: &document.namespace,
            owner: &document.owner,
            type_revision: &document.type_revision,
            purpose: &document.purpose,
            classification: &document.classification,
            title: &document.title,
            metadata: &document.metadata,
            content_ref: &document.content_ref,
        })?
    ))
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

    fn document() -> GovernedDocument {
        let content_ref = content_ref(MEDIA_PDF);
        GovernedDocument {
            contract_version: DOCUMENT_CONTRACT.into(),
            document_id: "doc:brief".into(),
            namespace: "records".into(),
            owner: "analyst".into(),
            type_revision: TYPE_REVISION_V1.into(),
            purpose: "case-review".into(),
            classification: "internal".into(),
            title: "Brief".into(),
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

    fn rendition() -> DocumentRendition {
        DocumentRendition {
            namespace: "records".into(),
            document_id: "doc:brief".into(),
            rendition_id: "rend:text".into(),
            class: RENDITION_EXTRACTED_TEXT.into(),
            parent_content_digest: content_digest_for(&content_ref(MEDIA_PDF)).unwrap(),
            content_ref: ContentReference {
                scheme: CONTENT_SCHEME_DIGEST.into(),
                digest: digest(2),
                media_type: MEDIA_TEXT_PLAIN.into(),
                byte_length: 32,
            },
            extractor_id: "extractor:text".into(),
            extractor_profile_digest: digest(3),
            attached_by: String::new(),
            attached_at_ms: 0,
        }
    }

    fn admit(runtime: &RuntimeDb) -> GovernedDocument {
        pin_ceiling(runtime, "analyst", "internal");
        admit_document(runtime, "analyst", &document(), 1_000).unwrap()
    }

    fn retrieve(
        runtime: &RuntimeDb,
        fields: &[&str],
        purpose: &str,
        ceiling: Option<&str>,
    ) -> Result<DocumentView, String> {
        retrieve_document(
            runtime,
            "analyst",
            &DocumentRetrieve {
                namespace: "records".into(),
                document_id: "doc:brief".into(),
                purpose: Some(purpose.into()),
                fields: fields.iter().map(|field| (*field).to_string()).collect(),
                classification_ceiling: ceiling.map(str::to_string),
            },
            2_000,
        )
    }

    #[test]
    fn authorized_admit_extract_retrieve_hold_and_delete() {
        let runtime = db();
        let admitted = admit(&runtime);
        let attached = attach_rendition(&runtime, "analyst", &rendition(), 1_500).unwrap();
        let view = retrieve(
            &runtime,
            &[FIELD_CONTENT_REF, FIELD_METADATA, FIELD_RENDITIONS],
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
        assert_eq!(view.renditions.unwrap(), vec![attached]);
        assert_eq!(
            retrieve(&runtime, &[], "case-review", Some("internal"))
                .unwrap()
                .content_ref,
            None
        );

        let held = place_hold(
            &runtime,
            "analyst",
            "records",
            "doc:brief",
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
            delete_document(&runtime, "analyst", "records", "doc:brief", 4_000).unwrap_err(),
            DOCUMENT_HELD
        );
        assert_eq!(
            expire_document(&runtime, "analyst", "records", "doc:brief", 4_000).unwrap_err(),
            DOCUMENT_HELD
        );
        assert_eq!(
            retrieve_document(
                &runtime,
                "analyst",
                &DocumentRetrieve {
                    namespace: "records".into(),
                    document_id: "doc:brief".into(),
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
        release_hold(
            &runtime,
            "analyst",
            "records",
            "doc:brief",
            "hold:1",
            12_000,
        )
        .unwrap();
        delete_document(&runtime, "analyst", "records", "doc:brief", 5_000).unwrap();
        assert_eq!(
            retrieve(&runtime, &[], "case-review", Some("internal")).unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        assert_eq!(
            admit_document(&runtime, "analyst", &document(), 6_000).unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        assert!(
            runtime
                .list_governed_renditions("records", "doc:brief")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn replay_is_deterministic_and_partial_or_unknown_input_fails() {
        let runtime = db();
        let first = admit(&runtime);
        let second = admit_document(&runtime, "analyst", &document(), 2_000).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.content_digest, second.content_digest);

        let mut changed = document();
        changed.content_ref.digest = digest(9);
        changed.content_digest.clear();
        assert_eq!(
            admit_document(&runtime, "analyst", &changed, 3_000).unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );

        let mut unknown = serde_json::to_value(document()).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("hidden".into(), serde_json::json!("nope"));
        assert!(serde_json::from_value::<GovernedDocument>(unknown).is_err());
    }

    #[test]
    fn unauthorized_purpose_classification_and_foreign_owner_fail_closed() {
        let runtime = db();
        admit(&runtime);
        assert_eq!(
            retrieve(
                &runtime,
                &[FIELD_CONTENT_REF],
                "other-purpose",
                Some("internal")
            )
            .unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        assert_eq!(
            retrieve(
                &runtime,
                &[FIELD_CONTENT_REF],
                "case-review",
                Some("public")
            )
            .unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        assert_eq!(
            retrieve_document(
                &runtime,
                "intruder",
                &DocumentRetrieve {
                    namespace: "records".into(),
                    document_id: "doc:brief".into(),
                    purpose: Some("case-review".into()),
                    fields: vec![FIELD_CONTENT_REF.into()],
                    classification_ceiling: Some("restricted".into()),
                },
                2_000,
            )
            .unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        assert_eq!(
            retrieve(&runtime, &["secret"], "case-review", Some("internal")).unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
    }

    #[test]
    fn unknown_format_corrupt_digest_and_unsupported_revision_fail_before_disclosure() {
        let runtime = db();
        pin_ceiling(&runtime, "analyst", "internal");
        let mut bad_media = document();
        bad_media.content_ref.media_type = "application/x-unknown".into();
        bad_media.content_digest.clear();
        assert_eq!(
            admit_document(&runtime, "analyst", &bad_media, 1_000).unwrap_err(),
            FORMAT_UNSUPPORTED
        );
        let mut bad_revision = document();
        bad_revision.type_revision = "v2".into();
        bad_revision.content_digest.clear();
        assert_eq!(
            admit_document(&runtime, "analyst", &bad_revision, 1_000).unwrap_err(),
            REVISION_UNSUPPORTED
        );
        let mut corrupt = document();
        corrupt.content_digest = digest(8);
        assert_eq!(
            admit_document(&runtime, "analyst", &corrupt, 1_000).unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        admit_document(&runtime, "analyst", &document(), 1_000).unwrap();
        let mut mismatch = rendition();
        mismatch.parent_content_digest = digest(8);
        assert_eq!(
            attach_rendition(&runtime, "analyst", &mismatch, 2_000).unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        let mut bad_class = rendition();
        bad_class.class = "ocr-box".into();
        assert_eq!(
            attach_rendition(&runtime, "analyst", &bad_class, 2_000).unwrap_err(),
            REVISION_UNSUPPORTED
        );
    }

    #[test]
    fn expiry_is_explicit_and_blocks_retrieve_without_manufacturing_success() {
        let runtime = db();
        admit(&runtime);
        assert!(
            expire_document(&runtime, "analyst", "records", "doc:brief", -1)
                .unwrap_err()
                .contains("non-negative")
        );
        expire_document(&runtime, "analyst", "records", "doc:brief", 9_000).unwrap();
        assert_eq!(
            admit_document(&runtime, "analyst", &document(), 9_000).unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        assert_eq!(
            retrieve_document(
                &runtime,
                "analyst",
                &DocumentRetrieve {
                    namespace: "records".into(),
                    document_id: "doc:brief".into(),
                    purpose: Some("case-review".into()),
                    fields: Vec::new(),
                    classification_ceiling: Some("internal".into()),
                },
                9_000,
            )
            .unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        assert_eq!(
            attach_rendition(&runtime, "analyst", &rendition(), 9_100).unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
        assert_eq!(
            delete_document(&runtime, "analyst", "records", "doc:brief", 9_200).unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
    }

    #[test]
    fn same_document_id_is_isolated_per_namespace_and_renditions_cannot_cross_parents() {
        let runtime = db();
        pin_ceiling(&runtime, "analyst", "internal");
        pin_ceiling(&runtime, "counsel", "internal");
        let mut other = document();
        other.namespace = "legal".into();
        other.owner = "counsel".into();
        admit_document(&runtime, "analyst", &document(), 1_000).unwrap();
        admit_document(&runtime, "counsel", &other, 1_000).unwrap();
        attach_rendition(&runtime, "analyst", &rendition(), 1_500).unwrap();
        let mut other_rendition = rendition();
        other_rendition.namespace = "legal".into();
        other_rendition.parent_content_digest = content_digest_for(&other.content_ref).unwrap();
        attach_rendition(&runtime, "counsel", &other_rendition, 1_600).unwrap();
        let records = runtime
            .list_governed_renditions("records", "doc:brief")
            .unwrap();
        let legal = runtime
            .list_governed_renditions("legal", "doc:brief")
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(legal.len(), 1);
        assert_eq!(records[0].namespace, "records");
        assert_eq!(legal[0].namespace, "legal");
        assert_eq!(
            retrieve_document(
                &runtime,
                "analyst",
                &DocumentRetrieve {
                    namespace: "legal".into(),
                    document_id: "doc:brief".into(),
                    purpose: Some("case-review".into()),
                    fields: vec![FIELD_RENDITIONS.into()],
                    classification_ceiling: Some("internal".into()),
                },
                2_000,
            )
            .unwrap_err(),
            DOCUMENT_UNAVAILABLE
        );
    }

    #[test]
    fn postgres_surface_is_explicitly_unavailable() {
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "governed documents are unavailable on the PostgreSQL community runtime"
        );
    }
}
