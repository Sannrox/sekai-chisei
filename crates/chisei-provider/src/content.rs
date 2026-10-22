//! Provider-neutral bounded content contracts and validation.
//!
//! Resolved payloads are deliberately transient and use redacted `Debug`
//! implementations so accidental diagnostics cannot disclose content.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

use crate::llm::{ToolCall, ToolDef};

pub const CONTENT_CONTRACT_VERSION: &str = "chisei.content-execution/v1";
pub const DISCLOSURE_AUTHORITY: &str = "chisei.policy/v1";
pub const MAX_CONTENT_PARTS: usize = 32;
pub const MAX_CONTENT_PART_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_CONTENT_AGGREGATE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REFERENCE_BYTES: usize = 256;
const MAX_ID_BYTES: usize = 128;
const MAX_PROVENANCE_BYTES: usize = 256;
const MAX_DISCLOSURE_REASON_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentKind {
    Text,
    Image,
    Audio,
    Document,
}

impl ContentKind {
    pub fn modality(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Document => "document",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureState {
    Accepted,
    Redacted,
    Omitted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentProvenance {
    pub source: String,
    pub source_id: String,
    pub source_version: String,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDescriptor {
    pub part_id: String,
    pub kind: ContentKind,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256_digest: String,
    pub reference: String,
    pub provenance: ContentProvenance,
    pub disclosure_state: DisclosureState,
    pub disclosure_reason: String,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedPayload {
    Text(String),
    Bytes(Vec<u8>),
}

impl ResolvedPayload {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(value) => value.as_bytes(),
            Self::Bytes(value) => value,
        }
    }
}

impl fmt::Debug for ResolvedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedPayload")
            .field("redacted", &true)
            .field("byte_length", &self.as_bytes().len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedContentPart {
    pub descriptor: ContentDescriptor,
    pub payload: ResolvedPayload,
}

impl fmt::Debug for ResolvedContentPart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedContentPart")
            .field("descriptor", &self.descriptor)
            .field("payload", &self.payload)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ContentMessage {
    pub role: String,
    pub parts: Vec<ResolvedContentPart>,
    pub tool_call_id: String,
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone)]
pub struct ContentChatRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<ContentMessage>,
    pub tools: Vec<ToolDef>,
    pub max_tokens: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentCapabilities {
    pub input_kinds: Vec<ContentKind>,
    pub output_kinds: Vec<ContentKind>,
    pub media_types: Vec<String>,
    pub reference_modes: Vec<String>,
    pub max_parts: usize,
    pub max_part_bytes: u64,
    pub max_aggregate_bytes: u64,
    pub streaming: bool,
}

pub fn validate_descriptors<'a>(
    descriptors: impl IntoIterator<Item = &'a ContentDescriptor>,
) -> Result<(), String> {
    let descriptors = descriptors.into_iter().collect::<Vec<_>>();
    if descriptors.is_empty() {
        return Err("at least one content part is required".into());
    }
    if descriptors.len() > MAX_CONTENT_PARTS {
        return Err(format!(
            "content part count exceeds the hard limit of {MAX_CONTENT_PARTS}"
        ));
    }
    let mut ids = HashSet::new();
    let mut total = 0_u64;
    for descriptor in descriptors {
        validate_descriptor(descriptor)?;
        if !ids.insert(descriptor.part_id.as_str()) {
            return Err("content part ids must be unique".into());
        }
        total = total
            .checked_add(descriptor.byte_length)
            .ok_or_else(|| "content aggregate byte length overflow".to_string())?;
        if total > MAX_CONTENT_AGGREGATE_BYTES {
            return Err(format!(
                "content aggregate exceeds the hard limit of {MAX_CONTENT_AGGREGATE_BYTES} bytes"
            ));
        }
    }
    Ok(())
}

pub fn validate_descriptor(descriptor: &ContentDescriptor) -> Result<(), String> {
    validate_bounded_identifier("part id", &descriptor.part_id, MAX_ID_BYTES)?;
    validate_media_type(descriptor.kind, &descriptor.media_type)?;
    if descriptor.byte_length == 0 || descriptor.byte_length > MAX_CONTENT_PART_BYTES {
        return Err(format!(
            "content part byte length must be between 1 and {MAX_CONTENT_PART_BYTES}"
        ));
    }
    validate_sha256_digest(&descriptor.sha256_digest)?;
    validate_opaque_reference(&descriptor.reference)?;
    validate_bounded_identifier(
        "provenance source",
        &descriptor.provenance.source,
        MAX_PROVENANCE_BYTES,
    )?;
    validate_bounded_identifier(
        "provenance source id",
        &descriptor.provenance.source_id,
        MAX_PROVENANCE_BYTES,
    )?;
    validate_bounded_identifier(
        "provenance source version",
        &descriptor.provenance.source_version,
        MAX_PROVENANCE_BYTES,
    )?;
    match descriptor.disclosure_state {
        DisclosureState::Accepted if !descriptor.disclosure_reason.trim().is_empty() => {
            return Err("accepted content must not carry a disclosure reason".into());
        }
        DisclosureState::Redacted | DisclosureState::Omitted => {
            validate_bounded_identifier(
                "content disclosure reason",
                &descriptor.disclosure_reason,
                MAX_DISCLOSURE_REASON_BYTES,
            )?;
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_resolved_part(part: &ResolvedContentPart) -> Result<(), String> {
    validate_descriptor(&part.descriptor)?;
    if part.descriptor.disclosure_state != DisclosureState::Accepted {
        return Err("only accepted content may carry a resolved payload".into());
    }
    match (&part.descriptor.kind, &part.payload) {
        (ContentKind::Text, ResolvedPayload::Text(_)) => {}
        (ContentKind::Text, ResolvedPayload::Bytes(_)) => {
            return Err("text content requires the text payload field".into());
        }
        (_, ResolvedPayload::Bytes(_)) => {}
        (_, ResolvedPayload::Text(_)) => {
            return Err("binary content requires the bytes payload field".into());
        }
    }
    let bytes = part.payload.as_bytes();
    if bytes.len() as u64 != part.descriptor.byte_length {
        return Err("resolved content byte length does not match its descriptor".into());
    }
    verify_sha256_digest(bytes, &part.descriptor.sha256_digest)
}

pub fn validate_capabilities(capabilities: &ContentCapabilities) -> Result<(), String> {
    if capabilities.max_parts == 0 || capabilities.max_parts > MAX_CONTENT_PARTS {
        return Err("content capability part limit exceeds the hard bound".into());
    }
    if capabilities.max_part_bytes == 0 || capabilities.max_part_bytes > MAX_CONTENT_PART_BYTES {
        return Err("content capability per-part limit exceeds the hard bound".into());
    }
    if capabilities.max_aggregate_bytes == 0
        || capabilities.max_aggregate_bytes > MAX_CONTENT_AGGREGATE_BYTES
        || capabilities.max_aggregate_bytes < capabilities.max_part_bytes
    {
        return Err("content capability aggregate limit is invalid".into());
    }
    if capabilities.output_kinds != [ContentKind::Text] {
        return Err(
            "content capability output must be text; output media requires an owned reference provider"
                .into(),
        );
    }
    if capabilities.reference_modes != ["opaque"] {
        return Err("content capability reference mode must be opaque".into());
    }
    for media_type in &capabilities.media_types {
        normalize_media_type(media_type)?;
    }
    Ok(())
}

pub fn validate_sha256_digest(value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("content digest must use sha256:<64 lowercase hex>".into());
    };
    if hex.len() != 64
        || !hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("content digest must use sha256:<64 lowercase hex>".into());
    }
    Ok(())
}

pub fn verify_sha256_digest(bytes: &[u8], expected: &str) -> Result<(), String> {
    validate_sha256_digest(expected)?;
    let actual = format!("sha256:{:x}", Sha256::digest(bytes));
    if actual == expected {
        Ok(())
    } else {
        Err("resolved content digest does not match its descriptor".into())
    }
}

pub fn normalize_media_type(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 127
        || normalized.contains(';')
        || normalized.contains(char::is_whitespace)
    {
        return Err(
            "content media type must be a normalized type/subtype without parameters".into(),
        );
    }
    let Some((kind, subtype)) = normalized.split_once('/') else {
        return Err("content media type must be a normalized type/subtype".into());
    };
    if kind.is_empty()
        || subtype.is_empty()
        || !kind.bytes().all(valid_media_token_byte)
        || !subtype.bytes().all(valid_media_token_byte)
    {
        return Err("content media type contains unsupported characters".into());
    }
    Ok(normalized)
}

pub fn validate_media_type(kind: ContentKind, value: &str) -> Result<(), String> {
    let normalized = normalize_media_type(value)?;
    let allowed = match kind {
        ContentKind::Text => matches!(
            normalized.as_str(),
            "text/plain" | "text/markdown" | "application/json"
        ),
        ContentKind::Image => matches!(
            normalized.as_str(),
            "image/png" | "image/jpeg" | "image/gif" | "image/webp"
        ),
        ContentKind::Audio => matches!(
            normalized.as_str(),
            "audio/wav" | "audio/mpeg" | "audio/mp4" | "audio/ogg"
        ),
        ContentKind::Document => matches!(
            normalized.as_str(),
            "application/pdf" | "text/plain" | "text/markdown"
        ),
    };
    if allowed {
        Ok(())
    } else {
        Err(format!(
            "media type {normalized:?} is not supported for {} content",
            kind.modality()
        ))
    }
}

pub fn validate_opaque_reference(value: &str) -> Result<(), String> {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() > MAX_REFERENCE_BYTES
        || value != value.trim()
        || value.contains(char::is_control)
        || value.contains(char::is_whitespace)
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.contains('@')
        || value.starts_with('/')
        || value.contains("://")
        || lower.starts_with("data:")
        || lower.starts_with("file:")
        || lower.contains("bearer")
        || lower.contains("token=")
        || lower.contains("key=")
        || lower.contains("secret=")
    {
        return Err("content reference must be a credential-free opaque handle".into());
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
    }) {
        return Err("content reference contains unsupported characters".into());
    }
    Ok(())
}

pub fn descriptor_digest<'a>(
    descriptors: impl IntoIterator<Item = &'a ContentDescriptor>,
) -> String {
    let mut hasher = Sha256::new();
    for descriptor in descriptors {
        for value in [
            descriptor.part_id.as_bytes(),
            descriptor.kind.modality().as_bytes(),
            descriptor.media_type.as_bytes(),
            descriptor.sha256_digest.as_bytes(),
            descriptor.reference.as_bytes(),
            descriptor.provenance.source.as_bytes(),
            descriptor.provenance.source_id.as_bytes(),
            descriptor.provenance.source_version.as_bytes(),
        ] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        hasher.update(descriptor.byte_length.to_be_bytes());
        hasher.update(descriptor.provenance.observed_at_ms.to_be_bytes());
        hasher.update([match descriptor.disclosure_state {
            DisclosureState::Accepted => 1,
            DisclosureState::Redacted => 2,
            DisclosureState::Omitted => 3,
        }]);
        hasher.update((descriptor.disclosure_reason.len() as u64).to_be_bytes());
        hasher.update(descriptor.disclosure_reason.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn validate_bounded_identifier(label: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max
        || value != value.trim()
        || value.contains(char::is_control)
    {
        Err(format!(
            "{label} is required and must not exceed {max} bytes"
        ))
    } else {
        Ok(())
    }
}

fn valid_media_token_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(kind: ContentKind, media_type: &str, payload: &[u8]) -> ContentDescriptor {
        ContentDescriptor {
            part_id: "part-1".into(),
            kind,
            media_type: media_type.into(),
            byte_length: payload.len() as u64,
            sha256_digest: format!("sha256:{:x}", Sha256::digest(payload)),
            reference: "fixture:part-1".into(),
            provenance: ContentProvenance {
                source: "fixture".into(),
                source_id: "case-1".into(),
                source_version: "v1".into(),
                observed_at_ms: 1,
            },
            disclosure_state: DisclosureState::Accepted,
            disclosure_reason: String::new(),
        }
    }

    #[test]
    fn validates_and_redacts_resolved_payloads() {
        let payload = b"secret text";
        let part = ResolvedContentPart {
            descriptor: descriptor(ContentKind::Text, "text/plain", payload),
            payload: ResolvedPayload::Text("secret text".into()),
        };
        validate_resolved_part(&part).unwrap();
        let debug = format!("{part:?}");
        assert!(!debug.contains("secret text"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn rejects_credentials_and_digest_drift() {
        assert!(validate_opaque_reference("https://user:secret@example.test").is_err());
        assert!(validate_opaque_reference("store:item?token=secret").is_err());
        let mut part = ResolvedContentPart {
            descriptor: descriptor(ContentKind::Image, "image/png", b"png"),
            payload: ResolvedPayload::Bytes(b"changed".to_vec()),
        };
        assert!(validate_resolved_part(&part).is_err());
        part.payload = ResolvedPayload::Bytes(b"png".to_vec());
        validate_resolved_part(&part).unwrap();
    }
}
