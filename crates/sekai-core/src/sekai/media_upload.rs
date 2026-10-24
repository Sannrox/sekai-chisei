//! Governed media uploads (#1623, ADR 0123).
//!
//! A client uploads a file in chunks, then completes the upload. Completing
//! checks the client's SHA-256 over the stored bytes and creates a
//! `media_attachment` object in the namespace. The object carries the
//! upload's access marking and the ordinary object grants and policy, so a
//! read of the file is a read of that object. The result is a media
//! reference, `sekai-media:<object id>`, usable as an Action parameter or a
//! media property value.
//!
//! Sessions and bytes are durable, so any instance can continue an upload
//! another started. The upload id derives from the namespace, the uploader
//! and the client's idempotency key: repeating a begin returns the same
//! session, and once complete the same reference.

use sha2::{Digest, Sha256};

pub const MEDIA_KIND: &str = "media_attachment";
pub const REFERENCE_PREFIX: &str = "sekai-media:";
/// Largest file one upload may hold.
pub const MAX_MEDIA_BYTES: u64 = 64 * 1024 * 1024;
/// Largest chunk one call may send or read, well under the gRPC frame cap.
pub const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_KEY_BYTES: usize = 256;
const MAX_MEDIA_TYPE_BYTES: usize = 255;
const MAX_FILE_NAME_BYTES: usize = 255;

/// Object properties of a completed upload.
pub const PROPERTY_UPLOAD_ID: &str = "upload_id";
pub const PROPERTY_SHA256: &str = "sha256";
pub const PROPERTY_SIZE_BYTES: &str = "size_bytes";
pub const PROPERTY_MEDIA_TYPE: &str = "media_type";
pub const PROPERTY_FILE_NAME: &str = "file_name";

/// What a client declares when it begins an upload. Everything here is
/// fixed for the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaUploadRequest {
    pub namespace: String,
    pub uploader: String,
    pub idempotency_key: String,
    pub size_bytes: u64,
    /// Lowercase hex SHA-256 of the whole file.
    pub sha256: String,
    pub media_type: String,
    pub file_name: String,
    /// Empty when the file is unmarked.
    pub access_marking: String,
}

/// A stored session. `object_id` is set once the upload completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaUpload {
    pub upload_id: String,
    pub request: MediaUploadRequest,
    pub received_bytes: u64,
    /// Bumped each time a checksum failure drops the received bytes, so a
    /// completion acts only on the attempt it hashed.
    pub attempt: u64,
    pub object_id: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl MediaUpload {
    pub fn reference(&self) -> Option<String> {
        self.object_id.as_deref().map(reference)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    Invalid(String),
    NotFound,
    /// The idempotency key is taken by a different declaration.
    Conflict,
    /// The chunk does not continue the upload; holds the expected offset.
    Offset(u64),
    /// The upload is already complete.
    Completed,
    /// The upload moved on since it was read (another completion reset it).
    Changed,
    Storage(String),
}

impl MediaUploadRequest {
    pub fn validate(&self) -> Result<(), MediaError> {
        let invalid = |message: &str| Err(MediaError::Invalid(message.into()));
        if self.namespace.is_empty() || self.uploader.is_empty() {
            return invalid("namespace and uploader are required");
        }
        if self.idempotency_key.is_empty()
            || self.idempotency_key.len() > MAX_KEY_BYTES
            || self.idempotency_key.chars().any(char::is_control)
        {
            return invalid("idempotency_key must be 1 to 256 bytes without control characters");
        }
        if self.size_bytes == 0 || self.size_bytes > MAX_MEDIA_BYTES {
            return Err(MediaError::Invalid(format!(
                "size_bytes must be between 1 and {MAX_MEDIA_BYTES}"
            )));
        }
        if self.sha256.len() != 64
            || !self
                .sha256
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return invalid("sha256 must be 64 lowercase hex characters");
        }
        let token = |value: &str| {
            !value.is_empty()
                && value
                    .chars()
                    .all(|c| c.is_ascii_graphic() && c != ',' && c != ';')
        };
        if self.media_type.len() > MAX_MEDIA_TYPE_BYTES
            || !self
                .media_type
                .split_once('/')
                .is_some_and(|(kind, subtype)| token(kind) && token(subtype))
        {
            return invalid("media_type must be a type/subtype such as image/jpeg");
        }
        if self.file_name.len() > MAX_FILE_NAME_BYTES
            || self
                .file_name
                .chars()
                .any(|c| c.is_control() || c == '/' || c == '\\')
        {
            return invalid(
                "file_name must be at most 255 bytes, without control characters or path separators",
            );
        }
        Ok(())
    }

    /// The session id: the same namespace, uploader and key always name the
    /// same upload, and nothing else does.
    pub fn upload_id(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [&self.namespace, &self.uploader, &self.idempotency_key] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        format!("upload-{}", &hex(&hasher.finalize())[..40])
    }

    /// The object a completed upload becomes.
    pub fn object_id(&self) -> String {
        format!("media-{}", &self.upload_id()["upload-".len()..])
    }
}

pub fn reference(object_id: &str) -> String {
    format!("{REFERENCE_PREFIX}{object_id}")
}

/// The object id a reference names.
pub fn parse_reference(reference: &str) -> Result<&str, MediaError> {
    reference
        .strip_prefix(REFERENCE_PREFIX)
        .filter(|id| id.starts_with("media-") && id.len() <= 128)
        .ok_or_else(|| MediaError::Invalid("not a sekai-media reference".into()))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The SHA-256 of a stored upload, read back in chunks through `read`.
pub fn stored_sha256(
    size_bytes: u64,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, MediaError>,
) -> Result<String, MediaError> {
    let mut hasher = Sha256::new();
    let mut offset = 0;
    while offset < size_bytes {
        let want = MAX_CHUNK_BYTES.min((size_bytes - offset) as usize);
        let bytes = read(offset, want)?;
        if bytes.is_empty() {
            return Err(MediaError::Storage(format!(
                "stored media ends at {offset} of {size_bytes} bytes"
            )));
        }
        hasher.update(&bytes);
        offset += bytes.len() as u64;
    }
    Ok(hex(&hasher.finalize()))
}

/// The bytes `[offset, offset + len)` from stored chunks `(offset, data)`
/// in offset order that overlap that range.
pub fn assemble(chunks: Vec<(u64, Vec<u8>)>, offset: u64, len: usize) -> Vec<u8> {
    let end = offset + len as u64;
    let mut out = Vec::with_capacity(len);
    for (start, data) in chunks {
        let from = offset + out.len() as u64;
        let to = end.min(start + data.len() as u64);
        if to <= from {
            continue;
        }
        if start > from {
            break;
        }
        out.extend_from_slice(&data[(from - start) as usize..(to - start) as usize]);
    }
    out
}

/// Whether a chunk must be stored, given the session: `Ok(false)` is a
/// retried chunk the session already holds.
pub fn check_append(upload: &MediaUpload, offset: u64, len: usize) -> Result<bool, MediaError> {
    if upload.object_id.is_some() {
        return Err(MediaError::Completed);
    }
    if len == 0 || len > MAX_CHUNK_BYTES {
        return Err(MediaError::Invalid(format!(
            "a chunk holds 1 to {MAX_CHUNK_BYTES} bytes"
        )));
    }
    let end = offset.saturating_add(len as u64);
    if offset < upload.received_bytes && end <= upload.received_bytes {
        return Ok(false);
    }
    if offset != upload.received_bytes {
        return Err(MediaError::Offset(upload.received_bytes));
    }
    if end > upload.request.size_bytes {
        return Err(MediaError::Invalid(format!(
            "the chunk passes the declared size of {} bytes",
            upload.request.size_bytes
        )));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> MediaUploadRequest {
        MediaUploadRequest {
            namespace: "field".into(),
            uploader: "alice".into(),
            idempotency_key: "photo-1".into(),
            size_bytes: 3,
            sha256: hex(&Sha256::digest(b"abc")),
            media_type: "image/jpeg".into(),
            file_name: "site.jpg".into(),
            access_marking: String::new(),
        }
    }

    #[test]
    fn ids_follow_namespace_uploader_and_key() {
        let base = request();
        assert_eq!(base.upload_id(), request().upload_id());
        for changed in [
            MediaUploadRequest {
                namespace: "other".into(),
                ..request()
            },
            MediaUploadRequest {
                uploader: "bob".into(),
                ..request()
            },
            MediaUploadRequest {
                idempotency_key: "photo-2".into(),
                ..request()
            },
        ] {
            assert_ne!(changed.upload_id(), base.upload_id());
        }
        // Length prefixes keep ("ab", "c") apart from ("a", "bc").
        let split = |namespace: &str, uploader: &str| MediaUploadRequest {
            namespace: namespace.into(),
            uploader: uploader.into(),
            ..request()
        };
        assert_ne!(split("ab", "c").upload_id(), split("a", "bc").upload_id());
        let object = base.object_id();
        assert_eq!(parse_reference(&reference(&object)).unwrap(), object);
        assert!(parse_reference("sekai-media:obj-1").is_err());
        assert!(parse_reference("https://example.invalid/x").is_err());
    }

    #[test]
    fn declarations_are_validated() {
        assert!(request().validate().is_ok());
        let cases = [
            MediaUploadRequest {
                size_bytes: 0,
                ..request()
            },
            MediaUploadRequest {
                size_bytes: MAX_MEDIA_BYTES + 1,
                ..request()
            },
            MediaUploadRequest {
                sha256: "ABC".into(),
                ..request()
            },
            MediaUploadRequest {
                media_type: "jpeg".into(),
                ..request()
            },
            MediaUploadRequest {
                file_name: "../etc/passwd".into(),
                ..request()
            },
            MediaUploadRequest {
                idempotency_key: String::new(),
                ..request()
            },
        ];
        for case in cases {
            assert!(
                matches!(case.validate(), Err(MediaError::Invalid(_))),
                "{case:?}"
            );
        }
    }

    #[test]
    fn ranges_are_assembled_from_chunks() {
        let chunks = || {
            vec![
                (0, b"abc".to_vec()),
                (3, b"defg".to_vec()),
                (7, b"h".to_vec()),
            ]
        };
        assert_eq!(assemble(chunks(), 0, 8), b"abcdefgh");
        assert_eq!(assemble(chunks(), 2, 3), b"cde");
        assert_eq!(assemble(chunks(), 7, 10), b"h");
        assert_eq!(
            assemble(vec![(0, b"ab".to_vec()), (5, b"x".to_vec())], 0, 6),
            b"ab"
        );
    }

    #[test]
    fn appends_continue_at_the_received_offset() {
        let upload = MediaUpload {
            upload_id: request().upload_id(),
            request: MediaUploadRequest {
                size_bytes: 10,
                ..request()
            },
            received_bytes: 4,
            attempt: 0,
            object_id: None,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        assert_eq!(check_append(&upload, 4, 6), Ok(true));
        assert_eq!(check_append(&upload, 0, 4), Ok(false));
        assert_eq!(check_append(&upload, 2, 4), Err(MediaError::Offset(4)));
        assert_eq!(check_append(&upload, 6, 2), Err(MediaError::Offset(4)));
        assert!(matches!(
            check_append(&upload, 4, 7),
            Err(MediaError::Invalid(_))
        ));
        let done = MediaUpload {
            object_id: Some("media-x".into()),
            ..upload
        };
        assert_eq!(check_append(&done, 4, 1), Err(MediaError::Completed));
    }

    #[test]
    fn the_stored_digest_reads_every_chunk() {
        let bytes: Vec<u8> = (0..(MAX_CHUNK_BYTES * 2 + 7)).map(|i| i as u8).collect();
        let digest = stored_sha256(bytes.len() as u64, |offset, want| {
            let start = offset as usize;
            Ok(bytes[start..(start + want).min(bytes.len())].to_vec())
        })
        .unwrap();
        assert_eq!(digest, hex(&Sha256::digest(&bytes)));
        let short = stored_sha256(10, |_, _| Ok(Vec::new()));
        assert!(matches!(short, Err(MediaError::Storage(_))));
    }
}
