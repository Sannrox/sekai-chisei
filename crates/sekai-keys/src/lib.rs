//! Envelope-encryption contract for customer-managed keys (ADR 0113).
//!
//! Stores take wrapped DEKs and an unwrap grant. They never receive the KEK.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Default in-process DEK cache lifetime.
pub const DEFAULT_DEK_CACHE_TTL: Duration = Duration::from_secs(60);

const FILE_MAGIC: &[u8; 4] = b"SKK1";
const FILE_VERSION: u8 = 1;
const FILE_FLAG_KEK_REVOKED: u8 = 0x01;
const FILE_FLAG_HAS_PREVIOUS: u8 = 0x02;
const MAX_ID_BYTES: usize = 256;
const MAX_REVOKED_DEKS: usize = 10_000;

/// Runtime profile that admits or refuses development providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeProfile {
    Development,
    Production,
}

/// Provider kind reported by [`KeyProvider::describe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderKind {
    Memory,
    File,
    Kmip,
    Pkcs11,
    CloudKms,
}

/// Why a DEK is unwrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyPurpose {
    Store,
    Spill,
    Cache,
    Backup,
    Export,
}

/// Opaque key identifier. Never a secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(value: impl Into<String>) -> Result<Self, KeyError> {
        Ok(Self(parse_id_value(value.into(), "key_id")?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        KeyId::new(value).map_err(serde::de::Error::custom)
    }
}

/// Tenant isolation key on every wrap and unwrap.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(value: impl Into<String>) -> Result<Self, KeyError> {
        Ok(Self(parse_id_value(value.into(), "tenant_id")?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TenantId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        TenantId::new(value).map_err(serde::de::Error::custom)
    }
}

/// 32-byte data key. Redacted in Debug; zeroized on drop.
#[derive(Clone, Zeroize)]
pub struct Dek([u8; 32]);

impl Dek {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

impl Drop for Dek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Wrapped DEK ciphertext plus public binding metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedDek {
    pub kek_id: KeyId,
    pub dek_id: KeyId,
    pub tenant_id: TenantId,
    pub purpose: KeyPurpose,
    ciphertext: Vec<u8>,
}

impl WrappedDek {
    pub fn new(
        kek_id: KeyId,
        dek_id: KeyId,
        tenant_id: TenantId,
        purpose: KeyPurpose,
        ciphertext: Vec<u8>,
    ) -> Result<Self, KeyError> {
        let kek_id = KeyId::new(kek_id.as_str())?;
        let dek_id = KeyId::new(dek_id.as_str())?;
        let tenant_id = TenantId::new(tenant_id.as_str())?;
        if ciphertext.len() < 13 {
            return Err(KeyError::WrapFailed);
        }
        Ok(Self {
            kek_id,
            dek_id,
            tenant_id,
            purpose,
            ciphertext,
        })
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Time-bounded permission to unwrap for one tenant and purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrapGrant {
    pub tenant_id: TenantId,
    pub purpose: KeyPurpose,
    pub expires_unix_secs: i64,
}

/// Audit row for one unwrap. Contains no key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnwrapAudit {
    pub tenant_id: TenantId,
    pub engine: String,
    pub purpose: KeyPurpose,
    pub key_id: KeyId,
}

/// Successful unwrap: DEK plus the audit event the caller must record.
#[derive(Debug)]
pub struct UnwrapOutcome {
    pub dek: Dek,
    pub audit: UnwrapAudit,
}

/// Public provider description. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderDescription {
    pub kind: ProviderKind,
    pub kek_id: KeyId,
    pub algorithm: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    EmptyField(&'static str),
    Revoked,
    GrantDenied,
    WrongTenant,
    WrongPurpose,
    UnknownKey,
    ProductionProviderRefused,
    RotationOverlapActive,
    InvalidField(&'static str),
    WrapFailed,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(name) => write!(f, "{name} must not be empty"),
            Self::Revoked => f.write_str("key is revoked"),
            Self::GrantDenied => f.write_str("unwrap grant denied"),
            Self::WrongTenant => f.write_str("wrapped DEK tenant does not match grant"),
            Self::WrongPurpose => f.write_str("wrapped DEK purpose does not match grant"),
            Self::UnknownKey => f.write_str("key is unknown"),
            Self::ProductionProviderRefused => {
                f.write_str("development key provider is refused in production profiles")
            }
            Self::RotationOverlapActive => f.write_str("KEK rotation overlap is already active"),
            Self::InvalidField(name) => write!(f, "{name} is invalid"),
            Self::WrapFailed => f.write_str("wrap or unwrap failed"),
        }
    }
}

impl std::error::Error for KeyError {}

fn parse_id_value(value: String, field: &'static str) -> Result<String, KeyError> {
    if value.trim().is_empty() {
        return Err(KeyError::EmptyField(field));
    }
    if value.contains('\0') || value.len() > MAX_ID_BYTES {
        return Err(KeyError::InvalidField(field));
    }
    Ok(value)
}

/// Fail closed when a production profile is given a development provider.
pub fn admit_provider(profile: RuntimeProfile, kind: ProviderKind) -> Result<(), KeyError> {
    match (profile, kind) {
        (RuntimeProfile::Production, ProviderKind::Memory | ProviderKind::File) => {
            Err(KeyError::ProductionProviderRefused)
        }
        _ => Ok(()),
    }
}

/// Customer key provider. Engines call wrap/unwrap; they never see the KEK.
pub trait KeyProvider {
    fn describe(&self) -> ProviderDescription;
    fn wrap(
        &self,
        tenant_id: &TenantId,
        purpose: KeyPurpose,
        dek: &Dek,
    ) -> Result<WrappedDek, KeyError>;
    /// Wrap an existing DEK under the current KEK, keeping tenant, purpose, and
    /// DEK id so revocation still matches after KEK rotation.
    fn rewrap(&self, wrapped: &WrappedDek, dek: &Dek) -> Result<WrappedDek, KeyError>;
    fn unwrap(
        &self,
        wrapped: &WrappedDek,
        grant: &UnwrapGrant,
        engine: &str,
        now_unix_secs: i64,
    ) -> Result<UnwrapOutcome, KeyError>;
    /// Install a new current KEK. Envelopes wrapped under the previous KEK
    /// still unwrap during overlap. A second rotation while overlap is active
    /// fails closed. Store bytes are not rewritten.
    fn rotate_kek(&self) -> Result<KeyId, KeyError>;
    /// Drop the previous KEK after stores have rewrapped under the current KEK.
    fn complete_kek_rotation(&self) -> Result<(), KeyError>;
    fn revoke_kek(&self) -> Result<(), KeyError>;
    fn revoke_dek(&self, dek_id: &KeyId) -> Result<(), KeyError>;
}

struct ProviderState {
    kek_id: KeyId,
    kek: [u8; 32],
    previous: Option<(KeyId, [u8; 32])>,
    dek_revoked: HashSet<String>,
    kek_revoked: bool,
}

impl Drop for ProviderState {
    fn drop(&mut self) {
        self.kek.zeroize();
        if let Some((_, previous)) = &mut self.previous {
            previous.zeroize();
        }
    }
}

impl fmt::Debug for ProviderState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderState")
            .field("kek_id", &self.kek_id)
            .field("kek", &"<redacted>")
            .field("previous", &self.previous.as_ref().map(|(id, _)| id))
            .finish_non_exhaustive()
    }
}

fn purpose_tag(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Store => "store",
        KeyPurpose::Spill => "spill",
        KeyPurpose::Cache => "cache",
        KeyPurpose::Backup => "backup",
        KeyPurpose::Export => "export",
    }
}

fn envelope_aad(
    tenant_id: &TenantId,
    purpose: KeyPurpose,
    dek_id: &KeyId,
) -> Result<Vec<u8>, KeyError> {
    let mut aad = Vec::new();
    write_len_bytes(&mut aad, tenant_id.as_str().as_bytes())?;
    write_len_bytes(&mut aad, purpose_tag(purpose).as_bytes())?;
    write_len_bytes(&mut aad, dek_id.as_str().as_bytes())?;
    Ok(aad)
}

fn wrap_dek(
    kek: &[u8; 32],
    dek: &Dek,
    tenant_id: &TenantId,
    purpose: KeyPurpose,
    dek_id: &KeyId,
) -> Result<Vec<u8>, KeyError> {
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| KeyError::WrapFailed)?;
    let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());
    let aad = envelope_aad(tenant_id, purpose, dek_id)?;
    let mut out = nonce.to_vec();
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: dek.as_bytes().as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| KeyError::WrapFailed)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unwrap_dek(
    kek: &[u8; 32],
    ciphertext: &[u8],
    tenant_id: &TenantId,
    purpose: KeyPurpose,
    dek_id: &KeyId,
) -> Result<Dek, KeyError> {
    if ciphertext.len() < 13 {
        return Err(KeyError::WrapFailed);
    }
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| KeyError::WrapFailed)?;
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let aad = envelope_aad(tenant_id, purpose, dek_id)?;
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext[12..],
                    aad: &aad,
                },
            )
            .map_err(|_| KeyError::WrapFailed)?,
    );
    let bytes: [u8; 32] = pt.as_slice().try_into().map_err(|_| KeyError::WrapFailed)?;
    Ok(Dek::from_bytes(bytes))
}

fn random_key_id(prefix: &str) -> KeyId {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(prefix.len() + 1 + 32);
    hex.push_str(prefix);
    hex.push('-');
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    KeyId(hex)
}

fn lock_state(
    state: &Mutex<ProviderState>,
) -> Result<std::sync::MutexGuard<'_, ProviderState>, KeyError> {
    state.lock().map_err(|_| KeyError::WrapFailed)
}

impl ProviderState {
    fn new(kek_id: KeyId, kek: [u8; 32]) -> Self {
        Self {
            kek_id,
            kek,
            previous: None,
            dek_revoked: HashSet::new(),
            kek_revoked: false,
        }
    }

    fn kek_for(&self, kek_id: &KeyId) -> Result<&[u8; 32], KeyError> {
        if self.kek_id == *kek_id {
            return Ok(&self.kek);
        }
        match &self.previous {
            Some((id, key)) if id == kek_id => Ok(key),
            _ => Err(KeyError::UnknownKey),
        }
    }

    fn wrap(
        &mut self,
        tenant_id: &TenantId,
        purpose: KeyPurpose,
        dek: &Dek,
    ) -> Result<WrappedDek, KeyError> {
        self.wrap_with_id(tenant_id, purpose, dek, random_key_id("dek"))
    }

    fn rewrap(&mut self, wrapped: &WrappedDek, dek: &Dek) -> Result<WrappedDek, KeyError> {
        if self.kek_revoked || self.dek_revoked.contains(wrapped.dek_id.as_str()) {
            return Err(KeyError::Revoked);
        }
        let tenant_id = TenantId::new(wrapped.tenant_id.as_str())?;
        let dek_id = KeyId::new(wrapped.dek_id.as_str())?;
        let kek = self.kek_for(&wrapped.kek_id)?;
        let recovered = unwrap_dek(
            kek,
            wrapped.ciphertext(),
            &tenant_id,
            wrapped.purpose,
            &dek_id,
        )?;
        if recovered.as_bytes() != dek.as_bytes() {
            return Err(KeyError::WrapFailed);
        }
        self.wrap_with_id(&tenant_id, wrapped.purpose, dek, dek_id)
    }

    fn wrap_with_id(
        &mut self,
        tenant_id: &TenantId,
        purpose: KeyPurpose,
        dek: &Dek,
        dek_id: KeyId,
    ) -> Result<WrappedDek, KeyError> {
        if self.kek_revoked {
            return Err(KeyError::Revoked);
        }
        let tenant_id = TenantId::new(tenant_id.as_str())?;
        let ciphertext = wrap_dek(&self.kek, dek, &tenant_id, purpose, &dek_id)?;
        WrappedDek::new(self.kek_id.clone(), dek_id, tenant_id, purpose, ciphertext)
    }

    fn unwrap(
        &self,
        wrapped: &WrappedDek,
        grant: &UnwrapGrant,
        engine: &str,
        now_unix_secs: i64,
    ) -> Result<UnwrapOutcome, KeyError> {
        if self.kek_revoked || self.dek_revoked.contains(wrapped.dek_id.as_str()) {
            return Err(KeyError::Revoked);
        }
        if now_unix_secs >= grant.expires_unix_secs {
            return Err(KeyError::GrantDenied);
        }
        let tenant_id = TenantId::new(wrapped.tenant_id.as_str())?;
        let grant_tenant = TenantId::new(grant.tenant_id.as_str())?;
        if tenant_id != grant_tenant {
            return Err(KeyError::WrongTenant);
        }
        if wrapped.purpose != grant.purpose {
            return Err(KeyError::WrongPurpose);
        }
        let kek = self.kek_for(&wrapped.kek_id)?;
        let dek = unwrap_dek(
            kek,
            wrapped.ciphertext(),
            &tenant_id,
            wrapped.purpose,
            &wrapped.dek_id,
        )?;
        Ok(UnwrapOutcome {
            dek,
            audit: UnwrapAudit {
                tenant_id,
                engine: engine.to_string(),
                purpose: wrapped.purpose,
                key_id: wrapped.dek_id.clone(),
            },
        })
    }

    fn rotate_kek(&mut self) -> Result<KeyId, KeyError> {
        if self.kek_revoked {
            return Err(KeyError::Revoked);
        }
        if self.previous.is_some() {
            return Err(KeyError::RotationOverlapActive);
        }
        let mut new_kek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_kek);
        let new_id = random_key_id("kek");
        let mut previous_kek = [0u8; 32];
        previous_kek.copy_from_slice(&self.kek);
        self.previous = Some((self.kek_id.clone(), previous_kek));
        self.kek.zeroize();
        self.kek = new_kek;
        self.kek_id = new_id.clone();
        Ok(new_id)
    }

    fn complete_kek_rotation(&mut self) -> Result<(), KeyError> {
        if self.kek_revoked {
            return Err(KeyError::Revoked);
        }
        if let Some((_, mut previous)) = self.previous.take() {
            previous.zeroize();
        }
        Ok(())
    }

    fn revoke_kek(&mut self) {
        self.kek_revoked = true;
        self.kek.zeroize();
        if let Some((_, previous)) = &mut self.previous {
            previous.zeroize();
        }
        self.previous = None;
    }

    fn revoke_dek(&mut self, dek_id: &KeyId) -> Result<bool, KeyError> {
        if self.dek_revoked.contains(dek_id.as_str()) {
            return Ok(false);
        }
        if self.dek_revoked.len() >= MAX_REVOKED_DEKS {
            return Err(KeyError::WrapFailed);
        }
        self.dek_revoked.insert(dek_id.as_str().to_string());
        Ok(true)
    }
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), KeyError> {
    let len = u16::try_from(bytes.len()).map_err(|_| KeyError::WrapFailed)?;
    write_u16(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_state(state: &ProviderState) -> Result<Vec<u8>, KeyError> {
    let mut out = Vec::new();
    out.extend_from_slice(FILE_MAGIC);
    out.push(FILE_VERSION);
    let mut flags = 0u8;
    if state.kek_revoked {
        flags |= FILE_FLAG_KEK_REVOKED;
    }
    if state.previous.is_some() {
        flags |= FILE_FLAG_HAS_PREVIOUS;
    }
    out.push(flags);
    write_len_bytes(&mut out, state.kek_id.as_str().as_bytes())?;
    let kek = if state.kek_revoked {
        [0u8; 32]
    } else {
        state.kek
    };
    out.extend_from_slice(&kek);
    if let Some((id, key)) = &state.previous {
        write_len_bytes(&mut out, id.as_str().as_bytes())?;
        let key = if state.kek_revoked { [0u8; 32] } else { *key };
        out.extend_from_slice(&key);
    }
    write_u32(
        &mut out,
        u32::try_from(state.dek_revoked.len()).map_err(|_| KeyError::WrapFailed)?,
    );
    for dek_id in &state.dek_revoked {
        write_len_bytes(&mut out, dek_id.as_bytes())?;
    }
    Ok(out)
}

fn take_bytes<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], KeyError> {
    if cur.len() < n {
        return Err(KeyError::WrapFailed);
    }
    let (head, rest) = cur.split_at(n);
    *cur = rest;
    Ok(head)
}

fn take_u16(cur: &mut &[u8]) -> Result<u16, KeyError> {
    let bytes = take_bytes(cur, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take_u32(cur: &mut &[u8]) -> Result<u32, KeyError> {
    let bytes = take_bytes(cur, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn take_len_string(cur: &mut &[u8]) -> Result<String, KeyError> {
    let len = usize::from(take_u16(cur)?);
    if len == 0 || len > MAX_ID_BYTES {
        return Err(KeyError::WrapFailed);
    }
    let bytes = take_bytes(cur, len)?;
    let value = std::str::from_utf8(bytes).map_err(|_| KeyError::WrapFailed)?;
    Ok(value.to_owned())
}

fn decode_state(bytes: &[u8]) -> Result<ProviderState, KeyError> {
    let mut cur = bytes;
    let magic = take_bytes(&mut cur, 4)?;
    if magic != FILE_MAGIC {
        return Err(KeyError::WrapFailed);
    }
    let version = take_bytes(&mut cur, 1)?[0];
    if version != FILE_VERSION {
        return Err(KeyError::WrapFailed);
    }
    let flags = take_bytes(&mut cur, 1)?[0];
    let kek_revoked = flags & FILE_FLAG_KEK_REVOKED != 0;
    let has_previous = flags & FILE_FLAG_HAS_PREVIOUS != 0;
    let kek_id = KeyId::new(take_len_string(&mut cur)?)?;
    let kek_bytes = take_bytes(&mut cur, 32)?;
    let mut kek = [0u8; 32];
    kek.copy_from_slice(kek_bytes);
    let previous = if has_previous {
        let id = KeyId::new(take_len_string(&mut cur)?)?;
        let prev_bytes = take_bytes(&mut cur, 32)?;
        let mut prev = [0u8; 32];
        prev.copy_from_slice(prev_bytes);
        Some((id, prev))
    } else {
        None
    };
    let revoked_count = take_u32(&mut cur)? as usize;
    if revoked_count > MAX_REVOKED_DEKS {
        return Err(KeyError::WrapFailed);
    }
    let mut dek_revoked = HashSet::new();
    for _ in 0..revoked_count {
        dek_revoked.insert(take_len_string(&mut cur)?);
    }
    if !cur.is_empty() {
        return Err(KeyError::WrapFailed);
    }
    Ok(ProviderState {
        kek_id,
        kek,
        previous,
        dek_revoked,
        kek_revoked,
    })
}

fn held_paths() -> &'static Mutex<HashSet<PathBuf>> {
    static HELD_PATHS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    HELD_PATHS.get_or_init(|| Mutex::new(HashSet::new()))
}

#[derive(Debug)]
struct PathClaim {
    path: PathBuf,
}

impl PathClaim {
    fn acquire(path: PathBuf) -> Result<Self, KeyError> {
        let mut held = held_paths().lock().map_err(|_| KeyError::WrapFailed)?;
        if !held.insert(path.clone()) {
            return Err(KeyError::WrapFailed);
        }
        Ok(Self { path })
    }
}

impl Drop for PathClaim {
    fn drop(&mut self) {
        if let Ok(mut held) = held_paths().lock() {
            held.remove(&self.path);
        }
    }
}

fn try_exclusive_lock(file: &std::fs::File) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `file` owns the fd for the duration of this call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(KeyError::WrapFailed);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(KeyError::WrapFailed)
    }
}

fn resolve_kek_path(path: &Path) -> Result<PathBuf, KeyError> {
    match fs::symlink_metadata(path) {
        Ok(_) => fs::canonicalize(path).map_err(|_| KeyError::WrapFailed),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|_| KeyError::WrapFailed)?
                    .join(path)
            };
            let name = absolute.file_name().ok_or(KeyError::WrapFailed)?;
            match absolute.parent() {
                Some(parent) if parent.exists() => {
                    let parent = fs::canonicalize(parent).map_err(|_| KeyError::WrapFailed)?;
                    Ok(parent.join(name))
                }
                _ => Ok(absolute),
            }
        }
        Err(_) => Err(KeyError::WrapFailed),
    }
}

fn lock_path_for(path: &Path) -> Result<PathBuf, KeyError> {
    let name = path.file_name().ok_or(KeyError::WrapFailed)?;
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok(dir.join(format!("{}.lock", name.to_string_lossy())))
}

fn exclusive_create_0600(path: &Path) -> Result<std::fs::File, KeyError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|_| KeyError::WrapFailed)
}

fn open_lock_file(path: &Path) -> Result<std::fs::File, KeyError> {
    if fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(KeyError::WrapFailed);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|_| KeyError::WrapFailed)?;
    try_exclusive_lock(&file)?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(file)
}

fn remove_orphan_tmps(path: &Path) -> Result<(), KeyError> {
    let name = path.file_name().ok_or(KeyError::WrapFailed)?;
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let prefix = format!(".{}.tmp-", name.to_string_lossy());
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        if is_owned_tmp_name(&file_name.to_string_lossy(), &prefix) {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

fn is_owned_tmp_name(name: &str, prefix: &str) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    let mut parts = rest.splitn(2, '-');
    match (parts.next(), parts.next()) {
        (Some(pid), Some(nonce)) => {
            !pid.is_empty()
                && !nonce.is_empty()
                && pid.chars().all(|ch| ch.is_ascii_digit())
                && nonce.chars().all(|ch| ch.is_ascii_digit())
        }
        _ => false,
    }
}

fn persist_atomic(path: &Path, state: &ProviderState) -> Result<(), KeyError> {
    let encoded = Zeroizing::new(encode_state(state)?);
    let file_name = path
        .file_name()
        .ok_or(KeyError::WrapFailed)?
        .to_string_lossy();
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut nonce = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut nonce);
    let tmp = dir.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        u32::from_le_bytes(nonce)
    ));
    {
        let mut file = exclusive_create_0600(&tmp)?;
        if file
            .write_all(&encoded)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(&tmp);
            return Err(KeyError::WrapFailed);
        }
    }
    if let Err(error) = sync_dir(dir) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    if fs::rename(&tmp, path).is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(KeyError::WrapFailed);
    }
    sync_dir(dir)?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        let file = std::fs::File::open(dir).map_err(|_| KeyError::WrapFailed)?;
        file.sync_all().map_err(|_| KeyError::WrapFailed)?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

fn load_state(path: &Path) -> Result<ProviderState, KeyError> {
    owner_only_or_fail(path)?;
    let mut file = std::fs::File::open(path).map_err(|_| KeyError::WrapFailed)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes)
        .map_err(|_| KeyError::WrapFailed)?;
    decode_state(&bytes)
}

fn owner_only_or_fail(path: &Path) -> Result<(), KeyError> {
    let metadata = fs::metadata(path).map_err(|_| KeyError::WrapFailed)?;
    #[cfg(unix)]
    {
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyError::WrapFailed);
        }
    }
    let _ = metadata;
    Ok(())
}

fn describe_locked(kind: ProviderKind, state: &Mutex<ProviderState>) -> ProviderDescription {
    match lock_state(state) {
        Ok(guard) => ProviderDescription {
            kind,
            kek_id: guard.kek_id.clone(),
            algorithm: "AES-256-GCM",
        },
        Err(_) => ProviderDescription {
            kind,
            kek_id: KeyId(String::from("unavailable")),
            algorithm: "AES-256-GCM",
        },
    }
}

/// In-memory provider for tests and local development.
#[derive(Debug)]
pub struct MemoryKeyProvider {
    state: Mutex<ProviderState>,
}

impl MemoryKeyProvider {
    pub fn new(profile: RuntimeProfile) -> Result<Self, KeyError> {
        admit_provider(profile, ProviderKind::Memory)?;
        let mut kek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut kek);
        Ok(Self {
            state: Mutex::new(ProviderState::new(random_key_id("kek"), kek)),
        })
    }
}

impl KeyProvider for MemoryKeyProvider {
    fn describe(&self) -> ProviderDescription {
        describe_locked(ProviderKind::Memory, &self.state)
    }

    fn wrap(
        &self,
        tenant_id: &TenantId,
        purpose: KeyPurpose,
        dek: &Dek,
    ) -> Result<WrappedDek, KeyError> {
        lock_state(&self.state)?.wrap(tenant_id, purpose, dek)
    }

    fn rewrap(&self, wrapped: &WrappedDek, dek: &Dek) -> Result<WrappedDek, KeyError> {
        lock_state(&self.state)?.rewrap(wrapped, dek)
    }

    fn unwrap(
        &self,
        wrapped: &WrappedDek,
        grant: &UnwrapGrant,
        engine: &str,
        now_unix_secs: i64,
    ) -> Result<UnwrapOutcome, KeyError> {
        lock_state(&self.state)?.unwrap(wrapped, grant, engine, now_unix_secs)
    }

    fn rotate_kek(&self) -> Result<KeyId, KeyError> {
        lock_state(&self.state)?.rotate_kek()
    }

    fn complete_kek_rotation(&self) -> Result<(), KeyError> {
        lock_state(&self.state)?.complete_kek_rotation()
    }

    fn revoke_kek(&self) -> Result<(), KeyError> {
        lock_state(&self.state)?.revoke_kek();
        Ok(())
    }

    fn revoke_dek(&self, dek_id: &KeyId) -> Result<(), KeyError> {
        lock_state(&self.state)?.revoke_dek(dek_id).map(|_| ())
    }
}

struct FileInner {
    _lock_file: std::fs::File,
    state: ProviderState,
    durable: bool,
}

impl fmt::Debug for FileInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileInner")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// File-backed development KEK. Refused in production profiles.
#[derive(Debug)]
pub struct FileKeyProvider {
    path: PathBuf,
    _claim: PathClaim,
    inner: Mutex<FileInner>,
}

impl FileKeyProvider {
    /// Open or create a development KEK file. Existing files are never truncated.
    /// New files are created exclusively with owner-only mode on Unix. One
    /// process may hold a given path at a time.
    pub fn open(path: impl AsRef<Path>, profile: RuntimeProfile) -> Result<Self, KeyError> {
        admit_provider(profile, ProviderKind::File)?;
        let requested = path.as_ref().to_path_buf();
        if let Some(parent) = requested.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|_| KeyError::WrapFailed)?;
        }
        let path = resolve_kek_path(&requested)?;
        let lock_file = open_lock_file(&lock_path_for(&path)?)?;
        remove_orphan_tmps(&path)?;
        let state = if path.exists() {
            load_state(&path)?
        } else {
            let mut kek = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut kek);
            let state = ProviderState::new(random_key_id("kek"), kek);
            kek.zeroize();
            persist_atomic(&path, &state)?;
            state
        };
        let claim = PathClaim::acquire(path.clone())?;
        Ok(Self {
            path,
            _claim: claim,
            inner: Mutex::new(FileInner {
                _lock_file: lock_file,
                state,
                durable: true,
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_inner(&self) -> Result<std::sync::MutexGuard<'_, FileInner>, KeyError> {
        self.inner.lock().map_err(|_| KeyError::WrapFailed)
    }

    fn persist_inner(path: &Path, inner: &mut FileInner) -> Result<(), KeyError> {
        match persist_atomic(path, &inner.state) {
            Ok(()) => {
                inner.durable = true;
                let _ = remove_orphan_tmps(path);
                Ok(())
            }
            Err(error) => {
                inner.durable = false;
                Err(error)
            }
        }
    }

    fn ensure_durable(path: &Path, inner: &mut FileInner) -> Result<(), KeyError> {
        if inner.durable {
            Ok(())
        } else {
            Self::persist_inner(path, inner)
        }
    }
}

impl KeyProvider for FileKeyProvider {
    fn describe(&self) -> ProviderDescription {
        match self.lock_inner() {
            Ok(inner) => ProviderDescription {
                kind: ProviderKind::File,
                kek_id: inner.state.kek_id.clone(),
                algorithm: "AES-256-GCM",
            },
            Err(_) => ProviderDescription {
                kind: ProviderKind::File,
                kek_id: KeyId(String::from("unavailable")),
                algorithm: "AES-256-GCM",
            },
        }
    }

    fn wrap(
        &self,
        tenant_id: &TenantId,
        purpose: KeyPurpose,
        dek: &Dek,
    ) -> Result<WrappedDek, KeyError> {
        let mut inner = self.lock_inner()?;
        Self::ensure_durable(&self.path, &mut inner)?;
        inner.state.wrap(tenant_id, purpose, dek)
    }

    fn rewrap(&self, wrapped: &WrappedDek, dek: &Dek) -> Result<WrappedDek, KeyError> {
        let mut inner = self.lock_inner()?;
        Self::ensure_durable(&self.path, &mut inner)?;
        inner.state.rewrap(wrapped, dek)
    }

    fn unwrap(
        &self,
        wrapped: &WrappedDek,
        grant: &UnwrapGrant,
        engine: &str,
        now_unix_secs: i64,
    ) -> Result<UnwrapOutcome, KeyError> {
        let mut inner = self.lock_inner()?;
        Self::ensure_durable(&self.path, &mut inner)?;
        inner.state.unwrap(wrapped, grant, engine, now_unix_secs)
    }

    fn rotate_kek(&self) -> Result<KeyId, KeyError> {
        let mut inner = self.lock_inner()?;
        Self::ensure_durable(&self.path, &mut inner)?;
        let id = inner.state.rotate_kek()?;
        Self::persist_inner(&self.path, &mut inner)?;
        Ok(id)
    }

    fn complete_kek_rotation(&self) -> Result<(), KeyError> {
        let mut inner = self.lock_inner()?;
        Self::ensure_durable(&self.path, &mut inner)?;
        if inner.state.previous.is_none() {
            return inner.state.complete_kek_rotation();
        }
        inner.state.complete_kek_rotation()?;
        Self::persist_inner(&self.path, &mut inner)
    }

    fn revoke_kek(&self) -> Result<(), KeyError> {
        let mut inner = self.lock_inner()?;
        Self::ensure_durable(&self.path, &mut inner)?;
        inner.state.revoke_kek();
        Self::persist_inner(&self.path, &mut inner)
    }

    fn revoke_dek(&self, dek_id: &KeyId) -> Result<(), KeyError> {
        let mut inner = self.lock_inner()?;
        Self::ensure_durable(&self.path, &mut inner)?;
        if !inner.state.revoke_dek(dek_id)? {
            return Ok(());
        }
        Self::persist_inner(&self.path, &mut inner)
    }
}

/// Shared checks every store adapter must pass against its provider.
pub mod conformance {
    use super::*;

    /// Revoked key means no reads; KEK rotation loses no plaintext; Debug has no key bytes.
    pub fn assert_provider_contract(provider: &(impl KeyProvider + fmt::Debug)) {
        let tenant = TenantId::new("tenant-a").expect("tenant");
        let dek = Dek::generate();
        let wrapped = provider
            .wrap(&tenant, KeyPurpose::Store, &dek)
            .expect("wrap");
        let grant = UnwrapGrant {
            tenant_id: tenant.clone(),
            purpose: KeyPurpose::Store,
            expires_unix_secs: 10_000,
        };
        let recovered = provider
            .unwrap(&wrapped, &grant, "test-engine", 1)
            .expect("unwrap");
        assert_eq!(recovered.dek.as_bytes(), dek.as_bytes());
        let audit = format!("{:?}", recovered.audit);
        assert!(!audit.contains(&hex_hint(dek.as_bytes())));
        assert_eq!(recovered.audit.engine, "test-engine");

        let rotated_id = provider.rotate_kek().expect("rotate");
        assert_ne!(rotated_id, wrapped.kek_id);
        let after_rotate = provider
            .unwrap(&wrapped, &grant, "test-engine", 1)
            .expect("unwrap after rotate");
        assert_eq!(after_rotate.dek.as_bytes(), dek.as_bytes());

        provider.revoke_kek().expect("revoke");
        assert_eq!(
            provider
                .unwrap(&wrapped, &grant, "test-engine", 1)
                .map(|_| ())
                .unwrap_err(),
            KeyError::Revoked
        );
        let rendered = format!("{provider:?}");
        assert!(rendered.contains("redacted") || !rendered.contains(&hex_hint(dek.as_bytes())));
    }

    fn hex_hint(bytes: &[u8; 32]) -> String {
        bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId::new("tenant-a").expect("tenant")
    }

    fn grant() -> UnwrapGrant {
        UnwrapGrant {
            tenant_id: tenant(),
            purpose: KeyPurpose::Store,
            expires_unix_secs: 10_000,
        }
    }

    fn unique_kek_path() -> PathBuf {
        let mut nonce = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut nonce);
        std::env::temp_dir().join(format!(
            "sekai-keys-{}-{}.kek",
            std::process::id(),
            u32::from_le_bytes(nonce)
        ))
    }

    fn remove_kek_files(path: &Path) {
        let _ = fs::remove_file(path);
        if let Ok(lock_path) = lock_path_for(path) {
            let _ = fs::remove_file(lock_path);
        }
    }

    #[test]
    fn memory_provider_passes_conformance() {
        let provider = MemoryKeyProvider::new(RuntimeProfile::Development).expect("provider");
        conformance::assert_provider_contract(&provider);
    }

    #[test]
    fn production_refuses_memory_and_file_providers() {
        assert_eq!(
            MemoryKeyProvider::new(RuntimeProfile::Production).map(|_| ()),
            Err(KeyError::ProductionProviderRefused)
        );
        let path = unique_kek_path();
        assert_eq!(
            FileKeyProvider::open(&path, RuntimeProfile::Production).map(|_| ()),
            Err(KeyError::ProductionProviderRefused)
        );
        assert!(!path.exists());
    }

    #[test]
    fn unwrap_refuses_wrong_tenant_purpose_and_expired_grant() {
        let provider = MemoryKeyProvider::new(RuntimeProfile::Development).expect("provider");
        let dek = Dek::generate();
        let wrapped = provider
            .wrap(&tenant(), KeyPurpose::Store, &dek)
            .expect("wrap");
        let other_tenant = TenantId::new("tenant-b").expect("tenant");
        assert_eq!(
            provider
                .unwrap(
                    &wrapped,
                    &UnwrapGrant {
                        tenant_id: other_tenant,
                        purpose: KeyPurpose::Store,
                        expires_unix_secs: 10_000,
                    },
                    "engine",
                    1,
                )
                .map(|_| ()),
            Err(KeyError::WrongTenant)
        );
        assert_eq!(
            provider
                .unwrap(
                    &wrapped,
                    &UnwrapGrant {
                        tenant_id: tenant(),
                        purpose: KeyPurpose::Spill,
                        expires_unix_secs: 10_000,
                    },
                    "engine",
                    1,
                )
                .map(|_| ()),
            Err(KeyError::WrongPurpose)
        );
        assert_eq!(
            provider
                .unwrap(&wrapped, &grant(), "engine", 10_000)
                .map(|_| ()),
            Err(KeyError::GrantDenied)
        );
    }

    #[test]
    fn revoked_dek_cannot_be_unwrapped() {
        let provider = MemoryKeyProvider::new(RuntimeProfile::Development).expect("provider");
        let dek = Dek::generate();
        let wrapped = provider
            .wrap(&tenant(), KeyPurpose::Store, &dek)
            .expect("wrap");
        provider.revoke_dek(&wrapped.dek_id).expect("revoke dek");
        assert_eq!(
            provider.unwrap(&wrapped, &grant(), "engine", 1).map(|_| ()),
            Err(KeyError::Revoked)
        );
    }

    #[test]
    fn debug_redacts_dek_and_kek() {
        let dek = Dek::from_bytes([9u8; 32]);
        let rendered = format!("{dek:?}");
        assert_eq!(rendered, "Dek(<redacted>)");
        assert!(!rendered.contains("09"));
        let provider = MemoryKeyProvider::new(RuntimeProfile::Development).expect("provider");
        let state = format!("{provider:?}");
        assert!(state.contains("<redacted>"));
        assert!(!state.contains("SigningKey"));
    }

    #[test]
    fn file_provider_reopens_envelopes_and_uses_owner_mode() {
        let path = unique_kek_path();
        let dek = Dek::generate();
        let wrapped = {
            let provider = FileKeyProvider::open(&path, RuntimeProfile::Development).expect("open");
            #[cfg(unix)]
            {
                let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
            let wrapped = provider
                .wrap(&tenant(), KeyPurpose::Store, &dek)
                .expect("wrap");
            let recovered = provider
                .unwrap(&wrapped, &grant(), "engine", 1)
                .expect("unwrap");
            assert_eq!(recovered.dek.as_bytes(), dek.as_bytes());
            provider.rotate_kek().expect("rotate");
            wrapped
        };
        let provider = FileKeyProvider::open(&path, RuntimeProfile::Development).expect("reopen");
        let recovered = provider
            .unwrap(&wrapped, &grant(), "engine", 1)
            .expect("unwrap after reopen");
        assert_eq!(recovered.dek.as_bytes(), dek.as_bytes());
        drop(provider);
        remove_kek_files(&path);
    }

    #[test]
    fn foreign_envelope_cannot_be_unwrapped() {
        let first = MemoryKeyProvider::new(RuntimeProfile::Development).expect("first");
        let second = MemoryKeyProvider::new(RuntimeProfile::Development).expect("second");
        let dek = Dek::generate();
        let wrapped = first
            .wrap(&tenant(), KeyPurpose::Store, &dek)
            .expect("wrap");
        assert_eq!(
            second.unwrap(&wrapped, &grant(), "engine", 1).map(|_| ()),
            Err(KeyError::UnknownKey)
        );
    }

    #[test]
    fn empty_tenant_id_rejects_deserialize() {
        let err = serde_json::from_str::<TenantId>("\" \"").expect_err("blank tenant");
        assert!(err.to_string().contains("tenant_id"));
        let err = serde_json::from_str::<KeyId>("\"\"").expect_err("empty key");
        assert!(err.to_string().contains("key_id"));
        assert_eq!(
            TenantId::new("a\0b"),
            Err(KeyError::InvalidField("tenant_id"))
        );
        assert_eq!(
            KeyId::new("x".repeat(MAX_ID_BYTES + 1)),
            Err(KeyError::InvalidField("key_id"))
        );
        let err = serde_json::from_str::<TenantId>("\"a\\u0000b\"").expect_err("nul tenant");
        assert!(err.to_string().contains("tenant_id"));
    }

    #[test]
    fn second_kek_rotation_fails_while_overlap_active() {
        let provider = MemoryKeyProvider::new(RuntimeProfile::Development).expect("provider");
        provider.rotate_kek().expect("first rotate");
        assert_eq!(provider.rotate_kek(), Err(KeyError::RotationOverlapActive));
    }

    #[test]
    fn file_provider_refuses_second_open_of_same_path() {
        let path = unique_kek_path();
        let first = FileKeyProvider::open(&path, RuntimeProfile::Development).expect("open");
        assert_eq!(
            FileKeyProvider::open(&path, RuntimeProfile::Development).map(|_| ()),
            Err(KeyError::WrapFailed)
        );
        drop(first);
        let _second = FileKeyProvider::open(&path, RuntimeProfile::Development).expect("reopen");
        drop(_second);
        remove_kek_files(&path);
    }

    #[cfg(unix)]
    #[test]
    fn file_provider_lock_uses_canonical_path() {
        let path = unique_kek_path();
        let provider = FileKeyProvider::open(&path, RuntimeProfile::Development).expect("open");
        let link = path.with_extension("link");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert_eq!(
            FileKeyProvider::open(&link, RuntimeProfile::Development).map(|_| ()),
            Err(KeyError::WrapFailed)
        );
        drop(provider);
        let via_link =
            FileKeyProvider::open(&link, RuntimeProfile::Development).expect("open via link");
        drop(via_link);
        remove_kek_files(&path);
        let _ = fs::remove_file(&link);
    }

    #[test]
    fn complete_kek_rotation_allows_another_rotate() {
        let provider = MemoryKeyProvider::new(RuntimeProfile::Development).expect("provider");
        let dek = Dek::generate();
        let wrapped = provider
            .wrap(&tenant(), KeyPurpose::Store, &dek)
            .expect("wrap");
        provider.rotate_kek().expect("first rotate");
        provider
            .unwrap(&wrapped, &grant(), "engine", 1)
            .expect("unwrap during overlap");
        provider.complete_kek_rotation().expect("complete rotation");
        assert_eq!(
            provider.unwrap(&wrapped, &grant(), "engine", 1).map(|_| ()),
            Err(KeyError::UnknownKey)
        );
        provider.rotate_kek().expect("second rotate");
    }

    #[test]
    fn rewrap_keeps_dek_id_so_revocation_still_applies() {
        let provider = MemoryKeyProvider::new(RuntimeProfile::Development).expect("provider");
        let dek = Dek::generate();
        let wrapped = provider
            .wrap(&tenant(), KeyPurpose::Store, &dek)
            .expect("wrap");
        provider.rotate_kek().expect("rotate");
        let rewrapped = provider.rewrap(&wrapped, &dek).expect("rewrap");
        assert_eq!(rewrapped.dek_id, wrapped.dek_id);
        assert_ne!(rewrapped.kek_id, wrapped.kek_id);
        let recovered = provider
            .unwrap(&rewrapped, &grant(), "engine", 1)
            .expect("unwrap rewrap");
        assert_eq!(recovered.dek.as_bytes(), dek.as_bytes());
        let other = Dek::generate();
        assert_eq!(
            provider.rewrap(&wrapped, &other).map(|_| ()),
            Err(KeyError::WrapFailed)
        );
        provider.revoke_dek(&wrapped.dek_id).expect("revoke");
        assert_eq!(
            provider
                .unwrap(&rewrapped, &grant(), "engine", 1)
                .map(|_| ()),
            Err(KeyError::Revoked)
        );
    }

    #[test]
    fn revoke_dek_stops_at_persisted_limit() {
        let provider = MemoryKeyProvider::new(RuntimeProfile::Development).expect("provider");
        for index in 0..MAX_REVOKED_DEKS {
            provider
                .revoke_dek(&KeyId::new(format!("dek-{index}")).expect("id"))
                .expect("revoke");
        }
        assert_eq!(
            provider.revoke_dek(&KeyId::new("dek-overflow").expect("id")),
            Err(KeyError::WrapFailed)
        );
    }
}
