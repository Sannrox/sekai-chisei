use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Native `DiscoverCapabilities` contract. Distinct from
/// `chisei.provider-capabilities/v1` (HTTP provider-profile matrix).
pub const CONTRACT_VERSION: &str = "1.0";
pub const DEFAULT_PAGE_SIZE: usize = 50;
pub const MAX_PAGE_SIZE: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogError {
    UnsupportedContractVersion,
    CatalogVersionUnavailable,
    InvalidPageToken,
}

pub fn negotiate_contract_version(requested: &str) -> Result<&'static str, CatalogError> {
    if requested.trim().is_empty() || requested == CONTRACT_VERSION {
        Ok(CONTRACT_VERSION)
    } else {
        Err(CatalogError::UnsupportedContractVersion)
    }
}

pub fn page_size(requested: u32) -> usize {
    if requested == 0 {
        DEFAULT_PAGE_SIZE
    } else {
        (requested as usize).min(MAX_PAGE_SIZE)
    }
}

pub fn snapshot_version(context: &[String], canonical_entries: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CONTRACT_VERSION.as_bytes());
    for value in context {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    for entry in canonical_entries {
        hasher.update((entry.len() as u64).to_be_bytes());
        hasher.update(entry);
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub fn resolve_offset(
    requested_version: &str,
    page_token: &str,
    current_version: &str,
) -> Result<usize, CatalogError> {
    if !requested_version.is_empty() && requested_version != current_version {
        return Err(CatalogError::CatalogVersionUnavailable);
    }
    if page_token.is_empty() {
        return Ok(0);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(page_token)
        .map_err(|_| CatalogError::InvalidPageToken)?;
    let decoded = String::from_utf8(decoded).map_err(|_| CatalogError::InvalidPageToken)?;
    let (version, offset) = decoded
        .rsplit_once('|')
        .ok_or(CatalogError::InvalidPageToken)?;
    if version != current_version {
        return Err(CatalogError::CatalogVersionUnavailable);
    }
    offset
        .parse::<usize>()
        .map_err(|_| CatalogError::InvalidPageToken)
}

pub fn next_page_token(version: &str, next_offset: usize, total: usize) -> String {
    if next_offset >= total {
        String::new()
    } else {
        URL_SAFE_NO_PAD.encode(format!("{version}|{next_offset}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_negotiation_is_exact_and_defaults_to_latest() {
        assert_eq!(negotiate_contract_version("").unwrap(), CONTRACT_VERSION);
        assert_eq!(
            negotiate_contract_version(CONTRACT_VERSION).unwrap(),
            CONTRACT_VERSION
        );
        assert_eq!(
            negotiate_contract_version("2.0"),
            Err(CatalogError::UnsupportedContractVersion)
        );
    }

    #[test]
    fn page_token_is_bound_to_snapshot_version() {
        let token = next_page_token("sha256:one", 10, 20);
        assert_eq!(resolve_offset("", &token, "sha256:one").unwrap(), 10);
        assert_eq!(
            resolve_offset("", &token, "sha256:two"),
            Err(CatalogError::CatalogVersionUnavailable)
        );
    }

    #[test]
    fn snapshot_version_is_deterministic_and_context_bound() {
        let entries = vec![b"a".to_vec(), b"b".to_vec()];
        let first = snapshot_version(&["namespace-a".into(), "alice".into()], &entries);
        let repeat = snapshot_version(&["namespace-a".into(), "alice".into()], &entries);
        let other = snapshot_version(&["namespace-a".into(), "bob".into()], &entries);
        assert_eq!(first, repeat);
        assert_ne!(first, other);
    }
}
