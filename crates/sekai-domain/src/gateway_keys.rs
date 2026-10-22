use sha2::{Digest, Sha256};

/// Hex SHA-256 of a gateway or credential secret, as stored for lookup.
pub fn hash_gateway_key(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_key_hash_is_stable() {
        assert_eq!(
            hash_gateway_key("sk-chisei-codex-app"),
            hash_gateway_key("sk-chisei-codex-app")
        );
        assert_ne!(
            hash_gateway_key("sk-chisei-codex-app"),
            hash_gateway_key("sk-chisei-other")
        );
    }
}
