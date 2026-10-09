//! Compile-time package and git identity for the control-plane binaries.

pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_VERSION: &str = env!("SEKAI_GIT_VERSION");
pub const GIT_COMMIT: &str = env!("SEKAI_GIT_COMMIT");

#[cfg(test)]
mod tests {
    use super::{GIT_COMMIT, GIT_VERSION, PKG_VERSION};

    #[test]
    fn build_identity_is_populated() {
        assert!(!PKG_VERSION.is_empty());
        assert!(!GIT_VERSION.is_empty());
        assert!(!GIT_COMMIT.is_empty());
    }
}
