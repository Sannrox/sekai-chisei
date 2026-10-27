/// Release builds pass these; `build/release-images.sh` sets both.
pub const VERSION_ENV: &str = "SEKAI_GIT_VERSION";
pub const COMMIT_ENV: &str = "SEKAI_GIT_COMMIT";

#[cfg(not(test))]
pub fn emit() {
    let pkg = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let lines = cargo_instructions(env_nonempty(VERSION_ENV), env_nonempty(COMMIT_ENV), &pkg);
    for line in lines {
        println!("{line}");
    }
}

pub struct GitIdentity {
    pub version: String,
    pub commit: String,
}

/// Stamp identity: release env wins, otherwise `<pkg>-dev` and `unknown`.
/// Git is never read, so commits and branch switches do not rebuild dependents.
pub fn resolve_git_identity(
    env_version: Option<String>,
    env_commit: Option<String>,
    pkg: &str,
) -> GitIdentity {
    GitIdentity {
        version: env_version.unwrap_or_else(|| format!("{pkg}-dev")),
        commit: env_commit.unwrap_or_else(|| "unknown".to_string()),
    }
}

/// Every line the build script prints. Rebuild inputs are the two env vars only.
pub fn cargo_instructions(
    env_version: Option<String>,
    env_commit: Option<String>,
    pkg: &str,
) -> Vec<String> {
    let identity = resolve_git_identity(env_version, env_commit, pkg);
    vec![
        format!("cargo:rerun-if-env-changed={VERSION_ENV}"),
        format!("cargo:rerun-if-env-changed={COMMIT_ENV}"),
        format!("cargo:rustc-env={VERSION_ENV}={}", identity.version),
        format!("cargo:rustc-env={COMMIT_ENV}={}", identity.commit),
    ]
}

#[cfg(not(test))]
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
