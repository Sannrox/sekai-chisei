#[cfg(not(test))]
use std::process::Command;

/// `git describe` arguments for local identity. `--dirty` is omitted so
/// index-only rewrites cannot change the stamped version or force a rebuild.
pub const GIT_DESCRIBE_ARGS: &[&str] = &["describe", "--tags", "--always"];

#[cfg(not(test))]
pub fn emit() {
    println!("cargo:rerun-if-env-changed=SEKAI_GIT_VERSION");
    println!("cargo:rerun-if-env-changed=SEKAI_GIT_COMMIT");
    if let Some(git_dir) = git(&["rev-parse", "--git-dir"]) {
        let common_dir = git(&["rev-parse", "--git-common-dir"]).unwrap_or_else(|| git_dir.clone());
        let head = std::fs::read_to_string(format!("{git_dir}/HEAD")).ok();
        for line in git_rerun_if_changed_lines(&git_dir, &common_dir, head.as_deref()) {
            println!("{line}");
        }
    }
    let pkg = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let identity = resolve_git_identity(
        env_nonempty("SEKAI_GIT_VERSION"),
        env_nonempty("SEKAI_GIT_COMMIT"),
        git(GIT_DESCRIBE_ARGS),
        git(&["rev-parse", "HEAD"]),
        pkg,
    );
    println!("cargo:rustc-env=SEKAI_GIT_VERSION={}", identity.version);
    println!("cargo:rustc-env=SEKAI_GIT_COMMIT={}", identity.commit);
}

pub struct GitIdentity {
    pub version: String,
    pub commit: String,
}

/// Stamp identity: explicit release env wins, then git, then the crate version.
pub fn resolve_git_identity(
    env_version: Option<String>,
    env_commit: Option<String>,
    git_describe: Option<String>,
    git_head: Option<String>,
    pkg: String,
) -> GitIdentity {
    GitIdentity {
        version: first_nonempty(&[env_version, git_describe]).unwrap_or(pkg),
        commit: first_nonempty(&[env_commit, git_head]).unwrap_or_else(|| "unknown".to_string()),
    }
}

/// Cargo rebuild inputs for git identity. Watches HEAD and refs, never the index.
pub fn git_rerun_if_changed_lines(
    git_dir: &str,
    common_dir: &str,
    head_contents: Option<&str>,
) -> Vec<String> {
    let mut lines = vec![
        format!("cargo:rerun-if-changed={git_dir}/HEAD"),
        format!("cargo:rerun-if-changed={common_dir}/packed-refs"),
        format!("cargo:rerun-if-changed={common_dir}/refs/tags"),
    ];
    if let Some(head) = head_contents
        && let Some(rel) = head.trim().strip_prefix("ref: ")
    {
        let rel = rel.trim();
        if !rel.is_empty() && is_safe_git_ref(rel) {
            lines.push(format!("cargo:rerun-if-changed={common_dir}/{rel}"));
        }
    }
    lines
}

/// Reject path traversal and cargo-instruction injection; allow git-legal
/// names such as `refs/heads/feature+counters`.
fn is_safe_git_ref(rel: &str) -> bool {
    if !rel.starts_with("refs/") || rel.as_bytes().contains(&0) {
        return false;
    }
    if rel.bytes().any(|b| b < 0x20 || b == b'\\' || b == 0x7f) {
        return false;
    }
    std::path::Path::new(rel)
        .components()
        .all(|component| matches!(component, std::path::Component::Normal(_)))
}

#[cfg(not(test))]
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(not(test))]
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn first_nonempty(candidates: &[Option<String>]) -> Option<String> {
    candidates.iter().cloned().find_map(|value| value)
}
