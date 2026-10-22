#[path = "../build/emit_git_version.rs"]
mod emit_git_version;

use emit_git_version::{cargo_instructions, resolve_git_identity};

#[test]
fn build_script_never_watches_git_paths() {
    for (version, commit) in [(None, None), (Some("1.1.0".into()), Some("abc123".into()))] {
        let lines = cargo_instructions(version, commit, "1.1.0");
        assert!(
            lines
                .iter()
                .all(|line| !line.starts_with("cargo:rerun-if-changed=")),
            "a commit or branch switch must not rebuild dependents: {lines:?}"
        );
        assert!(lines.contains(&"cargo:rerun-if-env-changed=SEKAI_GIT_VERSION".into()));
        assert!(lines.contains(&"cargo:rerun-if-env-changed=SEKAI_GIT_COMMIT".into()));
    }
}

#[test]
fn release_env_is_stamped() {
    let lines = cargo_instructions(Some("1.1.0".into()), Some("abc123".into()), "0.0.0");
    assert!(lines.contains(&"cargo:rustc-env=SEKAI_GIT_VERSION=1.1.0".into()));
    assert!(lines.contains(&"cargo:rustc-env=SEKAI_GIT_COMMIT=abc123".into()));
}

#[test]
fn local_build_reports_dev_identity_without_git() {
    let identity = resolve_git_identity(None, None, "1.1.0");
    assert_eq!(identity.version, "1.1.0-dev");
    assert_eq!(identity.commit, "unknown");
}
