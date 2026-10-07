#[path = "../build/emit_git_version.rs"]
mod emit_git_version;

use emit_git_version::{GIT_DESCRIBE_ARGS, git_rerun_if_changed_lines, resolve_git_identity};

#[test]
fn describe_omits_dirty_so_index_stat_noise_cannot_change_identity() {
    assert!(
        !GIT_DESCRIBE_ARGS.contains(&"--dirty"),
        "local describe must not depend on worktree dirty state"
    );
    assert_eq!(GIT_DESCRIBE_ARGS, ["describe", "--tags", "--always"]);
}

#[test]
fn rerun_watches_head_and_refs_not_the_index() {
    let lines =
        git_rerun_if_changed_lines("/repo/.git", "/repo/.git", Some("ref: refs/heads/main\n"));
    assert!(
        lines.iter().all(|line| !line.contains("/index")),
        "index rewrite must not rebuild: {lines:?}"
    );
    assert!(lines.contains(&"cargo:rerun-if-changed=/repo/.git/HEAD".into()));
    assert!(lines.contains(&"cargo:rerun-if-changed=/repo/.git/packed-refs".into()));
    assert!(lines.contains(&"cargo:rerun-if-changed=/repo/.git/refs/tags".into()));
    assert!(lines.contains(&"cargo:rerun-if-changed=/repo/.git/refs/heads/main".into()));
}

#[test]
fn rerun_watches_git_legal_ref_names_outside_ascii_alnum() {
    let lines = git_rerun_if_changed_lines(
        "/repo/.git",
        "/repo/.git",
        Some("ref: refs/heads/feature+counters\n"),
    );
    assert!(
        lines.contains(&"cargo:rerun-if-changed=/repo/.git/refs/heads/feature+counters".into()),
        "git-legal + in a branch name must still be watched: {lines:?}"
    );
}

#[test]
fn rerun_rejects_ref_path_traversal() {
    let lines = git_rerun_if_changed_lines(
        "/repo/.git",
        "/repo/.git",
        Some("ref: refs/heads/../../etc/passwd\n"),
    );
    assert!(
        lines
            .iter()
            .all(|line| !line.contains("etc/passwd") && !line.contains("..")),
        "unsafe HEAD ref must not become a cargo watch: {lines:?}"
    );
}

#[test]
fn detached_head_does_not_invent_a_ref_watch() {
    let lines = git_rerun_if_changed_lines(
        "/wt/.git",
        "/repo/.git",
        Some("a91c90a4d8dc08c2668db843f6d0d97f04d04481\n"),
    );
    assert!(
        lines
            .iter()
            .all(|line| !line.contains("refs/heads") && !line.contains("/index"))
    );
    assert!(lines.contains(&"cargo:rerun-if-changed=/wt/.git/HEAD".into()));
}

#[test]
fn release_env_overrides_git_describe() {
    let identity = resolve_git_identity(
        Some("1.1.0".into()),
        Some("abc123".into()),
        Some("1.1.0-dirty".into()),
        Some("deadbeef".into()),
        "0.0.0".into(),
    );
    assert_eq!(identity.version, "1.1.0");
    assert_eq!(identity.commit, "abc123");
}

#[test]
fn local_identity_uses_describe_without_requiring_env() {
    let identity = resolve_git_identity(
        None,
        None,
        Some("1.1.0-3-ga91c90a".into()),
        Some("a91c90a4d8dc08c2668db843f6d0d97f04d04481".into()),
        "1.1.0".into(),
    );
    assert_eq!(identity.version, "1.1.0-3-ga91c90a");
    assert_eq!(identity.commit, "a91c90a4d8dc08c2668db843f6d0d97f04d04481");
}
