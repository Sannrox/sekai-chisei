use std::process::Command;

#[test]
fn removed_top_level_aliases_fail_with_their_canonical_replacement() {
    for (alias, canonical) in [
        ("credential", "admin access credential"),
        ("team", "admin access team"),
        ("gateway", "admin gateway"),
        ("action", "admin governance action"),
        ("memory", "admin governance memory"),
        ("gunshi", "admin governance gunshi"),
        ("governed-subject", "admin governance subject"),
        ("attest", "admin assurance attest"),
        ("compliance", "admin assurance compliance"),
        ("provenance", "admin assurance provenance"),
        ("replay", "admin assurance replay"),
        ("federation", "admin federation"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_sekaictl"))
            .args([alias, "--help"])
            .output()
            .expect("sekaictl should run");

        assert_eq!(output.status.code(), Some(2), "{alias}");
        assert!(output.stdout.is_empty(), "{alias}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("`sekaictl {alias}` was removed in 0.2.0; use `sekaictl {canonical}`\n"),
            "{alias}"
        );
    }
}

#[test]
fn canonical_admin_paths_still_render_command_specific_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_sekaictl"))
        .args(["admin", "access", "credential", "--help"])
        .output()
        .expect("sekaictl should run");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("sekaictl admin access credential")
    );
}
