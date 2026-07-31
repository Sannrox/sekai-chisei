use std::path::PathBuf;
use std::process::Command;

fn repository_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn offline_validation_json_matches_the_v1_golden_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_sekaictl"))
        .args([
            "admin",
            "evaluation",
            "plan",
            "validate",
            repository_file("tests/fixtures/evaluation/plan-v1.json")
                .to_str()
                .unwrap(),
            "--offline",
            "--json",
        ])
        .output()
        .expect("sekaictl should run");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        include_str!("golden/evaluation-plan-validate-v1.json")
    );
}

#[test]
fn execution_requires_explicit_confirmation_before_any_connection() {
    let output = Command::new(env!("CARGO_BIN_EXE_sekaictl"))
        .args([
            "admin",
            "evaluation",
            "plan",
            "execute",
            "acme",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .output()
        .expect("sekaictl should run");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "execute requires --yes; resolve is the non-executing dry-run boundary\n"
    );
}
