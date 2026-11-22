//! Process proof that usage errors print `Display` text, not the `Debug`
//! `Custom { kind: Other, ... }` wrapper from returning `Result` from `main`.

use std::process::{Command, Output};

fn sekaictl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sekaictl"))
        .args(args)
        .env_clear()
        .output()
        .expect("spawn sekaictl")
}

#[test]
fn bad_replay_invocation_prints_plain_usage_and_exits_2() {
    let output = sekaictl(&["admin", "assurance", "replay", "export"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        !stderr.contains("Custom {"),
        "usage must not print Debug: {stderr}"
    );
    assert!(
        stderr.contains("sekaictl admin assurance replay export"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("\\n"),
        "usage newlines must be real lines, not escaped: {stderr}"
    );
}
