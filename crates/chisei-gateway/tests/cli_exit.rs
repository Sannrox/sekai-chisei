//! Early-exit commands return without serving. Telemetry flush is the `run`
//! wrapper in `main`; these cases prove the printed outcome is unchanged.

use std::process::{Command, Output};

fn gateway(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chisei-gateway"))
        .args(args)
        .env_clear()
        .output()
        .expect("spawn chisei-gateway")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn early_exit_paths_keep_their_codes_and_messages() {
    let report = gateway(&["report", "--help"]);
    assert!(report.status.success(), "{report:?}");
    assert!(
        stdout(&report).contains("Usage: chisei-gateway report"),
        "{}",
        stdout(&report)
    );

    let refresh = gateway(&["refresh", "--help"]);
    assert!(refresh.status.success(), "{refresh:?}");
    assert!(
        stdout(&refresh).contains("Usage: chisei-gateway refresh"),
        "{}",
        stdout(&refresh)
    );

    let unknown = gateway(&["not-a-command"]);
    assert!(!unknown.status.success(), "{unknown:?}");
    assert!(
        stderr(&unknown).contains("unknown chisei-gateway command"),
        "{}",
        stderr(&unknown)
    );

    let config = gateway(&[]);
    assert!(!config.status.success(), "{config:?}");
    assert!(
        stderr(&config).contains("a configured provider API key is required"),
        "{}",
        stderr(&config)
    );
}
