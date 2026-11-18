//! The server and MCP binaries refuse arguments they do not understand instead
//! of starting anyway.

use std::process::Command;

#[test]
fn unknown_arguments_exit_with_usage_and_start_nothing() {
    for (binary, args) in [
        (env!("CARGO_BIN_EXE_sekai-chisei"), &["bogus"][..]),
        (env!("CARGO_BIN_EXE_sekai-mcp"), &["bogus"][..]),
        (env!("CARGO_BIN_EXE_sekai-mcp"), &["--help", "bogus"][..]),
    ] {
        let output = Command::new(binary)
            .args(args)
            .env_remove("SEKAI_MCP_PRINCIPAL")
            .output()
            .expect("binary should run");
        assert_eq!(output.status.code(), Some(2), "{binary} {args:?}");
        assert!(output.stdout.is_empty(), "{binary} {args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("usage")
                || String::from_utf8_lossy(&output.stderr).contains("Environment:"),
            "{binary} {args:?}"
        );
    }
}

#[test]
fn server_help_prints_usage_and_exits_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"))
        .arg("--help")
        .output()
        .expect("sekai-chisei should run");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("gateway-report"));
}
