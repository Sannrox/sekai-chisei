//! The real child applies its sandbox on this Linux host and proves it
//! holds. Linux only; CI runs it.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

const CHILD: &str = env!("CARGO_BIN_EXE_sekai-change-capture");

/// Runs the child in self-test mode over a loopback socket and returns
/// its exit code and report.
fn self_test(start: &[u8]) -> (Option<i32>, serde_json::Value, String) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let _peer = listener.accept().unwrap();
    let fd = socket.as_raw_fd();
    let mut command = Command::new(CHILD);
    command
        .args(["self-test", "--socket-fd", &fd.to_string()])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    // SAFETY: fcntl is async-signal-safe and touches no parent memory.
    unsafe {
        command.pre_exec(move || match libc::fcntl(fd, libc::F_SETFD, 0) {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        });
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(start).unwrap();
    let output = child.wait_with_output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    let report = serde_json::from_str(text.trim()).unwrap_or_default();
    (output.status.code(), report, text)
}

#[test]
fn the_sandbox_holds_and_the_report_never_carries_the_credential() {
    // Built at run time; no credential literal lives in the source.
    let credential = format!(
        "probe-{}-{:?}",
        std::process::id(),
        std::time::Instant::now()
    );
    let start = serde_json::json!({ "credential": credential, "read_paths": [CHILD] });

    let (code, report, text) = self_test(start.to_string().as_bytes());

    assert_eq!(code, Some(0), "report: {text}");
    assert_eq!(report["sandbox"], "held");
    assert_eq!(report["credential_bytes"], credential.len());
    let checks = report["checks"].as_object().unwrap();
    assert!(checks.len() >= 10);
    assert!(checks.values().all(|passed| passed == true), "{text}");
    assert!(!text.contains(&credential));
}

#[test]
fn a_malformed_start_runs_nothing() {
    let (code, _, text) = self_test(br#"{"credential":"x","unknown":1}"#);
    assert_eq!(code, Some(2));
    assert!(text.is_empty());
}
