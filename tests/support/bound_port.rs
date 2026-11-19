//! Learn the port a child server bound when it was started with `GRPC_PORT=0`
//! or `OPS_PORT=0`.
//!
//! Picking a free port in the test and passing it to the child races with every
//! other process on the machine. The server binds first and logs the bound
//! address, so tests read the port from there. The child's `RUST_LOG` must let
//! the listener's info line through.

use std::path::Path;
use std::process::Child;
use std::time::{Duration, Instant};

/// Logged by `sekai_chisei::grpc` once the TCP gRPC listener is bound.
pub const GRPC_LISTENING: &str = "gRPC server listening addr=";
/// Logged by `sekai_chisei::obs::ops` once the ops listener is bound.
pub const OPS_LISTENING: &str =
    "ops listener serving health, metrics, and authenticated console addr=";

/// Waits for the `marker` line in `log_path` and returns the bound port.
/// Panics with the log when the child exits first (a bind failure shows its
/// own error, not a timeout) or `budget` passes.
pub fn wait_for_logged_port(
    child: &mut Child,
    log_path: &Path,
    marker: &str,
    budget: Duration,
) -> u16 {
    let deadline = Instant::now() + budget;
    loop {
        let log = read_log(log_path);
        if let Some(port) = logged_port(&log, marker) {
            return port;
        }
        if let Some(status) = child.try_wait().expect("poll child") {
            panic!("server exited with {status} before listening:\n{log}");
        }
        if Instant::now() >= deadline {
            panic!("server did not log {marker:?} within {budget:?}:\n{log}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The log with ANSI color sequences removed.
pub fn read_log(log_path: &Path) -> String {
    let raw = std::fs::read_to_string(log_path).unwrap_or_default();
    let mut plain = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI sequence: ESC [ parameters final-byte.
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
}

/// The port on the first `marker` line, if the log has one.
pub fn logged_port(log: &str, marker: &str) -> Option<u16> {
    log.lines()
        .find_map(|line| line.split_once(marker))
        .and_then(|(_, addr)| {
            addr.split_whitespace()
                .next()?
                .rsplit(':')
                .next()?
                .parse()
                .ok()
        })
}

#[test]
fn reads_the_port_from_a_colored_listening_line() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("server.log");
    std::fs::write(
        &log,
        "\u{1b}[32m INFO\u{1b}[0m \u{1b}[2msekai_chisei::grpc\u{1b}[0m\u{1b}[2m:\u{1b}[0m \
         gRPC server listening \u{1b}[3maddr\u{1b}[0m\u{1b}[2m=\u{1b}[0m127.0.0.1:60792\n\
         gRPC server listening on UDS (mode 0600)\n",
    )
    .unwrap();
    assert_eq!(logged_port(&read_log(&log), GRPC_LISTENING), Some(60792));
    assert_eq!(
        logged_port("gRPC server listening on UDS", GRPC_LISTENING),
        None
    );
}
