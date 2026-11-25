//! The runtime side of change capture (ADR 0170): it dials the Source's
//! database after the egress check and starts the sandboxed
//! `sekai-change-capture` child over that connection.
//!
//! The child never chooses a destination. The runtime resolves and checks
//! the endpoint ([`connect_admitted`]), connects, and lets the child
//! inherit the connected socket. The child gets an empty environment, its
//! own process group, the Source's credential once on stdin, and the
//! bounds of [`crate::child`]. It applies its sandbox before it reads any
//! data and exits `unavailable` when the host cannot apply it.
//!
//! [`CaptureChild::self_test`] runs the child's own proof that the sandbox
//! holds on this host; the runtime offers change capture only where it
//! passes, and never off Linux.

use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sekai_source_sdk::{Destination, EgressAllowlist};
use serde::Deserialize;

use crate::child::{self, Bounds, ChildError, Finished};

/// The child executable's name, installed beside the runtime's.
pub const CAPTURE_CHILD_NAME: &str = "sekai-change-capture";

/// The child's exit status when the host cannot apply its sandbox.
const EXIT_UNAVAILABLE: i32 = 3;
/// The most a self-test may write: a short JSON report.
const MAX_SELF_TEST_OUTPUT: u64 = 64 * 1024;
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Why the runtime did not connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectRefused {
    /// The destination has no port or the Source's allowlist refuses it;
    /// nothing was dialed.
    Egress,
    /// No resolved address accepted a connection.
    Unreachable,
}

/// Checks `destination` against `egress`, then connects to it. Nothing is
/// dialed when the check refuses.
pub fn connect_admitted(
    destination: &Destination,
    egress: &EgressAllowlist,
) -> Result<TcpStream, ConnectRefused> {
    let port = destination.port.ok_or(ConnectRefused::Egress)?;
    if !egress.permits(destination) {
        return Err(ConnectRefused::Egress);
    }
    (destination.host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| ConnectRefused::Unreachable)?
        .find_map(|address| TcpStream::connect_timeout(&address, CONNECT_TIMEOUT).ok())
        .ok_or(ConnectRefused::Unreachable)
}

/// Why this host cannot run change capture. The reason names a missing
/// capability or a failed check, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable(pub String);

/// The installed change-capture child.
#[derive(Debug, Clone)]
pub struct CaptureChild {
    path: PathBuf,
}

impl CaptureChild {
    /// The child installed beside this runtime, if there is one.
    pub fn beside_runtime() -> Option<Self> {
        child::beside_runtime(CAPTURE_CHILD_NAME).map(|path| Self { path })
    }

    /// Runs the child's self-test over a loopback connection with a
    /// throwaway credential, and passes only when the child reports its
    /// sandbox held. `read_paths` are the files the capture modes will
    /// read, such as the trust roots; the self-test proves they stay
    /// readable.
    pub fn self_test(&self, read_paths: &[&Path]) -> Result<(), Unavailable> {
        if !cfg!(target_os = "linux") {
            return Err(Unavailable("not linux".into()));
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| loopback())?;
        let socket = TcpStream::connect(listener.local_addr().map_err(|_| loopback())?)
            .map_err(|_| loopback())?;
        // The peer stays open while the child runs, so its end is connected.
        let _peer = listener.accept().map_err(|_| loopback())?;
        let credential = format!("self-test-{:?}", std::time::SystemTime::now());
        let finished = self
            .run(
                "self-test",
                &socket,
                &start(&credential, read_paths),
                SELF_TEST_TIMEOUT,
            )
            .map_err(|error| Unavailable(format!("self-test {error:?}")))?;
        verdict(&finished, credential.len())
    }

    /// Starts the child in `mode` over `socket` with `start` on stdin, and
    /// waits for it within `timeout`.
    fn run(
        &self,
        mode: &str,
        socket: &TcpStream,
        start: &[u8],
        timeout: Duration,
    ) -> Result<Finished, ChildError> {
        let fd = socket.as_raw_fd();
        let mut command = Command::new(&self.path);
        command.args([mode, "--socket-fd", &fd.to_string()]);
        child::inherit_fd(&mut command, fd);
        let bounds = Bounds {
            timeout,
            max_output: MAX_SELF_TEST_OUTPUT,
        };
        child::run_bounded(command, start, bounds)
    }
}

fn loopback() -> Unavailable {
    Unavailable("loopback".into())
}

/// The child's start message: the credential, once, and its read paths.
fn start(credential: &str, read_paths: &[&Path]) -> Vec<u8> {
    serde_json::json!({ "credential": credential, "read_paths": read_paths })
        .to_string()
        .into_bytes()
}

#[derive(Deserialize)]
struct Report {
    sandbox: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    credential_bytes: Option<usize>,
}

/// Passes only a clean exit whose report says the sandbox held and that
/// the whole credential arrived.
fn verdict(finished: &Finished, credential_bytes: usize) -> Result<(), Unavailable> {
    let report: Option<Report> = serde_json::from_slice(&finished.output).ok();
    match (finished.status.code(), report) {
        (Some(0), Some(report))
            if report.sandbox == "held" && report.credential_bytes == Some(credential_bytes) =>
        {
            Ok(())
        }
        (
            Some(EXIT_UNAVAILABLE),
            Some(Report {
                reason: Some(reason),
                ..
            }),
        ) if reason.len() <= 32
            && reason
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ') =>
        {
            Err(Unavailable(reason))
        }
        _ => Err(Unavailable("self-test failed".into())),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use super::*;

    fn finished(code: i32, output: &str) -> Finished {
        Finished {
            status: ExitStatus::from_raw(code << 8),
            output: output.as_bytes().to_vec(),
        }
    }

    #[test]
    fn only_a_held_report_with_the_whole_credential_passes() {
        let held = r#"{"sandbox":"held","credential_bytes":5,"checks":{}}"#;
        assert_eq!(verdict(&finished(0, held), 5), Ok(()));
        assert!(
            verdict(&finished(0, held), 6).is_err(),
            "credential cut short"
        );
        assert!(verdict(&finished(1, held), 5).is_err(), "a check failed");
        let broken = r#"{"sandbox":"broken","credential_bytes":5}"#;
        assert!(verdict(&finished(0, broken), 5).is_err());
        let unavailable = r#"{"sandbox":"unavailable","reason":"landlock"}"#;
        assert_eq!(
            verdict(&finished(EXIT_UNAVAILABLE, unavailable), 5),
            Err(Unavailable("landlock".into()))
        );
        assert_eq!(
            verdict(&finished(0, "not json"), 5),
            Err(Unavailable("self-test failed".into()))
        );
    }

    #[test]
    fn a_refused_destination_is_never_dialed() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let destination = Destination::parse(&format!("127.0.0.1:{port}")).unwrap();
        let other = EgressAllowlist::parse(&["127.0.0.2"]).unwrap();
        assert_eq!(
            connect_admitted(&destination, &other).err(),
            Some(ConnectRefused::Egress)
        );
        assert!(listener.accept().is_err(), "nothing connected");
        let portless = Destination::parse("127.0.0.1").unwrap();
        let any_port = EgressAllowlist::parse(&["127.0.0.1"]).unwrap();
        assert_eq!(
            connect_admitted(&portless, &any_port).err(),
            Some(ConnectRefused::Egress)
        );
        assert!(connect_admitted(&destination, &any_port).is_ok());
    }

    /// A stand-in child: it checks its arguments, then writes its start
    /// message to the inherited socket and its environment to stdout.
    const ECHO_CHILD: &str = r#"#!/bin/bash
[ "$1" = self-test ] && [ "$2" = --socket-fd ] || exit 2
cat >&"$3" || exit 1
env
"#;

    #[test]
    fn the_child_gets_the_socket_and_its_start_once_with_no_environment() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(CAPTURE_CHILD_NAME);
        std::fs::write(&path, ECHO_CHILD).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let credential = format!("value-{}", std::process::id());
        let start = start(&credential, &[]);

        let finished = CaptureChild { path }
            .run("self-test", &socket, &start, SELF_TEST_TIMEOUT)
            .unwrap();
        drop(socket);

        assert!(finished.status.success());
        let mut received = Vec::new();
        peer.read_to_end(&mut received).unwrap();
        assert_eq!(
            received, start,
            "the start message, once, through the socket"
        );
        let environment = String::from_utf8(finished.output).unwrap();
        let inherited: Vec<&str> = environment
            .lines()
            .filter(|line| {
                !["PWD=", "SHLVL=", "_=", "OLDPWD="]
                    .iter()
                    .any(|own| line.starts_with(own))
            })
            .collect();
        assert!(inherited.is_empty(), "inherited environment: {inherited:?}");
    }
}
