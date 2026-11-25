//! The change-capture child (ADR 0170). The connector runtime starts one
//! per capture Source, beside its own executable, as
//! `sekai-change-capture <mode> --socket-fd <fd>`:
//!
//! - fd `<fd>` is a TCP socket the runtime already connected to the
//!   Source's egress-allowlisted database; the child opens no other
//!   connection;
//! - stdin carries one [`Start`] message, at most [`MAX_START_BYTES`], then
//!   closes: the Source's credential, once, and the files the child may
//!   read;
//! - the environment is empty, and the runtime bounds the child's time and
//!   output from outside.
//!
//! Before it reads any data the child closes every other inherited
//! descriptor and applies its [`sandbox`]. A host that cannot apply it
//! fails closed: the child exits [`EXIT_UNAVAILABLE`] with a named reason
//! and never runs unsandboxed.
//!
//! Modes: `self-test` applies the sandbox and proves it holds, writing a
//! [`self_test`] report. The capture families are later modes.

pub mod sandbox;
pub mod self_test;

use serde::Deserialize;

/// The largest start message the child reads.
pub const MAX_START_BYTES: u64 = 1024 * 1024;

/// Exit status: the sandbox was applied and held.
pub const EXIT_OK: i32 = 0;
/// Exit status: a self-test check found the sandbox not holding.
pub const EXIT_BROKEN: i32 = 1;
/// Exit status: a malformed invocation or start message.
pub const EXIT_USAGE: i32 = 2;
/// Exit status: the host cannot apply the sandbox.
pub const EXIT_UNAVAILABLE: i32 = 3;

/// What the runtime sends on stdin, once.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    /// The value of the one credential slot the Source names.
    pub credential: String,
    /// Paths the child may read after the sandbox applies, such as the
    /// system trust roots. Nothing else is readable, and nothing writable.
    #[serde(default)]
    pub read_paths: Vec<String>,
}

impl Start {
    /// Parses a start message; `None` when it is malformed or oversize.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() as u64 > MAX_START_BYTES {
            return None;
        }
        serde_json::from_slice(bytes).ok()
    }
}

/// Parses `<mode> --socket-fd <fd>`.
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Option<(String, i32)> {
    let mut args = args.into_iter();
    let mode = args.next()?;
    if args.next()? != "--socket-fd" {
        return None;
    }
    let fd = args.next()?.parse::<i32>().ok().filter(|fd| *fd > 2)?;
    args.next().is_none().then_some((mode, fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_message_carries_the_credential_and_nothing_unknown() {
        let start = Start::parse(br#"{"credential":"c","read_paths":["/x"]}"#).unwrap();
        assert_eq!(start.credential, "c");
        assert_eq!(start.read_paths, ["/x"]);
        assert!(Start::parse(br#"{"credential":"c","other":1}"#).is_none());
        assert!(Start::parse(br#"{"read_paths":[]}"#).is_none());
        let oversize = vec![b' '; MAX_START_BYTES as usize + 1];
        assert!(Start::parse(&oversize).is_none());
    }

    #[test]
    fn the_socket_must_be_a_descriptor_above_stdio() {
        let args = |list: &[&str]| parse_args(list.iter().map(|arg| arg.to_string()));
        assert_eq!(
            args(&["self-test", "--socket-fd", "7"]),
            Some(("self-test".into(), 7))
        );
        assert_eq!(args(&["self-test", "--socket-fd", "2"]), None);
        assert_eq!(args(&["self-test", "--socket-fd", "x"]), None);
        assert_eq!(args(&["self-test", "--socket-fd", "7", "more"]), None);
        assert_eq!(args(&["self-test"]), None);
    }
}
