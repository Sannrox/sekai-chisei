//! Bounded child processes the runtime starts beside itself: the object
//! parser worker and the change-capture child (ADR 0170).
//!
//! The runtime bounds every child from outside: an empty environment, its
//! own process group, a wall-time limit after which the child and every
//! process it started are killed, and a cap on the bytes it may write. Its
//! input is written once to stdin, which is then closed; stderr is
//! discarded.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// The outer bounds of one child run.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bounds {
    pub(crate) timeout: Duration,
    pub(crate) max_output: u64,
}

/// A child that ran to its own exit within its bounds.
#[derive(Debug)]
pub(crate) struct Finished {
    pub(crate) status: ExitStatus,
    pub(crate) output: Vec<u8>,
}

/// Why a child produced no [`Finished`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildError {
    /// The executable could not be started.
    Spawn,
    /// The child overran its time or output bound and was killed.
    Overran,
}

/// The executable `name` installed beside this runtime's, if there is one.
pub(crate) fn beside_runtime(name: &str) -> Option<PathBuf> {
    let path = std::env::current_exe()
        .ok()?
        .with_file_name(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    path.is_file().then_some(path)
}

/// Runs `command` once with `input` on stdin, under `bounds`. The command's
/// environment is cleared and its stdio replaced here.
pub(crate) fn run_bounded(
    mut command: Command,
    input: &[u8],
    bounds: Bounds,
) -> Result<Finished, ChildError> {
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Its own process group, so a deadline kill reaches anything it
    // started too; one left holding stdout would stall the read below.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn().map_err(|_| ChildError::Spawn)?;
    let mut stdin = child.stdin.take().ok_or(ChildError::Spawn)?;
    let mut stdout = child.stdout.take().ok_or(ChildError::Spawn)?;
    // Feed and drain on their own threads so neither pipe can stall the
    // other. A child that stops reading early just closes its stdin.
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let _ = stdin.write_all(input);
        });
        // Reading stops one byte past the cap and closes the pipe, so an
        // oversize child cannot block on a full pipe.
        let output = scope.spawn(move || {
            let mut output = Vec::new();
            (&mut stdout)
                .take(bounds.max_output + 1)
                .read_to_end(&mut output)
                .map(|_| output)
        });
        let deadline = Instant::now() + bounds.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    kill_group(&mut child);
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let output = output.join().ok().and_then(Result::ok);
        match (status, output) {
            (Some(status), Some(output)) if output.len() as u64 <= bounds.max_output => {
                Ok(Finished { status, output })
            }
            _ => Err(ChildError::Overran),
        }
    })
}

/// Lets the child inherit `fd` under its own number: the runtime's
/// descriptors are close-on-exec, so this clears the flag on `fd` alone,
/// in the child between fork and exec. The caller keeps `fd` open until
/// the child has started.
#[cfg(unix)]
pub(crate) fn inherit_fd(command: &mut Command, fd: std::os::fd::RawFd) {
    // SAFETY: the hook only calls fcntl, which is async-signal-safe, and
    // touches no memory of the parent.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(command, move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

/// Kills the child's process group, or the child alone where there are
/// no groups.
fn kill_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(group) = libc::pid_t::try_from(child.id()) {
        // SAFETY: kill only sends a signal; the group is the one the child
        // was started in, which nothing else joins.
        unsafe { libc::kill(-group, libc::SIGKILL) };
        return;
    }
    let _ = child.kill();
}
