//! `self-test`: proves from inside the applied sandbox that it holds. The
//! runtime runs it to decide whether this host can offer change capture.
//!
//! The report is one JSON object on stdout:
//! `{"sandbox":"held"|"broken","credential_bytes":n,"checks":{name:bool}}`.
//! It names checks and counts bytes; it never carries the credential.

use serde_json::{Map, Value, json};

/// Runs every check after [`crate::sandbox::enter`] succeeded, and returns
/// the report with whether all checks held.
pub fn run(socket_fd: i32, credential: &str, read_paths: &[String]) -> (Value, bool) {
    let checks = imp::checks(socket_fd, read_paths);
    let held = checks.iter().all(|(_, passed)| *passed);
    let checks: Map<String, Value> = checks
        .into_iter()
        .map(|(name, passed)| (name.to_owned(), Value::Bool(passed)))
        .collect();
    let report = json!({
        "sandbox": if held { "held" } else { "broken" },
        "credential_bytes": credential.len(),
        "checks": checks,
    });
    (report, held)
}

/// The report for a host that cannot apply the sandbox.
pub fn unavailable(reason: &str) -> Value {
    json!({ "sandbox": "unavailable", "reason": reason })
}

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::CString;

    /// The highest descriptor checked for leaks.
    const MAX_CHECKED_FD: i32 = 1024;

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// Whether a call that returned `result` was refused by the filter.
    fn refused(result: libc::c_long) -> bool {
        result == -1 && errno() == libc::EPERM
    }

    pub(super) fn checks(socket_fd: i32, read_paths: &[String]) -> Vec<(&'static str, bool)> {
        vec![
            ("environment_empty", std::env::vars_os().next().is_none()),
            (
                "socket_inherited",
                crate::sandbox::is_connected_socket(socket_fd),
            ),
            ("no_other_descriptors", no_other_descriptors(socket_fd)),
            ("socket_refused", socket_refused()),
            ("exec_refused", exec_refused()),
            ("trace_refused", trace_refused()),
            ("io_ring_refused", io_ring_refused()),
            ("write_refused", write_refused()),
            ("unlisted_read_refused", unlisted_read_refused()),
            ("listed_read_allowed", listed_read_allowed(read_paths)),
        ]
    }

    fn no_other_descriptors(socket_fd: i32) -> bool {
        (3..=MAX_CHECKED_FD)
            .filter(|fd| *fd != socket_fd)
            // SAFETY: F_GETFD only reads the descriptor's flags.
            .all(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1)
    }

    fn socket_refused() -> bool {
        [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX]
            .into_iter()
            // SAFETY: a raw socket call; any descriptor it returns is
            // closed below.
            .all(|family| {
                let result =
                    unsafe { libc::syscall(libc::SYS_socket, family, libc::SOCK_STREAM, 0) };
                if result >= 0 {
                    unsafe { libc::close(result as i32) };
                }
                refused(result)
            })
    }

    fn exec_refused() -> bool {
        let program = c"/bin/true";
        let argv = [program.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        // SAFETY: argv and envp are null-terminated arrays of valid C
        // strings that outlive the call. Were it allowed, the process
        // would be replaced and the runtime would see no report.
        let result = unsafe {
            libc::syscall(
                libc::SYS_execve,
                program.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        };
        refused(result)
    }

    fn trace_refused() -> bool {
        // SAFETY: PTRACE_TRACEME takes no pointers.
        refused(unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) })
    }

    fn io_ring_refused() -> bool {
        let mut params = [0u8; 120];
        // SAFETY: the kernel writes at most the 120-byte setup parameters.
        refused(unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, params.as_mut_ptr()) })
    }

    fn write_refused() -> bool {
        let path = CString::new(format!(
            "/tmp/sekai-change-capture-self-test-{}",
            std::process::id()
        ))
        .expect("no interior nul");
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
        // SAFETY: path is a valid C string; a created file is removed.
        let fd = unsafe { libc::open(path.as_ptr(), flags, 0o600) };
        if fd >= 0 {
            unsafe {
                libc::close(fd);
                libc::unlink(path.as_ptr());
            }
            return false;
        }
        true
    }

    fn unlisted_read_refused() -> bool {
        // SAFETY: a valid C string; a returned descriptor is closed.
        let fd = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            return false;
        }
        true
    }

    fn listed_read_allowed(read_paths: &[String]) -> bool {
        // Opening read-only works for files and directories alike.
        read_paths
            .iter()
            .all(|path| std::fs::File::open(path).is_ok())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    /// Unreachable: the sandbox never applies off Linux.
    pub(super) fn checks(_socket_fd: i32, _read_paths: &[String]) -> Vec<(&'static str, bool)> {
        vec![("linux", false)]
    }
}
