//! The child's sandbox (ADR 0170), applied to itself before it reads any
//! data. Linux only; every other host is [`Unavailable`].
//!
//! - Descriptors: only stdio and the inherited socket stay open.
//! - Filesystem (Landlock, ABI 3 or newer, fully enforced): no write,
//!   truncate or create anywhere; read only beneath the start message's
//!   `read_paths`.
//! - System calls (seccomp): no new socket, connection, listener or
//!   program, no tracing or reading another process's memory, no
//!   asynchronous I/O ring that could do either outside the filter. A
//!   call from another architecture's ABI kills the child.
//!
//! The filter is a short denylist rather than an allowlist: the child's
//! code is ours, and what it must not do is reach a second destination or
//! a value it was not given.

/// Why the sandbox could not be applied: the missing host capability, by
/// name. It never carries a path or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable(pub &'static str);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

/// Whether `fd` is a connected socket.
pub fn is_connected_socket(fd: i32) -> bool {
    imp::is_connected_socket(fd)
}

/// Closes every descriptor but stdio and `socket_fd`, then applies the
/// filesystem rules and the system-call filter. On error nothing may run.
pub fn enter(socket_fd: i32, read_paths: &[String]) -> Result<(), Unavailable> {
    imp::enter(socket_fd, read_paths)
}

#[cfg(target_os = "linux")]
mod imp {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, path_beneath_rules,
    };

    use super::Unavailable;

    /// Landlock ABI 3 (kernel 6.2) is the first that refuses truncation.
    const LANDLOCK_ABI: ABI = ABI::V3;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xC000_00B7;

    /// x32 calls share the x86_64 audit arch; their number carries this bit.
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    /// The calls the filter refuses with `EPERM`.
    const DENIED: &[libc::c_long] = &[
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ];

    pub(super) fn is_connected_socket(fd: i32) -> bool {
        // SAFETY: fstat and getpeername only write into the stack values
        // passed to them, sized for those calls.
        unsafe {
            let mut stat = std::mem::zeroed::<libc::stat>();
            if libc::fstat(fd, &mut stat) != 0 || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
                return false;
            }
            let mut address = std::mem::zeroed::<libc::sockaddr_storage>();
            let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            libc::getpeername(fd, (&raw mut address).cast(), &mut length) == 0
        }
    }

    pub(super) fn enter(socket_fd: i32, read_paths: &[String]) -> Result<(), Unavailable> {
        close_other_descriptors(socket_fd)?;
        restrict_filesystem(read_paths)?;
        install_filter()
    }

    fn close_other_descriptors(socket_fd: i32) -> Result<(), Unavailable> {
        let keep = u32::try_from(socket_fd).map_err(|_| Unavailable("descriptor"))?;
        let ranges = [(3, keep.checked_sub(1)), (keep + 1, Some(u32::MAX))];
        for (first, last) in ranges {
            let Some(last) = last.filter(|last| *last >= first) else {
                continue;
            };
            // SAFETY: close_range only closes descriptors; none of these
            // are in use by this process's Rust objects.
            if unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) } != 0 {
                return Err(Unavailable("close_range"));
            }
        }
        Ok(())
    }

    fn restrict_filesystem(read_paths: &[String]) -> Result<(), Unavailable> {
        let unavailable = |_| Unavailable("landlock");
        let status = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(LANDLOCK_ABI))
            .map_err(unavailable)?
            .create()
            .map_err(unavailable)?
            .add_rules(path_beneath_rules(
                read_paths,
                AccessFs::from_read(LANDLOCK_ABI),
            ))
            .map_err(unavailable)?
            .restrict_self()
            .map_err(unavailable)?;
        match status.ruleset {
            RulesetStatus::FullyEnforced => Ok(()),
            _ => Err(Unavailable("landlock")),
        }
    }

    fn statement(code: u32, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jump_if_equal(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf,
            k,
        }
    }

    /// The filter program: kill on a foreign architecture (and x32),
    /// `EPERM` on a denied call, allow the rest.
    pub(super) fn program() -> Vec<libc::sock_filter> {
        let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
        let ret = libc::BPF_RET | libc::BPF_K;
        let deny = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        // seccomp_data: nr at offset 0, arch at offset 4.
        let mut program = vec![
            statement(load, 4),
            jump_if_equal(AUDIT_ARCH, 1, 0),
            statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
            statement(load, 0),
        ];
        #[cfg(target_arch = "x86_64")]
        program.extend([
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: X32_SYSCALL_BIT,
            },
            statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
        ]);
        for call in DENIED {
            program.push(jump_if_equal(*call as u32, 0, 1));
            program.push(statement(ret, deny));
        }
        program.push(statement(ret, libc::SECCOMP_RET_ALLOW));
        program
    }

    fn install_filter() -> Result<(), Unavailable> {
        let mut program = program();
        let fprog = libc::sock_fprog {
            len: u16::try_from(program.len()).map_err(|_| Unavailable("seccomp"))?,
            filter: program.as_mut_ptr(),
        };
        // SAFETY: prctl reads the program through `fprog`, which points at
        // `program` for the duration of the call; the kernel copies it.
        let installed = unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &raw const fprog,
                ) == 0
        };
        installed.then_some(()).ok_or(Unavailable("seccomp"))
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::Unavailable;

    pub(super) fn is_connected_socket(_fd: i32) -> bool {
        false
    }

    pub(super) fn enter(_socket_fd: i32, _read_paths: &[String]) -> Result<(), Unavailable> {
        Err(Unavailable("not linux"))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn the_filter_checks_the_architecture_first_and_ends_by_allowing() {
        let program = super::imp::program();
        assert_eq!(program[0].k, 4, "loads seccomp_data.arch first");
        let last = program.last().unwrap();
        assert_eq!(last.k, libc::SECCOMP_RET_ALLOW);
        assert!(program.len() < 64);
    }
}
