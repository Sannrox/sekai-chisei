# ADR 0170: Sandboxed change capture and the replication slot lifecycle

- Status: accepted
- Date: 2026-11-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3083 (#3083)
- Supersedes: none
- Superseded by: none
- Related: ADR 0118, ADR 0148

## Context

Change capture reads a database's change stream as a connector type of
the one connector runtime (ADR 0148). Unlike a snapshot page, a capture
runs for a long time against a remote database, holds a credential, and
parses untrusted bytes from the network. The Issue requires remote
databases only from the Source's egress allowlist over verified TLS, a
sandbox profile, and failing closed when the sandbox cannot apply. The
maintainer accepted the sandbox and PostgreSQL as the first capture family
on 2026-11-25.

## Decision

1. **One sandboxed child per capture Source.** The runtime starts the
   `sekai-change-capture` executable installed beside its own. The child
   gets an empty environment, its own process group, a wall-time and
   output bound, and stderr discarded, through the same bounded launcher
   as the object parser worker.
2. **The runtime dials; the child never chooses a destination.** The
   runtime resolves the Source's endpoint, checks it against the egress
   allowlist, connects, and lets the child inherit the connected socket
   (`--socket-fd`). Nothing is dialed when the check refuses. The child
   runs TLS over that socket with the runtime's verified roots plus the
   operator's CA, which it reads under the read-only rule below.
3. **The credential crosses once.** The Source's one credential slot
   reaches the child in a single start message on stdin, which then
   closes. No other credential binding is in the child's address space.
4. **The child sandboxes itself before it reads data.** It closes every
   descriptor but stdio and the socket, then applies:
   - a filesystem ruleset (Landlock ABI 3 or newer, fully enforced) that
     grants no write, create or truncate anywhere and read only beneath
     the paths in its start message;
   - a system-call filter that refuses with `EPERM` new sockets,
     connections and listeners, program execution, tracing, reading
     another process's memory, taking another process's descriptors, and
     asynchronous I/O rings; a call under a foreign architecture's ABI,
     or the x32 ABI, kills the child. No new privileges are possible.
   The filter is a denylist: the child's code is ours, and the boundary is
   what it must not reach, not every call it may make.
5. **Fail closed.** When the host cannot apply either part, the child exits
   before reading data with a named reason, and the run fails as
   `unavailable` with that reason. The child's `self-test` mode applies
   the sandbox and proves each refusal from inside it; the runtime offers
   change capture only on Linux hosts where it passes. Elsewhere the type
   is not offered and its Sources are not listed.
6. **Supervision.** The runtime restarts a dead child with backoff under
   the Source's lease. The capture position stays in the plane-owned
   checkpoint (ADR 0118), so a restart resumes from the last committed
   page.
7. **PostgreSQL first: one slot and one publication per Source,** both
   named in the Source's configuration. An existing slot is used; a
   missing one is created. `check` names a role without replication
   permission, or a write-ahead log level other than `logical`, before any
   data is read.
8. **Slot lifecycle.** The runtime records whether it created the slot.
   Deleting the Source drops a slot the runtime created and leaves an
   operator-named pre-existing slot in place. A disabled Source keeps its
   slot, and Source health reports the log the slot retains, so the cost
   on the source database is visible rather than silent.

## Clarification (2026-11-26): a pre-existing slot at the first sync

Point 7's "an existing slot is used" holds once the Source has synced.
At the first sync, a slot the runtime did not just create may already be
past the snapshot the sync copies, so the changes between them would be
lost without notice. `check` therefore refuses an operator-named slot that
already exists before the first sync as "slot ahead of the snapshot",
unless the runtime created it in the same first sync. The runtime never
drops or re-creates that slot to get past the refusal; the operator drops
it or names another. The refusal lives with the first-sync logic, which
knows whether a sync has completed; the change-capture child alone does
not.

## Consequences

- The sandbox's dependencies live only in the child crate; the runtime
  depends on none of them.
- Development hosts other than Linux cannot run change capture; its
  sandbox tests run on Linux in CI and in Linux containers.
- A kernel without Landlock ABI 3, or a container profile that refuses
  the sandbox's own calls, makes the type unavailable on that host rather
  than weaker.
- A retained slot holds log on the source database until the Source is
  re-enabled or deleted; health makes that visible.

## Rejected alternatives

- A network namespace plus a filtering proxy: needs privileges a runtime
  container usually lacks.
- A container per capture: adds a container runtime dependency this
  local-first runtime does not require.
- Running unsandboxed with a warning: the Issue requires failing closed.
- Applying the sandbox in the runtime between fork and exec: the filter
  would refuse the child's own exec.
