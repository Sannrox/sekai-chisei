# ADR 0088: One object-log host owns identity; clerk processes are its clients

- Status: accepted
- Date: 2026-09-23
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/1083
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1082 (#1082)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0080](0080-dual-community-runtime-storage.md),
  [ADR 0081](0081-evaluate-reads-mikura-library.md),
  [ADR 0082](0082-separate-chisei-and-sekai-durable-stores.md)

## Context

#1082 asked how several clerk processes observe the same `(kind, key)`
after a single write, without each process owning an object log and without
a multi-writer warehouse. #944 retires the SQL object-type index as object
authority and waits on this answer.

Evidence collected for #1082:

- **How the log is opened today.** Every clerk process that sets
  `SEKAI_OBJECT_LOG` opens the log in-process through one process-scoped
  mikura `Store` handle. Admits append through it (#1106), and the
  dual-read canary reads through it (#1110). The handle is safe only while
  one process writes the file. A second clerk process pointed at the same
  path would be a second writer, which mikura does not support.
- **Operator profiles.** One process with SQLite (Combined) is the default.
  Several clerk processes already share PostgreSQL as the clerk database
  (ADR 0080), and the Sekai and Chisei planes run as separate processes
  (ADR 0082). Only the SQL object-type index is visible to all of them.
- **The pinned library.** mikura `v0.1.0` is an in-process library crate
  with no host binary or wire contract. ADR 0081 already names a hosted
  ingest and evaluate process as mikura's destination, not its current
  crate. A host needs a newer published tag, the same prerequisite that
  blocks the pin bump in #1111.

Mature ontology platforms run the object store as a dedicated backing
service. Many application services read objects and submit writes through
that service's API. None of them embeds its own copy of the object index,
and none of them is the store's owner merely because it happened to serve
the first write. Writes funnel through one owner; reads go to the same
owner or its read replicas, never to a peer application's memory.

## Decision

Accept option 2 of #1082 as the target process boundary. Keep option 1 as
the contract until that target is reachable.

- **Target.** One object-log host owns the log and its identity
  generations. Every clerk process, whether Combined, `sekai-plane`, or a
  replica sharing PostgreSQL, is a client of that host for load, evaluate,
  and append. No clerk process owns the log.
- **Interim (option 1).** Until a published mikura tag ships the host and
  its wire contract, the SQL object-type index stays the identity shared
  across clerk processes. The in-process `Store` stays a single-process
  ingest and canary path, pointed at by at most one clerk process.
- **#944.** Stays blocked. It now waits on a published mikura tag with the
  host contract and a clerk adapter for it, the same tag-then-adapt shape
  as #1111, rather than on an open design question.

## Alternatives considered

- **Option 3: one clerk process owns `Store`, the others call its RPCs.**
  Rejected. It makes one clerk replica special, couples clerk scaling and
  restarts to object ownership, and puts object-log service semantics into
  the clerk, which ADR 0081 keeps out.
- **Option 4: a multi-writer warehouse, replica set, or partition key.**
  Rejected. No published downtime or capacity miss shows that one host
  restoring from its log cannot serve.
- **Option 1 as the permanent answer.** Rejected as the target, because it
  leaves the SQL index as object authority, which ADR 0073 says it is not.
  It remains the interim contract.

## Consequences

- Operators must not point two clerk processes at the same
  `SEKAI_OBJECT_LOG` path. Cross-process identity comes from the SQL index
  until the host ships.
- #944's dependency becomes concrete: a mikura release with the host, then
  a clerk adapter. It is no longer a design gap.
- No wire, storage, or configuration change in this repository now.

## Validation

Documentation-only decision. Proof that clerk processes share identity
through the host belongs to the adapter Issue that follows the mikura
release: write once through one clerk process, read the same generation
from a second, and fail closed on mismatch.

## Amendment: host released and adapted (#1196)

mikura `v0.2.0` (pinned by #1111) ships `mikura-host` with its versioned
JSON-lines wire contract, which satisfies the release prerequisite above. The
clerk adapter (`src/sekai/object_log_host.rs`) is its client:

- `SEKAI_OBJECT_LOG_HOST` routes object-log admits (append plus generation
  read) through the host.
- It is exclusive with a local `SEKAI_OBJECT_LOG`.
- A non-loopback host requires `SEKAI_OBJECT_LOG_HOST_BEARER`.
- Every host or wire failure fails the ingest closed, with no local
  fallback.

The validation above now runs as a test against a real host on loopback: one
client writes, a second reads the same generation, and a committed record
that does not carry the admitted properties fails closed. The SQL object-type
index is still the evaluate authority. Retiring it remains #944, which now
waits only on dual-read soak evidence.
