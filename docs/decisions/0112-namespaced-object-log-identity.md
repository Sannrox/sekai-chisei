# ADR 0112: Plane namespace is part of object-log identity

- Status: accepted
- Date: 2026-10-17
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1552 (#1552)
- Supersedes: none
- Superseded by: none
- Amends: [ADR 0091](0091-object-log-owns-evaluate-identity.md)
- Related: [ADR 0081](0081-evaluate-reads-mikura-library.md),
  [ADR 0088](0088-one-object-log-host-many-clerk-clients.md)

## Context

ADR 0091 made the object-log own generations and typed-object identity, but
the pinned store still keyed records by `(kind, key)`. One plane log could
hold objects from several namespaces in the same identity space, so a
single-namespace migration could not recover them, and same-key objects in
different namespaces collided. Dual-read could not answer a namespace-scoped
evaluate from that log.

Mikura now writes `MIKURAV2` with identity `(namespace, kind, key)` and
refuses `MIKURAV1` on open. Existing logs move only through an explicit
offline step.

## Decision

1. **Identity is `(namespace, kind, key)`.** Admission ingest, generation
   reads, dual-read evaluate, and the object-log host client pass the plane
   namespace. Two namespaces may reuse the same `(kind, key)` without sharing
   generations.
2. **`MIKURAV1` fails closed on open** with a message that names the
   migration. The source log is never rewritten in place; it remains the
   rollback copy.
3. **Migrate by projection.** An offline command reads the pre-namespace log
   and assigns each record its plane namespace by looking up `(kind, key)` in
   the SQL object projection. An identity unknown to the projection, or
   present in more than one namespace, fails the whole migration closed and
   writes nothing. The mikura store namespace is the plane namespace.
4. **The mikura pin is a main commit after the namespace change**, including
   `Store::migrate_unnamespaced_with` so a mixed-namespace log can be mapped
   without duplicating records.

## Alternatives considered

- **Prefix log kinds with namespace.** Rejected in ADR 0091: it rewrites
  `(kind, key)` and breaks existing logs.
- **One namespace for the whole log.** Rejected: a process log already mixed
  plane namespaces under one `(kind, key)` space.
- **Open `MIKURAV1` with a default namespace.** Silent reinterpretation.

## Consequences

- Dual-read evaluate is namespace-scoped and can compare SQL paths in one
  namespace without counting other namespaces' objects of the same kind.
- Operators migrate each existing log before opening it on this pin with
  `sekaictl admin store migrate-object-log --src <legacy> --dst <namespaced>`.
  The command looks up `(kind, key)` in SQL `object_type_index*` and clerk
  objects, and leaves the source file untouched.
- SQL `object_type_index*` remains a rebuildable serving projection.
