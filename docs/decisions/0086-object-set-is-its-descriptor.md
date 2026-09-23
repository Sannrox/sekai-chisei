# ADR 0086: An ObjectSet is its descriptor; members are not stored

- Status: accepted
- Date: 2026-09-23
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/1097
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1088 (#1088)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0066](0066-object-set-evaluate.md),
  [ADR 0073](0073-source-and-action-objects.md),
  [ADR 0080](0080-dual-community-runtime-storage.md)

## Context

ADR 0066 made `EvaluateObjectSet` evaluate a revision-bound descriptor
through the authorized list and traverse paths. The name "revision-bound
ObjectSet" left open whether the server keeps a set: a stored artifact with
its own identity and member list, or a fresh evaluation on every call.

Evidence collected for #1088:

- Consumers. The MCP adapter and the generated HTTP clients
  (`sdk/typescript/http.ts`, `sdk/python/sekai_http.py`) call
  `EvaluateObjectSet` on demand and keep nothing. `sekaictl` has no
  ObjectSet command. Object-change subscriptions do not reuse the
  descriptor. No consumer needs stored members.
- Invalidation. A stored member list goes stale on the same events the
  evaluate fence already checks: a definition publish (new
  `definition_digest`), an object-security activation, a grant change, and
  any object write. Storing members would duplicate that fence as a second
  cache to invalidate. A missed invalidation would serve members the reader
  may no longer see.
- Storage. Member lists grow with the data, not with the descriptor. The
  descriptor is bounded: v1 allows four filters, one order, and one hop, and
  v2 adds bounded hops and cost limits.

Mature ontology platforms persist a saved object set as its definition: the
typed filter and traversal, bound to a schema revision. They do not persist
a frozen member list that outlives the data and permissions it was computed
from. Every read resolves members again against current data and the
reader's current grants. Where a static member list exists, it is an
explicit workflow artifact that is authorized again when read, not the
default form of a set.

## Decision

Evaluate-once remains the 1.x contract (option 1 of #1088).

- The durable, shareable form of an ObjectSet is its descriptor, including
  the pinned `definition_digest`. A client that wants to reuse a set stores
  the descriptor and evaluates it again.
- The server stores no member list, page, or set identity.
  `EvaluateObjectSet` resolves members from live authorized rows on every
  call. `authority` stays false.
- A stale pin after a definition publish is the signal to regenerate the
  descriptor against the new revision, as ADR 0066 already requires.
- A stored, receipt-like member artifact (option 2) or materialized
  snapshot kind (option 3) needs a named consumer that cannot use a stored
  descriptor. Either would arrive as a new feature Issue and ADR, re-authorize
  on every read, and stay outside object authority (ADR 0073, ADR 0080).

## Alternatives considered

- Option 2: a stored receipt-like artifact (member ids, digest, definition
  pin). Deferred until a consumer names the need. It adds an invalidation
  surface without a caller.
- Option 3: materialize members into the object log or SQL as a snapshot
  kind. Rejected for 1.x: it creates a second copy of object membership,
  which ADR 0066 and ADR 0073 forbid treating as authority.

## Consequences

Operator and client docs describe the descriptor as the saved form of a set
and say that no member list is kept. Nothing changes on the wire, in
storage, or in the RPC maturity ledger.

## Validation

Documentation-only decision. The existing `EvaluateObjectSet` fixtures
already prove the stale-pin, hidden-member, and continuation fences that
make re-evaluation from a stored descriptor safe.
