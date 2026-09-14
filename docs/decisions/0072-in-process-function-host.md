# ADR 0072: Keep ontology functions on an in-process host API

- Status: accepted
- Date: 2026-09-14
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/909
- Issue: https://github.com/Sannrox/sekai-chisei/issues/881 (#881)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0020](0020-shared-type-revisions-and-object-sync.md),
  [ADR 0063](0063-object-action-describe-preview.md)

## Context

`CreateFunction` already persists a pipeline of `self`, `filter`, `traverse`,
`aggregate`, and `transform` steps. The plane executes that pipeline
in-process at computed-property read time. There is no public execute RPC and
no guest-code runtime. Issue #881 asked how customer-authored logic should run
without a full agent run. A guest language, bytecode format, or isolated
process was not measured.

## Decision

1. Ontology functions are an **in-process host API** over authorized objects
   and object sets. Grow the existing `CreateFunction` pipeline and its
   read-time executor. The host is scoped to the invoking principal. Clock and
   randomness are host-provided and recorded. Budgets and replay live on the
   operation receipt.
2. Functions stay **read-only** with respect to type-revision identity.
   Derived views are not persisted onto a type revision
   ([ADR 0020](0020-shared-type-revisions-and-object-sync.md)).
3. Functions are **never** delegated to an agent-harness run.
4. **Guest code**, if added later, runs behind that same host API in a
   plane-owned isolated guest. The guest sees only host-provided capabilities.
   There is no ambient network or filesystem. This ADR does not pick a guest
   language, bytecode format, or engine.
5. A later **additive isolated-process profile** may run the same host API
   outside the control-plane process. It does not replace the in-process host
   and is not selected until cold start, memory, replay, and CI toolchain are
   measured.

## Alternatives considered

- Treat every function as an agent-harness run. Rejected: too heavy for
  sub-second validation and not deterministic under replay.
- Select an isolated-process or guest engine now. Rejected: no envelope
  numbers exist; picking one would invent a runtime.
- Wait to grow the host until a guest engine exists. Rejected: the pipeline
  host already ships and is the contract a later guest must call.

## Consequences

Host-API growth is not blocked on a guest engine. #882 remains the guest-code
runtime and stays implementation-blocked on measurements. Function-backed
Action validation (#883) still waits on that runtime. A later isolated-process
profile, if measured, is additive and uses the same host API.

## Validation

Existing function-pipeline and computed-property tests remain the host
contract. A later guest spike must publish p95, cold start, memory cap, replay
equality, and reproducible CI builds before #882 can become ready.
