# ADR 0094: Scoped contexts author immutable definition drafts

- Status: Accepted
- Decision: [Discussion #1258](https://github.com/Sannrox/sekai-chisei/discussions/1258)

## Decision

Admit scoped authenticated contexts for qualified `sekai.SekaiService`
`GetDefinitionBranch`, `CreateDefinitionBranch`, and `ApplyDefinitionBranchEdit`.
Use server-established RPC identity. Preserve actual context scopes, namespace
and revision-wide read grants, member administration grants, actor attribution,
canonical validation, exact-head compare-and-swap, and request-bound idempotency.

Branch creation and editing are separate operations with separate retry keys.
After an uncertain transport outcome, retry the identical request and key with
fresh transport credentials. Changing a request under the same key conflicts.
A stale head requires reload and a deliberate new edit.

This extends scoped draft transport without a new store, schema, RPC, or
credential authority. Experimental RPC defaults and the tenant-free community
runtime remain unchanged. Proposal approval, merge, and publication admission
remain unchanged. Agent promotion still requires the certification integration
from ADR 0079; draft writes execute no Agents, Actions, or providers.

## Evidence

Real TCP scoped authoring, immutable historical reads, write scope and grant
denial, expiry/replay/audience rejection, qualified routing, unchanged published
head, and refused unrelated mutation admission. Existing SQLite/PostgreSQL branch
conformance proves exact-head conflicts and request-bound retries.
