# ADR 0093: Agent drafts use immutable definition members

- Status: Accepted
- Decision: [Discussion #1251](https://github.com/Sannrox/sekai-chisei/discussions/1251)

## Context

Authoring needs durable, typed Agent documents and exact-revision read-back.
The definition branch store already provides canonical JSON, namespace-bound
member and revision digests, idempotent writes, and compare-and-swap heads.

## Decision

Add `agent` to that store's member kinds. Its document contract is
`sekai.agent-definition/v1`: `name`, `task_class`, `instructions`, and
`allowed_action_types`. Reject unsupported fields, duplicate JSON keys,
noncanonical identifiers, duplicate Action references, and oversized content.
Action references declare intended use; they grant no execution authority.

Add experimental `GetDefinitionMember` for one member at an exact revision.
Authenticate and authorize the namespace first, retain the existing read grant
requirement for every member of the revision, and verify content and revision
binding before returning a body. Missing and unreadable members share one
unavailable response. Do not expose credentials or provider configuration.

Agent documents remain drafts. Reject publishing or merging a revision that
contains an Agent until the bound certification gate from ADR 0079 is integrated.
Ordinary proposal approval cannot substitute for certification.

## Consequences

SQLite and PostgreSQL reuse existing tables and migrations. Existing member
kinds and digests retain their contracts. Draft storage does not execute Agents,
resolve models, or change the published definition pointer. Clients must opt in
to experimental RPCs explicitly to use document read-back.
