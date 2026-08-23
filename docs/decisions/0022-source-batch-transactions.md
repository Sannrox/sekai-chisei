# ADR 0022: Admit inbound records as plane-committed source batches

- Status: proposed
- Date: 2026-08-23
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/665
- Supersedes: none
- Superseded by: none
- Related: ADR 0013, ADR 0020, ADR 0021

## Context

ADR 0020 separates type revisions, inbound object sync, evidence observations,
and permit-backed write-back. ADR 0021 fixes GitHub Issue and PullRequest as the
only current object-sync source and treats webhook, document, and poll delivery
as transport into one identity contract.

The existing mapper derives stable object identity but does not define durable
batch admission or checkpoint ownership. Issue #665 requires a source adapter
SDK and conformance kit whose retries, partial progress, and restart behavior
cannot manufacture convergence. That requires a persistence and authority
decision rather than a library-only wrapper around the mapper.

## Decision

1. Source adapters emit bounded, versioned source batches. Adapters retain
   source credentials and untrusted source transport details.
2. The control plane admits each batch through one transaction lifecycle:
   `OPEN`, followed by exactly one of `COMMITTED` or `ABORTED`.
3. An adapter may propose an opaque next cursor. The control plane owns the
   checkpoint and advances it only after the corresponding batch commits.
4. Server-owned mapping projects committed records onto one type-revision
   object identity. The server re-derives source and object identity and rejects
   identity movement or an unbound type revision.
5. Exact replay is idempotent. A reused idempotency key with different content,
   a stale or foreign checkpoint, an unknown contract version, or ambiguous
   authority fails before mutation or checkpoint advance.
6. Evidence adapters remain observations. Outbound mutation remains a governed
   Action using permit-backed `external_mutate`.
7. The first family remains `source_control.object_sync` for GitHub Issue and
   PullRequest records. This decision adds no pipeline, plugin runtime,
   transform language, connector marketplace, credential store, or second
   source family.
8. Version 1 binds that family to one code-owned
   `sekai.source-type-revision/v1` descriptor and digest documented in
   `docs/object-sync.md`. Callers cannot register or invent revisions; a later
   configurable revision requires its own decision.
9. One adapter outbox may retain only one distinct unresolved batch per
   namespace, source instance, and type revision. Re-enqueuing the exact batch
   is idempotent.

## Alternatives considered

- **Compile source adapters into the control-plane process.** Rejected because
  source credentials, third-party code, and source failures would enter the
  trusted process and couple adapter releases to the server.
- **Publish only a conformance wrapper around the in-memory mapper.** Rejected
  because a wrapper cannot own checkpoint advancement or prove restart and
  ambiguous-progress behavior.
- **Let adapters advance checkpoints.** Rejected because transport success is
  not proof that object, audit, lineage, and checkpoint state committed.
- **Build a general ingestion pipeline or connector marketplace.** Rejected by
  ADR 0020; the current need is one bounded source and one identity contract.

## Consequences

- Issue #665 owns the source-batch contract, source adapter SDK, persistence
  seam, and reusable conformance profile.
- Snapshot, change-feed, and webhook transports in Issues #671, #672, and #673
  must submit through the same batch contract.
- SQLite and reusable PostgreSQL implementations must share commit, abort,
  replay, conflict, and checkpoint conformance.
- The control plane gains durable batch metadata and source checkpoints.
  Retention must preserve committed batch evidence while referenced objects or
  downstream decisions remain retained.
- A later source still requires a new bounded decision under ADR 0021.

## Validation

- A checkpoint never changes for an `OPEN` or `ABORTED` transaction.
- Exact committed-batch replay returns the prior result without a second
  mutation.
- Reusing an immutable source version with different payload content fails
  before object or checkpoint mutation.
- Unknown versions, identity conflicts, missing authority, and stale or foreign
  checkpoints fail before mutation.
- GitHub Issue and PullRequest records continue sharing the existing source-id
  number space; other GitHub kinds and other sources remain rejected.
- Evidence admission cannot upsert an object-sync identity, and object sync
  cannot redeem an external-action permit.
