# ADR 0138: Caller-scoped ad-hoc governed transform runs

- Status: accepted
- Date: 2026-10-28
- Owners: @Sannrox
- Discussion: none, resolved in Issue #1957
- Issue: #1957
- Supersedes: none
- Superseded by: none
- Related: [ADR 0110](0110-governed-transform-preview.md),
  [ADR 0101](0101-analytical-transform-profile.md),
  [ADR 0102](0102-isolated-process-transform-profile.md),
  [ADR 0074](0074-plane-owned-transforms.md)

## Context

A governed run commits an output and a receipt, but only for a definition
stored with `PutGovernedTransform` and only for a credential admin
(`RunGovernedTransform`). Preview (ADR 0110) reads as the caller but commits
nothing. An interactive client acting for an ordinary principal must
therefore store a definition per attempt, or run as an admin and bypass the
caller's read policy. This adds a member-callable execution path and a
dataset lifetime of its own, so the boundary is recorded here.

## Decision

1. **Inline definition, caller's authority.** Experimental
   `RunAdHocGovernedTransform` takes an inline `GovernedTransform`, a
   `session_label` and an `idempotency_key` from any authenticated principal
   with read access to the namespace. The definition is validated as Put
   validates it and is never stored in the catalog or listed by
   `ListGovernedTransforms`. Every declared input passes the same dataset read
   checks as preview and put; a denied input refuses the whole run before any
   run, queued work or receipt exists.
2. **Identity per caller.** A run's identity is a digest of the namespace, the
   calling principal, the `session_label` and the `idempotency_key`. A retried
   submission with the same identity returns the existing run and receipt,
   across a restart, and creates nothing new. The caller is part of the
   identity, so one caller can neither reach nor collide with another's run
   by guessing a key. The same identity with a different definition is
   refused.
3. **Scratch output.** The output is a scratch dataset named from the run
   identity, owned by the caller, and read under normal dataset policy. It
   carries an expiry set from a plane retention; a sweep deletes expired
   scratch datasets and their rows. The run receipt stays. A later ad-hoc run
   in the same session may read a scratch output as an input, under the same
   checks as any input.
4. **Fixed output budget.** Plane configuration caps output rows and bytes;
   the request cannot raise them. A run over either cap fails with
   `transform_adhoc_output_budget` and writes no output. Output is never
   truncated.
5. **Governed like any run.** Markings propagate from inputs to the output
   (`markings_in`, `markings_out`). The run is signed into the receipt chain
   with its definition digest, engine, runtime image, input versions and
   `session_label`. The new receipt field is empty on existing receipts and
   left out of their digest when empty, so existing digests stay stable.
6. **Same engines and queue.** `analytical` runs execute in-process (ADR
   0101). `isolated_process` runs use the existing transform claim queue (ADR
   0102) with an `adhoc` mark, so workers claim them with the published claim
   client, and quota hooks apply as for stored runs. A separate queue is
   rejected for the reason ADR 0110 gives.
7. **Experimental.** `DiscoverCapabilities` reports `sekai.transforms.adhoc`,
   disabled unless experimental RPCs are enabled.

Delivery is in layers: the analytical path with identity, scratch output,
budget and receipt; the retention sweep; and the isolated-process path.

## Alternatives considered

- Store a definition per attempt and run it. Rejected: floods the catalog and
  still needs an admin to run.
- Run as an admin on the caller's behalf. Rejected: bypasses the caller's
  read policy.
- Let preview commit. Rejected: changes the contract of a non-committing call.
- An idempotency key scoped only to the namespace. Rejected: one caller could
  observe another's run by reusing a key.

## Consequences

Exploratory clients get governed, receipted results without catalog writes
or admin authority. Scratch datasets add a lifetime class that every dataset
listing and retention path must respect. Object-set inputs, live processes
between runs and promoting a session into stored definitions stay out of
scope.

## Validation

Tests on both community backends: a non-admin principal runs inline SQL and
receives a run, a scratch output and a signed receipt naming the session; a
denied input leaves no run, work or receipt; markings reach the output and
receipt; a repeated key across a restart yields one run and one receipt; an
over-budget output fails typed with no output; an expired scratch dataset is
gone while its receipt remains; an isolated-process run completes through the
published claim client.
