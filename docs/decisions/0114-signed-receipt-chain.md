# ADR 0114: Signed per-namespace receipt chain, verifiable offline

- Status: accepted
- Date: 2026-10-18
- Owners: @Sannrox
- Discussion: none; decided in the implementation pull request for #1449
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1449
- Supersedes: none
- Superseded by: none
- Related: [ADR 0082](0082-separate-chisei-and-sekai-durable-stores.md),
  [ADR 0097](0097-in-process-transform-host.md),
  [ADR 0102](0102-isolated-process-transform-profile.md)

## Context

The decision ledger (#1240) already hash-chains policy decisions, but a
database writer can recompute that unkeyed chain. Action receipts, governed
transform runs, and agent-turn receipts (operation receipts that record
`model_called`) were not signed. Checking them required store access, so an
auditor could not prove a namespace's receipts were genuine, complete, and
unaltered.

Isolated-process runners already emit the same `TransformRun` JSON as the
in-process host (ADR 0097 / ADR 0102). The chain must wrap that body rather
than invent a second transform receipt.

## Decision

1. Each namespace has one Ed25519-signed SHA-256 hash chain of receipt
   bodies. Kinds are `action`, `transform_run`, and `agent_turn`. The hashed
   payload is seq, previous hash, namespace, kind, receipt id, the exact
   stored JSON string, and `created_at_ms`.
2. Hash, sign, rotate, checkpoint, and offline verify live in `sekai-types`.
   The plane persists the chain on the Chisei store. Isolated runners do not
   take a Sekai crate dependency; they produce the transform-run body, and
   the plane chains it when the run is recorded on a store that holds the
   chain table.
3. Signing keys rotate. The current seed is
   `CHISEI_RECEIPT_CHAIN_SIGNING_KEY` (32-byte Ed25519 seed, 64 hex chars).
   After the seed changes, `CHISEI_RECEIPT_CHAIN_PREVIOUS_PUBLIC_KEYS` lists
   historical public keys so genesis, historical entries, and the signed
   latest checkpoint still authenticate, including when dataset redaction
   verifies the bundle before re-signing. Public keys are published with
   the bundle. Receipts signed before rotation keep verifying.
4. A signed genesis checkpoint (seq 0, empty prefix) starts the chain for
   pre-existing unchained data. A latest checkpoint covers the head. Periodic
   checkpoints land every 32 entries. Receipt body updates, including
   lifecycle event appends, append a new chain entry when the latest
   revision for that receipt id changed. Genesis also issues an empty
   latest checkpoint. Append authenticates that checkpoint with the
   configured signing keys (not keys stored in the writable database)
   and refuses if it is missing or does not match the stored rows.
   Dataset field redaction authenticates the existing namespace chain
   with the operator keys, then rewrites chained transform-run bodies
   in place and re-signs so partition selectors and member digests do
   not remain in historical revisions. Redaction of chained bodies
   requires the signing key; it does not re-sign a chain that fails
   verification.
5. `sekaictl admin assurance receipts export|verify` is the offline path.
   Verify requires `--trusted-key` (Ed25519 public key hex or `sha256:`
   key-id fingerprint). Bundle-published keys are not a trust anchor.
   Verify reports the first bad receipt position. No public transparency log
   or third-party timestamping.

## Alternatives considered

- Sign only at export time. Rejected: a store writer could reorder rows
  before export, which is the unkeyed-ledger threat.
- Put the library in the plane crate. Rejected: isolated runners and the CLI
  verifier need the same contract without gRPC or storage.
- Chain transform runs on the Sekai dest in Combined Split. Deferred: the
  unified chain table is a Chisei family; community combined stores hold both
  families and chain every kind. Split transform chaining follows the Chisei
  dest once writes are routed through it.
- Independently gossiped heads or a transparency log so a restored earlier
  signed prefix cannot pass as the current export. Rejected: that is a public
  transparency log, which is a non-goal. An auditor who kept a prior export
  can compare heads; the verifier of one bundle cannot.

## Consequences

Existing receipts stay readable. New writes chain when the signing key is
configured. Export of a namespace that has no genesis fails closed. Combined
Split community PostgreSQL migrates the chain on the Chisei dest (`0081`).

## Validation

`sekai-types` tests cover export-verify, alter/remove/reorder at the exact
position, key rotation, and isolated-process `TransformRun` JSON. SQLite
persistence tests cover write-path chaining and tamper at the stored
position.
