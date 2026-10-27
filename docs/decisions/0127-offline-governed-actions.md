# ADR 0127: Offline governed Actions decide at arrival against a base version

- Status: accepted
- Date: 2026-10-23
- Issue: #1580
- Related: [ADR 0126](0126-device-bound-assertions.md), #102 (offline leases)

## Context

Field devices prepare ordinary governed Actions while disconnected and submit them hours later. The object they acted on may have changed in the meantime. Policy must not be evaluated on the device, a retry must not apply twice, and the result has to show the client what happened.

## Decision

1. **Submission.** An offline submission is the ordinary `SubmitActionInstance` plus an `offline` record:
   - the prepare time;
   - the base version, which is the bound object's `updated` time when the device read it;
   - each field the Action writes as the device saw it: its properties, and `name` when it renames, with an unset value meaning absent. This is an ordered list, so the decoded request re-encodes to the bytes the device proof signed;
   - an optional offline lease id.

   It requires a type whose `object_mutation` is `update`, and an object of that type's kind in the submission's namespace. Any other object counts as not found, so a conflict never reports on it. Objects have no separate version counter, and the update path already refuses to write over a change made after planning.
2. **Device.** The request needs a device-bound assertion and the device's proof over it (ADR 0126). `SubmitActionInstance` is the first RPC on the list that checks proofs. The device id comes from the assertion, never from the request.
3. **Decision at arrival.** Criteria, policy and budget are decided when the submission arrives, exactly as for an online submit. A policy changed after the device prepared the Action therefore applies.
4. **Conflict rule per type.** If the object moved past the base, the type's `offline_conflict` decides:
   - `reject_any` (the default): any change is a conflict;
   - `reject_touched`: a conflict only if a written property changed, compared against the base values the device sent;
   - `last_writer_wins`: as `reject_touched`, but the listed `last_writer_wins_properties` may be overwritten.
5. **Conflict outcome.** A conflict denies the instance with `deny_reason` `offline_conflict` and stores the conflict: the object, its base and current versions, and the differing properties. Every existing path already treats `denied` as terminal.
6. **Concurrent change.** If the object changes between the conflict check and the write, the write is refused and the instance dropped, so a new submit is judged against the new state.
7. **Exactly once.** The offline record is part of the request digest, so a retry with the same idempotency key returns the stored outcome, and a different submission under the same key is refused.
8. **Receipt.** The intent event records the offline provenance: the prepare time, the base, the device, the lease and any conflict.

## Alternatives considered

- Evaluating policy on the device. Rejected: it would decide authority with stale rules.
- Object history to reconstruct base values. Rejected for now: the device already has the values it acted on, and sending them keeps the rule check local to one read.
- A new `conflict` status. Rejected: every consumer of instance status would need it, and `denied` with a reason and a record says the same.

## Consequences

Versions are update times in milliseconds, so two writes within one millisecond share a version. Every submission therefore carries a base for each written field, and those are compared under every rule, even when the version matches. A change to a field the Action does not write, made within the same millisecond as the version the device read, is not detected by `reject_any`. A durable per-write revision would close that gap.

Device assertions must carry write scope for devices to submit Actions. Merging free-form text stays out of scope.

## Validation

Tests cover each case:
- a duplicate submission returns the stored outcome;
- a stale base conflicts under the strict rule;
- under `reject_touched`, a change to another property applies and a change to a written property conflicts;
- a policy change between prepare and submit applies at submit;
- receipts carry the offline fields;
- an offline submit without a device-bound credential is refused.
