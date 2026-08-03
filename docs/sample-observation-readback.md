# Sample observation readback

`RecordSampleObservation` is the authenticated admission path used by optional
learning adapters. A bounded readback is available through
`GetSampleObservation` for the same service principals that are authorized for
telemetry admission. Non-`root`/`local` service principals must also hold a
viewer grant on the requested namespace boundary.

The request names both the observation `request_id` and its `namespace`. Chisei
matches both identifiers exactly, preserving the existing v1 write and
idempotency semantics; clients should use canonical identifiers without
surrounding whitespace. It returns a non-sensitive projection containing:

- the request and namespace identities;
- a deterministic `sha256:` digest of the non-sensitive readback projection;
- `recorded` state;
- the original observation timestamp; and
- the read timestamp.

The RPC never returns the specification, model output, prompt, credentials,
or provider diagnostics. After namespace authorization, a namespace mismatch
and an absent observation both return `NOT_FOUND`, preventing cross-namespace
enumeration. An unauthorized service principal receives `PERMISSION_DENIED`
before the row query. The readback is a view of the bounded scoring-admission
queue: after the scoring worker compacts a consumed row, the read returns
`NOT_FOUND` rather than claiming historical evidence that is no longer present
in this surface. Durable scored evidence is owned by the evaluation and
receipt records.

The contract is additive and preserves the existing write RPC and v1 clients.
Recording and reading are separate authorization checks: a telemetry writer
does not automatically receive namespace read access.
