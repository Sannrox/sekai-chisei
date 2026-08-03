# Runtime claim pressure (`sekai.runtime-work-pressure/v1`)

Sekai Chisei exposes a bounded, read-only pressure projection for an external
worker-pool manager. The projection is a capacity signal, not a second queue,
scheduler, or claim authority. Chisei remains authoritative for admission,
claims, leases, fencing, retry/park decisions, dead-lettering, and receipts.

## RPC and scope

`GetRuntimeWorkPressure` accepts a required `namespace` and `runtime_id` and
returns one `RuntimeWorkPressure` document. There is no wildcard runtime
selector. The caller needs namespace read access; the runtime selector keeps
the result within exactly one logical runtime scope. The response contains no
task text, parameters, credentials, effect ids, operation ids, or claim ids.

The contract is versioned as `sekai.runtime-work-pressure/v1` and is additive
to the runtime claim API. A caller must treat an unknown contract version as
non-authoritative.

## Fields and semantics

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer schema version; currently `1`. |
| `contract_version` | Stable contract name, currently `sekai.runtime-work-pressure/v1`. |
| `namespace`, `runtime_id` | Exact requested scope. |
| `sampled_at_ms` | Control-plane timestamp for this aggregate sample. |
| `sample_status` | `current`, `degraded`, or `unknown`; only `current` may inform capacity changes. |
| `degraded_reason` | Bounded machine reason when the sample is not authoritative. |
| `authoritative` | `true` only for a successful current aggregate from Chisei storage. |
| `approximate` | `false` for v1; counts and age are exact for the sample. |
| `claimable_count` | Ready effects plus effects whose claim lease is currently expired. |
| `oldest_claimable_age_ms` | Age of the oldest claimable effect at `sampled_at_ms`; `0` when empty. |
| `active_claim_count` | Claimed effects whose lease is still live. |
| `expired_claim_count` | Claimed effects whose lease has expired and can create reclaim pressure. |
| `parked_count` | Intentionally parked effects awaiting governed continuation. |
| `failed_count` | Runtime effects in the terminal failed state. |
| `dead_lettered_count` | Runtime effects exhausted by claim/lease/park retry limits. |

The backend computes these values with one aggregate query. It does not load
or return every effect, so a large backlog does not require materializing task
payloads in the Chisei process. The projection is read-only and does not
change claim state or affect admission.

## Tenkai consumption example

Tenkai may use the projection together with the Shikigami worker-host
lifecycle snapshot. It must fail closed for missing, stale, degraded, or
unknown evidence:

```text
pressure = GetRuntimeWorkPressure(namespace, runtime_id)

if pressure.contract_version != "sekai.runtime-work-pressure/v1"
   or pressure.sample_status != "current"
   or not pressure.authoritative:
    record degraded evidence
    keep the last safe capacity intent
    do not scale up
else:
    consider claimable_count and oldest_claimable_age_ms
    together with healthy Shikigami capacity
```

`active_claim_count` describes work already being executed; it is not
additional backlog. `expired_claim_count`, `failed_count`, `dead_lettered_count`,
and `parked_count` are diagnostic pressure signals and do not grant Tenkai
permission to claim, retry, park, dead-letter, or acknowledge work.

Storage or projection errors return a document with `sample_status=unknown`,
`authoritative=false`, and a non-empty `degraded_reason` rather than fabricating
zero pressure. Namespace authorization failures remain permission errors and
never return a foreign projection. Effect JSON strings containing NUL are
rejected on new writes; PostgreSQL samples containing legacy JSONB-incompatible
strings fail closed as `unknown` rather than poisoning the aggregate query.

## Ownership and compatibility

- Tenkai owns worker-pool desired state, rollout, health, drain, and capacity
  intent.
- Shikigami executes already-claimed work and reports worker-host lifecycle.
- Sekai Chisei owns admitted work, claim/lease/fence state, retry/park and
  dead-letter decisions, and operation receipts.

This projection is intentionally not a recovery dependency for Chisei and is
not a replacement for `ListClaimableActionWork` or `ClaimActionWork`.
