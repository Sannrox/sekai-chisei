# Host-executor permit conformance

Issue: [#296](https://github.com/Sannrox/sekai-chisei/issues/296).  
Profile: [`tests/fixtures/host_executor_permit_conformance/v1.json`](../tests/fixtures/host_executor_permit_conformance/v1.json).  
Suite: `tests/host_executor_permit_conformance.rs`.

## Purpose

Third-party host executors redeem external-action permits and submit execution
evidence. This profile is the **provider-free, deterministic** checklist that a
harness must pass before it is trusted as a reference integration.

It does **not** certify commercial vendors, add new permit cryptography, or
require network access.

## Run

```bash
cargo test --test host_executor_permit_conformance
```

CI already runs the full `cargo test` matrix; this binary has no ignored
network-only cases.

## Required cases

Keep this table synchronized with every `required_cases` entry in the versioned
fixture. A third-party harness maps each id to an automated test.

| Case | Class | Expectation |
| --- | --- | --- |
| `verify_ok_with_capabilities` | positive | `verify_for_executor` succeeds for reference executors |
| `verify_rejects_missing_capability` | negative | refuses incomplete host capabilities |
| `verify_rejects_bad_signature` | negative | refuses tampered signature |
| `verify_rejects_outside_validity_window` | negative | refuses outside not_before / expires |
| `verify_rejects_executor_mismatch` | negative | host context executor must match permit |
| `verify_rejects_harness_mismatch` | negative | requesting harness must match permit |
| `verify_rejects_arguments_digest_mismatch` | negative | arguments digest must match permit |
| `verify_rejects_target_mismatch` | negative | target selectors must match permit |
| `verify_rejects_precondition_mismatch` | negative | observed preconditions must match |
| `verify_rejects_untrusted_issuer` | negative | untrusted issuer is refused |
| `verify_rejects_untrusted_key_id` | negative | untrusted key id is refused (issuer may match) |
| `redeem_is_idempotent` | positive | same key converges without double consume |
| `redeem_after_revoke_fails` | negative | revoked permit cannot be redeemed |
| `execution_evidence_shape` | positive | terminal host report validates |
| `broken_harness_must_fail_each_negative` | meta | broken mock fails every negative |

## Reference executors

The suite exercises the same two material executor styles documented in
[external-action-execution.md](external-action-execution.md):

- `executor:filesystem` + `atomic_rename`
- `executor:http` + `conditional_request`

## Integrating a third-party harness

1. Implement host-side checks equivalent to `verify_for_executor` **before**
   redeem/execute.
2. Map each `required_cases` id to an automated test in your repo.
3. Keep a deliberately broken mock that fails every `class=negative` case so the
   suite cannot pass vacuously.
4. Pin the profile `version` string in your certification report.

Version: `sekai.host-executor-permit-conformance/v1`.
