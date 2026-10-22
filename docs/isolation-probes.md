# Isolation probes

Isolation bugs are replayed as a regression suite and, against a deployment,
by a guarded runner.

## Catalogue

`src/grpc/isolation_probes.rs` (`sekai.isolation-probes/v1`) names every past
isolation bypass, the denial its probe expects, and the tests that replay it.
They run in-process with the normal test suite. Add an entry with every new
isolation bug; a catalogue entry without a probe fails the suite.

## Runner against a deployment

```sh
SEKAI_PROBE_TARGET_ALLOWLIST=<endpoint>[,<endpoint>...] \
sekaictl admin assurance probes run --target <endpoint> \
  --tenant <ns> --tenant-token-file <file> \
  --foreign-tenant <ns> --foreign-token-file <file> --foreign-object <id> \
  --ledger probes.jsonl --advisories advisories/
sekaictl admin assurance probes summary --ledger probes.jsonl --week-start-ms <ms>
```

Schedule `run` from the deployment's scheduler; each call checks the remote
object-read surface once:

| Probe | Expected |
| --- | --- |
| `unauthenticated_read`: read the foreign object with no credential | `Unauthenticated` or `PermissionDenied` |
| `cross_tenant_read`: read it as the probing tenant | `PermissionDenied` or `NotFound` |

These are generic checks against a running deployment. The specific
regressions in the catalogue stay covered in-process by the test suite.

The target guard is the safety boundary and fails closed:

- the endpoint must match an entry of `SEKAI_PROBE_TARGET_ALLOWLIST` exactly;
  with the variable unset or empty, every target is refused;
- both tenants must be synthetic: their namespace boundaries, read with each
  tenant's own credential, carry `synthetic = true` (see synthetic tenants in
  `src/sekai/synthetic.rs`). A real tenant is refused;
- the probed object must exist in the foreign tenant, read as that tenant, so
  a stale id cannot pass for a denial;
- the advisory directory must be owner-only, checked before any probe runs.

Tokens are read from files and never printed.

## Ledger, summary and findings

Every attempt, including a refused run, is appended (fsynced) to the JSON
Lines ledger as `sekai.probe-ledger/v1`; a torn last line left by a crash is
dropped before the next append, and overlapping runs serialize on a lock of
the ledger file. Connecting and each call time out after 30
seconds, so an unresponsive target is a recorded failure. `summary` computes the week from the
ledger alone: attempts and refused runs, counts per probe and outcome, and
the attempts that found a bypass.

A bypass writes a private security advisory draft (the request body of a
repository security advisory, with reproduction steps) under `--advisories`,
owner-only (directory `0700`, files `0600`; an existing directory others can
reach is refused), and makes `run` exit non-zero. A
draft that cannot be written never hides the finding: the bypass is still
recorded and the failure reported. A probe that cannot decide also exits
non-zero, since isolation was not verified. Submit it through private vulnerability
reporting (SECURITY.md). The runner never opens an issue or posts anything.
