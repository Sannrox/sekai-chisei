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
  --ledger probes.jsonl --advisories advisories/ [--specs <dir>]
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
  `crates/sekai-core/src/sekai/synthetic.rs`). A real tenant is refused;
- the probed object must exist in the foreign tenant, read as that tenant, so
  a stale id cannot pass for a denial;
- the advisory directory must be owner-only, checked before any probe runs.

Tokens are read from files and never printed.

## Declarative probe specs

A probe spec (`sekai.probe-spec/v1`, #1680) is a probe as data, so an agent
can propose one without ever calling an RPC itself:

```json
{
  "schema": "sekai.probe-spec/v1",
  "id": "get-links-cross-tenant",
  "as": "tenant",
  "call": {"rpc": "GetLinks", "direction": "outgoing"},
  "expect": {"codes": ["PermissionDenied", "NotFound"], "reason": "optional message text"}
}
```

- `as` is `tenant` (the probing tenant's credential) or `anonymous`.
- `call` is one read-only, object-scoped RPC: `GetObject`, `GetLinks`,
  `GetLinkedObjects` (`relation`, `direction`), `ListObjectComments`
  (`include_resolved`) or `GetLineage` (`max_nodes` up to 100). It is always
  made on the run's foreign object. `ListObjectComments` is experimental: a
  target serves it only with `SEKAI_EXPERIMENTAL_RPCS=1`, and otherwise its
  refusal is a `mismatch`, not a pass.
- `expect` lists the denial codes that pass (`Unauthenticated`,
  `PermissionDenied`, `NotFound`, `FailedPrecondition`, `InvalidArgument`),
  and optionally text the status message must contain.

A spec names no endpoint, credential, tenant or object; any other field is a
validation error. `--specs <dir>` loads every `*.json` spec and validates
the set before the target guard runs, so a malformed spec refuses the run
before any call. Specs run after the built-in probes, behind the same guard
and into the same ledger (counted as `spec:<id>`). A call that succeeds is a
bypass with an advisory draft whose reproduction embeds the spec; a call
denied otherwise than expected is a `mismatch`. Both make `run` exit
non-zero; `Unavailable`, timeouts and internal errors are inconclusive.

`tests/fixtures/probe_specs/` is the declarative part of the regression
catalogue: the test suite runs every spec there against an isolating
in-process deployment and requires each to be denied. Promote a finding by
adding its spec there; it fails until the bypass is fixed.

## Agent-proposed specs

A red-team agent keeps the catalogue level with new surface. The agent only
reads its inputs and writes a report. It never calls an RPC and holds no
endpoint or credential, so the only way to reach a target is through the
guarded runner:

1. Assemble the inputs in a scratch directory: `surface.diff` is the
   `proto/` diff since the last release tag (`git diff <tag>..HEAD --
   proto/`), and `bugs/<n>.md` holds one closed `risk:security` issue each.
2. Run the agent harness's red-team profile in that directory. Its final
   report is `{"specs": [...], "unsupported": [{"rpc", "why"}]}`. A run has a
   turn and time budget, and a model-cost cap of $25 a run and $60 a month.
3. Import the report:
   `sekaictl admin assurance probes import --report <summary.json> --specs <dir>`.
   The whole report is validated as one spec set before anything is
   written, so one invalid spec refuses all of it. Each spec is written as
   `<id>.json`. A spec that is already there is left alone; an id that
   already holds a different spec refuses the import. The output lists what
   was written, what was unchanged, and the `unsupported` RPCs.
4. Run the imported specs against a test deployment with
   `probes run --specs <dir>`, never against production.
5. Promote a spec that found a bypass by copying it into
   `tests/fixtures/probe_specs/`. It fails there until the bypass is fixed.

A spec can only call the five RPCs above. When the diff adds an RPC that a
spec cannot express, the agent lists it under `unsupported` with the
reason, and does not stretch another RPC to cover it. Supporting such an RPC
is a change to `sekai.probe-spec/v1`, shaped as its own issue.

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
