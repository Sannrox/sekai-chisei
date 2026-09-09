# Source write-back example

`source_writeback` is a local, deterministic fixture that joins inbound object
sync with permit-backed external mutation. It starts an isolated SQLite control
plane and a loopback GitHub Issue/executor store. The fixture Issue may describe
a service incident; the admitted source type remains GitHub Issue.

## Run the fixture

From the repository root:

```bash
cargo run --locked --example source_writeback
cargo test --locked --test source_writeback_example
```

No server, provider, credential, network, or hosted GitHub endpoint is
required. The command creates empty local state, starts the loopback source
HTTP listener, and exits nonzero when any assertion fails. Generated databases
and fixture files stay under the process temp directory.

## What the command applies

1. It admits one synthetic GitHub Issue through `ApplySourceBatch`, then
   refreshes the same source/object identity with a later source version.
2. A changed fixture version before conditional mutation is refused. The
   independent applied-effect counter stays at zero.
3. Revoked authorization cannot redeem. The fixture record is not mutated.
4. One authorized write-back admits a governed Action with `external_mutate`,
   verifies the host permit, and redeems it. Replaying the same intent keeps
   the original permit and Action identities; a changed intent cannot reuse
   those keys.
5. The loopback executor commits the update and loses its response. Host
   evidence stays `outcome_unknown` until source readback. Recovery does not
   retry the effect against the new version.
6. Restarting the control plane from the same SQLite file preserves the
   projected object, Action, receipt, and the fixture's independent effect
   counter.

The report is JSON. It contains bounded identities, the GitHub type digest,
receipt and evidence references, and the pass/fail flags for stale
precondition, denial, replay, response-loss recovery, and restart. It does not
include source payloads, permits' signatures in full, credentials, or raw
cursor bytes.

The example is a development runner, not a production authority, RPC, source
vendor, or exactly-once execution claim.
