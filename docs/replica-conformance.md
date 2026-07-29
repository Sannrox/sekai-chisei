# Replica conformance adapter

`replica-conformance` is a local deterministic adapter for composed-runtime
test harnesses. It opens two independent Sekai Chisei runtime instances against
one isolated temporary SQLite authority and exercises the real shared-state
implementation.

```bash
cargo run --locked --bin replica-conformance
```

The command emits one compact JSON object using
`sekai.replica-conformance/v1` and exits unsuccessfully when a check fails.
Consumers must pin both `version` and `evidence_ref`; an unknown version or
changed evidence digest is incompatible and must fail closed. The evidence
digest covers the schema, adapter, two-replica harness, runtime dispatch, lease
fencing, and coordination implementation sources used by the checks.

Checks cover duplicate admission, stale lease fencing, stale-work
reconciliation, authority readiness, and loss/restore identifier
reconciliation. Store loss is `unavailable`. A restored store with the wrong
authority identifier is `unknown` and remains unready. Only the matching
restored authority is `current`.

The adapter accepts no external paths or identifiers. It uses fixed synthetic
fixtures and local temporary storage. Output is bounded to five checks and four
observations per check and contains no database paths, payloads, credentials,
or raw errors. This is conformance evidence, not a production
high-availability claim.
