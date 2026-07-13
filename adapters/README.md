# External evidence reference adapters

These programs demonstrate the adapter boundary without adding vendor clients to
the Sekai core:

- `evidence_github_check_webhook` accepts one GitHub `check_run` webhook payload
  on stdin. Collection and webhook authentication remain the responsibility of
  the surrounding webhook receiver.
- `evidence_http_health_poll` performs one bounded HTTP GET against a health
  endpoint and translates the response into expiring operational-health
  evidence.

Both use `sdk.rs` to build the canonical `sekai.evidence/v1` envelope, calculate
the content digest and replay key, persist the exact delivery in a durable local
outbox, and call `SubmitEvidence`. Unknown-outcome retries reload the same
envelope and idempotency key; a returned Sekai result acknowledges the outbox
entry. `EVIDENCE_OUTBOX_DIR` can override the default
`data/evidence-adapter-outbox`. The adapters never write Sekai graph state
directly and never inject Chisei context.

Before running an adapter, an administrator must register its producer
capability and immutable schema version through the evidence control-plane API.
The producer must own the configured source instance and be allowed to submit
the adapter's evidence type, namespace, target kind, classification, and
`upsert` intent.

Common environment variables:

- `SEKAI_TARGET` (defaults to `http://127.0.0.1:50051`)
- `SEKAI_AUTH_TOKEN` when the control plane requires bearer authentication
- `EVIDENCE_PRODUCER_IDENTITY`
- `EVIDENCE_SOURCE_INSTANCE`
- `EVIDENCE_NAMESPACE`
- `EVIDENCE_TARGET_EXTERNAL_ID`
- `EVIDENCE_TARGET_KIND`
- `EVIDENCE_CLASSIFICATION` (defaults to `internal`)

The GitHub adapter uses evidence type `source_control.check_run` and schema
`adapter.github.check_run@1.0.0`:

```sh
cargo run --example evidence_github_check_webhook < check_run.json
```

The health adapter uses evidence type `operations.health_snapshot` and schema
`adapter.http.health_snapshot@1.0.0`. It also requires `HEALTH_ENDPOINT` and
`HEALTH_SOURCE_RECORD_ID`; `HEALTH_EVIDENCE_TTL_MS` defaults to five minutes:

```sh
cargo run --example evidence_http_health_poll
```

Conformance fixtures live in `adapters/fixtures/` and run without network access
through `cargo test --test evidence_adapters`.
