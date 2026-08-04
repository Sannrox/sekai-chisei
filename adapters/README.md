# External evidence reference adapters

These programs demonstrate the adapter boundary without adding vendor clients to
the Sekai core:

- `evidence_github_check_webhook` accepts one GitHub `check_run` webhook payload
  on stdin. Collection and webhook authentication remain the responsibility of
  the surrounding webhook receiver.
- `evidence_http_health_poll` performs one bounded HTTP GET against a health
  endpoint and translates the response into expiring operational-health
  evidence.
- `evidence_ontology_concept_catalog` maps one structured concept-catalog
  document into `ontology.concept_catalog` evidence for governed
  ontology-definition proposals (#147). Extraction and review stay in Sekai
  core; the adapter never mutates definitions.

All three use `sdk.rs` to build the canonical `sekai.evidence/v1` envelope, calculate
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
- `SEKAI_CREDENTIAL` when the control plane requires bearer authentication
- `EVIDENCE_PRODUCER_IDENTITY`
- `EVIDENCE_SOURCE_INSTANCE`
- `EVIDENCE_NAMESPACE`
- `EVIDENCE_TARGET_EXTERNAL_ID`
- `EVIDENCE_TARGET_KIND`
- `EVIDENCE_CLASSIFICATION` (defaults to `internal`)

The GitHub adapter uses evidence type `source_control.check_run` and schema
`adapter.github.check_run@1.0.0`. Because GitHub timestamps do not provide a
strict event sequence, distinct same-second payloads are retained as separate,
attributable observations instead of being forced into a false version order:

```sh
cargo run --example evidence_github_check_webhook < check_run.json
```

The health adapter uses evidence type `operations.health_snapshot` and schema
`adapter.http.health_snapshot@1.0.0`. It also requires `HEALTH_ENDPOINT` and
`HEALTH_SOURCE_RECORD_ID`; `HEALTH_EVIDENCE_TTL_MS` defaults to five minutes:

```sh
cargo run --example evidence_http_health_poll
```

The concept-catalog adapter uses evidence type `ontology.concept_catalog` and
schema `adapter.ontology.concept_catalog@1.0.0`. After admission, ontology
admins call `ProposeOntologyDefinitions` (prefer `dry_run=true` first) and
`ReviewOntologyDefinitionProposal`:

```sh
cargo run --example evidence_ontology_concept_catalog \
  < adapters/fixtures/ontology_concept_catalog.service.json
```

Conformance fixtures live in `adapters/fixtures/` and run without network access
through `cargo test --test evidence_adapters`.

Authorized consumers can inspect one admitted submission by ID through
`GetEvidenceSubmission`. The response is bounded metadata and lifecycle
history; payload content remains inside the governed evidence projection and is
not exposed through a second public read endpoint. `ListEvidenceSubmissions`
remains metadata-only and bounded.

`batch_responses_harness.rs` is a headless batch-evaluation integration. It uses
an independent Responses SSE decoder against the complete canonical harness
fixture corpus, then maps terminal runs into the same operation-receipt and
external-evidence contracts as interactive harnesses. Its conformance suite runs
with `cargo test --test batch_harness_conformance`. The runnable target reads a
Responses SSE stream from standard input and emits the assembled terminal result:

```sh
cargo run --example batch_responses_harness < response.sse
```

Host executors reporting redeemed external actions use the same SDK and outbox.
See [external-action execution evidence](../docs/external-action-execution.md)
for the lifecycle schema, permit verification, and reconciliation contract.
