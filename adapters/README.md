# External reference adapters

Discovery of built-in adapter profiles and families is available through gRPC
`SekaiService.ListEvidenceAdapters` and
`sekai_chisei::evidence_adapter_catalog` (control-plane scope, not tenant). See
[evidence-adapter-catalog.md](../docs/evidence-adapter-catalog.md).

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
- `evidence_social_post_snapshot` and `evidence_social_reply` map bounded social
  observation documents into `social.post_snapshot` and `social.reply` evidence.
  Collection (manual export, webhook fan-in, external poller, or CLI) stays
  outside the control plane; see
  [social-evidence-adapters.md](../docs/social-evidence-adapters.md).

The evidence adapters use `sdk.rs` to build the canonical `sekai.evidence/v1` envelope, calculate
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

The social adapters use evidence types `social.post_snapshot` /
`social.reply` and schemas `adapter.social.post_snapshot@1.0.0` /
`adapter.social.reply@1.0.0`. Target the durable publication or post external
id the product already owns; do not point the funnel at raw network credentials:

```sh
cargo run --example evidence_social_post_snapshot \
  < adapters/fixtures/social_post_snapshot.7d.json
cargo run --example evidence_social_reply \
  < adapters/fixtures/social_reply.sample.json
```

Conformance fixtures live in `adapters/fixtures/` and run without network access
through `cargo test --test evidence_adapters`.

## GitHub object sync

`github_object_sync.rs` is the fixed source adapter for normalized GitHub Issue
and PullRequest fixtures. It is not an evidence adapter and does not appear in
`ListEvidenceAdapters`. Issues and pull requests share the repository number
identity `github:<owner>/<repository>#<number>`. The normalizer rejects other
kinds, foreign repositories, invalid revisions or numbers, secret-like
properties, raw/unknown fixture fields, and oversized input.
The content digest excludes `observed_at_ms`, so polling the same immutable
source revision later does not manufacture a source-content conflict.

`object_sync_sdk.rs` builds and serializes `sekai.source-batch/v1`. Its local
outbox writes the exact normalized batch under a cross-process lock with
no-replace publication and directory fsync before calling a transport. The SDK
accepts only the code-owned `sekai.source-type-revision/v1` GitHub
Issue/PullRequest digest
`sha256:97a329c80d00af0525c6076aef9f8162471eee9c108cefae42f68a8309fb708a`.
Replay order is deterministic, and only one distinct unresolved batch may
exist for a namespace/source-instance/type-revision binding; exact re-enqueue
remains idempotent.
Unknown delivery outcomes and mismatched commit replies stay pending; only an
exact committed batch digest, idempotency key, and checkpoint cursor remove an
entry. Rejected batches may move to a bounded quarantine with a value-free
reason code. The SDK has no credential or bearer-metadata fields and persists
neither source payload bodies nor remote response bodies.

A transport maps the dependency-light callbacks to
`SekaiService.ApplySourceBatch` and `SekaiService.GetSourceSyncState`:

```rust
let record = github_object_sync::translate(fixture, "sannrox/sekai-chisei")?;
let batch = object_sync_sdk::build_source_batch(
    &config,
    &committed_cursor,
    &proposed_cursor,
    collected_at_ms,
    vec![record],
)?;
let outbox = object_sync_sdk::SourceOutbox::open(
    "data/source-adapter-outbox",
    object_sync_sdk::OutboxLimits::default(),
)?;
outbox.enqueue(&batch)?;                 // durable write before RPC
outbox.flush(&mut rpc_transport, true)?; // callback applies the source batch
let state = rpc_transport.get_source_sync_state(
    &object_sync_sdk::GetSourceSyncStateInput {
        namespace: config.namespace.clone(),
        source_instance: config.source_instance.clone(),
        type_digest: config.type_digest.clone(),
    },
)?;
```

The surrounding process injects authentication into its RPC client in memory;
it must not pass credentials to the adapter config or outbox. Snapshot,
change-feed, and webhook collection transports remain separate follow-up work.
Offline conformance runs through:

```sh
cargo test --test object_sync_adapters
```

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
