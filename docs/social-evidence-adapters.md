# Social observation evidence adapters

Reference adapters for fixed-window post metrics and reply observations.
Collection stays outside Sekai core; these programs only normalize a document
into the evidence funnel:

```text
collector document (stdin)
  → translate / validate
  → sekai.evidence/v1 envelope + local outbox
  → SubmitEvidence
  → admission / projection
```

They never invoke BirdClaw, the X API, or any social client. A manual export,
webhook receiver, or external poller can feed the same JSON shapes. Stdin is
the same reference edge used by the GitHub and ontology catalog adapters—not a
customer product surface.

## Evidence types

| Type | Schema id | Schema version | Document fixture |
| --- | --- | --- | --- |
| `social.post_snapshot` | `adapter.social.post_snapshot` | `1.0.0` | `adapters/fixtures/social_post_snapshot.7d.json` |
| `social.reply` | `adapter.social.reply` | `1.0.0` | `adapters/fixtures/social_reply.sample.json` |

### `social.post_snapshot`

Required fields:

- `post_id` — network post identifier
- `window` — `24h` or `7d`
- `observed_at` — RFC 3339 collection/observation time
- `metrics` — exactly `impressions`, `likes`, `replies`, `reposts`, `quotes` (non-negative integers)

Optional provenance:

- `source_system` — defaults to `manual` (for example `manual`, `birdclaw`, `x_activity`)
- `account` — public handle or account label (never credentials)

Generated digests (`source_system` of `birdclaw_digest` / `generated_digest`) are rejected.

Source identity:

- `source_record_id` = `post_id`
- `source_version` = `{window}-complete-v1`
- `source_sequence` = `1` for `24h`, `2` for `7d`

### `social.reply`

Required fields:

- `reply_id`, `parent_post_id`, `author_reference`, `text`, `created_at` (RFC 3339)

Optional:

- `collected_at` (defaults to `created_at`)
- `public_metrics` subset of the snapshot metric names
- `source_system`, `account`

Reply `text` is untrusted remote content (`content_trust=untrusted_remote_text`
in provenance). It must not be executed as instructions or policy.

Source identity:

- `source_record_id` = `reply_id`
- `source_version` = `1`
- `source_sequence` = `1`

## Producer registration

Before submit, register a producer and exact schemas through the evidence
control-plane API. Suggested operator values:

| Field | Example |
| --- | --- |
| `EVIDENCE_PRODUCER_IDENTITY` | `social:observation-funnel` |
| `EVIDENCE_SOURCE_INSTANCE` | account or collector instance label |
| `EVIDENCE_NAMESPACE` | product or ops namespace |
| `EVIDENCE_TARGET_KIND` | publication or post kind the product uses (for example `hibiki.publication`) |
| `EVIDENCE_TARGET_EXTERNAL_ID` | durable publication / post external id in that namespace |
| `EVIDENCE_CLASSIFICATION` | often `public` for network-visible metrics |

The producer must be allowed to submit both evidence types against the chosen
namespace, source instance, target kind, classification, and `upsert` intent.

## Run

```sh
export SEKAI_TARGET=http://127.0.0.1:50051
export EVIDENCE_PRODUCER_IDENTITY=social:observation-funnel
export EVIDENCE_SOURCE_INSTANCE=example_handle
export EVIDENCE_NAMESPACE=acme
export EVIDENCE_TARGET_EXTERNAL_ID=publication:example-1
export EVIDENCE_TARGET_KIND=hibiki.publication
export EVIDENCE_CLASSIFICATION=public

cargo run --example evidence_social_post_snapshot \
  < adapters/fixtures/social_post_snapshot.7d.json

cargo run --example evidence_social_reply \
  < adapters/fixtures/social_reply.sample.json
```

Conformance (no network):

```sh
cargo test --test evidence_adapters
```

## Non-goals

- Publishing to a social network
- Holding network credentials
- Storing full account history in the graph
- Treating model-generated digests as observations
- Hosted multi-tenant webhook gateway as core product surface

Collectors (manual JSON, webhook receivers, BirdClaw, X Activity) remain
outside this repository's control plane. They feed these adapters or submit
equivalent envelopes.
