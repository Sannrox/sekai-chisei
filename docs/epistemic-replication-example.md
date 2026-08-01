# Epistemic replication example

`epistemic_replication` is a local, deterministic adapter fixture for the
epistemic work. It keeps the domain vocabulary in the versioned package at
[`examples/epistemic-replication/profile-v1.json`](../examples/epistemic-replication/profile-v1.json)
and uses only existing control-plane contracts.

## Run the fixture

From the repository root:

```bash
cargo run --locked --example epistemic_replication
cargo test --locked --test epistemic_replication_example
```

No server, provider, credential, network, or external model is required. The
report is JSON and contains only bounded identities, digests, lifecycle labels,
policy actions, receipt references, per-case receipt/outcome digests, and
normalized evaluation counters. The fixture does not require a portable
ontology database; the example's versioned domain package is registered through
the generic schema API. If you are auditing a repository ontology separately,
initialize and validate that database with the `sekai` CLI before relying on it.

## What the command applies

1. The adapter parses the versioned package and registers the eight domain
   classes (`ResearchQuestion`, `Claim`, `Protocol`, `ExperimentRun`,
   `Replication`, `Observation`, `Outcome`, and `Context`) through the generic
   schema registry. These names do not become core protocol types or durable
   domain tables.
2. It seeds one claim with fixed protocol and artifact identities, plus two
   independently attributed result objects. The evidence adapter admits and
   projects supporting and contradicting results, then admits lifecycle markers
   that produce stale and retracted source states. Insufficient evidence is a
   deliberate no-admission fixture.
3. Complete generic receipts are used to derive a contested Kioku candidate
   with exact supporting and contradicting evidence links. A local human review
   promotes it, then the existing evidence-reassessment surface binds the
   admitted submission identities and creates a successor. A second explicit
   review promotes that provenance-bound candidate to `active`; the original
   version remains superseded rather than silently rewritten.
4. The fixed claim digest is bound into a persisted, domain-local evaluation
   plan/manifest. The adapter publishes the evaluator and plan through the
   control-plane boundary, resolves a real governed invariant, executes the
   immutable manifest, and reads the canonical step/gate receipt back from the
   execution index.
5. The artifact identity is independently checked through the existing
   software-release governed-subject reference shape: a digest of the fixture
   source plus schema, protocol manifest, artifact, and evaluation plan
   build-definition references are all exact and fresh. This generic artifact
   decision is intentionally separate from the research-claim evaluation; no
   research profile is added to core.
6. Six payload-free #492 cases are compared through the existing
   `claim_only`/`epistemic_framed` evaluator. Both arms use the same authorized,
   post-review memory version and source state; only their explicit admission
   policy configuration differs. The report includes the exact arm
   configuration identities, fixture digest, receipt/outcome digests, metrics,
   and fail-closed regression gate.

The example is intentionally an adapter-shaped executable fixture. Adding a
scientific domain resource, endpoint, table, or workflow engine to core would
violate the boundary this issue is meant to demonstrate.
