# Governed subject evaluation

`EvaluateGovernedSubject` evaluates an externally owned immutable subject
without sending its payload to Chisei. The authenticated caller supplies a
versioned profile, opaque identity, canonical SHA-256 content digest, bounded
opaque evidence references, and a registered evaluation profile. Chisei
validates the profile, makes a fixed-vocabulary decision, and persists the
binding and result on the canonical operation receipt.

The result decision is one of `allow`, `deny`, `unavailable`, or `unknown`.
Failures use bounded codes and sanitized messages. `GetOperationReceipt` is the
authoritative reconciliation path after a timeout or interrupted submission;
the submission response and process exit state are not decision authority.

## Registered profiles

- `example.software-release-candidate/v1` requires one each of
  `source_tree`, `manifest`, `artifact`, and `build_definition`.
- `example.policy-bundle/v1` requires one each of `policy_document` and
  `policy_schema`.

The profiles allow only the named reference kinds. References are opaque local
identifiers, never URLs or filesystem paths. Unknown versions, profiles,
evaluation profiles, unregistered reference kinds, duplicate references,
incomplete profiles, oversized values, malformed digests, and future
observations fail closed. Stale evidence returns a bounded `unknown` result.

The initial registered evaluation profiles are deterministic conformance
profiles:

- `chisei.subject-evaluation/allow/v1`
- `chisei.subject-evaluation/deny/v1`
- `chisei.subject-evaluation/unavailable/v1`
- `chisei.subject-evaluation/timeout/v1`

Profile registration is compiled into the control plane, and these initial
conformance evaluators require the `root` or local administrative principal.
An ordinary namespace writer cannot select an `allow` outcome. Future
non-conformance profiles must execute a trusted server-side evaluator rather
than encode a desired decision in caller input. Callers cannot upload
validators, add receipt attributes, grant execution authority, or turn a
subject decision into an external-action permit.

## Plan-backed software release evaluation

`EvaluateGovernedSubjectWithPlan` is a separate additive entry point for
`example.software-release-candidate/v2`. It does not reinterpret the existing
v1 subject or fixed conformance evaluation profiles. The request binds an
opaque release-candidate identity, its canonical content digest, one exact
immutable `plan_version_id`, authorized evidence-object identities, an explicit
evaluation time, and a bounded total execution duration. The RPC requires an
authenticated namespace writer.

This is a software-release situation adapter, not a generic evaluation
workflow. Its selected plan may use only the already governed bounded DAG,
typed inputs, exact immutable evaluator implementations, required/advisory
classification, and the fixed fail-closed reducer. Other subject families must
introduce their own versioned profile contract, invariant vocabulary, evidence
schemas, plans, and compiled evaluators. They do not inherit release semantics.

The complete decision trace is:

1. Authenticate and authorize the namespace before looking up the plan.
2. Validate the v2 release profile and bind the subject identity/content
   digest plus the exact request inputs.
3. Resolve the exact plan against the authorized Sekai invariant-set snapshot
   at `evaluation_time_ms`. There is no `latest` plan or invariant fallback.
4. Freeze the plan digest, invariant-set digest, exact invariant and waiver
   versions, evaluator definition and implementation digests, and admitted
   evidence into a resolved manifest.
5. Execute that manifest through the exact compiled deterministic evaluators.
   The manifest digest is the execution idempotency identity.
6. Reduce step receipts with the fixed reducer and map the terminal gate
   verdict into a plan-backed governed-subject decision.
7. Persist the decision on a canonical operation receipt whose parent is the
   evaluation-execution operation. The receipt, not the RPC response, is the
   reconciliation authority.

The returned decision contains bounded identity-only explainability: plan,
manifest, invariant-set, execution, gate-decision, step-receipt, and
covered/waived/uncovered invariant identities or digests. It contains no
subject payload or protected evidence content. The governed receipt references
the subject, plan, invariant set, manifest, execution, and every step digest;
the manifest and execution receipt provide the forward trace to exact
invariants, waivers, evaluators, evidence digests, step results, and the gate
decision. The governed receipt's `parent_operation_id` points back to the
execution receipt. `GetOperationReceipt` reads both receipts with normal
namespace authorization.

Required evaluator failure maps to `deny`. Missing, stale, inaccessible,
subject-mismatched, or unbound evidence; an incomplete or uncovered invariant
set; and insufficient information map to `unknown`. Disabled, absent,
unsupported, timed-out, capacity-exhausted, or failed evaluator execution maps
to `unavailable` unless a required failure already requires `deny`. Only a
complete invariant set where every gate-blocking invariant passed through a
required node or has an exact valid waiver can produce `allow`.

Retries with the same actor, namespace, and request ID return the first durable
governed decision; changed bindings conflict. Requests that independently
resolve to the same manifest reuse its execution operation and gate decision,
so they cannot produce a conflicting deterministic verdict. External reporter
APIs cannot append to either execution receipts or plan-backed governed
decision receipts.

SQLite and PostgreSQL use the same manifest, execution-index, and canonical
receipt contracts. No plan-backed-only decision table exists: the operation
receipt remains authority, avoiding a second mutable decision record.

Operational rollback disables this one additive RPC at the server/gateway or
disables the affected evaluator definitions for future resolution. Existing
v1 calls continue unchanged. Immutable plans, manifests, execution receipts,
and governed decision receipts remain readable; rollback must not delete their
tables or referenced Sekai facts/evidence. Restoring a backup must preserve
their exact content digests and operation identities.

## Local typed adapter

The fixed software-release adapter accepts only the fields in the checked-in
[example fixture](../tests/fixtures/governed_subject/software-release-candidate-v1.json):

```bash
sekaictl admin governance subject software-release \
  tests/fixtures/governed_subject/software-release-candidate-v1.json \
  --namespace default \
  --request-id release-v1.2.3
```

The adapter derives the subject identity from every typed field. Changing the
revision, source-tree digest, manifest digest, artifact reference, artifact
digest, or build-definition digest changes that identity. It sends no source,
artifact payload, repository path, prompt, credential, or raw tool output.

An identical retry returns the original operation and receipt digest. Reusing
the same actor, namespace, and request ID with any changed identity, content
digest, reference, evaluation profile, or other binding returns an idempotency
conflict.

Reference observation time is validated for freshness and the first accepted
timestamp is retained on the receipt, but it is not subject identity. A client
retry may reconstruct the same reference at a later wall-clock instant without
changing the original authoritative evidence time.

After an interrupted submission, reconcile by the original request ID and its
actor/namespace scope:

```bash
sekaictl receipt release-v1.2.3 --request-id \
  --scope governed-subject:7:default:local
```

The decimal component is the UTF-8 byte length of the namespace, making the
namespace/actor boundary unambiguous even when either value contains `:`.

## Authenticated Tenkai provenance

`ExportGovernedSubjectProvenance` is a separate, situation-specific bridge from
one completed v1 software-release receipt to Tenkai's compiled
`example.governed-subject-receipt/v1` admission profile. It is not an arbitrary
receipt-signing service and does not apply to policy bundles, plan-backed v2
decisions, caller-defined profiles, or caller-supplied metadata.

The authenticated namespace writer supplies an export ID, operation ID, and the
expected subject, manifest, artifact, and receipt digests. Before signing,
Chisei reloads the canonical receipt and requires:

- the exact completed `governed_subject_evaluation` operation and receipt
  schema;
- an authoritative, still-fresh `allow` result;
- the software-release v1 subject identity;
- matching manifest and artifact references and content digests; and
- the exact current canonical receipt digest.

Chisei derives Tenkai's release `content_digest` from the manifest and artifact
digests using Tenkai's domain-separated canonical encoding. It does not reuse
the broader Chisei subject digest, whose meaning includes every typed release
candidate field. The signed envelope contains only Tenkai's fixed fields, one
operation reference to the reconciled receipt, observation/expiry times, and an
Ed25519 signature from issuer `sekai-chisei`.

After evaluating the checked-in fixture, copy the returned operation and
receipt digests into the export command:

```bash
sekaictl admin governance subject provenance export \
  tests/fixtures/governed_subject/software-release-candidate-v1.json \
  --operation-id governed-subject-<digest> \
  --receipt-digest sha256:<receipt-digest> \
  --export-id tenkai-release-v1.2.3 \
  --output governed-subject.json

sekaictl admin governance subject provenance trust-root \
  --export-id tenkai-release-v1.2.3 \
  --output provenance-trust.toml
```

The JSON file is the strict Tenkai envelope. The TOML file has Tenkai's
`version = 1` trust-root shape and contains only the derived key ID, issuer
identity, and public key. Neither API nor CLI exposes the signing seed.

Export IDs are immutable within the authenticated principal's scope. An exact
retry returns the first durable envelope; changed bindings conflict. The
server commits the export before responding, so a client interrupted after
commit safely reconciles by repeating the same command. Once an envelope
expires, replay fails closed and the operator must use a new export ID after
fresh governed evaluation.

Exports live in a dedicated append-only persistence surface with equivalent
SQLite and PostgreSQL implementations. They are not generic Sekai objects and
cannot be created, updated, or deleted through object CRUD APIs.

Rotate keys by configuring a new seed and activation window for future export
IDs. Each durable export stores its matching public key, so `trust-root
--export-id` continues to return the historical root required for that exact
envelope after server rotation. Tenkai accepts one `sekai-chisei` root per
trust file; publish an envelope with the root retrieved for that export.
Retiring a key stops new issuance, while envelope expiry bounds acceptance of
already issued evidence.

The export is evidence only. It grants no release, promotion, gate, delivery,
or external-action authority; Tenkai independently authenticates and admits it
against the exact manifest and artifact tree.

Operational rollback removes or retires the signing key and disables the two
additive provenance RPCs. It must retain the append-only export table so prior
envelopes and their historical public roots remain reconcilable.
