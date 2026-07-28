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

## Local typed adapter

The fixed software-release adapter accepts only the fields in the checked-in
[example fixture](../tests/fixtures/governed_subject/software-release-candidate-v1.json):

```bash
sekaictl governed-subject software-release \
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
