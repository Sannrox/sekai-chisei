# Inspectable reversible learning changes

Issue: [#714](https://github.com/Sannrox/sekai-chisei/issues/714), pinned on
plans by [#1091](https://github.com/Sannrox/sekai-chisei/issues/1091)  
Decision: [ADR 0043](decisions/0043-reversible-learning-changes.md),
[ADR 0085](decisions/0085-governed-learning-changes-context-only.md)

A recorded learning candidate is not adoption. Activation requires a
`chisei.learning-change/v1` record that binds baseline, candidate, and evidence
digests. Approval and activation are explicit. Rollback supersedes history and
does not rewrite the source learning object.

```text
sekaictl admin learning propose --namespace payments --learning-id learning-1 \
  --evidence-digest sha256:...
sekaictl admin learning inspect --namespace payments --learning-id learning-1
sekaictl admin learning approve --namespace payments --learning-id learning-1
sekaictl admin learning activate --namespace payments --learning-id learning-1
sekaictl admin learning rollback --namespace payments --learning-id learning-1
```

Stale, hidden, unknown, or lease-lost inputs return the same unavailable
result. Lease loss is an explicit reconciliation state and blocks later
approval or activation. SQLite is the reference store. PostgreSQL stays
unavailable.

## Pin an active learning on the next plan

A verification that recorded a learning closes the loop when a later
`PlanExecution` pins it. Bind the learning to the evidence of the verification
(for example the digest of the verified operation's receipt), approve it, and
activate it, then pass the approved digest on the next plan:

```text
sekaictl admin learning propose --namespace payments --learning-id learning-1 \
  --evidence-digest sha256:<verification-evidence>
sekaictl admin learning approve  --namespace payments --learning-id learning-1
sekaictl admin learning activate --namespace payments --learning-id learning-1
```

```json
{
  "input": {
    "namespace": "payments",
    "spec": "review the retry path",
    "learning_pin": {
      "learning_id": "learning-1",
      "candidate_digest": "sha256:<candidate_digest from propose>"
    }
  }
}
```

A pinned learning changes **context only**. Its bounded title and prevention
text is added to the plan's context as untrusted data after routing and
review-policy decisions, so it cannot influence them. The route, tools, policy,
and budget are exactly what they would be without the pin, and the reasoning
and target of the learning are not disclosed. Ordinary disclosure rules still
apply: the caller must be able to read the learning object, and on a route that
may not receive its text (an external provider unless the learning's
`chisei.egress.external_properties` names both `title` and `prevention`, which
is part of the approved digest) the pin is refused instead of dropped.

The plan carries `learning_references`, and the plan receipt's context event
cites the learning change ID, the approved candidate digest, the verification
evidence digest, and the source request, so the lineage reads operation,
verification, learning, plan. The receipt never copies the learning text.

Every unusable pin fails closed with one non-disclosing error,
`FAILED_PRECONDITION: learning pin is unavailable`: a proposed or approved but
not yet active learning, a rolled-back one, a wrong digest, a learning whose
content changed after approval, an unknown learning, another namespace, a
learning under lease-loss reconciliation, a learning the caller may not read or
the selected route may not receive, the PostgreSQL community runtime, and the
template-only sanitization contract. A caller without access to the
namespace is refused before any learning is considered. `rollback` disables the
learning for later plans immediately. The eval-owned context-expansion gate
guards automatic retrieval and does not apply to an explicit pin.
