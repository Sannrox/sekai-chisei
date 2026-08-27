# Inspectable reversible learning changes

Issue: [#714](https://github.com/Sannrox/sekai-chisei/issues/714)  
Decision: [ADR 0043](decisions/0043-reversible-learning-changes.md)

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
