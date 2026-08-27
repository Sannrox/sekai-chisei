# Bounded source health

Issue: [#685](https://github.com/Sannrox/sekai-chisei/issues/685)  
Decision: [ADR 0046](decisions/0046-bounded-source-health.md)

Source health is a `sekai.source-health/v1` projection of authorized object-sync
state. It reports checkpoint age, lag, last success, and a bounded failure
class. It does not write, advance a checkpoint, probe a remote connector, or
store credentials.

```text
sekaictl admin sync health --namespace acme --source-instance owner/repo \
  --type-digest sha256:<github-object-sync-type-digest>
```

Classes are `healthy`, `delayed`, `blocked`, and `unavailable`. Hidden and
unknown sources share one unavailable result. Unknown versions, foreign
identity, invalid checkpoints, and ambiguous lifecycle fail closed before any
mutation. Replay of the same durable state is identical. Restart reads the
current checkpoint. Audit records class, namespace, failure class, and
outcome — not cursors. SQLite and reusable PostgreSQL share
`get_source_sync_state` and the same in-process projector.
