# Bounded source health

Issue: [#685](https://github.com/Sannrox/sekai-chisei/issues/685)  
Decision: [ADR 0046](decisions/0046-bounded-source-health.md)

Source health is a `sekai.source-health/v1` projection of authorized object-sync
state. It reports checkpoint age, lag, last success, and a bounded failure
class. It does not write, advance a checkpoint, probe a remote connector, or
store credentials.

`GetSourceHealth` (#2193, `experimental`) returns one source's projection.
It authorizes as `GetSourceSyncState`: read on the namespace and a type the
namespace admits. Another tenant's namespace is refused; within the tenant a
namespace the caller may not read reports as an unknown source. Every call
is audited as `source.health` under the caller's credential.

```text
sekaictl admin sync health --namespace acme --source-instance owner/repo \
  --type-digest sha256:<github-object-sync-type-digest> [--target <url-or-socket>]
```

The CLI reads through `GetSourceHealth` on a running plane with
`SEKAI_EXPERIMENTAL_RPCS=1` (`--target`, else `CHISEI_GRPC_URL`, else
`SEKAI_SOCKET`). `--actor` is retired: the plane audits the credential.

[Ontology health](ontology-health.md) scores the namespace's visible sources
as its `source` part.

Classes are `healthy`, `delayed`, `blocked`, and `unavailable`. Hidden and
unknown sources share one unavailable result. Unknown versions, foreign
identity, invalid checkpoints, and ambiguous lifecycle fail closed before any
mutation. Replay of the same durable state is identical. Restart reads the
current checkpoint. Audit records class, namespace, failure class, and
outcome, not cursors. SQLite and reusable PostgreSQL share
`get_source_sync_state` and the same in-process projector.

Inspect the latest quarantined result and preview a correction without a second
write plane. See [source quarantine](source-quarantine.md) and
[ADR 0061](decisions/0061-quarantine-repair-preview.md).
