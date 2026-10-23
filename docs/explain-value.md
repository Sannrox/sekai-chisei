# Explaining a property value

`ExplainValue` is an experimental RPC that answers "why is this value here?"
for one object property. It is classified `experimental`
([rpc-maturity.md](rpc-maturity.md)) and is rejected unless
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is enabled.

## Request

`object_id`, `property` (an object property or `name`), and `as_of_ms`. With
`as_of_ms` 0 the current value is explained; otherwise the value at that time.
A time before the object was created, or while it was deleted, reads as not
found.

The caller needs the same access as `ListObjectChanges`: namespace,
collaboration scope, object ACL, active read policy and marking. A property
the active policy does not grant is refused. Values are redacted as
`ListObjectChanges` redacts them. A write between the access check and the
history read aborts the request, to be retried, so no row escapes the check
that admitted it. Guest and shared-space callers, who see
filtered history, are refused: a write hidden from them would read as a gap.

## Chain

The chain is the history of the writes that set the property, oldest first,
read from the object's change rows. Every row carries the writer recorded with
it: a source transaction, a transform run at a checkpoint, an Action
instance, a direct write, or nothing. A row without a writer reads as
`unattributed` and is never inferred. Creation writes no property rows, so a
value set at creation starts with the creation row.

Each step names its writer kind, reference and receipt and joins the writer's
record into `details`:

| Writer | Details | Who may read them |
| --- | --- | --- |
| `source_transaction` | source binding, producer, batch status and outcome, and the object's source record (id, version, outcome) | the source's producer with namespace access, or a credential admin |
| `transform_run` | transform, definition digest, checkpoint, trigger, input and output markings | readers of the run's datasets, as `GetGovernedTransformRun` |
| `action_instance` | type and version, principal and delegating actor, status, policy and approval decisions | readers of the instance, as `GetActionInstance` |

A step whose record the caller may not read, or whose record is gone, is
reported as `hidden`. It keeps its time, field, value and writer kind, but no
reference, receipt, actor or details. `complete` is true only when no step is
hidden or unattributed and the value was recorded. Creation rows do not
copy property values (they do record the name), so the value an earlier incarnation of a deleted and
re-created object was created with is not recorded when no edit followed it;
it reads empty and incomplete. When retention has purged the creation row,
the chain starts at the oldest row kept and is incomplete.

`marking` and `marking_steps` explain the object's access marking at the same
time in the same way. Transform marking stamps are change rows attributed to
their run, so a stamped marking explains as the run that stamped it.
