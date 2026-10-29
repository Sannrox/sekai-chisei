# ADR 0140: Object-set inputs for governed transforms

- Status: accepted
- Date: 2026-10-29
- Owners: @Sannrox
- Discussion: none, resolved in Issue #1958
- Issue: #1958
- Supersedes: none
- Superseded by: none
- Related: [ADR 0086](0086-object-set-is-its-descriptor.md),
  [ADR 0066](0066-object-set-evaluate.md),
  [ADR 0102](0102-isolated-process-transform-profile.md),
  [ADR 0138](0138-caller-scoped-ad-hoc-transform-runs.md)

## Context

A governed transform reads datasets only. Data that lives as objects reaches
a transform only through an export into a dataset, which needs an export
grant and loses the per-run read check against the principal a run reads
as. ADR 0086 keeps the durable form of an object set as its descriptor and
stores no member list; it names a run-scoped member artifact as the kind of
named consumer that needs its own decision. A transform input that must be
replayed is that consumer.

## Decision

1. **An input names a descriptor.** A transform input carries either a
   dataset or an inline object-set descriptor with its alias. The definition
   digest covers the descriptor; a definition with dataset inputs only keeps
   its digest, since the new field is left out when absent.
2. **Read as the run's principal.** Put and preview evaluate the set as the
   caller. A stored definition records the principal that put it, and every
   run evaluates its object sets as that principal; an ad-hoc run (ADR 0138)
   evaluates them as its caller. Evaluation applies exactly the read policy
   of `EvaluateObjectSet`: objects the principal may not read are left out,
   and a kind or namespace the principal may not read at all refuses the
   put, preview or run with `permission_denied`.
3. **Rows from objects.** Each object becomes one row: `id`, `name`, then its
   readable properties in name order. Properties the principal may not read
   are absent, as in a read. The column order is stable, so workers that
   consume rows keep working.
4. **Pinned per run, not per set.** A run evaluates its sets once, at
   admission, and keeps the rows in its input snapshot, as it does for
   dataset inputs. `input_versions` records a digest of each set's rows under
   its alias. This is a run's input record, not a stored set: no set identity
   or member list outlives the run outside its snapshot, and ADR 0086 holds
   for object sets themselves. The snapshot is bounded by the existing input
   budget.
5. **Replay re-authorizes.** A replay reads the pinned rows, so the result
   does not drift with later object changes. It first checks that the
   replaying principal may still read every pinned object; if not, the
   replay is refused rather than silently changing its input.
6. **Markings follow the objects.** The markings of the objects read join
   `markings_in` and reach `markings_out`, as a dataset's object marking
   does; restricted properties a principal may not read are not in its rows.
7. **Workers opt in.** Isolated-process work with an object-set input is
   placed only on runtimes that registered the label
   `sekai.input.object-set=v1`, through the existing placement requirement
   (ADR 0102). A worker that does not understand object-set inputs never
   sees such work, instead of reading an empty input. `ReadTransformRunInputs`
   streams the pinned rows under the input's alias.
   `DiscoverCapabilities` reports `sekai.transforms.object-set-inputs`.

Delivery is in layers: the input contract, evaluation and pinning with the
in-process path; the isolated-process claim path, where the admitted input
snapshot keeps the set's rows under its pin key; and replay. The first layer
reads plain sets (no aggregation or traversal) over unindexed kinds, needs a
dataset input beside them, and refuses object-set inputs on a definition with
a schedule or trigger, which runs with no caller to read the set as. The
putter's reader record names the definition digest it put, so a run of any
other definition finds no reader. A deployment with an enterprise extension
reads only with an authenticated context, which a stored run does not keep
for its putter; there, stored runs with object-set inputs are refused and an
ad-hoc run reads the set as its caller. Until replay lands, a retried
ad-hoc identity reads its sets again as its caller before it returns the
committed run, and returns it only when each set's digest matches the pin:
the run keeps row digests, not members, so an unchanged digest is the check
that the caller still reads every pinned object. A set that changed, or no
longer reads, refuses the retry. An empty set keeps the columns its kind
declares. Restricted properties stay out of every reader's rows in this
layer, and a set may not filter on one: their classifications have no
marking that would carry them into the output. Branch runs, and any path
that cannot evaluate a definition's object sets, refuse it. Rows carry
stored properties, not computed ones, whose dependency reads and
classifications this layer cannot bound. The budget bounds a set's read
before the run starts.

## Alternatives considered

- Export into a dataset first. Rejected: a manual step that needs an export
  grant and loses the per-run read check.
- Evaluate live on every read of a run. Rejected: a replay would drift and
  a worker's reads would disagree with admission.
- A stored set identity shared across runs. Rejected for the reasons of ADR
  0086; the pin belongs to the run.

## Consequences

Transforms can join objects with datasets under object-level read policy.
Runs keep more input in their snapshots, within the input budget. A stored
definition's object-set inputs depend on its putter's continued access.
Stored runs keep the object-set rows they read, keyed by digest, so replay
can read them: the copy outlives a later change or deletion of its objects.
A replay refuses such an object, as it cannot read it again, but the copy
stays at rest; removing a deleted object's pinned rows (the rows carry its
id) is follow-up work, as is expiring pins with dataset version retention.
Live or incremental object-set inputs, and writing objects back, stay out of
scope.

## Validation

Tests on both community backends: a SQL transform joining a dataset and an
object set produces the expected rows and a receipt naming both pinned
inputs; a principal with partial access sees only readable objects, and one
without access to the kind is refused at put, preview and run; a marked
object marks the output and receipt; an isolated run reads the pinned rows
matching `EvaluateObjectSet` for the same principal; a replay reads the
pinned rows after the objects change; dataset-only definition digests are
unchanged over stored fixtures.
