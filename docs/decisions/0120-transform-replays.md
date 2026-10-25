# ADR 0120: Transform replays run on a fresh branch over pinned versions

- Status: accepted
- Date: 2026-10-22
- Owners: @Sannrox
- Discussion: none (resolved in Issue #1585)
- Issue: #1585
- Supersedes: none
- Superseded by: none
- Related: [ADR 0119](0119-dataset-branches.md)

## Context

Incident analysis and change review need to re-run a pipeline as of earlier
input versions, or with a changed transform, and see what would have been
different, without touching what objects and other transforms read.

## Decision

1. A replay is a branch run (ADR 0119) with every input pinned to a dataset
   version: the version the request names, else the one current at
   `as_of_ms`, else the latest. An input with no version yet reads as empty.
   A pinned version must exist and still hold its rows. The run writes a new
   branch of the output dataset, `replay-` plus the start of the replay id,
   and never an existing one.
2. A replay runs the stored transform, or a candidate definition that keeps
   the transform's namespace, id and output dataset. Transform definitions
   have no history, so the candidate is how a changed transform is tried
   before it is saved. Isolated-process transforms are refused, as for
   branch runs.
3. The record pins each input's version, row count and digest, the
   definition digest and whether it was a candidate, the engine version and
   the request's options. It flags SQL that calls time or random functions
   as possibly non-deterministic. It carries the output digest in the run
   receipt's scheme, so it compares with the original run's `output_digest`.
4. The diff compares the replay output with a baseline version of the
   output (chosen like an unpinned input): column set, row counts and
   digests, and rows added, removed and changed. Rows are matched by the
   request's key column, else the key of the one object type backed by the
   output, else compared whole. It lists up to 100 changed keys and 10
   sample rows. Downstream impact is the output and every dataset fed from
   it through governed transforms of the replay's namespace, each with the
   object types it backs there. Consumers in other namespaces are not
   listed: they may belong to other tenants.
   Changed keys and sample rows are returned with the replay but not
   stored: they are values of the data, and redaction must not have to find
   them in replay records. The stored record keeps counts and digests.
5. Promotion is the branch's proposal and merge by another principal;
   discarding is deleting the branch. The record stays as the receipt in
   `sekai_transform_replays` (SQLite and PostgreSQL `0089_transform_replays`).
   If the record cannot be written, the replay's branch is dropped.
6. `ReplayGovernedTransform` is admitted like a branch run (credential
   admin, namespace tenant, transform quota gate). The caller must read
   every input of the stored and the candidate definition and write the
   output. The replay runs only if the stored definition is still the one
   checked, re-read inside the replay transaction. Property read grants are
   not applied to the run, its branch or the samples, and pinned versions can
   hold fields the current schema dropped, so a replay touching a dataset
   whose policy enforces property grants is refused. A baseline holds at most
   a million rows, checked before it is read, and is read under the
   transform's memory and time budget; the diff keeps only its bounded
   keys and samples. `GetTransformReplay` returns a record only to its tenant
   and to callers who may read its output and inputs.

## Consequences

Dataset versions keep rows, not schemas (#1412), so a replay declares each
input with the dataset's columns at replay time and records them. A schema
change since a pinned version can therefore change or fail a replay of it;
pinning schemas with versions is a separate change.

The diff holds both sides in memory, a small multiple of the budgeted
baseline and the run's own output, while the replay transaction is open.

Replays reuse the branch run's marking rule, so a replay whose derived
marking would raise the output's is refused, and sample rows are only shown
to callers who may read both sides. Replay records have no retention of their
own; branches are deleted by operators as ADR 0119 describes. Replaying
actions or agent turns is out of scope.

## Amendment 2026-10-25

#1795 adds shadow runs. A shadow is one candidate replay per run of the
active revision, pinned to that run's receipt `input_versions` and diffed
against the output version the run wrote, so both sides read the same
inputs. A run that writes its output records the output's latest version
in its own transaction, beside its finish (`output_version_id`;
PostgreSQL `0119_transform_run_output_version`), so the link needs no
timestamps; runs from before it are skipped. An input the candidate adds
is pinned to the version written before the run was admitted. A
replay record now also keeps that baseline digest in the receipt's scheme
(`baseline_output_digest`; empty on older records). Shadows run on
request, never on a schedule or trigger, which keeps compute visible and
under the quota gate. The summed report is returned, not stored.

## Amendment 2026-10-25 (promotion)

#1796 stores each shadow report (`sekai_transform_shadow_reports`; SQLite,
and PostgreSQL `0120_transform_shadow_reports`) by id with counts and
digests, never changed keys or samples. A report passes when it compared at
least one run. A namespace that opted in (`sekai_transform_shadow_requirements`)
merges a definition proposal that changes a governed transform only with a
passing report for that candidate. The candidate is matched by its member
digest, without schedule or trigger, and against the revision running at
merge time, inside the merge transaction. New and removed transforms, a
transform moved to another output dataset or isolated-process on either
side, and rollbacks are exempt: there
is nothing a shadow can compare, or the revision was promoted before. History and rollback
are the definition proposal's.
