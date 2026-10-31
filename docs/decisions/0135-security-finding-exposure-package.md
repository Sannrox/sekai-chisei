# ADR 0135: Ship security findings and exposures as a types-only domain package

- Status: accepted
- Date: 2026-10-28
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1923 (#1923, part of #1668)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0052](0052-capability-package-certification.md),
  [ADR 0073](0073-source-and-action-objects.md),
  [ADR 0095](0095-feedback-evidence-finding-package.md)

## Context

Security findings come from probes, reviews, scanners, agents, and advisories.
Each source keeps them in its own store. Issue #1668 asks for a governed record
of a finding, of its exposure on a deployed target, and later of the decisions
taken on it. This first slice covers findings and exposures. ADR 0095 already
settles how a domain package ships: types only, certified members, objects
written through governed Actions, and no domain-specific core RPC.

## Decision

1. The security package (`pkg:security.finding-exposure/v1`) is **types only**,
   following ADR 0095. It registers ontology classes, ObjectTypes, governed
   Action types, and an evaluation member. It certifies the `ontology`,
   `action_type`, and `evaluation` members. It packages no live instances and
   is not a runtime grant.
2. **Finding identity is its problem signature.** A finding is unique per
   namespace by `problem_signature`. A second report of the same problem is
   recorded as an **occurrence** of that finding. The finding Action refuses a
   duplicate signature and names the existing finding.
3. **Occurrence identity is the source occurrence id.** An occurrence is unique
   per namespace by `occurrence_id`, so a replayed observation never counts as
   a new occurrence. Replaying the same Action request stays the core
   idempotent no-op.
4. **Hypotheses are not measured facts.** A hypothesis is its own kind, disjoint
   from occurrences and exposures. An exposure verdict other than `unknown`
   must cite a measured occurrence of the same finding as `evidence_id`.
   Citing a hypothesis, or any other object, is refused.
5. **Exposure identity is the finding and the deployed target.** One exposure
   exists per finding, release, and environment. A verdict update cannot change
   that target.
6. Identities are stamped into `external_id` with a kind prefix and enforced at
   commit by a partial unique index on `(namespace, external_id)` for the
   finding, occurrence, and exposure kinds, on SQLite and PostgreSQL. This is
   the same primary-key analog as the feedback observation index. The
   plan-time checks only give a precise error.

7. **A disposition reopens when its basis no longer holds** (#1925). The
   exposure records the current facts of its target (dependency closure,
   release and configuration digests, reachable markings, advisory revision)
   through `security.exposure.basis`, which a connector or a transform
   write-back drives. A disposition whose basis differs from those facts, or
   whose expiry passed, is superseded by a `needs-review` disposition through
   `security.disposition.reopen`. Dispositions stay immutable. The reopen
   carries the basis unchanged and names the fact and its new value, and the
   validator refuses a reopen the facts do not warrant. Its object id derives
   from the disposition it reopens, and the successor index allows one
   successor, so a repeated or restarted pass reopens it once. Changes are
   found in the committed object-change feed, never by polling a source. The
   certification moves to `cert:security.finding-exposure/v1.2`. A server
   driver (#1954) runs these passes on every instance as an
   operator-configured principal (`SEKAI_SECURITY_REOPEN_RUN_AS`), checked
   for namespace write and write freezes like an Action binding's run, and
   keeps each namespace's feed position in a compare-and-set cursor.
8. **Agent disposition precision is measured, not asserted** (#1990). A
   disposition records `recorded_by`, the submitting principal,
   `recorder_kind`, whether it was an agent at that time, and
   `recorder_revision`, the definition revision of the site agent behind it.
   All three are stamped when the write is planned, overwriting any caller
   value, so an agent cannot claim another recorder's history and retiring a
   principal later does not rewrite it. `recorder_kind` comes from the
   Action instance's classification at submission, so a write parked for
   review keeps both its original submitter and how it was classified;
   admission counts a principal bound to a site agent instance as an agent.
   `recorder_revision` is read from the instance bindings when the write is
   planned, outside the commit fence: a parked write granted after its
   instance moved to a new revision counts toward the new one, and a
   revision change racing the commit can attribute that one disposition to
   the revision it replaced. Revision changes are rare operator Actions, and
   a misattributed disposition only moves evidence between two revisions of
   the same agent. A principal bound to a site agent instance is an
   agent whatever its name; instances that share a principal on different
   revisions stamp `ambiguous`, which no single revision's record absorbs. A
   measurement as of a time ignores later dispositions. Generic object
   writes of every package kind are refused, as the package rules and the
   stamped recorder hold only on the Action path; a streaming write-back
   plans through the Action rules with no submitter and so records no
   recorder. An agent's disposition is
   overturned by a reopen for a changed basis fact or a human supersede with
   a different disposition, and confirmed by a human supersede with the same
   one, a reopen for its own expiry, or standing unsuperseded for the settle
   period. A supersede by another agent resolves nothing. Precision is
   counted per recorder, revision and finding class (`finding_class` on the
   finding, `unclassified` when absent) over a trailing window, and a group
   below the minimum resolved count reads `incomplete` with no rate. The
   metrics are read by `sekaictl admin autonomy disposition-precision`. The
   certification moves to `cert:security.finding-exposure/v1.3`.

9. **A fix needs a regression probe** (#1989). While a `fixed` disposition
   heads an exposure's chain and no probe is bound to it, the exposure reads
   `needs-probe`. `security.probe.bind` binds a `security_regression_probe`
   to that disposition with the probe's results on the vulnerable and fixed
   revisions, and is refused unless the probe failed on the first and
   passed on the second, the revisions differ, and the disposition is the
   current fixed head. It is marked at least as high as the disposition it
   names, so only a caller cleared for that marking binds it. The probe names a Chisei isolation catalogue entry or
   an external test reference; running it stays with its suite. Binding to
   the disposition rather than the exposure needs no commit fence: if the
   chain moves on, the new head decides the state. One probe per
   disposition is checked at plan time only; a concurrent duplicate also
   clears `needs-probe` and does no harm. The certification moves to
   `cert:security.finding-exposure/v1.4`.

10. **Measured precision decides an agent's disposition autonomy** (#1991).
    An agent's disposition record or supersede parks for review in the
    `security.dispositions` queue unless its group (recorder, revision and
    the exposure's finding class) is promoted: measured, at least 95%
    precision, at most 5% overturned, over the 90-day window with at least
    20 resolved dispositions. These thresholds are package configuration,
    read with `sekaictl admin autonomy disposition-autonomy`. A promoted
    agent's submission skips only propose-only; a policy that requires
    approval still parks it. Admission evaluates the group when the agent
    submits, so a crossing is recorded at its next submission: a decision
    receipt naming the group, its counts and rates, and the thresholds. The
    latest receipt is the group's standing. A promotion applies only once
    its receipt is durable, and a gate that cannot answer keeps the agent
    under review. Each receipt's id derives from the group and its position
    in the group's history, which is read before the evidence, so instances
    racing on one crossing record it once and one working from older
    evidence cannot follow a newer receipt. Two instances that read the same
    position with different evidence write one receipt between them; a
    standing set from the earlier evidence is corrected at the agent's next
    submission.
11. **Action types are versioned with their bodies.** A governed Action
    type's body is immutable per version, so a namespace installed earlier
    refuses a changed body at the same version. The package registers its
    types at version 2 (adding `finding_class` and the disposition review
    queue), next to version 1, which stays for instances and clients that
    submit it. The reopen pass submits the newest version the namespace
    holds, so a server running ahead of a namespace's reinstall keeps
    reopening, and replays an attempt at the version it was first submitted
    at, so a reopen parked before a reinstall still replays. A test pins the version's bodies so a change cannot land
    without a new version.

12. **A remediation is a typed plan; each mitigation is its own Action** (#1669).
    `security.remediation.propose` records an optional patch reference, zero
    or more catalogue controls (`freeze`, `marking_raise`,
    `gateway_tool_disable`, `outbound_deny`), and an optional rollout
    reference. Applying a control is `security.mitigation.apply`; lifting it
    is `security.mitigation.lift`. Both park for a human. A low-tier
    proposal (no marked data, no rollout, not high or critical, not
    two-person) auto-admits; the rest park in `security.remediations`. A
    freeze is a `SCOPE_ACTION` write freeze and takes effect at the next
    admission after the apply is decided; the lift clears it the same way.
    Gateway tool-disable and outbound deny are recorded as decided
    mitigations with `gateway_audit=pending` so the gateway applies only
    after that decision. A marking raise is recorded with
    `marking_audit=pending` so the lattice raise happens only after that
    decision. A remediation that touches marked data needs the
    matching grant. A `fixed` disposition proposes lifting every active
    mitigation. The package registers these types at version 3. The
    certification moves to `cert:security.finding-exposure/v1.5`.

## Alternatives considered

- A findings store and domain RPC. Rejected for the same reason as ADR 0095: a
  second fact authority next to `SubmitActionInstance`.
- Counting occurrences in a property on the finding. Rejected: a counter cannot
  tell a replay from a new observation. A unique occurrence object can.
- One store-wide unique index on `(namespace, external_id)`. Rejected: empty
  and shared `external_id` values are common on other kinds.

## Consequences

Operators install and certify the package through the existing admin surfaces.
Fixture documents live under `tests/fixtures/security/`. Dispositions with a
validity basis (#1924) and their reopen on change or expiry (#1925) build on
these types.

## Validation

Crate tests install the fixtures into an in-memory runtime and cover:

- portable ontology import with validation and provenance
- package member certification
- a duplicate signature collapsing into one finding with several occurrences
- a replayed occurrence refused while the same request stays a no-op
- an exposure refusing a hypothesis, or an occurrence of another finding, as evidence
- a fixed exposure target
- a false positive reopened when its closure changes, with the fact in its
  receipt, and an expired disposition reopened once across a restart
- store-level uniqueness without the plan-time check
- concurrent duplicate findings keeping exactly one
