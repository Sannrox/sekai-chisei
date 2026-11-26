# ADR 0153: Eval cases recorded from reviewed Actions are references, replayed through the agent dry run

- Status: accepted
- Date: 2026-11-18 (accepted 2026-11-26)
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2305 (#2305)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0089](0089-park-and-decide-action-instances.md),
  [ADR 0109](0109-agent-dry-run.md),
  [ADR 0114](0114-signed-receipt-chain.md),
  [ADR 0120](0120-transform-replays.md)

## Context

Eval datasets are generated from synthetic tenants (`docs/eval-datasets.md`).
A suite covers only what a template author imagined, and "datasets built from
recorded traces" are out of scope. Meanwhile every parked Action instance that
a person decided is a labelled example. Its record holds the request, what the
agent proposed and whether a person granted or denied it.

What the stores hold today:

- **Review.** A parked instance is decided `grant` or `deny`, nothing else
  (ADR 0089). A grant applies the stored `parameters_json` unchanged. There is
  no "approved after edit" and no structured alternative. The reviewer's
  `reason` is free text on the receipt's `approval_decided` event and in
  decision memory.
- **Labels.** The instance holds `parameters_json`, `request_digest`,
  `decided_by`, `approval_decision` and `decided_at_ms`. Its receipt holds
  references and digests, never parameter values.
- **Markings.** An instance's marking is the least upper bound of its
  object's and its binding's markings. Reading the instance or its receipt
  needs clearance.
- **Erasure.** Erasure and redaction rewrite or re-sign stored artifacts in
  place: dataset versions (ADR 0119), receipt bodies (ADR 0114), the
  working-memory parameter erase. A copied value outside those paths is a
  value erasure cannot find.
- **No effects.** The agent dry run (ADR 0109) is the only path where the
  plane attests that nothing was submitted. The eval executor's "no effects"
  holds by construction: it asserts empty receipts and reads no store.
- **Datasets.** A dataset version is a digest over its definition and cases.
  `resolve` regenerates the dataset and answers "not found" for a version it no
  longer produces. A comparison is refused across versions.

This is the first place evaluation would touch tenant data. A wrong choice
copies restricted values into a store with weaker access rules, or lets an
evaluation apply a real Action.

## Decision

Eval datasets may hold cases recorded from decided Action instances, under
these rules.

1. **A recorded case is a reference.** It holds the namespace, the instance
   id, the instance's `request_digest`, the decision (`grant` or `deny`) and
   `decided_at_ms`. It copies no parameter or property values. The case input
   resolves at run time:
   - the instance's stored parameters;
   - the target object as of the proposal time, rebuilt from the change log
     the way counterfactual views rebuild it.

   It resolves through Sekai reads as the evaluating principal. A case whose
   source was erased, redacted or rewritten (its `request_digest` no longer
   matches) does not resolve.
2. **Only a human decision labels a case.** Only an instance that parked and
   was decided `grant` or `deny` by a person yields a case. The following
   yield none:
   - instances admitted or denied by policy alone;
   - `stale_on_resume` and other system outcomes;
   - plan reviews (one decision over a bundle).
3. **Expected means the decided Action, nothing more.**
   - `grant`: expected is "proposes this Action". The case matches on the
     Action type, version and parameter digest.
   - `deny`: expected is "does not propose this Action". Proposing something
     else, or nothing, passes.
   - No alternative Action is inferred. The reviewer's free-text `reason` is
     not part of the expectation. "Approved after edit" does not exist, so no
     case carries an edited Action.
4. **Replay goes through the plane's agent dry run only.**
   - A recorded case runs as a dry-run turn of the agent revision under
     evaluation. Its proposed Actions are `would_submit` and never admitted.
   - An external runtime is refused, as ADR 0109 already refuses runtimes
     whose stubs the plane cannot attest.
   - The step receipts the policy scorer reads come from the dry-run trace,
     not from an asserted empty set.
   - The executor still gets no Action authority.
5. **Markings follow the source, because nothing is copied.**
   - Listing a recorded dataset's cases shows references only to principals
     who can read each instance (instance marking).
   - A run needs the evaluating principal to read every case. If one does not
     resolve or is not readable, the run is refused: it is never silently
     scored on fewer cases, since comparisons need every case.
   - Retained execution evidence for a recorded case holds digests, the
     expected decision and the verdict, never resolved input values. When it
     must hold an output, that output inherits the instance's marking, as
     retained outputs already inherit fixture-input markings.
6. **Versions are digests of references; erasure retires a version.**
   - A recorded definition lists its instance ids explicitly. It is chosen at
     put time from a namespace, an Action type, a decision window and an
     optional outcome filter, then frozen.
   - Its version digest covers the definition and, per case, the instance id,
     `request_digest` and decision.
   - When a source is erased, that version stops resolving and answers "not
     found", as a regenerated dataset does today. Putting the definition again
     without the erased instance yields a new version.
   - Comparison across versions stays refused.
7. **Recording needs namespace admin and clearance over every case.**
   - Putting a recorded definition requires a namespace admin. A writer is
     not enough: the call turns review decisions into a reusable labelled
     set.
   - The caller must be able to read every listed instance. An unreadable
     instance answers the same as a missing one.
   - Each put leaves one audit decision naming the dataset, version and case
     count, not the instance ids.
8. **Out of scope:**
   - model-graded rubrics;
   - reviewer reasons as expectations;
   - plan-review cases;
   - cross-namespace datasets;
   - cases from instances decided before the feature ships whose target
     history has been compacted (they do not resolve and are not listed).

`docs/eval-datasets.md` keeps synthetic generation as the default and names
recorded definitions as the second source.

## Alternatives considered

- **Copy the input values into the eval store.** A copy is stable as objects
  change. It is also a second home for tenant data: it needs its own markings,
  and every erasure and redaction path must learn about it. The reference
  rebuilt "as of proposal time" gives the same stability for as long as the
  source is retained, and erasure needs no new path.
- **Keep datasets synthetic only.** This is safe and costs nothing. It also
  discards the only real-world label the product collects, and suites keep
  missing the cases operators actually decide.
- **Replay through the eval executor's existing no-effect path.** That path is
  safe by construction, but it never runs the agent, so it cannot answer
  "would this revision propose what the reviewer granted". The dry run can,
  and it already carries the plane's no-submission attestation.
- **Treat a deny as "propose the alternative".** No structured alternative
  exists, and free text is not a comparable expectation. Adding an
  edit-before-grant decision would change ADR 0089 and is a separate decision.

## Consequences

- Suites can cover real decisions without a second copy of tenant data.
  Markings, redaction and erasure keep working on the source alone.
- A recorded dataset can stop resolving when sources are erased or history is
  compacted. Operators re-put it to get a smaller version. Comparisons pinned
  to the old version stop working, by design.
- Runs pay for the as-of rebuild and dry-run turns. They are slower than
  synthetic cases.
- The deny expectation is weak ("not this Action"). It catches regressions to
  a known-bad proposal, not progress towards a better one.
- Follow-up work, one feature Issue (#3513):
  - the recorded definition contract and put/resolve;
  - the dry-run case runner;
  - case reads gated by markings;
  - the refusal semantics above;
  - tests on both backends.

## Validation

- A recorded run creates no Action instance, receipt or effect. A test counts
  instances, receipts and effects before and after a run on both backends.
- Erasing or redacting a source makes the version answer "not found" and
  leaves no input value in any eval table. A test scans the eval store for the
  erased value.
- A principal without clearance on one case's instance cannot list it, cannot
  run the dataset, and cannot tell it from a missing case.
- Revisit if an edit-before-grant decision is added to Action review. It would
  give grants a richer expectation.
