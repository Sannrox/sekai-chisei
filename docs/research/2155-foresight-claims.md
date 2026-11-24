# Foresight claims over objects and receipts

Issue: [#2155](https://github.com/Sannrox/sekai-chisei/issues/2155)
Date: 2026-11-24
Status: **recommendation: no native claim kind (option C)**

[Issue #2155](https://github.com/Sannrox/sekai-chisei/issues/2155) asked
whether the plane should compute claims about the future natively: a
deductive projection first ("this order misses its promised date unless acted
on"), and scored predictions later.

## Decision

Do not add a claim object kind, a claim log, or a plane-side rule engine.
Close #2155 with no ADR and no feature Issue.

A projection is an ObjectSet with a time bound, evaluated on a schedule by a
consumer, whose result is written back through a governed Action. Every part
of that exists today. Each invariant the Issue asked for is already held by an
existing concept:

| Invariant the Issue asked for | Held today by |
| --- | --- |
| A claim is superseded, never edited | The object change log keeps every property value with its writer ([ADR 0090](../decisions/0090-object-change-action-bindings.md) writes, `ObjectChange.writer_kind`/`writer_ref`) |
| Each claim ships its derivation | The Action instance receipt that wrote the value, named by `writer_ref` |
| Hit rate is recomputable | `ExplainValue` and counterfactual reads rebuild a value as of any time inside retention |
| Claims carry the markings of their inputs | A claim written as a property of the object it is about carries that object's markings, with no new derivation rule |
| Promoting a prediction model is governed | Model versions, stages and reviewed promotion (#3020, #3023, #3159) |
| Re-evaluation on a clock | Scheduled Action bindings (#3033) and the plane schedule tick |

This keeps the line [#659](659-derived-fact-admission.md) drew: functions
stay read-only, and derived material reaches the graph only as an asserted,
governed write. A claim kind would be the persisted derived-fact kind #659
declined.

## Evidence

### 1. Pain coverage

Option A covers real questions, and all of them are range filters on a
timestamp property plus a status filter:

- **Shipments that miss their requested delivery.** The rehearsal customer's
  shipments carry `requested_delivery` and a status: "requested before
  now + 48 h and not delivered".
- **Parked approvals about to expire.** Action instances carry
  `review_sla_deadline_ms`, and admission denies with `review_sla_expired`
  once it passes. "Deadline before now + 4 h and still parked" warns before
  the denial.
- **Leases near expiry.** Leases carry `expires_at_ms`: "expires before
  now + 1 h and not renewed".

An `ObjectSetDescriptor` already filters a declared property with `lt`/`lte`
(at most four filters). The only missing piece is the bound: the descriptor
takes a literal, not "now + duration", so the evaluator computes the literal
on each tick. That is one line in a consumer, not a plane feature.

### 2. Clock-driven re-evaluation cost

A scheduled pass is one indexed range filter per rule. The event-driven
alternative is the incremental membership update. The
[object-index envelope](876-object-index-envelope.md) measured both on SQLite:

| Scale | p95 filter (scheduled pass, per rule) | 1,000-key incremental (event-driven) |
| --- | ---: | ---: |
| 10⁷ objects | 3 ms | 1 ms |
| 10⁸ objects | 33 ms | 2 ms |

A rule re-evaluated every minute costs a few milliseconds per tick at 10⁷
objects. Time passing changes a claim without any change event, so an
event-driven engine needs a timer per claim on top of the change feed; a
scheduled pass catches clock-driven changes for free. Scheduled evaluation is
enough, as comparable platforms also find.

Not measured: PostgreSQL, and the product `EvaluateObjectSet` path rather
than the envelope harness. Neither changes the answer. The decision does not
turn on cost, and a two-orders-of-magnitude regression would still fit a
one-minute tick.

### 3. Time typing

`PropertyType::Timestamp` exists (`crates/sekai-types/src/object_schema.rs`),
so the ontology knows which properties are times. It does not know which time
is a deadline as opposed to a creation time. A rule names its property
explicitly, so a projection does not need that meaning typed. No lint or
annotation is needed now.

The real gap is upstream. The rehearsal customer stores `requested_delivery`
as text in two date formats. A range filter needs it landed as a `timestamp`
property, which is the Source mapping's job, not the rule's.

### 4. Outcome labels for calibration

For a projection, the outcome is later object state, not a receipt: "the
order was delivered after its promised date". The change log answers that,
and as-of reads rebuild the state the claim was made on. No outcome link on
decision receipts is needed. A scored prediction would need labels, and that
is the model-version lineage's job (#3020), not a new receipt link.

Limit: calibration only reaches back as far as the change log's retention
(`earliest_retained_seq` on `ListObjectChanges`). A namespace that wants a
year-long scoreboard needs a year of retention.

### 5. Mutable versus append-only

The Issue's concern was that writing output onto a property loses the track
record. Here it does not: a property write appends a change row with old
value, new value, writer and time. A consumer that wants only the latest claim
reads the property. One that wants the record reads the change log. An
append-only claim log would be a second copy of that history.

### 6. Acceptance fixture

The shipment case, as the acceptance scenario for any later feature:

1. A scheduled binding (#3033) submits a "check delivery risk" Action every
   five minutes.
2. Its executor evaluates shipments with `requested_delivery` before
   now + 48 h and a status other than delivered, as the binding's `run_as`.
3. For each match, a governed Action updates the shipment with
   `delivery_at_risk = true`. A shipment that left the set is updated to
   `false`.
4. An object-change subscription on `delivery_at_risk` notifies the
   dispatcher.
5. Later, the change log shows which `true` values preceded a delivery after
   `requested_delivery`. That is the hit rate, recomputed from history.

No step needs a new concept.

## Options compared

- **A. Projection only, native.** Rejected. It adds a rule engine, a claim
  kind and a claim log. Every invariant is already held, and the derived-fact
  line from #659 would move.
- **B. Projection plus prediction.** Rejected. As A, plus an embedded model
  runtime in the core. Model governance already exists for external training.
- **C. External consumer, governed write-back.** Recommended. It uses
  scheduled bindings, ObjectSets, governed Actions and the change log as they
  are.

## What would reopen this

- Several consumers rebuild the same "now + duration" bound and the same
  evaluator. Then a relative time bound on `ObjectSetDescriptor` (or a
  scheduled binding that evaluates a descriptor) is the small next step. It is
  still not a claim kind.
- A requirement that unevaluated claims fail closed inside the plane. In
  option C, "could not evaluate" is the consumer's to report. The plane cannot
  tell a missing write from "no risk".
