# ADR 0107: Two-way model-release evidence for opt-in hosted routes

- Status: accepted
- Date: 2026-10-13
- Owners: @Sannrox
- Discussion: none — resolved in Issue #1396
- Issue: #1396
- Supersedes: none
- Superseded by: none
- Related: [ADR 0106](0106-namespace-model-review-state.md)

## Context

Self-hosted model routes need a signed runtime health and canary statement
from the serving plane before they can be treated as current, and the serving
plane needs a signed evaluation statement before it will promote. Chisei does
not run canaries and does not import that crate. Existing hosted and provider
routes must stay admitted until a profile opts in.

## Decision

1. Chisei copies the Tenkai runtime-evidence schema and verifies Ed25519
   signatures against operator-installed trust roots. Canonical bytes use
   domain tags `TENKAI-MODEL-RUNTIME-EVIDENCE-V1` and
   `TENKAI-MODEL-EVALUATION-V1` with length-prefixed fields.
2. Chisei signs `chisei.model_evaluation_evidence.v1` from
   `EvalStore::compare_runs` on pinned eval sets. A failed comparison still
   signs; promote remains the serving plane's duty.
3. Admission is opt-in per customer-hosted profile
   (`require_runtime_evidence` plus a bound identity: provider, model,
   profile version, artifact digest, endpoint). Default routes are unchanged.
4. Missing, stale, or invalid evidence refuses closed at native planning and
   execution, gateway decide, hosted execution, and failover candidates.
   Allowed and denied admits write decision-ledger rows; unused fallbacks do
   not.
5. Operators ingest signed JSON; Chisei does not start canaries. Production
   feedback is stored as an operator note bound to the same identity.
6. Persistence is dual-backend. PostgreSQL migration
   `0063_chisei_model_release_evidence` is GATE:mig.

## Alternatives considered

- Require evidence on every hosted route. Rejected because currently admitted
  routes must keep working until an operator opts in.
- Import the serving crate for types. Rejected because the control plane must
  stay independent; the contract is copied schemas and canonical bytes.

## Consequences

- Trust roots, runtime evidence, evaluation exports, and feedback live in
  `chisei_model_release_*` tables on SQLite and PostgreSQL.
- Experimental RPCs and `sekaictl admin model-release-evidence` are the
  operator surface.
- Route admission (#1494) still runs first; evidence is a second gate only
  for opted-in hosted profiles.

## Validation

- Domain tests cover admit, missing, stale, invalid, untrusted, eval sign,
  and compare-runs export.
- SQLite and PostgreSQL conformance cover trust, ingest, export, and
  feedback.
