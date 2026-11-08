# Capability-package certification

Bind signer, manifest, compatibility, tests, and revocation to one verified
package digest. Certification is not a runtime grant and does not install,
deploy, or authorize invocation. See
[ADR 0052](decisions/0052-capability-package-certification.md).

## Contract

`sekai.capability-package-certification/v1` binds:

- identity `(namespace, certification_id)` and logical `package_id`
- a package digest over members and compatibility
- signer identity and digest
- test-suite and test-result digests
- a certification digest of those pins
- optional predecessor, supersession, revocation, and revocation timestamp

Closed member kinds are `change_set`, `action_type`, `ontology`, and
`evaluation`. The evidence and finding domain package
(`pkg:feedback.evidence-finding/v2`, ADR 0095) certifies ontology, Action
type, and evaluation members from `tests/fixtures/feedback/`. Observation
evidence may target `feedback_observation` or tenant-mode
`tenant_feedback_observation`; both write `feedback_observation` objects.
Observations carry `operation_id`, `observed_at_ms`, and `scope`; the v1
fixtures stay frozen for namespaces certified on v1.
The security
finding and exposure package (`pkg:security.finding-exposure/v1`, ADR 0135)
certifies the same member kinds from `tests/fixtures/security/`. Its
dispositions (#1924) record a decision on an exposure (`accept-risk`,
`false-positive`, `mitigated` or `fixed`) with the validity basis it relied
on: dependency closure, release and configuration digests, reachable
markings, advisory revision, and an optional expiry. Superseding records a
new disposition and keeps the previous one with its receipt. Accepting risk
on marked data needs the disposition marked at least as high as that data,
so only a caller cleared for those markings can accept it. The exposure
records the current facts of its target through `security.exposure.basis`. A
disposition returns to `needs-review` (#1925) when one of those facts differs
from its basis, or when its expiry passes: `security.disposition.reopen`
supersedes it with a `needs-review` disposition that names the fact, and its
receipt's idempotency key names it too. The package functions
`reopen_changed_basis` and `reopen_expired` find those dispositions from the
committed object-change feed and the stored expiry, and reopen each once.
With `SEKAI_SECURITY_REOPEN_RUN_AS` set, every Sekai-serving instance runs
them each minute (#1954) in every namespace holding the package, as that
principal and through the same namespace-write and write-freeze checks as an
Action binding's run. A namespace that refuses the principal is skipped and
logged. The feed position is stored per namespace and advanced by
compare-and-set, so instances running at once never move it backwards. Each
pass also sweeps every disposition heading its chain for an expiry or a basis
its exposure no longer has, so a change committed behind the feed position is
still caught.
A remediation (#1669) is a typed plan on an exposure: an optional patch
reference, catalogue mitigations (scoped freeze, marking raise, gateway
tool-disable, outbound deny), and an optional rollout reference. Applying
each mitigation is a separate reversible Action, parked until decided. A
low-tier proposal auto-admits; production changes, two-person plans, high
criticality, and marked data park in `security.remediations`. A freeze takes
effect at the next admission after approval. The gateway applies a
tool-disable or outbound deny only after that Action is decided. A
marking raise is recorded with `marking_audit=pending` until the lattice
records it. A `fixed` disposition proposes lifting every active
mitigation. The certification moves to `cert:security.finding-exposure/v1.5`.
The plane runs no feedback workers. Investigation (#1231) and GitHub
publication (#1232) are reference adapters outside the plane:
`adapters/feedback_investigation.rs` and `adapters/feedback_github_issues.rs`,
exercised by `tests/feedback_adapters.rs`.
The investigator advances an object-change binding of kind
`feedback_observation` and type `feedback.investigation.dispatch`, then takes
one fenced ActionWork claim per dispatch. The binding's first run arms it and
does not backfill. It gathers the same-signature cluster with a
property-filtered `ListObjects`, keeps observations in the trigger's scope
observed in the last 24 hours (observed time clamped to ingest time), and
counts distinct `operation_id`s. It requests one bounded analysis per
(namespace, signature, scope, 24-hour window) through `PlanExecution` and
`ExecutePlanStream`. Later dispatches in the window reuse the stored analysis.
It writes investigation, hypothesis, and finding objects through their
governed Actions as `feedback-investigation`. Namespace model budgets apply;
exhaustion records nothing and releases the claim. Inconclusive and malformed
results stay `internal`. The bindings and claim RPCs are experimental
(`SEKAI_EXPERIMENTAL_RPCS=1`; community PostgreSQL leaves action bindings
unavailable, ADR 0090).
The publisher treats the repository as a source writeback target
(`adapters/source_writeback.rs`). It posts only findings the investigation
runtime recorded (`recorded_by` is `feedback-investigation`), so a namespace
writer cannot qualify a finding by setting `classification`. A public marker
per (namespace, signature, scope) is the writeback key, and the issue's number and
update time are the record version. A lost create is seen on the next decision,
so it is never repeated. An unchanged issue needs no permit, and later
occurrences rewrite only the managed section and keep maintainer text. Only
issues the executor's account opened are adopted or counted. Public text is an
allowlist: a signature part appears only as plain identifier text and the
version only as semver; anything else reads `unspecified`, and model text is
never published. The executor holds the token. The daily new-issue cap
defaults to five per UTC day.
The quality worker (#1233) was removed. Existing `feedback-quality-` eval
cases stay stored and are still excluded from judge rubrics.
Neither package
ships live instances, and neither is a runtime grant.

## Operator workflow

```text
sekaictl admin packages certify --certification ./cert.json --actor reviewer
sekaictl admin packages get --namespace ops --certification-id cert:1 --actor reviewer
sekaictl admin packages verify --namespace ops --certification-id cert:1 \
  --certification ./cert.json --actor reviewer
sekaictl admin packages revoke --namespace ops --certification-id cert:1 \
  --reason "signer rotated" --actor reviewer
```

Exact replay of a live certification is idempotent. Independent verification
recomputes both digests from the submitted members, compatibility, signer, and
tests. A content or dependency change fails verification. Recertification
uses a new certification identity and a predecessor pin; the prior record
stays inspectable. Revoked certifications remain gettable and fail verify.

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, superseded, revoked, or digest-mismatched certification | `capability package is unavailable` |
| Unknown contract revision | `capability package revision is unsupported` |

SQLite stores certifications. PostgreSQL surfaces stay unavailable.
