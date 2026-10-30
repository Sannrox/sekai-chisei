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
(`pkg:feedback.evidence-finding/v1`, ADR 0095) certifies ontology, Action
type, and evaluation members from `tests/fixtures/feedback/`. The security
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
Combined-mode instances also run a feedback investigation worker (#1231)
every 15 seconds in every namespace holding the evidence and finding package.
Enabled object-change bindings of kind `feedback_observation` and type
`feedback.investigation.dispatch` admit one fenced ActionWork claim per new
observation. The first pin does not backfill. The worker claims at most one
investigation at a time, requests bounded analysis through `PlanExecution`
and `ExecutePlanStream` with no agent tools, and writes investigation,
hypothesis, and finding objects. Namespace model budgets apply; exhaustion
records no finding. Inconclusive and malformed results stay `internal` and
cannot dispatch a GitHub mutation. Combined-mode instances also run a GitHub
publisher (#1232) on the same 15-second interval. Qualifying findings create
or update one issue on the configured repository after external-action
authorization, executor verification, permit redemption, and execution
evidence. Publication strips private environment identifiers and private
repository or issue references. A durable mapping and public-safe marker
connect each problem signature to its issue; later occurrences update managed
content and leave maintainer text in place. Lost responses stay pending
reconciliation and are never retried blindly. Denied, expired, revoked,
mismatched, or missing permits, missing credentials, disabled issues, and
rate limits stay visible and retryable. The default cap is five new issues
per UTC day (`SEKAI_FEEDBACK_GITHUB_DAILY_CAP`). Owner and repository come
from `SEKAI_FEEDBACK_GITHUB_OWNER` and `SEKAI_FEEDBACK_GITHUB_REPO`; the
token is `SEKAI_FEEDBACK_GITHUB_TOKEN`. Those bindings and ActionWork claims
are experimental: community SQLite is the reference store, and community
PostgreSQL leaves action bindings unavailable (ADR 0090). The GitHub
publisher does not use action bindings.
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
