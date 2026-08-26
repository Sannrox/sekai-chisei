# Architecture

`sekai-chisei` is a governance control plane, not an agent runtime or workflow
engine. Agent clients and domain executors stay replaceable; the control plane
owns durable facts and the decisions that constrain an operation.

## Components

```text
OpenAI / Anthropic clients        Native integrations
            |                            |
            v                            v
     chisei-gateway              Gunshi fleet allocation
            |                            |
            |                            v
            |                   PlanExecution
            |                   (Kioku enrichment)
            |                            |
            |                            v
            |                   ExecutePlanStream
            |                            |
            +-------------+--------------+
                          v
                    Chisei decisions
              policy | budget | routing
              approval | eval | learning
                          |
                          v
                     Sekai facts
              graph | ACL | audit | lineage
              evidence | outcomes | memory
                          |
                          v
                  SQLite / PostgreSQL
```

### Sekai: durable facts

Sekai is the canonical operational memory. It stores typed objects and links,
schemas, datasets, lineage, audit history, access rules, coordination state,
external evidence, and governed memory candidates.

Important mutations are explicit. Object RPC mutations and object-mutating
built-in actions write audit rows in the same transaction as the object change.
Creates and deletes use lifecycle summaries; updates record changed scalar and
property fields.

Reusable PostgreSQL persistence also covers retention policies, scope-bound
immutable content, legal and operational holds, transactional garbage
collection, integrity-checked lifecycle archives, and reversible object
reconciliation. PostgreSQL collectors serialize per namespace so concurrent
release, hold, reconciliation, and collection attempts cannot double-delete a
payload or lose a retaining obligation. Selecting `SEKAI_DB_BACKEND=postgres`
with a validated `DATABASE_URL` activates these reusable surfaces as the
community runtime backend; it still does not add tenant, OIDC, OAuth, or
identity capabilities.

Reusable coordination leases use a dedicated namespace-scoped API. Every
acquisition receives a monotonically increasing generation and unique fencing
token; stale generations cannot refresh, release, or take over current state.
Object mutations with a lease precondition validate the active generation and
commit the graph mutation, object audit, and idempotency record in the same
backend transaction. Shared SQLite/PostgreSQL conformance covers this
cross-table contract; partial storage interfaces that cannot provide it fail
closed. See [Generation-fenced leases](leases.md) for the client and
downstream-executor contract.

Governed definition branches provide an additive authoring foundation above
immutable namespace-scoped definition revisions. Canonical member documents
and revisions are insert-only; only a stable branch head advances through an
exact compare-and-swap. Creation and edits recheck namespace and member
authorization and commit revision, request, audit, and head state atomically.
They do not mutate runtime facts or snapshot legacy schema and ontology rows.
A proposal pins exact base and candidate digests; merge compare-and-swaps the
namespace published head against an expected digest, stores a receipt in the
same transaction, and denies candidates that do not descend from the pinned
base. Close records a canonical reason without moving the head. See
[Governed definition branches](definition-branches.md),
[ADR 0024](decisions/0024-governed-definition-branches.md), and
[ADR 0026](decisions/0026-governed-branch-proposals.md).

Explicit namespace activation can add immutable object-security policy
revisions to direct object read, `ListObjects`, remaining object consumers, and
writes. SQLite and PostgreSQL compile the bounded v1 vocabulary into storage
predicates before rows, totals, ordering, filtering, limits, or offsets are
materialized. Write rules reauthorize current and proposed state inside the
persist transaction. Inactive namespaces retain existing behavior; activated
namespaces deny missing or unsupported policy while ACLs, team boundaries, and
markings remain narrowing layers. Optional property grants then omit hidden
values from authorized projections and fail closed on ungranted filters and
writes. See
[Object security policy](object-security.md),
[ADR 0025](decisions/0025-storage-enforced-object-security.md), and
[ADR 0027](decisions/0027-explicit-property-grants.md).

### Chisei: governed decisions

Chisei resolves how an operation may proceed. It owns policy, context
enrichment, budgets, egress decisions, approval requirements, model/runtime
routing, evaluation gates, outcome attribution, and learning rules.

The LLM provider adapters execute calls but do not own these decisions.
Provider-specific behavior stays behind the `sekai-provider` crate. The
`chisei-gateway` crate depends only on `sekai-proto` and `sekai-provider` among
workspace packages; governed decisions and durable mutations cross the gRPC
contract instead of reaching into control-plane implementation modules.

Provider registry persistence and lifecycle records are owned by
`provider_profile`; `provider_resolution` is the single orchestration boundary
that loads an execution snapshot and resolves canonical provider/model records.
Gateway and native gRPC transports consume that boundary, while provider
adapters receive an already resolved record and do not infer policy or routing.

### Gateway and native execution

The HTTP gateway accepts compatible OpenAI Responses, OpenAI Chat Completions,
and Anthropic Messages requests. It authenticates the caller, preflights policy
and budget decisions, routes to the resolved provider, streams the response,
and records normalized usage and audit evidence.

Native integrations use the gRPC planning and execution APIs. Both entry paths
share the same policy, data, and audit layers.

Ordered text, image, audio, and document inputs use the parallel
`PlanContentExecution` and `ExecuteContentPlanStream` contract. The ordinary
`ChatMessage` and text RPCs remain unchanged so an older server returns
`UNIMPLEMENTED` instead of silently dropping content. Content planning reuses
the native namespace, policy, routing, budget, evaluation, residency, privacy,
egress, and receipt boundaries, while a separate principal-bound cache prevents
content and text plan confusion. Hosts retain payload custody; resolved bytes
are bounded, digest-verified immediately before provider disclosure, redacted
from debug output, and excluded from durable provider-neutral state. See
[Bounded content execution](content-execution.md).

For fleet-managed native work, Gunshi is the outer allocation stage before
`PlanExecution`. The request binds an exact, durably issued allocation;
planning rejects modified allocations, stale policy revisions, conflicting
operation or tool scopes, and any live route that differs from the allocation.
Kioku remains inside `PlanExecution` as per-operation context enrichment.
Execution receipts retain both the native plan id and Gunshi's logical
operation and allocation provenance. Direct native planning remains available
when no fleet capacity envelope exists. See
[ADR 0015](decisions/0015-gunshi-allocation-precedes-native-planning.md).

For native Anthropic execution, provider profiles publish the versioned prompt-
cache contract and Chisei may opt into explicit upstream breakpoints only when
the stable prefix meets the conservative configured minimum. Cache identity
follows the provider's `tools` → `system` → `messages` order. Governed task
context and the current request remain after the final reusable breakpoint;
pending tool-call adjacency is preserved even when that makes conversation
history ineligible. Provider adapters canonicalize cache-relevant JSON and
return cache-read and cache-creation usage, but Chisei never stores prompt
content or upstream cache representations.

The versioned `chisei.prompt-cache-policy/v1` decision runs only after normal
privacy and egress governance. It uses bounded provider support, stable-prefix
size, accounting availability, reuse, and price-ratio inputs. Outcomes use a
fixed vocabulary (`enabled`, `bypassed`, `unavailable`, or `invalid`) with
bounded reasons; prompt text, cache keys, and content-derived identity never
enter decision metadata. Unavailable caching may fall back only to the already
selected provider, model, and privacy mode, and invalid controls or a budget
that requires cache savings fail explicitly.

Operational reports derive cold writes, warm reads, misses, hit rate, effective
cached share, and realized savings from namespace-authorized canonical
`llm_calls` rows. Missing provider accounting stays distinct from a cache miss.
The control plane does not expose upstream cache enumeration, retrieval, or
eviction operations.

Compatible gateway traffic remains caller-owned. Existing client breakpoints
are forwarded without Chisei adding, moving, or removing cache controls; any
future managed gateway caching requires its own explicit policy contract.

### External host actions

Host harnesses can submit a versioned external-action authorization request to
Chisei before invoking a tool, command, API, browser, or device executor.
Chisei binds the authenticated actor, namespace, operation lineage, canonical
argument digest, targets, preconditions, risk, expected effects, limits,
executor, and deadline into one stable request digest. The decision path reuses
action policy, approval, budget, blast-radius, namespace authorization, audit,
and idempotency boundaries while keeping external actions distinct from native
governed Action execution.

An authorization decision is not execution evidence. The v1 decision contract
does not issue a signed permit; permit issuance, redemption, and submitted host
evidence are separate protocol stages. A host must refuse execution unless it
can verify the eventual permit and enforce every declared constraint. Chisei
does not claim that an authorization or host observation proves a physical
effect occurred.

### Governed immutable subjects

Authenticated native callers can submit bounded, content-addressed subjects
through registered profiles without transferring subject payload ownership to
Chisei. The generic envelope contains only an opaque identity, canonical
digest, allowlisted evidence references, and an evaluation profile. Chisei
records the binding and fixed-vocabulary decision on the canonical operation
receipt; reconciliation therefore uses `GetOperationReceipt`. Profile
validators cannot grant execution authority or add arbitrary receipt
attributes. See [Governed subject evaluation](governed-subjects.md).

Operator clients may use `GetEffectivePolicySummary` to render a live,
read-only namespace projection of effective routing, configured budget limits,
bounded action-rule counts, and governed worker concurrency. Each section
reports its owning scope and revision or an explicit unconfigured state. The
projection never includes budget usage, request-specific verdicts, raw action
rules, credentials, or caller-supplied runtime capacity, and every request is
checked against namespace read access.

Native runtimes can use the namespace-scoped
[capability catalog](capability-catalog.md) (`DiscoverCapabilities` contract
`1.0`) to discover visible object queries, bounded retrieval surfaces, and
governed actions before invocation. Catalog visibility is filtered for the
authenticated authorization context and never acts as an authorization token;
invocation always rechecks live controls. Compatible HTTP clients use the
separate provider-profile matrix `GET /v1/chisei/capabilities`
(`chisei.provider-capabilities/v1`); that document has no grant semantics and
must not be submitted as decide `capability_requirements_json`.

`RetrieveContext` is asserted-only by default. Callers may opt into the fixed
query-time entailment profile for class inheritance/equivalence and explicitly
transitive ontology relations. Entailment uses an authorization-filtered,
content-revisioned ontology snapshot and returns asserted/derived explanation
steps with source fact references. Independent source-row, derived-row,
derivation-step, elapsed-time, and explanation-byte bounds return non-sensitive
truncation reasons; no derived facts are persisted.

## Core vocabulary

The public contract is namespace-first and domain-neutral:

- **namespace** — the isolation, policy, and data boundary;
- **actor** — a human, agent, service, or runtime identity;
- **operation** — the intended unit of governed work;
- **attempt** — one execution strategy for an operation;
- **action** — an effect proposed or performed during an attempt;
- **artifact** — an output produced by an attempt;
- **verification** — evidence about artifact or outcome quality; and
- **outcome** — the measured result attributed to an operation.

There is no separate first-class application scope. Repositories, incidents,
tickets, deployments, contracts, and other domain concepts belong in typed
schemas and adapters.

### Enterprise extension boundary

The SQLite/community runtime is single-operator and tenant-free. It creates no
tenant, membership, namespace-ownership, or tenant-credential state; exposes no
tenant administration RPCs; and strips caller-provided `x-sekai-tenant-id`
metadata at the authentication boundary. Credential protocol fields retained
for wire compatibility are ignored and never activate tenant authority.

The public crate exports backend-neutral authenticated-principal,
tenant-context, namespace-action, authorization-hook, and error contracts in
`enterprise`. A PostgreSQL enterprise distribution may implement and inject
those contracts into this authoritative process. Concrete tenant persistence,
OIDC/OAuth behavior, and enterprise composition are not part of the community
runtime.

The current injection seam admits enterprise credentials only to the
namespace-aware object, link, lease, traversal, and object-change RPCs that
invoke the authorization hook. Other Sekai and all Chisei RPCs fail closed for
enterprise-scoped credentials. Action execution and approval resumption also
remain unavailable until an enterprise composition can persist and re-derive
the authenticated approval identity.

SQLite startup detects populated legacy tenant tables or tenant-bound
credentials before normal migrations. It fails without changing them and
directs the operator to [Migrating legacy SQLite tenant state](tenant-migration.md).

## Trust boundaries

Enterprise human identity composes through the versioned, backend-neutral
contract documented in [Enterprise identity extension contract](enterprise-identity-extension.md).
The default SQLite service remains tenant-free and exposes no OAuth/OIDC
runtime endpoints. Validated human and machine credentials converge on one
internal authenticated context; caller metadata never constructs that context.

- Namespace and object access control apply when data is read or mutated.
- Gateway virtual keys and control-plane credentials identify principals; raw
  credential material must not enter audit evidence.
- Object context is filtered by schema classification and egress policy before
  an external provider receives it.
- Model output and graph-derived context remain untrusted data. Tool
  permissions and model-proposed effects must be checked at the host executor
  permit and governed effect boundaries.
- Evaluation gates can prevent a context expansion or learning rule from being
  adopted when candidate behavior regresses against its baseline.

The gateway reduces exposure but does not claim to solve prompt injection.
Applications must still constrain tool permissions and validate effects at
execution time.

### External-action permits

An allowed external-action authorization can be exchanged idempotently for a
short-lived Ed25519-signed permit. The permit binds the actor, namespace,
operation, harness, executor, versioned action and parameter schemas, exact
argument digest, targets, resource preconditions, effects, limits, policy
version, validity window, nonce, and online-redemption mode. Hosts must verify
the configured issuer and key, every binding, their advertised enforcement
capabilities, and current resource preconditions immediately before execution.

Online redemption consumes an invocation in the same SQLite transaction that
records its audit decision. Community PostgreSQL fails closed on
`redeem_permit` / `redeem_or_reconcile_permit` until dual-backend redeem
parity lands; hosts that need online redeem should use SQLite (or an enterprise
backend that implements redeem). Request, permit, redemption, and execution IDs
stay distinct, and an idempotency key makes an ambiguous retry return the
original redemption. Revocation and action/executor/harness/namespace/signing-key
kill switches stop future redemption without removing issuance or redemption
history. They cannot undo an effect that already started. The control plane
does not claim exactly-once external effects: redemption proves consumed
authorization, not execution or outcome.

Policy may additionally name action classes eligible for short
`offline_bounded` leases and actors eligible to delegate. Offline permits carry
signed time/invocation caps and explicitly state that disconnected operation
cannot provide global single-use or immediate revocation. Destructive action
classes remain online-only. Delegation is disabled by default and transfers,
rather than copies, unused parent authority into one narrower child. The signed
child preserves the initiating actor and complete parent chain; every live
link, depth bound, and non-expansion rule is rechecked before use. Offline
leases are not delegable because their local consumption is not globally
observable. On reconnection, the executor records each offline invocation
through the redemption endpoint before submitting evidence. This creates the
durable execution binding needed by evidence admission and detects duplicate or
over-cap reports without pretending the control plane authorized the action
immediately before execution.

Permit signing requires `CHISEI_PERMIT_SIGNING_KEY`, a 32-byte Ed25519 seed
encoded as 64 lowercase hexadecimal characters. `CHISEI_PERMIT_ISSUER` and
`CHISEI_PERMIT_KEY_ID` identify the trusted key. Production deployments should
inject the seed through a secret manager and rotate it as a signing credential;
it must never enter permits, audit evidence, logs, or exported bundles.

Redeemed permits accept attributed lifecycle observations through the existing
Sekai evidence funnel. Accepted, started, completed, failed, cancelled, and
outcome-unknown remain distinct. The signed permit window defines the terminal
evidence deadline; reconciliation raises an alert after it without treating
silence as success. Shomei may embed the signed permit and admitted host report,
while receipts keep host self-report, independent effect verification, and
downstream outcome separate.

## Persistence

SQLite is the server's default storage backend and runs in WAL mode for file
databases. PostgreSQL implements the reusable, non-tenant Sekai persistence
surface with backend-neutral contracts and shared SQLite/PostgreSQL
conformance for dual-backend inventory paths: core graph and authorization,
object-change and decision audit, datasets and virtual tables, action
definitions, function definitions, generation-fenced leases and guarded object
mutations, team-namespace bootstrap, principal credentials, coordination and
work admission, external evidence admission and
projection, policy attestations, handoffs, retention, scoped content, and
reconciliation. Known community Postgres fail-closed exceptions include public
audited ontology mutation RPCs (`upsert_*_with_audit`), FTS text search,
federation peer tables, registered Iceberg/Parquet snapshot projections,
and (on the Chisei side)
online permit redeem and Gunshi allocation state — see the parity guides.

A checked-in `sekai.rpc-inventory/v1` inventory maps every public `SekaiService`
RPC to shared backend evidence or an explicit computed/query implementation
with named durable dependencies. PostgreSQL may advertise the complete reusable
Sekai surface set only when that inventory validates. The inventory fails closed
when an RPC is added without classification or when tenant, OIDC, or OAuth
surfaces appear.

PostgreSQL migrations preserve stable graph query and audit ordering. Contract
updates carry the `updated` value read by the caller as an explicit
compare-and-swap token, preventing stale writers from silently overwriting a
committed revision. Lease mutations serialize by namespace and key, preserve
request idempotency, advance fencing generations monotonically, and record
their audit row in the same transaction. Evidence identity, payload, lifecycle,
projection, integrity, and audit records share their required transactions.

PostgreSQL is a supported community runtime backend when `SEKAI_DB_BACKEND=postgres`
and `DATABASE_URL` are set and migrations plus capability inventories validate
before listeners bind. The reusable Sekai, Chisei, gateway governance, and
operations health surfaces advertise only after dual-backend conformance
evidence is present (see [postgres-sekai-parity.md](postgres-sekai-parity.md)
and [postgres-chisei-parity.md](postgres-chisei-parity.md)). Object-kind changes
that require ontology constraint validation still fail closed on PostgreSQL
where that validation path is unavailable. Provider streams and secrets are not
treated as durable credentials. This contract does not activate tenant
persistence or identity endpoints.

Runtime composition uses the versioned `sekai.runtime-backend/v1` contract.
Its public metadata names the backend and the reusable Sekai, Chisei, gateway,
and operations surfaces it supports. Startup validates the complete community
requirement before binding listeners. Both SQLite and PostgreSQL advertise that
complete community set when their inventories validate; incomplete schemas fail
closed.

External evidence submissions are retained source records. Graph objects,
links, and evidence observations are rebuildable projections. Conflicting
submissions remain separately attributable instead of being collapsed into a
single asserted truth.

The fixed `sekai.governed-facts/v1` profile stores immutable requirement,
invariant, and waiver versions as reserved graph objects. It reuses graph ACLs,
classification markings, transactional object-change audit, and the shared
SQLite/PostgreSQL graph backend rather than creating a requirements database.
An authorization-filtered resolver returns a content-addressed invariant set
for one opaque subject and explicit evaluation time. Hidden reference closure
is omitted before canonicalization, and generic graph CRUD cannot mutate or
disclose these governance objects. Chisei later binds the returned exact
invariant versions to situation-specific evaluator definitions and plans.
Those `chisei.evaluator-definition/v1` and `chisei.evaluation-plan/v1`
resources are immutable and namespace scoped. Definitions identify deployed
deterministic implementations or bounded stochastic policies and their typed
contracts; plans form a bounded acyclic evaluation graph with exact invariant
coverage and one fixed fail-closed reducer. Mutable, audited evaluator
availability blocks future selection without rewriting historical plans.
`EvalSuite` remains test data and does not gain production gate authority. See
[Evaluation plans and evaluator definitions](evaluation-plans.md).

`ResolveEvaluationPlan` combines one exact plan with an opaque subject, the
content-addressed authorized invariant set for an explicit evaluation time,
current exact evaluator definitions, valid waivers, and admitted evidence. It
persists the result as an immutable `chisei.resolved-evaluation-manifest/v1`
document whose digest binds every semantic input. Resolution performs no
evaluator execution and has no independently managed public resource
lifecycle. Exact successful request replay remains available after evaluator
disablement or supersession; new requests fail closed against current
availability. See [Resolved evaluation manifests](evaluation-manifests.md).

The evaluation executor selects only compiled or explicitly registered external
implementations whose exact digest matches the manifest. Deterministic and
stochastic nodes use separate registries; external adapters run through a
bounded authenticated contract and never receive Chisei credentials.
Stochastic policies additionally freeze exact routing, sampling,
fixed trials, aggregation, variance, budget, egress, retention, and gate
eligibility. The executor runs ready nodes in stable topological order and
applies one fixed fail-closed reducer. Step and terminal truth are appended to
the canonical operation receipt; the execution table is only a
manifest-to-receipt index and query projections are reconstructed from receipt
events. Evaluator output content is hashed and discarded. See
[Evaluation execution](evaluation-execution.md).

`GetEvidenceSubmission` is the governed, single-record inspection path for an
admitted envelope. It returns bounded metadata and lifecycle history; retained
content remains inside the evidence projection and pipeline rather than gaining
a second public payload endpoint. Missing and unauthorized submissions remain
indistinguishable to callers, and rejected, quarantined, or incomplete
admission states fail closed.

### Governed context handoffs

Native integrations can transfer bounded context between principals with the
Sekai handoff API. A handoff is a versioned manifest of references to existing
operation receipts, work units, graph objects such as artifacts and
verification records, evidence submissions, and Kioku memories. It never
copies their content or grants access. The creator names one receiving
principal, namespace scope, purpose, expiry, lineage, and any references
deliberately omitted by policy, retention, or availability.

Creation validates every included reference through the creator's current read
path. Resolution is receiver-bound and rechecks the manifest digest, expiry,
revocation, supersession, exact referenced version, namespace access, object
ACLs, evidence lifecycle, Kioku lifecycle, and retention. A reference that has
become unavailable is returned only as a non-disclosing omission; an expired,
revoked, superseded, unauthorized, or corrupt manifest fails as not found.
Resolved manifests are receiver projections: unavailable reference identities
and versions are removed, so their digest identifies the creator's immutable
manifest but cannot be recomputed from a redacted projection.
Creation and revocation are idempotent and recorded with the manifest in the
handoff audit tables. Shared SQLite/PostgreSQL conformance covers the reusable
handoff contract; community runtime selection of PostgreSQL remains gated by
broader Chisei and gateway parity, not by handoff storage.

### Identity, content, and reconciliation

Retry identity is scoped to an operation and idempotency key and is bound to a
canonical request digest. Replaying that request returns its recorded result;
reusing the key for different canonical input fails explicitly. Source-record
identity remains producer, source instance, immutable source record ID, and
source version. Neither contract treats equal payloads as proof of one causal
occurrence.

Immutable content can share SQLite storage only within an identical namespace,
classification, encryption-key, and residency scope. The stored digest is
domain-separated and includes that scope, and content is readable only through
an independently authorized live reference. References retain their own actor,
operation, and causal identity even when their blob is shared. Retention and
legal holds, archive state, receipt dependencies, and attestation dependencies
block collection. Once those obligations and all live references are gone,
collection removes the payload while retaining required erasure tombstones and
audit events.

Object reconciliation is an explicit, append-only overlay over original graph
objects. Namespace, kind, external identity, source precedence, and
authoritative mappings define a case. Merge, alias, split, suppress, conflict,
and reversal decisions are idempotent and audited; they never delete the source
objects or their lineage. Semantic similarity is not a reconciliation action
and cannot silently merge evidence.

These storage and reconciliation contracts are part of the complete reusable
Sekai surface set implemented for both SQLite and PostgreSQL. They do not
activate community PostgreSQL runtime selection by themselves, and they do not
change the public protobuf contract.

Ontology relations opt into graph enforcement by setting `mapped_relation`.
New links and object updates that would violate the relation's effective domain
or range are rejected after endpoint authorization, including when class
membership is inherited or equivalent. Existing links are never rewritten;
operators must inspect the affected graph objects before enabling or remediating
a constraint.

## Design constraints

- Local-first and inspectable by default.
- Namespace-first isolation.
- Structured records over hidden conversational state.
- Explicit policy, audit, and approval behavior.
- Measured adoption of strategies and learnings.
- Incremental integration through compatible gateways and native APIs.

Operational epistemic-context aggregates, denominators, privacy boundaries,
and backend availability semantics are defined in
[epistemic-context-operations.md](epistemic-context-operations.md).

Read [VISION.md](../VISION.md) for the long-term direction and non-goals.
