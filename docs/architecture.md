# Architecture

`sekai-chisei` is a governance control plane, not an agent runtime or workflow
engine. Agent clients and domain executors stay replaceable; the control plane
owns durable facts and the decisions that constrain an operation.

## Components

```text
OpenAI / Anthropic clients        Native integrations
            |                            |
            v                            v
     chisei-gateway             PlanExecution / ExecutePlan
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
payload or lose a retaining obligation. These reusable surfaces do not activate
PostgreSQL as the community runtime backend and do not add tenant or identity
capabilities.

Reusable coordination leases use a dedicated namespace-scoped API. Every
acquisition receives a monotonically increasing generation and unique fencing
token; stale generations cannot refresh, release, or take over current state.
Lease-guarded create, update, and delete RPCs validate the active generation and
commit the graph mutation, object audit, and idempotency record in the same
backend transaction. Shared SQLite/PostgreSQL conformance covers this
cross-table contract; partial storage interfaces that cannot provide it fail
closed. See [Generation-fenced leases](leases.md) for the client and
downstream-executor contract.

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
`ExecuteAction` calls.

An authorization decision is not execution evidence. The v1 decision contract
does not issue a signed permit; permit issuance, redemption, and submitted host
evidence are separate protocol stages. A host must refuse execution unless it
can verify the eventual permit and enforce every declared constraint. Chisei
does not claim that an authorization or host observation proves a physical
effect occurred.

Operator clients may use `GetEffectivePolicySummary` to render a live,
read-only namespace projection of effective routing, configured budget limits,
bounded action-rule counts, and governed worker concurrency. Each section
reports its owning scope and revision or an explicit unconfigured state. The
projection never includes budget usage, request-specific verdicts, raw action
rules, credentials, or caller-supplied runtime capacity, and every request is
checked against namespace read access.

Native runtimes can use the namespace-scoped
[capability catalog](capability-catalog.md) to discover visible object queries,
bounded retrieval surfaces, and governed actions before invocation. Catalog
visibility is filtered for the authenticated authorization context and never
acts as an authorization token; invocation always rechecks live controls.

`SearchText` exposes the rebuildable SQLite FTS5 text representation and the
shared `HybridCandidate` envelope (research #152 / issue #360). Scores use
`text.fts5_bm25/v1` and never mint durable identities; authz is re-checked per
hit. See [text-fts.md](text-fts.md). Late fusion across adapters is #361.

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
  permissions and model-proposed effects must be checked at `ExecuteAction`.
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
records its audit decision. Request, permit, redemption, and execution IDs stay
distinct, and an idempotency key makes an ambiguous retry return the original
redemption. Revocation and action/executor/harness/namespace/signing-key kill
switches stop future redemption without removing issuance or redemption
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
databases. PostgreSQL implements the complete reusable, non-tenant Sekai
persistence surface with backend-neutral contracts and shared
SQLite/PostgreSQL conformance: core graph and authorization, object-change and
decision audit, datasets and virtual tables, ontology and action definitions,
function definitions, generation-fenced leases and guarded object mutations,
capability-package lifecycle, team-namespace bootstrap, principal credentials,
coordination and work admission, external evidence admission and projection,
policy attestations, handoffs, retention, scoped content, and reconciliation.

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

PostgreSQL is still not a drop-in replacement for the community process's
complete SQLite runtime. Chisei governed-decision persistence, gateway
governance, and operations composition remain outside the complete reusable
Sekai advertisement, so public runtime selection of PostgreSQL continues to
fail closed until those surfaces have equivalent parity. Object-kind changes
that require ontology constraint validation still fail closed on PostgreSQL
where that validation path is unavailable. Provider streams and secrets are not
treated as durable credentials. This contract does not activate tenant
persistence or identity endpoints.

Runtime composition uses the versioned `sekai.runtime-backend/v1` contract.
Its public metadata names the backend and the reusable Sekai, Chisei, gateway,
and operations surfaces it supports. Startup validates the complete community
requirement before binding listeners. SQLite advertises that complete set;
PostgreSQL selection fails early until later Chisei and gateway parity can
truthfully complete it.

External evidence submissions are retained source records. Graph objects,
links, and evidence observations are rebuildable projections. Conflicting
submissions remain separately attributable instead of being collapsed into a
single asserted truth.

`GetEvidenceSubmissionContent` is the governed, single-record read path for an
admitted envelope. It resolves the submission's projected `external_evidence`
object and rechecks that object's live ACL before returning the immutable
content and provenance. Missing and unauthorized submissions are deliberately
indistinguishable to callers, retained content is verified against its
canonical digest before disclosure, and metadata listing never includes
payloads. Available, superseded, stale, and retracted records remain readable
as retained source evidence; rejected, quarantined, and incomplete admission
states fail closed. Evidence classification is enforced through the projected
object ACL in the current contract; there is no separate caller-clearance
model.

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
operators can call `ReportOntologyLinkViolations` for an authorized,
read-only inventory before enabling or remediating a constraint.

## Design constraints

- Local-first and inspectable by default.
- Namespace-first isolation.
- Structured records over hidden conversational state.
- Explicit policy, audit, and approval behavior.
- Measured adoption of strategies and learnings.
- Incremental integration through compatible gateways and native APIs.

Read [VISION.md](../VISION.md) for the long-term direction and non-goals.
