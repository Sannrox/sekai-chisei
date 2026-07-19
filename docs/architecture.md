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

### Chisei: governed decisions

Chisei resolves how an operation may proceed. It owns policy, context
enrichment, budgets, egress decisions, approval requirements, model/runtime
routing, evaluation gates, outcome attribution, and learning rules.

The LLM provider adapters execute calls but do not own these decisions.
Provider-specific behavior stays behind `src/llm/` abstractions.

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

## Trust boundaries

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

## Persistence

SQLite is the server's current storage backend and runs in WAL mode for file
databases. PostgreSQL implementations exist for selected persistence
interfaces, but they are not a drop-in replacement for the server's complete
SQLite path. The graph, policy state, receipts, evidence, and audit history are
durable; provider streams and secrets are not treated as durable credentials.

External evidence submissions are retained source records. Graph objects,
links, and evidence observations are rebuildable projections. Conflicting
submissions remain separately attributable instead of being collapsed into a
single asserted truth.

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

These storage and reconciliation contracts belong to the complete SQLite
runtime. They do not expand the selected PostgreSQL persistence interfaces or
change the public protobuf contract.

## Design constraints

- Local-first and inspectable by default.
- Namespace-first isolation.
- Structured records over hidden conversational state.
- Explicit policy, audit, and approval behavior.
- Measured adoption of strategies and learnings.
- Incremental integration through compatible gateways and native APIs.

Read [VISION.md](../VISION.md) for the long-term direction and non-goals.
