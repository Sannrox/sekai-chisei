# Reference platform boundary research

Status: implementation guidance; persistence decision accepted in [ADR 0082](../decisions/0082-separate-chisei-and-sekai-durable-stores.md)
Research date: 2026-09-17
Scope: public, official first-party documentation only. The source material is translated into neutral capability names below. This note does not depend on, inspect, or reproduce any change-set from a pull request.

## Executive conclusion

The reference architecture is best understood as an authority stack, not as two
independent applications that happen to call one another:

    application and workflow experiences
            |
            v
    decision and AI orchestration
            |
            |  typed, authenticated, scoped API
            v
    semantic + governance authority
            |
            v
    durable data and transaction authority
            |
            v
    storage, compute, network, and deployment substrate

The reference architecture groups semantic language, semantic engine/tooling,
data and logic services, workflow services, applications, automations, and
product delivery over cross-cutting storage, compute, networking, security,
governance, and workspace capabilities. Deployment and continuous delivery are
treated as a separate substrate that hosts the other capabilities. This is a
capability and ownership model, not a prescription that every capability must
be a separate process. [Official architecture overview](https://www.palantir.com/docs/foundry/architecture-center/platforms)

For sekai-chisei, the correct translation is:

- sekai owns the Sekai store: durable data, semantic definitions,
  authorization enforcement, action admission, durable execution, mutation
  audit, and Sekai commit receipts.
- chisei owns a separate Chisei store for policy decisions, budgets,
  reservations, routing, evaluation, model/provider orchestration, workflow
  state, and Chisei decision receipts.
- chisei may read Sekai facts through a typed client and submit a versioned
  decision envelope, but it must not open the Sekai database or issue arbitrary
  object patches.
- sekai must re-check current authority and commit the action atomically. A
  decision from chisei is input to admission, not a substitute for current
  authorization or a proof that an effect occurred.

This preserves the repository's existing distinction between durable facts and
governed decisions while making the process boundary real.

## What the public architecture establishes

### 1. Durable data plane

The reference platform's foundational data representation is a dataset: a
logical wrapper around files with permissions, schema management, version
control, and updates over time. Dataset changes use explicit transactions with
open, commit, and abort states. [Dataset concepts and transactions](https://www.palantir.com/docs/foundry/data-integration/datasets)

Data is not treated as an undifferentiated application cache. The platform
records which inputs produced an output and which transformation logic was
used. Lineage is exposed as a first-class view over sources, datasets,
transformations, and downstream artifacts. [Introductory data and object concepts](https://www.palantir.com/docs/foundry/getting-started/introductory-concepts), [data lineage overview](https://www.palantir.com/docs/foundry/data-lineage/overview)

**Boundary implication.** The durable data plane should own bytes, canonical
records, schema/type revisions, transaction state, lineage, and recovery. A
consumer may receive an authorized projection or a revision-bound snapshot;
it should not receive a database handle or rely on private storage tables.

### 2. Semantic layer

The semantic layer sits above integrated data assets and maps them to
real-world concepts. It contains objects, properties, and links, but also the
action and function definitions that describe how those concepts can change.
The source documentation explicitly presents data, logic, action, and security
as a combined operational model rather than as a thin catalog over data.
[Semantic/operational layer overview](https://www.palantir.com/docs/foundry/ontology/overview), [semantic system architecture](https://www.palantir.com/docs/foundry/architecture-center/ontology-system)

The documentation distinguishes schema-like resources from their instances:
object types, link types, and action types define the model; objects and links
carry primary keys and actual property values. [Resource versus instance permissioning](https://www.palantir.com/docs/foundry/object-permissioning/overview)

**Boundary implication.** Semantic definitions are authoritative resources, not
DTOs reconstructed independently by each process. sekai should own the
canonical type/action/function descriptors and expose versioned, authorized
read contracts. chisei may cache or compile a descriptor for a decision, but
the descriptor revision must be carried into the commit request and checked by
sekai.

### 3. Governance and authorization

The reference platform separates discretionary role grants from mandatory
controls. Projects organize work and act as the primary boundary for role
grants, while markings, classifications, and organization constraints continue
to apply across projects and derivations. [Projects, roles, and mandatory controls](https://www.palantir.com/docs/foundry/security/projects-and-roles)

Authorization is applied at more than one level. Resource visibility and
instance visibility are different checks; an action requires permission on the
action definition and on all semantic resources it edits. Action application
also depends on visibility of the affected data and submission criteria.
[Semantic resource permissions](https://www.palantir.com/docs/foundry/object-permissioning/ontology-permissions), [action application permissions](https://www.palantir.com/docs/foundry/action-types/permissions)

New object types are documented as favoring action-only edits, so an application
can receive a meaningful, permissioned write operation without being granted
broad direct edit access to the backing data. [Action-only edit guidance](https://www.palantir.com/docs/foundry/action-types/permissions)

**Boundary implication.** Authorization is not a gateway-only concern and it
cannot be reduced to "the caller authenticated." The authoritative data and
semantic service must enforce it at read and commit time. chisei can apply
decision policy such as budget, routing, or evaluation, but it must not weaken
resource authorization or turn a forwarded principal header into identity.

### 4. Execution layer

Actions are reusable, named operation boundaries for creating, modifying,
deleting, and linking semantic objects. Their parameters form an interface
between the operation and consuming applications. [Action building blocks](https://www.palantir.com/docs/foundry/workshop/actions-overview), [action parameters](https://www.palantir.com/docs/foundry/action-types/parameter-overview)

Declarative action rules can be extended by function-backed actions for complex
multi-object edits. The action definition remains the governed entry point;
the function supplies execution logic behind it. [Action rules and function-backed actions](https://www.palantir.com/docs/foundry/action-types/explore-action-types), [server-side functions](https://www.palantir.com/docs/foundry/functions/overview)

External effects are explicitly distinguished from local object edits. A
webhook can run before edits, in which case failure prevents the edits, or after
edits, in which case the local success may already be visible when the external
call fails. [Action side effects](https://www.palantir.com/docs/foundry/action-types/explore-action-types), [side-effect overview](https://www.palantir.com/docs/foundry/action-types/side-effects-overview)

Automation is a scheduler/trigger layer over these primitives: conditions can
be time-based or data-based, and effects can submit actions, call functions,
invoke AI logic, or send notifications. [Automation conditions and effects](https://www.palantir.com/docs/foundry/automate)

The public documentation also describes staged edits being merged as a single
transaction. That is the relevant pattern for sekai: stage or validate the
full mutation set, then commit the durable local change as one unit.
[Single-transaction scenario merge](https://www.palantir.com/docs/foundry/action-types/explore-action-types)

**Boundary implication.** chisei should produce an intent/decision/plan and
durably hold any budget reservation in its own store; sekai should execute the
named operation. The Sekai commit service must own the transaction containing
the instance, object changes, effect records, audit evidence, idempotency
record, and Sekai commit receipt. The Chisei reservation is linked by an
operation id and finalized through an idempotent reconciliation protocol.
External effects must have their own lifecycle and reconciliation state; a
successful local commit must not be reported as proof of a remote effect.

### 5. AI and agent integration

The AI architecture is built on the same semantic, action, governance, and
developer foundations. It includes secure model connectivity, context
integration, agent lifecycle, observability, evaluation, automation, and
packaging/deployment. [AI architecture overview](https://www.palantir.com/docs/foundry/architecture-center/aip-architecture)

An agent is described as application logic with a semantic SDK client, tool
configuration, and agent logic. Published agents are callable functions and
can be triggered from applications, automation, SDKs, or semantic actions.
[Pro-code agent model](https://www.palantir.com/docs/foundry/agents/overview)

AI logic can query semantic data and compose edits, but the documentation
separates read-time authorization from downstream output and edits. AI logic
uses user/function permissions for the read path; the composed edit still needs
to pass through the governed action path. [AI logic security and edits](https://www.palantir.com/docs/foundry/logic)

Evaluation is a lifecycle capability, not an authorization result. Evaluation
suites compare test cases, evaluators, model/function versions, and run
variance to build confidence before production changes. [AI evaluation lifecycle](https://www.palantir.com/docs/foundry/aip-evals/overview)

External agent access uses scoped OAuth clients and either user-delegated or
service-to-service credentials. The same application restrictions and
underlying resource permissions apply to the exposed tools. [Agent authentication and authorization](https://www.palantir.com/docs/foundry/ontology-mcp/authentication-and-authorization), [application restrictions and scope intersection](https://www.palantir.com/docs/foundry/developer-console/application-restrictions)

**Boundary implication.** Treat model output as an untrusted proposal. The
agent may select a typed read or action tool, but the tool service must enforce
scope, current authorization, action constraints, preconditions, and audit. An
agent-facing API should expose capabilities and operation schemas, not SQL,
arbitrary mutation maps, or a privileged database credential.

### 6. Application layer

The application layer reads through the semantic object model, uses actions for
writeback, and uses functions for business logic. It does not define a second
write protocol for each screen. [Application builder boundary](https://www.palantir.com/docs/foundry/workshop/overview)

The developer SDK is generated from a selected subset of semantic resources and
uses scoped tokens in addition to the user's data permissions. The documentation
explicitly recommends treating the platform as the application backend and
notes that read-time controls do not automatically protect data after it has
been returned to the application. [Semantic SDK application model](https://www.palantir.com/docs/foundry/ontology-sdk/overview)

Custom applications, containerized code, APIs, and built-in applications are
therefore different frontends over shared semantic/data contracts. The
developer toolchain exposes object reads, actions, functions, and AI logic
through generated SDKs and APIs. [Developer toolchain contracts](https://www.palantir.com/docs/foundry/dev-toolchain/overview), [containerized application execution](https://www.palantir.com/docs/foundry/compute-modules/overview)

**Boundary implication.** ChiseiService is an application/decision surface,
not an alternate database façade. Its remote client should be the same typed
kind of contract that a first-party application would consume: narrow,
versioned, scoped, and explicit about reads, decisions, commits, and receipts.

## Database-free clarification

The public material does not establish that the AI-side implementation is
database-free. It describes server-side logic running in an isolated
environment, reading and proposing edits through platform APIs, while
evaluation sets, execution logs, traces, sessions, projects, and audit remain
durable platform resources. [Server-side functions](https://www.palantir.com/docs/foundry/functions/overview), [evaluation records](https://www.palantir.com/docs/foundry/integrate-models/evaluations-overview), [observability](https://www.palantir.com/docs/foundry/observability/overview), [session and audit controls](https://www.palantir.com/docs/foundry/ai-fde/security-and-governance)

Therefore, “database-free” in this repository was too broad. The accepted
boundary is database isolation, not statelessness:

- Chisei has no Sekai `RuntimeDb`, Sekai SQL handles, or Sekai migrations.
- Chisei persistence code owns the separate Chisei store; decision logic should
  depend on explicit repository interfaces rather than raw connections.
- Sekai authority APIs provide facts and commit authority; they do not become
  the storage API for Chisei budgets, workflows, evaluations, or receipts.
- Budget reservations, workflow state, evaluation records, and receipts must
  have an explicitly assigned durable owner; they must not hide in process-local
  memory.
- Any future cross-plane state must use an explicit ownership and persistence
  contract rather than a cross-database join.

### 7. Deployment and security substrate

The reference architecture assigns continuous delivery and infrastructure
management to a hosting substrate, while the data/semantic/AI capabilities
run above it. [Integrated deployment architecture](https://www.palantir.com/docs/foundry/architecture-center/platforms)

For self-hosted deployments, the official guidance calls for encryption at
rest and in transit, TLS 1.2 or newer, zero-trust access, network segmentation,
default-deny inbound traffic, controlled egress, hardened hosts, restricted
privileged access, and backups. [Self-hosted security guidance](https://www.palantir.com/docs/foundry/security/protect-foundry-installation)

The shared-responsibility model assigns infrastructure, storage, compute,
database, networking, patching, and platform monitoring to the platform
operator, while customer-built applications, identity/access configuration,
resource permissions, data, and application monitoring remain customer
responsibilities. [Shared security responsibilities](https://www.palantir.com/docs/foundry/security/shared-security-responsibility-model)

Audit records are a separate, structured security surface that identifies who
performed an action, what happened, when it happened, and which resources were
involved. [Audit log model](https://www.palantir.com/docs/foundry/security/audit-logs-overview)

**Boundary implication.** A two-process deployment needs plane-specific
readiness and security contracts: the decision process can be alive while its
authority dependency is unavailable, but it must not advertise mutation
readiness in that state. The process-to-process connection needs its own
authenticated service identity, bounded deadlines, explicit retry rules, TLS
configuration where applicable, and audit attribution that preserves both the
originating principal and the service hop.

## Recommended sekai-chisei ownership model

This table is a repository design inference from the source boundaries above,
not a claim that the reference platform exposes these exact process names.

| Concern | Authoritative owner | Allowed consumer behavior | Must not cross the boundary |
| --- | --- | --- | --- |
| Durable objects, links, datasets, revisions, lineage | sekai | Read an authorized projection with a revision/token | Direct database access from chisei |
| Semantic type/action/function descriptors | sekai | Read a pinned descriptor version; include its digest in decisions | Duplicate or silently diverging schemas in chisei |
| Resource authorization and current object visibility | sekai | Supply authenticated principal context and request scope | Trusting forwarded identity or client-supplied authorization verdicts |
| Decision policy, budget, routing, evaluation, learning | chisei | Compute a bounded, explainable decision from an authorized snapshot | Treating a decision as permission to write arbitrary data |
| Native action admission and durable commit | sekai | Submit a typed, versioned admission envelope | Chisei-side object mutation or receipt minting |
| Decision evidence, Chisei idempotency, and Chisei decision receipts | chisei store | Persist and query policy, budget, workflow, and evaluation evidence | Sekai mutation receipts or authority tables |
| Mutation audit, Sekai idempotency, and Sekai commit receipts | sekai store | Read the commit receipt by operation identity | A duplicate Chisei commit authority |
| External effect dispatch and reconciliation | Dedicated execution contract, coordinated by sekai | Submit declared effect intent and observe lifecycle | Claiming local commit proves external success |
| Models, prompts, tool planning, agent sessions | chisei or an application worker | Use scoped read/action tools | Giving the model database or unrestricted service credentials |
| User/application API | chisei for decision workflows; sekai for authoritative data APIs | Use typed APIs and capability discovery | Making application screens define private write paths |
| Process startup, transport, TLS, health, release | Deployment/operator substrate | Consume readiness and version signals | Binding a listener before required security and backend checks pass |

The key nuance is the governance row. chisei owns decision governance
(whether and how a request should proceed under policy, budget, routing, and
evaluation); sekai owns authority enforcement (whether the caller can see the
current resources and whether the named operation may commit). This keeps the
decision plane useful without allowing a stale or compromised decision process
to bypass the data plane.

## Target request flow

    caller / application / agent
              |
              | authenticated request
              v
    chisei: load authorized context through clerk
              |
              | policy + budget + routing + evaluation decision
              | persist decision and hold budget in Chisei store
              v
    chisei: build signed/versioned admission envelope
              |
              | action reference, descriptor digest, object revisions,
              | principal, operation id, decision digest, effect declarations
              v
    sekai: authenticate service hop
              |
              | re-read current facts and definitions
              | re-check authorization, constraints, preconditions, idempotency
              v
    sekai: atomic local commit
              |
              | object/link changes + action instance + audit + effect intent
              | + idempotency record + operation receipt
              v
    sekai: return receipt and bounded outcome
              |
              v
    chisei: finalize Chisei state after Sekai result
              |
              v
    chisei: present correlated decision and commit receipts

The chisei decision should be revision-bound. If an object, semantic
descriptor, policy revision, budget reservation, or action definition changed
between context read and commit, sekai should return a stale-context result
and require a new decision. This is a repository inference from the source
platform's versioned data, permissioned actions, and transaction boundaries.

## Contract shape to plan

The first remote contract should be small and authority-oriented:

1. **Authorized context reads:** bounded object reads, type/action descriptors,
   effective policy inputs, and relevant revision tokens.
2. **Action admission/commit:** one typed request carrying operation identity,
   authenticated caller context, action/type revisions, object references,
   expected revisions, decision digest, budget/evaluation references, and
   declared effects.
3. **Receipt lookup:** idempotent retrieval by operation identity, with
   Chisei decision and Sekai commit receipts kept distinct and a correlated
   summary available at the public façade.
4. **Capability discovery:** visibility-filtered descriptions of supported
   reads and action operations. Discovery must never be treated as an
   authorization token; commit must re-check live authority.

The public `SubmitActionInstance` façade remains the admission RPC; its
implementation should make the sequence explicit:

    read context -> decide in chisei -> submit admission -> commit in sekai -> read receipt

Do not make the first RPC a generic Execute endpoint. The source architecture
uses named, parameterized, permissioned operations; a generic endpoint would
hide the action schema, widen authorization, and make audit interpretation
ambiguous. This is an implementation inference from the action and application
contracts above.

## Phased rework plan

### Phase 0: freeze invariants

Document the existing action-instance behavior as compatibility invariants:
schema validation, submission criteria, policy, budget, idempotency, digest
binding, audit, effect records, receipts, and SQLite/PostgreSQL behavior. Mark
which fields are caller intent, chisei decision evidence, and sekai
authoritative commit evidence.

### Phase 1: make planes explicit

Add explicit combined, sekai, and chisei startup modes. combined keeps the
current compatibility composition while opening two stores. sekai opens only
the Sekai store and exposes authoritative services. chisei opens only the
Chisei store and fails readiness when its clerk endpoint is absent. Unknown
modes fail closed.

### Phase 2: extract a typed clerk contract

Create request/response types independent of RuntimeDb. Provide an in-process
adapter for combined and a remote transport adapter for split mode. The
contract should carry principal context, operation identity, descriptor
revision, expected object revisions, bounded error codes, and service-hop
attribution.

### Phase 3: centralize atomic commit

Introduce one Sekai backend command for admitted action persistence. Its
transaction must cover the action instance, all local object/link mutations,
effect intent, audit, Sekai idempotency, and Sekai commit receipt. Implement a
separate Chisei reservation/finalization protocol with leases and
reconciliation; do not attempt a distributed database transaction. Implement
and conformance-test SQLite and PostgreSQL paths before making remote
invocation the default.

### Phase 4: isolate chisei persistence

Refactor policy, budget, routing, and evaluation to operate on explicit
authorized context objects and repository interfaces. Move their durable
records to the Chisei store; replace Sekai `RuntimeDb` dependencies with the
typed Chisei store and clerk interfaces. Unsupported remote context must
return an explicit bounded result; it must never silently downgrade to a
weaker governance path.

### Phase 5: place AI and applications above the same contract

Agents and applications receive scoped reads and named actions. Model output
becomes a proposal that is validated by chisei and committed by sekai. Add
evaluation and audit correlation for model/tool calls, but keep those records
separate from authoritative object effects and external execution evidence.

### Phase 6: prove the process boundary

Add black-box subprocess tests that launch the actual binaries and verify:

- sekai serves only authoritative RPCs;
- chisei serves only decision/application RPCs;
- chisei starts with its own store but without Sekai database credentials;
- Sekai starts with its own store but without Chisei database credentials;
- combined mode keeps the stores physically separate;
- chisei refuses mutation readiness without CHISEI_SEKAI_ENDPOINT;
- remote invocation persists and reads back through sekai;
- wrong-plane RPCs fail with bounded status codes;
- caller authentication and service-hop authentication are distinct;
- replay, digest conflict, stale revision, and operation conflict are stable;
- injected failures leave no partial action, object, effect, audit, or receipt;
- restart and SQLite/PostgreSQL conformance preserve the same contract.

## Anti-patterns to reject

- **Module split without process split:** re-exporting facts or passing
  RuntimeDb through a clerk leaves the authority boundary inside one address
  space.
- **Decision-as-permission:** treating a chisei approval as sufficient for a
  write bypasses current authorization and revision checks.
- **Generic mutation RPC:** accepting arbitrary object patches hides semantic
  action identity, constraints, and audit meaning.
- **Stale context commit:** allowing a decision based on old objects or type
  definitions to commit without compare-and-swap or equivalent preconditions.
- **Receipt conflation:** treating decision, local commit, external effect, and
  downstream outcome as one success bit.
- **Agent privilege tunneling:** giving a model or agent a broad database,
  service-user, or internal endpoint credential.
- **External side effect inside the database transaction:** holding a database
  transaction open across an unreliable network call. Use a declared effect,
  durable lifecycle, idempotency key, and reconciliation instead.
- **Unhealthy readiness:** reporting chisei as ready to mutate while its
  authoritative dependency is unavailable.

## Decision

Adopt a backend-authority split:

    sekai = durable data + semantic definitions + authority enforcement + commit
    chisei = decision governance + AI/application orchestration

Keep semantic definitions, authorization enforcement, action execution,
transactionality, audit, and receipts on the sekai side. Keep policy
decisions, budgets, routing, evaluation, and agent/application orchestration
on the chisei side. Connect them with a narrow authenticated clerk contract
that is revision-bound and revalidated at commit time.

This is the smallest split that reflects the public reference architecture's
durable data, semantic, governance, execution, AI, application, and deployment
boundaries without importing its branded vocabulary or pretending that a
database façade is a process boundary.
