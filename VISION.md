# VISION

## Purpose

`sekai-chisei` is a local-first control plane for governed agent operations.

Its job is not to provide an agent runtime or merely call models. Its job is to
maintain enough durable context, policy, budget, verification, and outcome data
to make autonomous or semi-autonomous operations predictable, governable, and
continuously improvable across domains.

The product has two layers:

- `sekai` owns durable facts: namespaces, actors, operations, attempts, actions,
  artifacts, verification, outcomes, lineage, access, audit history, and memory
- `chisei` owns decisions: policy, context, routing, budgets, approvals,
  evaluation, and learning rules

`LlmService` executes provider calls but is not the policy boundary. Existing
OpenAI- and Anthropic-compatible clients enter through the gateway; native
integrations use `PlanExecution` and `ExecutePlan`. Both paths are governed by
the same control plane.

## Problem

Agent systems commonly fail in the same ways:

- They do not retain structured context across operations
- They cannot explain why a model, runtime, or action was chosen
- They do not accumulate reliable knowledge from prior outcomes
- They lack hard controls for spend, access, egress, and safety
- They struggle to compare one execution strategy against another

`sekai-chisei` closes those gaps with a local-first, inspectable service that
operators can control without coupling governance to one agent, model provider,
or domain executor.

## Vision

The system should answer five questions well:

1. What durable facts are relevant to this operation?
2. What actor, runtime, and model should handle it?
3. What constraints and approvals apply before action begins?
4. How do we verify and measure the outcome?
5. What should the system learn so the next attempt improves?

If this project succeeds, an organization can represent its operating
environment as a namespace-isolated graph, run agent operations through
governed entry paths, and improve future decisions through verified outcomes.

## Product Boundary

### Sekai: Durable Facts

`sekai` is the canonical operational memory:

- typed objects and relations for actors, operations, attempts, actions,
  artifacts, verification, and outcomes
- graph traversal, lineage, schema validation, derived properties, datasets,
  and virtual tables
- audit trails for decisions and object changes
- namespace-first access control around read and write behavior

This layer stays simple, queryable, and durable. Domain concepts such as a
repository, support ticket, campaign, contract, deployment, or clinical case
belong in schemas and adapters rather than the core contract.

### Semantic Ontology Layer

Above the durable graph sits a semantic ontology that lets objects be understood
by their meaning and relationships, not only their kind. It elevates the current
typed property graph into a reasoned knowledge layer:

- ontology classes, properties, and relations with inheritance, equivalence,
  disjointness, and domain/range constraints
- inference and entailment (subclass, transitivity, rules) over asserted facts
- temporal semantics for state over time and change causality
- semantic and reasoning-aware query surfaces, including an LLM-facing command
  set that composes resolve, expand, apply, retrieve, and summarize

The intended layering is:

```
Natural Language -> Semantic Ontology -> Knowledge Graph -> Governance Engine -> Agent Runtime
```

The ontology stays governed and namespace-scoped like the rest of `sekai`, and
remains interoperable with external standards (RDF/OWL, GraphQL). It adds meaning
above the durable facts; it does not pull domain-specific concepts into the core
contract, which continue to live in schemas and adapters.

### Chisei: Governed Decisions

`chisei` decides how operations may proceed:

- resolve allowed runtimes and models from namespace policy
- enforce budgets, egress rules, action policy, and approval requirements
- enrich operations with relevant memory and risk signals
- evaluate attempts and attribute outcomes
- adopt learning rules only through explicit governance

The decision layer makes policy choices inspectable instead of burying them in
an agent runtime or provider adapter.

### Governed Entry Paths

The gateway accepts existing OpenAI- and Anthropic-compatible clients. The
native execution API plans and executes an operation through `PlanExecution`
and `ExecutePlan`. These are two entry paths into the same control plane, not
separate products.

Agent runtimes and domain executors remain replaceable integrations. Bugyo and
Tenkai provide software-delivery behavior, but repository, worktree, commit,
test-suite, deployment, and ticket concepts do not define the core ontology.

### Evaluation And Learning Loop

The product supports a disciplined improvement cycle:

- define eval suites and verification criteria for outcomes
- compare candidate behavior against baselines
- mine recurring success and failure patterns
- enrich future operations with bounded historical context
- turn execution history into governed templates and learnings

The important shift is from "run an agent" to "govern an operation inside a
measurable system."

## Design Principles

- Local-first by default. Operators can run the control plane on their own
  infrastructure, with SQLite and gRPC as the initial baseline.
- Namespace-first isolation. Namespace remains the core policy and data
  boundary; there is no separate first-class application scope.
- Structured over conversational. Important facts become typed objects, links,
  datasets, policies, and audits instead of remaining in prompt text.
- Governed autonomy. Agents operate inside explicit budget, access, egress,
  action, and approval constraints.
- Measurable improvement. Strategies are compared against baselines and
  verified outcomes rather than adopted on intuition.
- Explainable decisions. Context, routing, access, actions, and outcomes remain
  inspectable after the fact.
- Incremental adoption. Existing clients can use the gateway while deeper
  integrations adopt the native execution API.

## Non-Goals

This project should not become:

- a generic workflow engine or agent runtime
- a thin proxy around third-party LLM APIs
- an opaque autonomous agent that cannot justify its decisions
- a domain-specific platform that embeds repositories, tickets, campaigns, or
  similar integration concepts in its core contracts
- a replacement for domain systems of record

It integrates with runtimes and domain systems while remaining focused on
durable facts, governed decisions, evaluation, and learning.

## Current State

The codebase already establishes the core direction:

- a Rust gRPC server with separate `sekai`, `chisei`, and `llm` services
- a SQLite-default object graph (optional community PostgreSQL for dual-backend
  reusable surfaces) with links, datasets, virtual tables, lineage, audit,
  actions, and security controls
- policy resolution, context enrichment, budget tracking, and model routing
- governed native execution and a compatible HTTP gateway
- evaluation, outcome, learning, and evolution primitives
- provider adapters for OpenAI, Anthropic, Ollama-compatible, and native
  endpoints

The next challenge is presenting and extending these primitives as one coherent,
domain-neutral operating model.

## Next Milestones

### Near Term

- Make the public surfaces communicate one product boundary
- Persist more execution history so decisions and outcomes are first-class data
- Tighten the connection between verification, learnings, and future decisions
- Continue hardening authorization and policy enforcement

### Mid Term

- Improve model and runtime selection using observed performance
- Strengthen lineage across operations, actions, artifacts, verification, and
  outcomes
- Support operational reporting for reliability, budget pressure, and agent
  effectiveness across domains

### Long Term

- Become the governance backbone for multi-agent operations across namespaces
  and teams
- Enable organizations to treat agent policy as infrastructure
- Make operational memory cumulative so every verified outcome improves future
  execution quality
- Grow the semantic ontology layer into first-class reasoning, temporal, and
  simulation capabilities over the governed graph

## Success Criteria

`sekai-chisei` is succeeding when:

- operators can inspect why an operation was routed to a model or runtime
- prior outcomes materially improve future context and decisions
- budgets, access, egress, action, and approval controls prevent unsafe or
  wasteful execution
- evaluation gates catch regressions before new strategies are adopted
- the graph becomes trusted operational memory across multiple domains
- a new domain can integrate through schemas and adapters without changing the
  core contracts

## Short Version

Build a system where agent operations are:

- context-aware
- policy-governed
- budget-constrained
- auditable
- verifiable
- measurable
- self-improving

That is the role `sekai-chisei` should own.
