# VISION

## Purpose

`sekai-chisei` should become the control plane for AI-assisted software delivery.

Its job is not just to call models. Its job is to maintain enough structured memory, policy, runtime context, and evaluation feedback to make autonomous or semi-autonomous coding agents predictable, governable, and continuously improvable.

In practical terms, this project combines two layers:

- `sekai`: a durable graph and dataset system for namespaces, components, agents, tasks, learnings, lineage, access, and audit history
- `chisei`: a decision layer that applies budget controls, policy resolution, task routing, model selection, evaluation, and evolution based on what `sekai` knows

The long-term goal is to make AI execution look less like isolated prompt calls and more like an operating system for engineering work.

## Problem

Most agent systems fail in the same ways:

- They do not retain structured context across tasks
- They cannot explain why a model, runtime, or action was chosen
- They do not accumulate reliable learnings from prior work
- They lack hard controls for spend, access, and safety
- They struggle to compare one prompting or execution strategy against another

`sekai-chisei` exists to close those gaps with a local-first, inspectable service that teams can control.

## Vision

The system should answer five questions well:

1. What is the relevant world model for this task?
2. What agent, runtime, and model should handle it?
3. What constraints apply before execution starts?
4. How do we measure whether the outcome was good?
5. What should the system learn so the next run improves?

If this project succeeds, an engineering organization can represent its working environment as a graph, run AI tasks against that graph through governed pipelines, and continuously improve task quality through evaluation and observed outcomes.

## Product Shape

### 1. World Model

`sekai` should be the canonical memory layer for operations:

- components, tasks, models, agents, policies, learnings, audit records, and graph relations
- typed relations between those objects
- graph traversal, lineage, schema validation, derived properties, datasets, and virtual tables
- audit trails for decisions and object changes
- access control around read and write behavior

This layer should stay simple, queryable, and durable. It is the ground truth that higher-level agent workflows depend on.

### 2. Agent Intelligence Policy Plane

`chisei` should decide how work gets executed:

- resolve allowed runtimes and models from namespace or namespace policy
- enforce token budgets and surface capacity pressure
- enrich tasks with prior learnings and risk signals
- recommend execution choices instead of treating every task as stateless
- maintain task-run history that can later be audited and improved

This layer should make routing decisions explicit rather than implicit.

### 3. Evaluation And Learning Loop

The project should support a disciplined improvement cycle:

- define eval suites and cases for task outcomes
- compare candidate behavior against baselines
- mine recurring success and failure patterns
- enhance future task specs with historical context
- turn execution history into reusable templates and learnings

The important shift is from "run an agent" to "run an agent inside a measurable system."

### 4. Provider Abstraction Without Provider Dependence

LLM access should be pluggable across OpenAI, Anthropic, local Ollama, and native endpoints, but the value of the project should not depend on any one provider.

The durable asset is the decision layer and the memory model around the providers, not the transport adapter itself.

## Design Principles

- Local-first by default. Teams should be able to run this on their own infrastructure with SQLite and gRPC as the initial operating baseline.
- Structured over conversational. Important facts should become typed objects, links, datasets, policies, and audits instead of staying trapped in prompt text.
- Governed autonomy. Agents should operate inside explicit budget, access, and policy constraints.
- Measurable improvement. New strategies should be compared against baselines, not adopted on intuition.
- Explainable decisions. Model choice, routing, access, and outcomes should be inspectable after the fact.
- Incremental adoption. The system should be useful even before every part of the graph or eval stack is fully populated.

## Non-Goals

This project should not become:

- a generic workflow engine with no opinion about AI delivery
- a thin proxy around third-party LLM APIs
- an opaque autonomous agent that cannot justify its decisions
- a monolithic developer platform that tries to replace source control, CI, or issue tracking

It should integrate with those systems as needed while remaining focused on memory, policy, evaluation, and orchestration.

## Current State

The codebase already establishes the core direction:

- a Rust gRPC server with separate `sekai`, `chisei`, and `llm` services
- a SQLite-backed object graph with links, datasets, virtual tables, lineage, audit, actions, and security controls
- policy resolution and budget tracking for AI execution
- a pipeline that enriches tasks, scores namespace risk, and recommends a model
- an evaluation store with baseline comparison
- evolution utilities that extract patterns and improve task specs
- provider adapters for OpenAI, Anthropic, Ollama-compatible, and native endpoints

That means the project is past the idea stage. The next challenge is turning these primitives into a coherent operating model.

## Next Milestones

### Near Term

- Make the gRPC surface feel like one coherent product, not a collection of adjacent primitives
- Persist more of the `chisei` runtime history so pipeline decisions and outcomes become first-class data
- Tighten the connection between eval results, learnings, and future pipeline recommendations
- Expand security and authorization from basic checks toward production-ready policy enforcement

### Mid Term

- Improve model and runtime selection using observed performance instead of defaults
- Build stronger lineage between tasks, code changes, evaluations, and deployed outcomes
- Support operational reporting for reliability, budget pressure, and agent effectiveness

### Long Term

- Become the backbone for multi-agent software delivery across many namespaces and teams
- Enable organizations to treat AI execution policy as infrastructure
- Make engineering memory cumulative so every completed task improves future execution quality

## Success Criteria

`sekai-chisei` is succeeding when:

- teams can inspect why a task was routed to a specific model or runtime
- prior learnings materially improve future task specs and outcomes
- budgets, access, and policy controls prevent unsafe or wasteful execution
- evaluation gates catch regressions before new agent strategies are adopted
- the graph becomes a trusted operational memory for engineering work

## Short Version

Build a system where AI coding work is:

- context-aware
- policy-governed
- budget-constrained
- auditable
- measurable
- self-improving

That is the role `sekai-chisei` should own.
