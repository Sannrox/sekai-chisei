# Research: core product interface vs full platform RPC surface

Issue: [#383](https://github.com/Sannrox/sekai-chisei/issues/383)  
Date: 2026-07-27  
Status: **recommendation complete**

## Decision question

What is the **supported product interface** for sekai-chisei (operators via
`sekaictl` and agents/SDKs via gRPC/catalog **equally**), and how should the
full public surface be **reduced and tiered** so platform and research APIs stop
defining the product by default?

## Maintainer locks (from #383)

| Topic | Decision |
| --- | --- |
| Wire shrink | Allowed |
| Core consumers | Operators (`sekaictl`) and agents/SDKs **equally** |
| Schema / interface / ontology | **Reduce** dual/triple models in this freeze |
| Timing | **ASAP** |

## Evidence collected

### Public RPC counts (repo HEAD)

| Service | RPCs |
| --- | ---: |
| `SekaiService` (`proto/sekai.proto`) | 137 |
| `ChiseiService` (`proto/chisei.proto`) | 73 |
| `LlmService` (`proto/llm.proto`) | 3 |
| **Total** | **213** |

Backend inventories map evidence, not product tier:

- `tests/fixtures/sekai_rpc_inventory/v1.json` — 137 entries; fields `rpc`,
  `kind`, `surfaces`, `evidence`, `durable_dependencies` (no product tier).
- `tests/fixtures/chisei_rpc_inventory/v1.json` — 76 entries; same shape.
- `complete_*_surfaces` lists dual-backend **storage** claims (#252 family), not
  “product complete.”

### Clustering (product usefulness, not storage)

| Bucket | Count (approx.) | Meaning |
| --- | ---: | --- |
| **Product spine** | ~55–65 | Ontology, facts, grants, policy/budget, plan/execute, receipt, default retrieval, credentials, capability discovery |
| **Platform machinery** | ~95–110 | Leases, guarded mutations, datasets, evidence pipeline, capability packages, external permits, work units, schema/interface registry, pattern IR |
| **Research / secondary lab** | ~45–55 | Evolve\*, deep eval matrix, portfolio, Gunshi auto, hybrid/FTS, temporal admin, gateway-internal decide/alias, scenario overlay, assurance export |

Exact membership of borderline RPCs (e.g. `ListObjects`, external-action
issue/redeem, basic eval suite CRUD) is less important than the **ratio**:
roughly **one quarter spine**, **half platform**, **one quarter lab**. Learning
213 methods is not a product onboarding path.

### Operator surface today (`sekaictl`)

Top-level commands (from `src/bin/sekaictl.rs` usage):

`credential` · `gateway` · `launch` · `doctor` · `smoke` · `action` · `attest` ·
`compliance` · `federation` · `estimate` · `provenance` · `ontology` ·
`receipt` · `replay` · `report` · `memory` · `models` · `team` · `gunshi`

**Gap for the product loop:** `ontology` only supports **`inspect`** (ADR 0003
static HTML). There is **no** `sekaictl ontology apply|define|seed` path that
creates classes/relations or seeds objects. Plan/execute is not a first-class
`sekaictl` journey either (native gRPC / examples / gateway instead).

Ops-heavy subcommands (gunshi allocation, federation, gateway setup) dominate
CLI surface relative to “define world → run one governed op.”

### Agent surface today (capability catalog)

Documented discoverable semantic capabilities
([capability-catalog.md](../capability-catalog.md)):

| Capability | RPC | Product role |
| --- | --- | --- |
| `sekai.semantic.resolve_ref` | `ResolveSemanticRef` | **Core** |
| `sekai.semantic.expand_relations` | `ExpandRelations` | **Core** |
| `sekai.context.retrieve` | `RetrieveContext` | **Core** (default retrieve) |
| `sekai.semantic.explain_derivation` | `ExplainDerivation` | **Core** |
| `sekai.text.search` | `SearchText` | Advanced |
| `sekai.hybrid.retrieve` | `HybridRetrieve` | Advanced |
| `sekai.pattern.execute` / `.explain` | pattern plan | Advanced (post-#375) |
| `sekai.scenario.evaluate` | `EvaluateScenario` | Experimental / lab |

Governed entry for execution remains `PlanExecution` / `ExecutePlan` (and
gateway HTTP). Catalog does not yet present a **short core pack**; agents see
the full discoverable set plus the rest of the wire.

### Type-system dual path (schema / interface / ontology)

From [ontology.md](../ontology.md) and proto RPCs:

| Layer | Role today | Product friction |
| --- | --- | --- |
| **Schema types** (`CreateSchemaType`, …) | Authoritative **object kind validation** | Required to store typed objects; invisible in “ontology first” story |
| **Interfaces** (`CreateInterface`, …) | Separate registry projected with types | Third authoring model; rarely needed for first domain |
| **Ontology classes/relations** | Semantic meaning, ACL’d definitions, proposals | Intended product “define the world” surface |
| **`ProjectSchemaToOntology`** | Schema → ontology bridge | Schema-first migration, not first-run default |
| **Proposals** | Evidence-driven / review workflow | Advanced governance, not day-0 |

A new user cannot complete “define ontology → create facts” with ontology RPCs
alone: object create still needs a **kind** backed by the schema registry.
Reduction must **unify the authoring path**, not pretend validation disappears.

### Mutation dual path

- `CreateObject` / `UpdateObject` / `DeleteObject`
- `GuardedCreateObject` / `GuardedUpdateObject` / `GuardedDeleteObject` (lease
  generation fence)

Two peer CRUD stories. Leases remain important platform machinery; parallel
RPC triples teach the wrong default.

### Retrieval dual path

Default product retrieve: **`RetrieveContext`** (+ semantic resolve/expand).  
Advanced: `SearchText`, `HybridRetrieve`, `ExecutePatternPlan`,
`EvaluateScenario`, raw `Traverse`.

### Related closed research (constraints)

| Ref | Constraint on this freeze |
| --- | --- |
| ADR **0003** / #150 | Ontology *inspection* stays static authenticated artifact — not a live editor |
| #283 | Console is day-2 ops; `sekaictl` remains primary local operator tool |
| #145 / #375 | Pattern IR is structured advanced query, not core SQL |
| #152 / #360 / #361 | Hybrid is advanced fusion, not default retrieve |
| #175 / #281 | Lookup-first uses semantic capabilities; model path remains for NL |
| #252 | Inventory completeness ≠ product core |

## Options compared

| Option | Fit under locks | Verdict |
| --- | --- | --- |
| 1. Facade + tiers only (wire forever stable) | Weak vs “shrink OK” + ASAP | **Bridge only** while shrink ships |
| **2. Facade + inventory tiers + staged shrink** | Matches equal CLI/agent consumers and shrink | **Recommend** |
| 3. Aggressive wire shrink before facade | High thrash; CLI still missing first-run | Reject as first move |
| 4. Split experimental services | Large packaging cost | **Defer**; re-evaluate after tiers exist |

## Recommendation (freeze)

### 1. Product definition (one sentence)

**sekai-chisei is the place you define a domain ontology, store governed facts
under that model, run plan/execute inside policy and budget, and inspect the
receipt—via `sekaictl` or the same core RPCs/catalog entries agents use.**

Gateway, gunshi auto, portfolio, evolve, federation admin, hybrid fusion, and
package lifecycle are **real platform or lab capabilities**, not the default
product definition.

### 2. Core interface map (≤ 25 concepts)

Each concept has a **primary CLI** target and a **primary agent/RPC** entry.
CLI cells marked *gap* are missing today and are follow-up feature work, not
optional polish.

| # | Concept | Primary CLI | Primary RPC / catalog | Notes |
| --- | --- | --- | --- | --- |
| 1 | Control plane process | `sekaictl doctor` / `launch` | (ops) | Local-first bootstrap |
| 2 | Principal credential | `sekaictl credential create\|list\|…` | `CreateCredential` / `ListCredentials` / rotate/revoke | Auth for both consumers |
| 3 | Namespace scope | flags / env on commands | request metadata / filters | Boundary, not a fat CRUD API |
| 4 | Ontology class | `sekaictl ontology apply` **(gap)** | `CreateOntologyClass` / `Get` / `List` / `Delete` | **Primary authoring** |
| 5 | Ontology relation | same apply **(gap)** | `CreateOntologyRelation` / … | Domain/range on classes |
| 6 | Kind materialization | *inside apply* **(gap)** | schema ensure (see type reduction) | Not a separate user concept |
| 7 | Object (fact) | `sekaictl ontology seed` or `object` **(gap)** | `CreateObject` / `GetObject` / `UpdateObject` / `DeleteObject` / `ListObjects` | Default unguarded; lease optional later |
| 8 | Link | same seed **(gap)** | `CreateLink` / `DeleteLink` / `GetLinks` / `GetLinkedObjects` | |
| 9 | Grant | `sekaictl` grant **(gap)** or team | `CreateGrant` / `DeleteGrant` / `ListGrants` / `CheckAccess` | |
| 10 | Ontology inspect | `sekaictl ontology inspect` | list class/relation RPCs + trace | ADR 0003 artifact |
| 11 | Policy | *gap* or existing ops | `SetNamespacePolicy` / `ResolvePolicy` / `GetEffectivePolicySummary` | Dry-run advanced |
| 12 | Budget | *gap* | `CheckBudget` / `SetBudgetLimit` / `RecordUsage` | |
| 13 | Models available | `sekaictl models` | `ListAvailableModels` | |
| 14 | Plan | *gap* | `PlanExecution` | Native entry |
| 15 | Execute | *gap* | `ExecutePlan` / `ExecutePlanStream` | |
| 16 | Receipt | `sekaictl receipt` | `GetOperationReceipt` | |
| 17 | Operation report | `sekaictl report` | receipt-derived | Day-1 explainability |
| 18 | Resolve ref | *gap* / agent | `ResolveSemanticRef` / `sekai.semantic.resolve_ref` | |
| 19 | Expand relations | agent | `ExpandRelations` / `sekai.semantic.expand_relations` | |
| 20 | Retrieve context | agent | `RetrieveContext` / `sekai.context.retrieve` | **Default retrieve** |
| 21 | Explain derivation | agent | `ExplainDerivation` / `sekai.semantic.explain_derivation` | |
| 22 | Discover capabilities | agent | `DiscoverCapabilities` | Core for agents; optional for humans |
| 23 | Audit read | `provenance` / report | `ListDecisions` / `ListObjectChanges` / `GetLineage` | |
| 24 | Egress check | (policy path) | `CheckEgress` | Safety default |
| 25 | LLM raw (non-product center) | gateway | `Chat` / `ChatStream` | Compatibility; not “main product” |

**Out of core map (implemented, non-default):** leases/guarded CRUD, datasets,
functions, evidence admission pipeline, capability packages + trust signers,
external permit full lifecycle, work units/contention, pattern plan, hybrid/FTS,
temporal history RPCs, eval/evolve matrix, portfolio, gunshi auto-allocation,
federation peer admin, scenario overlay, assurance export, gateway decide/alias
internals.

Rough **supported core wire target:** on the order of **~40–50 RPCs** called out
as core (including credential CRUD and ontology CRUD), not 213. The rest remain
callable but **advanced/experimental** until shrunk or left as power API.

### 3. Tier definitions

| Tier | Meaning | Discovery default |
| --- | --- | --- |
| **`core`** | Required for the product loop above; documented first; catalog “starter pack” | `sekaictl` help primary; catalog filter / docs default |
| **`advanced`** | Production platform (leases, evidence, packages, hybrid, pattern, external permits) | Explicit docs section; catalog full list |
| **`experimental`** | Lab / evolving (evolve\*, portfolio, scenario, gunshi auto, temporal admin) | Docs “lab”; may change or shrink first |

**Where enforced (staged):**

1. **Docs + `sekaictl` help** immediately (no wire break).
2. **Inventory metadata** next: optional `product_tier` (or `stability`) on
   `sekai.rpc-inventory/v1` and chisei inventory entries — **orthogonal** to
   backend `surfaces` / completeness. Agents and codegen read tier; do not
   redefine `complete_*_surfaces`.
3. **Catalog projection** prefers core semantic set in default discovery
   responses when a client requests `tier=core` (or equivalent); full list
   remains available.
4. **Wire shrink** per shortlist below with `risk:breaking` Issues.

### 4. Type-system reduction (locked)

**Primary product authoring model: ontology classes + relations.**

**Validation substrate: ObjectType / schema registry stays internal-or-advanced,
not a parallel user-facing model.**

| Decision | Detail |
| --- | --- |
| **User-facing primary** | Create/list/get/delete **ontology** classes and relations (and optional proposals as advanced governance). |
| **Kind materialization** | Core facade (`sekaictl ontology apply` and/or a single “ensure kind” path) **creates or updates the ObjectType** needed for instances so users do not learn `CreateSchemaType` on day 0. |
| **Interfaces** | **Demote to advanced/experimental.** Stop featuring in product docs and first-run. Prefer ontology + object kinds; phase toward deprecation of public interface CRUD if unused outside projection. |
| **`ProjectSchemaToOntology`** | **Advanced** schema-first migration bridge; not the default onboarding direction (default is ontology-first → ensure kind). |
| **Proposals** | **Advanced** (review workflow); core path may apply definitions directly under ontology admin grants. |
| **No silent domain builtins** | Domain classes remain user-defined; reduction is about *which registry users touch*, not baking domain into core. |

This satisfies “reduce” without claiming validation can be deleted in one PR.

### 5. Shrink shortlist (ordered for ASAP)

Severity: **H** = public break / rename; **M** = merge with compat shim window;
**L** = docs/tier only or CLI-only.

| Order | Candidate | Severity | Action |
| --- | ---: | --- | --- |
| S1 | Product facade for core loop | L→feature | `sekaictl ontology apply|seed`, thin plan/execute/receipt glue; no RPC delete |
| S2 | Inventory + catalog `product_tier` | L | Machine-readable tiers; agent default core pack |
| S3 | Interface registry demotion | M/H | Docs demote immediately; deprecate `Create/List/DeleteInterface` after usage audit; projection may keep reading legacy rows |
| S4 | Guarded vs unguarded object mutations | H | Prefer **one** object mutation family with optional lease/generation fields; shim guarded RPCs as aliases then remove |
| S5 | Capability package transitions | M | Merge evaluate/upgrade/rollback/disable/uninstall into one transition RPC + enum; keep get/install/trust separate if needed |
| S6 | External permit lifecycle | M | Collapse issue/verify/redeem/revoke/delegate where request shape allows; keep kill-switch distinct |
| S7 | Eval / Evolve surface | L then M | Tier all `Evolve*` + deep compare/variance as **experimental**; optional later move or drop from default builds only if packaging justifies (not required for ASAP) |
| S8 | Gateway-internal RPCs | L | `DecideGatewayExecution`, alias reserve/claim, `RecordGatewayAudit` documented as **gateway implementation**, not product API |
| S9 | Retrieval peers | L | Docs: single default `RetrieveContext`; hybrid/FTS/pattern advanced — no delete required ASAP |
| S10 | Service split | — | **Not recommended** in this freeze |

**Do not shrink** in the first wave: core ontology CRUD, object/link CRUD,
grants, plan/execute, receipts, credential CRUD, policy/budget resolve,
semantic resolve/expand/retrieve/explain, `DiscoverCapabilities`.

### 6. Breaking bar

| Change | Process |
| --- | --- |
| Docs/CLI/tier metadata only | Feature/docs Issue; no Discussion |
| Deprecation of advanced RPC with shim ≥ one release | Feature + `risk:breaking`; changelog |
| Hard delete/rename of public RPC without shim | **Design Discussion** or explicit maintainer ack on Issue if uncontested and pre-1.0 |
| Changing authz semantics of core path | `risk:security` + careful review; Discussion if trust model shifts |
| Redefining inventory `complete_*` via product tier | **Forbidden** — keep backend evidence separate |

Pre-1.0 + ASAP allow shrink **with** labeled Issues; still no silent renames.

### 7. Immediate follow-up Issues (shape next)

| ID | Suggested title | Type | Depends on |
| --- | --- | --- | --- |
| **A** | `feat(ops): sekaictl ontology-first apply/seed and product loop` | feature | this freeze |
| **B** | `feat(grpc): product_tier on RPC inventories and core catalog pack` | feature | this freeze |
| **C** | `refactor(sekai): demote interface registry; ontology-first kind ensure` | feature/refactor | A or parallel design |
| **D** | `refactor(sekai): unify guarded and unguarded object mutations` | refactor | B optional; Design Discussion if no shim |
| **E** | `refactor(sekai): capability-package transition RPC enum` | refactor | B |

**A and B** are the ASAP critical path (facade + agent tiers). Shrink verticals
**C–E** follow without waiting for lab cleanup.

### 8. Explicit non-changes this cycle

- No mass deletion of experimental RPCs in the research PR itself.
- No chat ontology studio; no console-as-first-run (console remains day-2 per #283).
- No Ontology SQL / SPARQL in core.
- No redefinition of PostgreSQL completeness.
- No change to ADR 0003 inspection model.
- Gateway remains a supported **entry path**, not removed.

## Exit artifacts

| Artifact | Status |
| --- | --- |
| This freeze | `docs/research/383-core-product-interface.md` |
| Follow-up Issues | Shape **A–E** after merge/ack of this recommendation |
| Implementation | Separate Issues/PRs; not #383 |

## Recommendation summary

Adopt **option 2**: treat ~quarter of the wire as **core product**, expose it
equally through **`sekaictl` gaps filled** and **catalog/inventory tiers**,
**reduce type authoring to ontology-first with automatic kind ensure**, and
execute a **staged shrink shortlist** (interfaces → mutation unify → package
transitions) under normal breaking-change process—not a single big-bang delete.
