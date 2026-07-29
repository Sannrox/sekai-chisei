# Kernel and extension boundary evaluation

- Issue: [#443](https://github.com/Sannrox/sekai-chisei/issues/443)
- Date: 2026-07-29
- Status: recommendation

## Recommendation

Keep one published `sekai-chisei` governance product and do not extract broad
Sekai facts, Chisei decision, or advanced-feature crates now.

The smallest recurring dividend is a narrower, documented public facade inside
the existing root crate:

1. Add stable facade modules for the ontology-first product loop and supported
   governance contracts.
2. Retain current root exports as compatibility shims throughout `0.1.x`;
   measure external use before narrowing them at a release boundary.
3. Continue extracting only acyclic leaf libraries with a demonstrated
   independent consumer, as `sekai-provider`, `sekai-proto`, and
   `sekai-admin-client` already do.
4. Require the extraction gates below before creating any kernel or extension
   package.

This is a keep-current-structure decision, not approval for a package split.
No Design Discussion is required for export inventory or visibility
characterization tests. A Design Discussion is required to design stable
facade modules or before extracting a facts kernel, decision kernel,
persistence kernel, or independently versioned extension.

## Evidence

### Validated ownership boundaries

The user-level Sekai ontology validated without issues before analysis.
`SekaiChiseiRepositoryOverview`, sourced from `README.md`, identifies the
ontology-first product loop as the public entry point. `ChiseiGatewayTranslator`,
sourced from `docs/gateway.md` and an accepted user decision, defines the
gateway as an HTTP translator that enforces one canonical control-plane
decision; it does not own policy, budget, evaluation, or routing.

These facts agree with ADR 0008 and rule out moving decision ownership into the
gateway or allowing extension composition to vary authorization, audit, or
persistence guarantees.

### Current workspace and public surface

`cargo metadata --locked --no-deps` reports six workspace packages:

| Package | Direction and role |
|---|---|
| `sekai-chisei` | Published governance product, server, CLI, persistence, and domain implementation |
| `sekai-proto` | Leaf protocol definitions used by the product, gateway, and admin client |
| `sekai-provider` | Leaf provider behavior used by the product and gateway |
| `sekai-admin-client` | Provider-neutral administration client; depends on proto/provider |
| `chisei-gateway` | Translator/enforcement edge; depends on proto/provider/admin client |
| `sekai-ontology` | Independent portable ontology library and CLI |

The root contains 187,423 Rust source lines, 47 integration-test files, and 52
public root modules or re-exports. In-repository `sekai_chisei::` references
are concentrated in `db` (99 occurrences), `sekai` (53), `gunshi_cli` (42),
`obs` (40), `grpc` (33), and `chisei` (28). Forty-three integration tests,
five examples, and the leaf-crate test suites consume the root facade.

The gateway and admin client have no production dependency on the root, but
both use it as a development dependency for control-plane test support. That
is useful test reuse, not evidence for a production ownership cycle. A broad
kernel extraction would have to relocate or duplicate those fixtures before it
could reduce test fan-out.

### Representative change fan-out

Static file-reference fan-out provides a reproducible lower bound. It avoids
claiming stable wall-clock savings from one warm local build.

| Representative area | Rust files containing related concepts | Boundary observation |
|---|---:|---|
| Gateway decision/setup/reporting | 15 | Already has leaf crates, but control-plane decision and test fixtures remain correctly in the product |
| Federation and peer import | 15 | Crosses Sekai facts, Chisei decisions, persistence, compliance, observability, CLI, and protocol-facing code |
| Temporal behavior | 8 | Small, but embedded in facts, decisions, persistence, and gRPC rather than independently deployable |
| Reporting, compliance, attestation, provenance | 54 | Reads shared receipts, evidence, audit, and persistence contracts; not independently versionable |
| Learning, Gunshi, Kioku, memory, evolution, promotion | 142 | Strongly coupled across Sekai, Chisei, DB, gRPC, gateway, provider, observability, and most conformance targets |

The normal workspace gate compiles the root library and binaries, 47
integration-test targets, examples, leaf crates, and doc tests. Moving one of
the cross-cutting families into a package would not remove those conformance
targets: SQLite/PostgreSQL parity, namespace isolation, authorization, audit,
receipts, and protocol compatibility would still require coordinated testing.
It would distribute the same fan-out across manifests and release units.

### Cross-boundary types and strongly connected clusters

The strongest clusters are semantic rather than Cargo cycles:

- `sekai` facts, `db` storage, and `grpc::sekai_service` share durable graph,
  audit, evidence, coordination, and authorization types.
- `chisei` decisions, `db` Chisei backends, and `grpc::chisei_service` share
  policy, budget, evaluation, receipt, and execution types.
- Learning and federation each use both clusters and inherit their persistence
  and conformance obligations.
- Reporting and assurance consume the same durable evidence and receipts whose
  compatibility they are intended to prove.

Splitting these clusters at module names would introduce transfer types,
adapter traits, duplicated fixtures, and coordinated schema/protocol releases
without making a feature independently safe to disable.

## Options compared

| Option | Concepts/packages added | Dependency/test effect | Release effect | Decision |
|---|---:|---|---|---|
| Narrow facade in root | 1–2 facade modules | Reduces accidental public coupling; no test duplication | One product release | Recommend |
| Private internal crates | 2+ packages plus adapters | Compiler-enforced direction, but shared DB/gRPC types and 47 conformance targets remain | One release but more manifest coordination | Defer until an acyclic seam is measured |
| Facts kernel + decision kernel | 2 published kernels plus product adapters | Separates names, not persistence/protocol/conformance obligations | At least three coordinated compatibility surfaces | Reject now |
| Core plus extension crates | One crate per advanced family | Candidate families still cross core DB, protocol, auth, audit, and receipts | Creates lockstep extension releases | Reject now |
| Feature-gated extensions | Feature matrix in one or more packages | Multiplies build/test combinations and risks guarantee drift | One release with combinatorial support states | Reject |
| Keep every current export | No change | Preserves accidental API growth and weak ownership signaling | One release | Reject in favor of facade work |

## Proposed ownership and dependency direction

```text
sekai-ontology (independent)
sekai-chisei    ──► sekai-admin-client, sekai-proto, sekai-provider
sekai-admin-client ──► sekai-proto, sekai-provider
chisei-gateway  ──► sekai-admin-client, sekai-proto, sekai-provider

Inside sekai-chisei:
Chisei governed decisions ──► Sekai durable facts
persistence and gRPC remain internal
```

Arrows point from a production consumer to a manifest dependency; they do not
denote authority transfer. Development-only dependencies from the gateway and
admin-client test suites back to `sekai-chisei` are excluded. The governance
product remains the system of record. Provider behavior remains behind
`sekai-provider`; the gateway remains a translator.

## Kernel and extension classification

The kernel remains a conceptual ownership boundary inside the product:

- ontology, graph, schema, evidence, lineage, audit, retention, security, and
  coordination facts;
- policy, authorization, budget, admission, routing decisions, evaluation,
  receipts, reconciliation, and governed execution;
- namespace isolation and SQLite/PostgreSQL parity;
- protocol services and compatibility migrations for those guarantees.

No current advanced family qualifies as an independently versionable
extension. Federation, temporal behavior, learning/Gunshi/Kioku, reporting,
compliance, attestation, and provenance remain product modules until they pass
the extraction gates. Provider adapters, portable ontology tooling,
provider-neutral administration, and the gateway are the existing justified
leaf boundaries.

## API, persistence, configuration, and release implications

- **API:** Add facades without removing existing exports. Inventory known
  external consumers and deprecate accidental exports before any `0.2.0`
  visibility change.
- **Persistence:** Keep schema ownership and backend parity in the product. Do
  not let an extension own migrations against shared tables.
- **Configuration:** Do not add feature combinations that can weaken
  authorization, audit, namespace isolation, or persistence behavior.
- **Release:** Keep one product version. Leaf crates may remain in the
  workspace, but independent publication is justified only by an independent
  consumer and a compatibility contract.

## Incremental path and rollback

1. Inventory root exports and classify them as supported facade, CLI/internal,
   or compatibility-only.
2. Add facade modules and compile-time consumer tests while leaving all current
   paths intact.
3. Measure which changes still rebuild and retest each target in CI.
4. For a candidate leaf, prototype an internal crate only after its production
   dependency graph is acyclic and it owns no shared persistence migration.
5. Compare clean and incremental build/test fan-out for at least ten
   representative changes.
6. Publish or feature-gate nothing until namespace, authorization, audit,
   receipt, and SQLite/PostgreSQL conformance tests pass in every supported
   composition.

The rollback point is step 2: facade modules can be removed without protocol,
storage, configuration, or release changes. An internal-crate prototype must
remain unpublished until its measured dividend is accepted.

## Extraction gates

A new package must demonstrate all of the following:

- at least one production consumer outside the root product;
- one-way production dependencies with no root dev-fixture dependency required
  for its own correctness suite;
- ownership of its public data types without mirroring root domain models;
- no ownership of shared database migrations;
- fewer affected build/test targets for representative changes, measured over
  at least ten changes;
- no new supported feature matrix for security or persistence guarantees;
- an explicit compatibility and release policy; and
- a net reduction in concepts, dependency edges, or coordinated targets rather
  than a redistribution across manifests.

Until a candidate meets those gates, the module boundary is the smaller and
safer boundary.

## Rejected splits that hide complexity

- Moving all `sekai/*` and `chisei/*` into two crates while leaving DB and gRPC
  types shared.
- Calling learning, federation, or assurance an extension while requiring core
  schema migrations and lockstep conformance tests.
- Feature-gating authorization, audit, receipt, namespace, or backend-parity
  paths.
- Giving the gateway policy ownership to make the control-plane package graph
  appear smaller.
- Publishing internal crates solely to improve directory organization.

## Reproduction

Evidence was collected with:

```text
sekai --db "$HOME/Library/Application Support/sekai/knowledge.db" --json validate
sekai --db "$HOME/Library/Application Support/sekai/knowledge.db" --json explain SekaiChiseiRepositoryOverview
sekai --db "$HOME/Library/Application Support/sekai/knowledge.db" --json explain ChiseiGatewayTranslator
cargo metadata --locked --no-deps --format-version 1
rg -c '^pub (mod|use) ' src/lib.rs
rg -o 'sekai_chisei::[A-Za-z_][A-Za-z0-9_]*'
find src -type f -name '*.rs' -print0 | xargs -0 wc -l
rg -l --glob '*.rs' 'gateway_decide|gateway_report|gateway_setup' src crates tests
rg -l --glob '*.rs' 'federation|peer_import' src crates tests
rg -l --glob '*.rs' 'temporal' src crates tests
rg -l --glob '*.rs' 'weekly_report|operation_report|statistics|compliance|attest|provenance' src crates tests
rg -l --glob '*.rs' 'gunshi|learning|kioku|memory|evolve|promotion' src crates tests
```

Each file-fan-out count is the line count of its corresponding `rg -l` result
over `src`, `crates`, and `tests` at merge base
`f2c13358509ac89c044613acc7f1522b5ea81fe0`.
