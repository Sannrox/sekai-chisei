# Object and Action integration contract

This is the supported integration map for an external application. It does not
add a protocol package, a REST surface, or browser access to server
credentials. Native gRPC remains the authority. The optional HTTP gateway is a
fail-closed translator, not a second catalog.

Follow **define → seed → plan → inspect receipt** using only the public
rows below. That catalog is the RPCs `sekaictl ontology` and the typed SDK
helpers actually call. Other `stable` wire RPCs remain invokable; they are
not “supported” sentences here. Visibility from `DiscoverCapabilities` is
descriptive; every invocation rechecks live namespace, ACL, policy, budget,
and schema.

## How to read the map

Status values:

| Status | Meaning |
| --- | --- |
| supported | Named RPC is on the advertised loop (`sekaictl ontology` or typed SDK helpers) or is an interface projection of that loop. |
| experimental | Shipped with an explicit product-tier or incomplete lifecycle. Requires `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature. See [rpc-maturity.md](rpc-maturity.md). |
| unavailable | Not a public contract on current `main`. |
| planned | Named by an open Issue; do not treat as shipped. |

Coverage:

- **SQLite** is the default community runtime.
- **PostgreSQL** means the reusable dual-backend path documented in
  [postgres-sekai-parity.md](postgres-sekai-parity.md) /
  [postgres-chisei-parity.md](postgres-chisei-parity.md). Fail-closed
  community Postgres surfaces (audited ontology mutations) stay out of this
  dual-backend set and join [#1086](https://github.com/Sannrox/sekai-chisei/issues/1086).
- **Rust** means `sekaictl`, examples, or the crate API.
- **TypeScript / Python** means the thin facades under [`sdk/`](../sdk/README.md).
  Those facades do not bundle a second proto snapshot. Generated HTTP clients
  (`sdk/typescript/http.ts`, `sdk/python/sekai_http.py`) call the same RPCs
  over the in-process HTTP/JSON projection.
- **MCP** is the `sekai-mcp` stdio projection host and the HTTP `/mcp`
  JSON-RPC endpoint on `SEKAI_HTTP_PORT`. Both reuse bearer identity. They
  are not a second protocol package.

<!-- integration-contract-rows -->

| Surface | Status | Owner | RPC | Docs | Proof |
| --- | --- | --- | --- | --- | --- |
| ObjectType / schema | supported | Sekai | `SekaiService.CreateSchemaType` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/domain-v1.json` |
| Ontology class | supported | Sekai | `SekaiService.CreateOntologyClass` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/domain-v1.json` |
| Ontology relation | supported | Sekai | `SekaiService.CreateOntologyRelation` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/domain-v1.json` |
| Definition branch edit | experimental | Sekai | `SekaiService.ApplyDefinitionBranchEdit` | [definition-branches.md](definition-branches.md) | `src/sekai/definition_branch.rs` |
| Object seed | supported | Sekai | `SekaiService.CreateObject` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/seed-v1.json` |
| Link seed | supported | Sekai | `SekaiService.CreateLink` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/seed-v1.json` |
| Plan execution | supported | Chisei | `ChiseiService.PlanExecution` | [architecture.md](architecture.md) | `sdk/typescript/client.test.ts` |
| Streamed execution | supported | Chisei | `ChiseiService.ExecutePlanStream` | [architecture.md](architecture.md) | `sdk/typescript/client.test.ts` |
| Operation receipt | supported | Chisei | `ChiseiService.GetOperationReceipt` | [ontology.md](ontology.md) | `sdk/typescript/client.test.ts` |
| Context retrieval | supported | Sekai | `SekaiService.RetrieveContext` | [ontology.md](ontology.md) | `tests/sekaictl_semantic_reads.rs` |
| Relation expansion | supported | Sekai | `SekaiService.ExpandRelations` | [ontology.md](ontology.md) | `tests/sekaictl_semantic_reads.rs` |
| Derivation explanation | supported | Sekai | `SekaiService.ExplainDerivation` | [ontology.md](ontology.md) | `tests/sekaictl_semantic_reads.rs` |
| Quality-trend report | supported | Chisei | `ChiseiService.GetQualityTrend` | [evaluation-quality-trends.md](evaluation-quality-trends.md) | `sdk/typescript/client.ts` |
| Native capability catalog | supported | Sekai | `SekaiService.DiscoverCapabilities` | [capability-catalog.md](capability-catalog.md) | `src/capability_codegen.rs` |
| Client-package record | supported | Sekai | `SekaiService` via `sekaictl admin sdk-packages` | [sdk-packages.md](sdk-packages.md) | `src/sekai/client_package.rs` |
| Compatibility matrix (#873) | supported | Interface | `compatibility.json` via `sekaictl admin compatibility` | [sdk-packages.md](sdk-packages.md) | `src/compatibility_matrix.rs` |
| Public RPC maturity (#871) | supported | Interface | `SekaiService.DiscoverCapabilities` | [rpc-maturity.md](rpc-maturity.md) | `src/rpc_maturity.rs` |
| Provider-profile matrix | supported | Gateway | HTTP `chisei.provider-capabilities/v1` | [capability-catalog.md](capability-catalog.md) | `crates/chisei-gateway/src/gateway.rs` |
| Action approval RPC | unavailable | Sekai | — | [governed-action-instances.md](governed-action-instances.md) | `src/sekai/action_instance_admission.rs` |
| MCP adapter | supported | Interface | `sekai-mcp` stdio host | [capability-catalog.md](capability-catalog.md) | `tests/mcp_adapter.rs` |
| HTTP/JSON ontology projection (#875) | supported | Interface | `POST /sekai.SekaiService/{Method}` / `POST /chisei.ChiseiService/{Method}` | [rpc-maturity.md](rpc-maturity.md) | `src/http_projection.rs` |
| HTTP MCP projection (#875) | supported | Interface | `POST /mcp` | [rpc-maturity.md](rpc-maturity.md) | `src/http_projection.rs` |
| Generated HTTP clients (#875) | supported | Interface | TypeScript / Python / Rust goldens | [sdk-packages.md](sdk-packages.md) | `src/http_codegen.rs` |
| Registry-published SDK | unavailable | Interface | — | [sdk-packages.md](sdk-packages.md) | `docs/sdk-packages.md` |

<!-- /integration-contract-rows -->

## Define → seed → plan → receipt

1. **Define.** Apply a domain document with
   `sekaictl ontology apply` ([ontology.md](ontology.md)) or call
   `CreateSchemaType` / `CreateOntologyClass` / `CreateOntologyRelation`.
   Community PostgreSQL fails closed for the audited class and relation
   mutations; SQLite is the advertised apply runtime until [#1086](https://github.com/Sannrox/sekai-chisei/issues/1086).
2. **Seed.** `sekaictl ontology seed` and SDK `seedFacts` call
   `CreateObject` / `CreateLink`. Typed SDK helpers do not call
   `ListObjects`, `GetObject`, or `EvaluateObjectSet`.
3. **Plan / execute.** `sekaictl ontology run` and SDK `runCoreLoop` call
   `PlanExecution` then `ExecutePlanStream`. They do not call
   `SubmitActionInstance`.
4. **Inspect receipt.** `GetOperationReceipt` is authoritative.

The TypeScript and Python facades expose that loop through
`runCoreLoop` ([sdk/README.md](../sdk/README.md)). Installation from a registry
is **not** a supported row; local artifacts and publication records are.

The MCP host allowlists `GetObject`, `EvaluateObjectSet`,
`DescribeObjectAction`, `PreviewObjectAction`, `SubmitActionInstance`, and
`GetOperationReceipt`. That allowlist is not the sekaictl/SDK product loop.

## Version, errors, pagination, authorization

| Concern | Contract |
| --- | --- |
| Protocol | `proto/sekai.proto` and `proto/chisei.proto`. SDKs take `protoRoot`; they do not embed a second snapshot. |
| Catalog version | Native `DiscoverCapabilities` contract `1.0`. Empty negotiates `1.0`; unsupported versions fail `FAILED_PRECONDITION`. Stale `page_token` / `catalog_version` fail `ABORTED`. |
| Pinned revisions | Definition members and ontology codegen pin a published digest. |
| Deprecation | Disable a `GovernedActionType` version; do not rewrite it. Retired source-type descriptors cannot authorize batches. |
| Errors | Denials are generic (`access denied`, `unavailable`). Hidden names are not disclosed. |
| Pagination | MCP `EvaluateObjectSet` uses signed page tokens. Offset without a namespace is not a live-authorization cursor. |
| Live authorization | Catalog visibility is not a grant. Seed, plan, and receipt read recheck the caller. |
| Dual catalogs | Native `DiscoverCapabilities` and HTTP `chisei.provider-capabilities/v1` are different documents. Mixing them in `capability_requirements_json` fails `capability_unsupported`. |

## Language and backend coverage

| Surface | Rust | TypeScript | Python | SQLite | PostgreSQL |
| --- | --- | --- | --- | --- | --- |
| Context / expand / explain | `sekaictl ontology context`, `expand`, `explain` | generated HTTP client | generated HTTP client | yes | unavailable (query-time entailment is SQLite-only; discovery reports `backend_postgres_entailment=0`) |
| Ontology apply (class / relation) | `sekaictl ontology apply` | not a typed helper | not a typed helper | yes | fail-closed |
| Object / link seed | `sekaictl ontology seed` | `runCoreLoop` | `run_core_loop` | yes | yes |
| Plan / receipt | `sekaictl ontology run` | `runCoreLoop` | `run_core_loop` | yes | see [postgres-chisei-parity.md](postgres-chisei-parity.md) |
| Client-package records | `sekaictl admin sdk-packages` | publication metadata only | publication metadata only | yes | unavailable |
| MCP allowlist | `sekai-mcp` | MCP stdio host | MCP stdio host | — | — |

## Gaps (not shipped)

These names appear in platform sequencing Issues. They are **not** the
advertised sekaictl/SDK loop on current `main`:

- ObjectSet query as a typed sekaictl/SDK helper ([#835](https://github.com/Sannrox/sekai-chisei/issues/835)); `EvaluateObjectSet` stays MCP-allowlisted and stable on the wire;
- application Action describe/preview as typed SDK helpers (`PreviewObjectAction` is MCP-allowlisted);
- object-change subscription as a sekaictl/SDK loop step ([#838](https://github.com/Sannrox/sekai-chisei/issues/838));
- a typed sekaictl/SDK helper for Action approval: `require_approval` now parks the instance and `DecideActionInstance` grants or denies it, but that RPC is experimental until a sekaictl or SDK consumer ships ([#1084](https://github.com/Sannrox/sekai-chisei/issues/1084)); preview still reports `require_approval` without granting it ([#836](https://github.com/Sannrox/sekai-chisei/issues/836));
- product-loop ontology apply on community PostgreSQL without fail-closed ([#1086](https://github.com/Sannrox/sekai-chisei/issues/1086));
- downloadable registry packages (publication records are not registry bytes).
