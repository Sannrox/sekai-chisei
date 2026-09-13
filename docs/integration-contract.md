# Object and Action integration contract

This is the supported integration map for an external application. It does not
add a protocol package, a REST surface, or browser access to server
credentials. Native gRPC remains the authority. The optional HTTP gateway is a
fail-closed translator, not a second catalog.

Follow **define → query → invoke → inspect receipt** using only the public
rows below. Visibility from `DiscoverCapabilities` is descriptive; every
invocation rechecks live namespace, ACL, policy, budget, and schema.

## How to read the map

Status values:

| Status | Meaning |
| --- | --- |
| supported | Authenticated callers may use the named RPC on current `main`. |
| experimental | Shipped with an explicit product-tier or incomplete lifecycle. |
| unavailable | Not a public contract on current `main`. |
| planned | Named by an open Issue; do not treat as shipped. |

Coverage:

- **SQLite** is the default community runtime.
- **PostgreSQL** means the reusable dual-backend path documented in
  [postgres-sekai-parity.md](postgres-sekai-parity.md) /
  [postgres-chisei-parity.md](postgres-chisei-parity.md).
- **Rust** means `sekaictl`, examples, or the crate API.
- **TypeScript / Python** means the thin facades under [`sdk/`](../sdk/README.md).
  Those facades do not bundle a second proto snapshot.
- **MCP** is the `sekai-mcp` stdio projection host over the v1 object, Action,
  and receipt allowlist. It is not a second protocol package.

<!-- integration-contract-rows -->

| Surface | Status | Owner | RPC | Docs | Proof |
| --- | --- | --- | --- | --- | --- |
| ObjectType / schema | supported | Sekai | `SekaiService.CreateSchemaType` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/domain-v1.json` |
| Ontology class | supported | Sekai | `SekaiService.CreateOntologyClass` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/domain-v1.json` |
| Ontology relation | supported | Sekai | `SekaiService.CreateOntologyRelation` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/domain-v1.json` |
| Published definition revision | supported | Sekai | `SekaiService.GetPublishedDefinitionRevision` | [definition-branches.md](definition-branches.md) | `src/ontology_codegen.rs` |
| Definition branch edit | experimental | Sekai | `SekaiService.ApplyDefinitionBranchEdit` | [definition-branches.md](definition-branches.md) | `src/sekai/definition_branch.rs` |
| Object create / read | supported | Sekai | `SekaiService.CreateObject` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/seed-v1.json` |
| Object get | supported | Sekai | `SekaiService.GetObject` | [architecture.md](architecture.md) | `examples/source_writeback.rs` |
| Object list | supported | Sekai | `SekaiService.ListObjects` | [capability-catalog.md](capability-catalog.md) | `tests/concurrent_source_ingestion.rs` |
| Object reference (external id) | supported | Sekai | `SekaiService.FindByExternalId` | [object-sync.md](object-sync.md) | `examples/source_writeback.rs` |
| Property query | supported | Sekai | `SekaiService.FindByProperty` | [capability-catalog.md](capability-catalog.md) | `src/grpc/authorized_query_lifecycle.rs` |
| Link create / read | supported | Sekai | `SekaiService.CreateLink` | [ontology.md](ontology.md) | `tests/fixtures/product_loop/seed-v1.json` |
| Graph traverse | supported | Sekai | `SekaiService.Traverse` | [capability-catalog.md](capability-catalog.md) | `src/grpc/sekai_service.rs` |
| Native capability catalog | supported | Sekai | `SekaiService.DiscoverCapabilities` | [capability-catalog.md](capability-catalog.md) | `src/capability_codegen.rs` |
| Object-security policy | supported | Sekai | `SekaiService.PutObjectSecurityPolicyRevision` | [capability-catalog.md](capability-catalog.md) | `tests/object_security_backend_conformance.rs` |
| Object-security activation | supported | Sekai | `SekaiService.ActivateObjectSecurityPolicies` | [capability-catalog.md](capability-catalog.md) | `tests/object_security_backend_conformance.rs` |
| Governed Action type | supported | Sekai | `SekaiService.PutGovernedActionType` | [governed-action-types.md](governed-action-types.md) | `examples/source_writeback.rs` |
| Action instance submit | supported | Sekai | `SekaiService.SubmitActionInstance` | [governed-action-instances.md](governed-action-instances.md) | `examples/source_writeback.rs` |
| Action instance get | supported | Sekai | `SekaiService.GetActionInstance` | [governed-action-instances.md](governed-action-instances.md) | `examples/source_writeback.rs` |
| Action effect | supported | Sekai | `SekaiService.GetActionEffect` | [governed-action-effects.md](governed-action-effects.md) | `examples/source_writeback.rs` |
| Evidence submit | supported | Sekai | `SekaiService.SubmitEvidence` | [evidence-adapter-catalog.md](evidence-adapter-catalog.md) | `examples/source_writeback.rs` |
| Plan execution | supported | Chisei | `ChiseiService.PlanExecution` | [architecture.md](architecture.md) | `sdk/typescript/client.test.ts` |
| Streamed execution | supported | Chisei | `ChiseiService.ExecutePlanStream` | [architecture.md](architecture.md) | `sdk/typescript/client.test.ts` |
| Operation receipt | supported | Chisei | `ChiseiService.GetOperationReceipt` | [ontology.md](ontology.md) | `sdk/typescript/client.test.ts` |
| Quality-trend report | supported | Chisei | `ChiseiService.GetQualityTrend` | [evaluation-quality-trends.md](evaluation-quality-trends.md) | `src/grpc/chisei_service.rs` |
| Client-package record | supported | Sekai | `SekaiService` via `sekaictl admin sdk-packages` | [sdk-packages.md](sdk-packages.md) | `src/sekai/client_package.rs` |
| Compatibility matrix (#873) | supported | Interface | `compatibility.json` via `sekaictl admin compatibility` | [sdk-packages.md](sdk-packages.md) | `src/compatibility_matrix.rs` |
| Provider-profile matrix | supported | Gateway | HTTP `chisei.provider-capabilities/v1` | [capability-catalog.md](capability-catalog.md) | `crates/chisei-gateway/src/gateway.rs` |
| ObjectSet query (#835) | supported | Sekai | `SekaiService.EvaluateObjectSet` | [object-set.md](object-set.md) | `src/grpc/object_set_query.rs` |
| Application Action describe | supported | Sekai | `SekaiService.DescribeObjectAction` | [governed-action-instances.md](governed-action-instances.md) | `src/grpc/sekai_service.rs` |
| Application Action preview | supported | Sekai | `SekaiService.PreviewObjectAction` | [governed-action-instances.md](governed-action-instances.md) | `src/grpc/sekai_service.rs` |
| Action approval RPC | unavailable | Sekai | — | [governed-action-instances.md](governed-action-instances.md) | `src/sekai/action_instance_admission.rs` |
| Object-change subscription (#838) | supported | Sekai | `SekaiService.ReadObjectChangeSubscription` | [object-change-subscriptions.md](object-change-subscriptions.md) | `src/grpc/object_change_subscription.rs` |
| MCP adapter | supported | Interface | `sekai-mcp` stdio host | [capability-catalog.md](capability-catalog.md) | `tests/mcp_adapter.rs` |
| Registry-published SDK | unavailable | Interface | — | [sdk-packages.md](sdk-packages.md) | `docs/sdk-packages.md` |

<!-- /integration-contract-rows -->

## Define → query → invoke → receipt

1. **Define.** Apply a domain document with
   `sekaictl ontology apply` ([ontology.md](ontology.md)) or call
   `CreateSchemaType` / `CreateOntologyClass` / `CreateOntologyRelation`.
   Published members are revision-pinned
   (`GetPublishedDefinitionRevision`).
2. **Query.** Authenticate, pass a canonical namespace, and call
   `DiscoverCapabilities` then `ListObjects` / `GetObject` /
   `FindByExternalId` / `EvaluateObjectSet`. Object-security activation is
   rechecked per row. Page tokens are bound to principal, namespace, policy
   activation, and query digest; a changed digest fails closed. A descriptor
   or cached ObjectSet is not authority.
3. **Invoke.** Register a `GovernedActionType`, then
   `SubmitActionInstance`. Send `x-sekai-capability` and
   `x-sekai-namespace` as in [capability-catalog.md](capability-catalog.md).
   For model execution, use `PlanExecution` then `ExecutePlanStream`.
4. **Inspect receipt.** `GetOperationReceipt` is authoritative. Action
   instance and effect reads explain harvest state; they do not replace the
   receipt.

The TypeScript and Python facades expose the same loop through
`runCoreLoop` ([sdk/README.md](../sdk/README.md)). They still call the RPCs
above. Installation from a registry is **not** a supported row; local artifacts
and publication records are.

## Version, errors, pagination, authorization

| Concern | Contract |
| --- | --- |
| Protocol | `proto/sekai.proto` and `proto/chisei.proto`. SDKs take `protoRoot`; they do not embed a second snapshot. |
| Catalog version | Native `DiscoverCapabilities` contract `1.0`. Empty negotiates `1.0`; unsupported versions fail `FAILED_PRECONDITION`. Stale `page_token` / `catalog_version` fail `ABORTED`. |
| Pinned revisions | Definition members and ontology codegen pin a published digest. |
| Deprecation | Disable a `GovernedActionType` version; do not rewrite it. Retired source-type descriptors cannot authorize batches. |
| Errors | Denials are generic (`access denied`, `unavailable`). Hidden names are not disclosed. |
| Pagination | `ListObjects` and `EvaluateObjectSet` use signed page tokens. Offset without a namespace is not a live-authorization cursor. |
| Live authorization | Catalog visibility is not a grant. Object list, Action submit, and receipt read recheck the caller. |
| Dual catalogs | Native `DiscoverCapabilities` and HTTP `chisei.provider-capabilities/v1` are different documents. Mixing them in `capability_requirements_json` fails `capability_unsupported`. |

## Language and backend coverage

| Surface | Rust | TypeScript | Python | SQLite | PostgreSQL |
| --- | --- | --- | --- | --- | --- |
| Object read / list | yes | via facade transport | via facade transport | yes | yes |
| Action submit | yes | not a typed helper | not a typed helper | yes | see [postgres-sekai-parity.md](postgres-sekai-parity.md) |
| Plan / receipt | yes | `runCoreLoop` | `run_core_loop` | yes | see [postgres-chisei-parity.md](postgres-chisei-parity.md) |
| Client-package records | `sekaictl admin sdk-packages` | publication metadata only | publication metadata only | yes | unavailable |
| MCP | `sekai-mcp` | MCP stdio host | MCP stdio host | — | — |

## Gaps (not shipped)

These names appear in platform sequencing Issues. They are **not** integration
contracts on current `main`:

- first-class Action approval RPC (admission may persist `denied` instead; preview reports `require_approval` without granting it) ([#836](https://github.com/Sannrox/sekai-chisei/issues/836));
- authorized object-change subscriptions ([#838](https://github.com/Sannrox/sekai-chisei/issues/838));
- downloadable registry packages (publication records are not registry bytes).
