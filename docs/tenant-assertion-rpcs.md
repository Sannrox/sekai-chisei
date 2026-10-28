# RPCs for tenant assertions

A tenant-scoped identity assertion reaches only the RPCs the token
interceptor admits for it (`enterprise_namespace_method` in `src/grpc/mod.rs`).
Every admitted RPC authorizes the request's namespace against the assertion's
tenant in its handler. Admission does not lift the experimental gate: an RPC
classified `experimental` (see [RPC maturity](rpc-maturity.md)) still needs
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature. A namespace of another tenant is refused with
`PERMISSION_DENIED` before anything is read or written. The space role then
applies the RPC's read or write action.

## Added in #1777

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `PreviewObjectAction` | request | write (it runs admission as a dry run) |
| `ListGovernedActionTypes` | request | write (Action administration) |
| `ExplainDerivation` | request | read |
| `EvaluateObjectSet` | descriptor | read |
| `GetSourceSyncState` | request | read |
| `ReadObjectChangeSubscription` | subscription scope | write (a read can advance its cursor) |
| `CompareDefinitionRevisions` | request | read |
| `QueryObjectPolicyAudit` | request | read |

`tests` cover both sides. `tenant_assertions_reach_namespace_scoped_rpcs_only`
checks the allowlist and the space actions, and
`admitted_tenant_rpcs_refuse_another_tenants_namespace` checks the tenant
refusal of each one, with a successful call on the tenant's own namespace.

## Added in #1770

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `ChiseiService.GetQualityTrend` | request | read |
| `ChiseiService.GetOperationReceipt` | stored receipt | read |

Both authorize the namespace on the same tenant path as the Sekai
namespace RPCs, so a service principal is also held to its current
registration scope. `GetOperationReceipt` names no namespace, so the handler
checks the stored receipt's namespace before answering. The receipt must
also name the assertion's subject as its initiating actor; enterprise
contexts get no administrative inspection and no request-alias lookup. A
receipt outside the tenant's namespaces, one with no namespace, another
principal's receipt, or a failed lookup returns the same `NOT_FOUND` as a
missing id. `tenant_assertion_reads_only_its_own_receipts_and_quality_trend` and
`service_principal_reads_follow_its_live_registration_scope` cover both RPCs
through the token interceptor.

## Not available to tenant credentials

`CloseDefinitionProposal` stays with unscoped credentials
([ADR 0111](decisions/0111-scoped-definition-proposals.md)): a scoped
context may draft, propose, approve and merge, but not close.

The following act on the deployment's shared schema and ontology vocabulary,
which belongs to no namespace and so has no tenant to authorize against:

- `CreateSchemaType`
- `CreateOntologyClass`
- `CreateOntologyRelation`
- `ListOntologyClasses`
- `ListOntologyRelations`

Tenant callers read object types through the namespace's published
definition (`GetPublishedDefinitionRevision`, `ListSchemaTypes`) instead.
