# RPCs for tenant assertions

A tenant-scoped identity assertion reaches only the RPCs the token
interceptor admits for it (`enterprise_namespace_method` in `src/grpc/mod.rs`).
Every admitted RPC authorizes the request's namespace against the assertion's
tenant in its handler. Admission does not lift the experimental gate: an RPC
classified `experimental` (see [RPC maturity](rpc-maturity.md)) still needs
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature. A namespace of another tenant is refused with
`PERMISSION_DENIED` before anything is read or written. The space role then
applies the RPC's read or write action.

## Dataset RPCs

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `QueryRows` (#2097) | the dataset's binding object | read |
| `CreateDataset`, `AppendRows`, `UpdateDataset` (#2105) | the dataset's binding object | write |
| `ListDatasetVersions`, `GetDatasetVersion` | the dataset's binding object | read |
| `RollbackDataset` | the dataset's binding object | write |
| `ListDatasetHealthChecks`, `ListDatasetHealthResults`, `ListDatasetAlerts` | the dataset's binding object | read |
| `PutDatasetHealthCheck`, `RunDatasetHealthChecks` | the dataset's binding object | write |
| `ListDatasetBranches`, `CompareDatasetBranch` (#2104) | the dataset's binding object | read |
| `CreateDatasetBranch`, `DeleteDatasetBranch`, `ProposeDatasetBranchMerge`, `MergeDatasetBranch` (#2104) | the dataset's binding object | write |

These handlers make one decision (`authorize_dataset`). A dataset with no
binding object, or whose binding object is gone, has no namespace and is
refused with `PERMISSION_DENIED`. `CreateDataset` therefore binds a live
object in a writable namespace. The binding object must also be visible to
the caller (markings and object security policy). Guests stay refused; a host
grant does not admit them. Branch RPCs call `authorize_dataset` from
`branch_caller`. Governed transforms check their inputs' binding objects for
visibility.

When the binding object's policy enforces property grants, rows are held to
the readable columns for every caller, tenant or not: a `QueryRows`
projection or filter naming another column is refused, an unprojected query
returns only the readable ones, and version snapshots and the rows a rollback
returns drop the others. A policy that grants no column refuses the read.
`enterprise_query_rows_requires_namespace_read_for_the_tenant`,
`enterprise_dataset_reads_refuse_another_tenants_dataset`,
`enterprise_dataset_writes_require_live_namespace_binding` and
`enterprise_branch_rpcs_must_refuse_unbound_like_query_rows` drive the real
interceptor and the handlers, and `dataset_row_reads_honour_property_grants`
covers the columns.

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

## Added in #2193

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `GetSourceHealth` | request | read |

Within the tenant, a namespace the caller may not read reports as an
unknown source rather than a refusal (see [source health](source-health.md)).

## Added in #2203

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `ListPendingDecisions` | request | read, then each kind's decide action |

The read admits the call. Each review kind then applies the space role and
credential scope of its decide RPC, so an approver sees parked Actions and
plan reviews, and an editor sees definition and dataset branch proposals. A
kind the caller may not decide is empty rather than refused.

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
