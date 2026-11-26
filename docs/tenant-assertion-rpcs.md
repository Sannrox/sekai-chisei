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
| `ProposeDatasetRollback`, `DecideDatasetRollback` (#3186) | the dataset's binding object | write |
| `GetDatasetRollbackProposal`, `ListDatasetRollbackProposals` (#3186) | the dataset's binding object | read |
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

## Added in #3262

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `DryRunActionPolicy` | request | read (it writes only its audit decision) |

The handler's namespace grant decides access within the tenant, as for a
token caller, and the `action_policy.dry_run` decision names the assertion's
subject. `action_policy_dry_run_rpc_admits_a_granted_tenant_assertion` covers
it.

## Added in #3271

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `GetObjectSourceRecord` | stored object | read |

The handler reads the object through `GetObject`, so the tenant check,
markings and refusal codes are the same. A kind with restricted properties
withholds the payload from an assertion that may not read them.
`object_source_record_admits_a_tenant_assertion_under_get_object_rules` covers
it.

## Added in #3056

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `ChiseiService.ListEvalDatasetDefinitions` | request | read |
| `ChiseiService.GetEvalDatasetDefinition` | request | read |
| `ChiseiService.ListEvalDatasetCases` | request | read |
| `ChiseiService.ListEvalDatasetRunTrend` | request | read |
| `ChiseiService.CompareEvalDatasetRuns` | request | read (it reads both runs only) |

Admitted on `ChiseiService` only, like the #1770 reads, and authorized on
the same tenant path: an assertion reads only its tenant's namespaces, even
where its subject holds a grant elsewhere. Token callers keep the namespace
grant check. They stay experimental. `PutEvalDatasetDefinition` is not
admitted. `tenant_assertion_reads_its_namespaces_eval_datasets` covers all
five through the token interceptor.

## Added in #3089

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `ChiseiService.RunEvalDataset` | request | write |

Admitted on `ChiseiService` only and authorized on the same tenant path as
a namespace write: the assertion needs the `sekai.write` scope, writes only
its tenant's namespaces, and without an enterprise extension its subject
needs an editor or admin grant there. Token callers keep the editor or admin
grant check. There is no tenant-specific spend ceiling: `budget_micros`
bounds the run for every caller, and a stochastic case reserves its tokens
from the namespace's project budget (`project:<namespace>`). An assertion
cannot bind a run to an `artifact_digest`; that stays with credential
administration. It stays
experimental. `tenant_assertion_runs_an_eval_dataset_in_its_namespace`
covers it through the token interceptor.

## Added in #3043

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `ChiseiService.AppendUsageEvents` | each event | write |

Admitted on `ChiseiService` only, and it requires a tenant assertion: a
caller without one is refused, because there is no tenant to bill. Each
event's namespace is authorized as a namespace write. The tenant is the
assertion's tenant, the principal is the assertion's `act` (else its
subject), and the subject is recorded as the reporter
([ADR 0158](decisions/0158-reported-usage-enters-the-tenant-ledger.md)). It
stays experimental. `tenant_assertion_appends_reported_usage_for_its_principal`
covers it through the token interceptor.

## Added in #3085

| RPC | Namespace from | Space action |
| --- | --- | --- |
| `PreviewActionInstanceEffect` | stored instance | read |

The handler enforces the tenant on the instance's namespace and applies the
reads of `GetActionInstance`. It stays experimental.

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
