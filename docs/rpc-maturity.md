# Public RPC maturity

This table is a **projection** of backend and consumer evidence for every
public `SekaiService` and `ChiseiService` RPC. It does not invent invocation
authority. Live authorization, receipts, and dual-backend inventories remain
the system of record.

The **advertised** product catalog is the define → seed → plan → receipt loop
that `sekaictl ontology` and the typed SDK helpers actually call
(`CreateSchemaType`, `CreateOntologyClass`, `CreateOntologyRelation`,
`CreateObject`, `CreateLink`, `PlanExecution`, `ExecutePlanStream`,
`GetOperationReceipt`). Other `stable` RPCs stay invokable on the default
build; they are not “supported” integration sentences unless those callers
exist. Experimental and `remove` RPCs stay behind
`SEKAI_EXPERIMENTAL_RPCS=1` / `experimental-rpcs`. The ontology apply and
seed steps run on both community backends.

Machine-readable copy: [`tests/fixtures/rpc_maturity/v1.json`](../tests/fixtures/rpc_maturity/v1.json)
(`sekai.rpc-maturity/v1`). A test compares this page and that fixture with
`proto/sekai.proto` and `proto/chisei.proto`.

## Classification

| Class | Meaning | Default build |
| --- | --- | --- |
| `stable` | Real (non-fixture) backend and at least one SDK, host, or example consumer, or a required sibling of that public loop. At most 66 RPCs. | Invokable. |
| `experimental` | Shipped with a real or incomplete backend but not part of the default public loop. | Rejected (`FAILED_PRECONDITION`) unless `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is enabled. |
| `remove` | Research or sample path with no SDK, host, or example consumer. Classification and deprecation notes only in this change set; deletion is a later major-version PR. | Same gate as experimental during the deprecation window. |

`product_tier` (`core` / `advanced` / `experimental`) on capability catalogs
and RPC inventories is **orthogonal**. Catalog visibility is not a grant.

Admin CLI projections named by the source Issue (connector certification,
capability packages, cross-enterprise federation, lakehouse and warehouse
snapshots, image assets, bounded autonomy envelopes) are not public RPCs.
They stay out of the default RPC surface.

## Gate

`DiscoverCapabilities` always reports `sekai.rpc.experimental` on the core
pack. `lifecycle_state` is `disabled` unless the runtime flag or build
feature is on. Visibility of that entry is not permission to invoke an
experimental RPC.

SDK generation for the stable set succeeds without a denylist. Experimental
and `remove` RPCs are omitted automatically.

HTTP/JSON is a generated projection of the same `stable` unary RPCs
([ADR 0075](decisions/0075-http-ontology-projection.md)). Routes are
`POST /sekai.SekaiService/{Method}` and `POST /chisei.ChiseiService/{Method}`
on `SEKAI_HTTP_PORT`. Authorization, cursors, and hidden-row rules match gRPC.
Streaming RPCs stay on gRPC. Experimental RPCs stay behind this gate.

## Table

<!-- rpc-maturity-rows -->

| RPC | Storage path | Real backend | Known consumer | Classification |
| --- | --- | --- | --- | --- |
| `SekaiService.AcquireLease` | `sekai.leases` | yes | none | `experimental` |
| `SekaiService.GetLease` | `sekai.leases` | yes | none | `experimental` |
| `SekaiService.RefreshLease` | `sekai.leases` | yes | none | `experimental` |
| `SekaiService.ReleaseLease` | `sekai.leases` | yes | none | `experimental` |
| `SekaiService.TakeoverExpiredLease` | `sekai.leases` | yes | none | `experimental` |
| `SekaiService.ApplySourceBatch` | `sekai.object-sync` | yes | example | `stable` |
| `SekaiService.GetSourceSyncState` | `sekai.object-sync` | yes | example | `stable` |
| `SekaiService.RegisterSourceTypeDescriptor` | `sekai.object-sync` | yes | none | `experimental` |
| `SekaiService.InspectSourceTypeDescriptor` | `sekai.object-sync` | yes | none | `experimental` |
| `SekaiService.RetireSourceTypeDescriptor` | `sekai.object-sync` | yes | none | `experimental` |
| `SekaiService.CreateDefinitionBranch` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.GetDefinitionBranch` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.ApplyDefinitionBranchEdit` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.CreateDefinitionProposal` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.GetDefinitionProposal` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.ApproveDefinitionProposal` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.MergeDefinitionProposal` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.CloseDefinitionProposal` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.GetPublishedDefinitionRevision` | `sekai.definition-branch` | yes | none | `stable` |
| `SekaiService.CompareDefinitionRevisions` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.ReportDefinitionConsumerImpact` | `sekai.definition-branch, sekai.graph` | yes | none | `experimental` |
| `SekaiService.ClassifyDefinitionRevisionCompatibility` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.ExecuteDefinitionFactMigration` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.GetDefinitionFactMigration` | `sekai.definition-branch` | yes | none | `experimental` |
| `SekaiService.CreateObject` | `sekai.graph` | yes | sdk, host, cli | `stable` |
| `SekaiService.GetObject` | `sekai.graph` | yes | host, example | `stable` |
| `SekaiService.UpdateObject` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.DeleteObject` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.ListObjects` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.EvaluateObjectSet` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.RegisterObjectTypeDatasource` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.ReindexObjectType` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.GetObjectTypeIndexStatus` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.PutObjectTypeIndexEdit` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.PutGovernedTransform` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.RunGovernedTransform` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.GetGovernedTransformRun` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.ReadObjectChangeSubscription` | `sekai.graph, sekai.audit` | yes | none | `stable` |
| `SekaiService.PutObjectSecurityPolicyRevision` | `sekai.object-security` | yes | none | `stable` |
| `SekaiService.GetObjectSecurityPolicyRevision` | `sekai.object-security` | yes | none | `experimental` |
| `SekaiService.ActivateObjectSecurityPolicies` | `sekai.object-security` | yes | none | `stable` |
| `SekaiService.GetObjectSecurityActivation` | `sekai.object-security` | yes | none | `stable` |
| `SekaiService.PutPurposeAuthorization` | `sekai.object-security` | yes | none | `experimental` |
| `SekaiService.RevokePurposeAuthorization` | `sekai.object-security` | yes | none | `experimental` |
| `SekaiService.PutClassificationLattice` | `sekai.object-security` | yes | none | `experimental` |
| `SekaiService.GetClassificationLattice` | `sekai.object-security` | yes | none | `experimental` |
| `SekaiService.SimulateObjectPolicyChange` | `sekai.object-security` | yes | none | `experimental` |
| `SekaiService.QueryObjectPolicyAudit` | `sekai.object-security` | yes | none | `experimental` |
| `SekaiService.FindByExternalId` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.FindByProperty` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.CreateLink` | `sekai.graph` | yes | sdk, cli | `stable` |
| `SekaiService.DeleteLink` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.GetLinks` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.GetLinkedObjects` | `sekai.graph` | yes | none | `experimental` |
| `SekaiService.Traverse` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.RetrieveContext` | `sekai.graph, sekai.authorization, sekai.ontology-definitions` | yes | cli, sdk | `stable` |
| `SekaiService.ExpandRelations` | `sekai.graph, sekai.authorization, sekai.ontology-definitions` | yes | cli, sdk | `stable` |
| `SekaiService.ExplainDerivation` | `sekai.graph, sekai.authorization, sekai.ontology-definitions` | yes | cli, sdk | `stable` |
| `SekaiService.DiscoverCapabilities` | `sekai.graph, sekai.authorization` | yes | host | `stable` |
| `SekaiService.GetGovernedFactVersion` | `sekai.graph` | yes | none | `experimental` |
| `SekaiService.ResolveInvariantSet` | `sekai.graph, sekai.authorization` | yes | none | `experimental` |
| `SekaiService.ListSchemaTypes` | `sekai.graph` | yes | none | `stable` |
| `SekaiService.CreateSchemaType` | `sekai.graph` | yes | sdk, cli | `stable` |
| `SekaiService.ListOntologyClasses` | `sekai.ontology-definitions` | yes | none | `experimental` |
| `SekaiService.GetOntologyClass` | `sekai.ontology-definitions` | yes | none | `experimental` |
| `SekaiService.CreateOntologyClass` | `sekai.ontology-definitions` | yes | cli | `stable` |
| `SekaiService.DeleteOntologyClass` | `sekai.ontology-definitions` | yes | none | `experimental` |
| `SekaiService.ListOntologyRelations` | `sekai.ontology-definitions` | yes | none | `experimental` |
| `SekaiService.GetOntologyRelation` | `sekai.ontology-definitions` | yes | none | `experimental` |
| `SekaiService.CreateOntologyRelation` | `sekai.ontology-definitions` | yes | cli | `stable` |
| `SekaiService.DeleteOntologyRelation` | `sekai.ontology-definitions` | yes | none | `experimental` |
| `SekaiService.CreateFunction` | `sekai.function-definitions` | yes | none | `experimental` |
| `SekaiService.InvokeFunction` | `sekai.function-definitions` | yes | none | `experimental` |
| `SekaiService.ListFunctions` | `sekai.function-definitions` | yes | none | `experimental` |
| `SekaiService.CreateDataset` | `sekai.datasets` | yes | host | `stable` |
| `SekaiService.UpdateDataset` | `sekai.datasets` | yes | host | `stable` |
| `SekaiService.ListDatasets` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.AppendRows` | `sekai.datasets` | yes | host | `stable` |
| `SekaiService.QueryRows` | `sekai.datasets` | yes | host | `stable` |
| `SekaiService.CreateVirtualTable` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.ListVirtualTables` | `sekai.datasets` | yes | none | `experimental` |
| `SekaiService.CreateGrant` | `sekai.authorization` | yes | host | `stable` |
| `SekaiService.DeleteGrant` | `sekai.authorization` | yes | host | `stable` |
| `SekaiService.ListGrants` | `sekai.authorization` | yes | host | `stable` |
| `SekaiService.CheckAccess` | `sekai.authorization` | yes | host | `stable` |
| `SekaiService.EnsureTeamNamespace` | `sekai.team-namespaces, sekai.authorization, sekai.graph, sekai.audit` | yes | none | `experimental` |
| `SekaiService.RecordDecision` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.ListDecisions` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.ListObjectChanges` | `sekai.audit, sekai.graph` | yes | none | `experimental` |
| `SekaiService.GetAttestation` | `sekai.attestations, sekai.audit` | yes | none | `experimental` |
| `SekaiService.ListAttestations` | `sekai.attestations, sekai.audit` | yes | none | `experimental` |
| `SekaiService.VerifyAttestation` | `sekai.attestations, sekai.audit` | yes | none | `experimental` |
| `SekaiService.PutGovernedActionType` | `sekai.audit` | yes | example | `stable` |
| `SekaiService.GetGovernedActionType` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.ListGovernedActionTypes` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.SetGovernedActionTypeEnabled` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.SubmitActionInstance` | `sekai.audit` | yes | host, example | `stable` |
| `SekaiService.DecideActionInstance` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.PutActionBinding` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.RunActionBinding` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.DescribeObjectAction` | `sekai.audit` | yes | none | `stable` |
| `SekaiService.PreviewObjectAction` | `sekai.audit` | yes | none | `stable` |
| `SekaiService.GetActionInstance` | `sekai.audit` | yes | example | `stable` |
| `SekaiService.ListActionInstances` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.GetActionEffect` | `sekai.audit` | yes | example | `stable` |
| `SekaiService.ListActionEffects` | `sekai.audit` | yes | example | `stable` |
| `SekaiService.ListClaimableActionWork` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.ClaimActionWork` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.HeartbeatActionClaim` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.AckActionWork` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.ReportActionClaimEvent` | `sekai.audit` | yes | none | `experimental` |
| `SekaiService.SetActionPolicy` | `sekai.action-definitions, sekai.audit` | yes | none | `experimental` |
| `SekaiService.GetActionPolicy` | `sekai.action-definitions, sekai.audit` | yes | none | `experimental` |
| `SekaiService.ListActionPolicies` | `sekai.action-definitions, sekai.audit` | yes | none | `experimental` |
| `SekaiService.GetLineage` | `sekai.graph, sekai.audit` | yes | none | `experimental` |
| `SekaiService.CreateContentionScope` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.UpdateContentionScope` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.GetContentionScope` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.ListContentionScopes` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.CreateWorkUnit` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.GetWorkUnit` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.ListWorkUnits` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.TryAdmitWorkUnit` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.HeartbeatWorkUnit` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.CompleteWorkUnit` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.FailWorkUnit` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.CancelWorkUnit` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.ListReservations` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.ListRunEvents` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.ReconcileWorkUnits` | `sekai.coordination` | yes | none | `experimental` |
| `SekaiService.CreateCredential` | `sekai.credentials` | yes | host | `stable` |
| `SekaiService.RotateCredential` | `sekai.credentials` | yes | host | `stable` |
| `SekaiService.RevokeCredential` | `sekai.credentials` | yes | host | `stable` |
| `SekaiService.ListCredentials` | `sekai.credentials` | yes | host | `stable` |
| `SekaiService.GetProvenanceReport` | `sekai.audit, sekai.evidence, sekai.graph` | yes | none | `experimental` |
| `SekaiService.RegisterEvidenceSchema` | `sekai.evidence` | yes | example | `stable` |
| `SekaiService.ListEvidenceAdapters` | `sekai.evidence` | yes | none | `experimental` |
| `SekaiService.SubmitEvidence` | `sekai.evidence` | yes | example | `stable` |
| `SekaiService.GetEvidenceSubmission` | `sekai.evidence` | yes | none | `experimental` |
| `SekaiService.ListEvidenceSubmissions` | `sekai.evidence` | yes | none | `experimental` |
| `SekaiService.CreateHandoff` | `sekai.handoffs` | yes | none | `experimental` |
| `SekaiService.RevokeHandoff` | `sekai.handoffs` | yes | none | `experimental` |
| `ChiseiService.EvaluateGovernedSubject` | `chisei.execution` | yes | none | `experimental` |
| `ChiseiService.ExportGovernedSubjectProvenance` | `chisei.execution` | yes | none | `experimental` |
| `ChiseiService.ExecuteEvaluationManifest` | `chisei.evaluation` | yes | cli | `stable` |
| `ChiseiService.CancelEvaluationExecution` | `chisei.evaluation` | yes | none | `experimental` |
| `ChiseiService.AuthorizeExternalAction` | `chisei.approvals` | yes | example | `stable` |
| `ChiseiService.TransitionExternalAction` | `chisei.approvals` | yes | example | `stable` |
| `ChiseiService.RedeemExternalActionPermit` | `chisei.approvals` | yes | example | `stable` |
| `ChiseiService.SetExternalActionPolicy` | `chisei.approvals` | yes | none | `experimental` |
| `ChiseiService.RecordUsage` | `chisei.budget` | yes | host | `stable` |
| `ChiseiService.SetBudgetLimit` | `chisei.budget` | yes | none | `stable` |
| `ChiseiService.DecideGatewayExecution` | `chisei.policy, chisei.budget` | yes | host | `stable` |
| `ChiseiService.SetNamespacePolicy` | `chisei.policy` | yes | none | `stable` |
| `ChiseiService.GetEffectivePolicySummary` | `chisei.policy` | yes | none | `experimental` |
| `ChiseiService.PlanExecution` | `chisei.policy, chisei.budget, chisei.execution` | yes | sdk, cli | `stable` |
| `ChiseiService.ExecutePlanStream` | `chisei.execution` | yes | sdk, cli | `stable` |
| `ChiseiService.PlanContentExecution` | `chisei.policy, chisei.budget, chisei.execution` | yes | sdk | `stable` |
| `ChiseiService.ExecuteContentPlanStream` | `chisei.execution` | yes | sdk | `stable` |
| `ChiseiService.ReportOperationEvent` | `chisei.execution` | yes | sdk | `stable` |
| `ChiseiService.GetOperationReceipt` | `chisei.execution` | yes | sdk, host, cli | `stable` |
| `ChiseiService.GetQualityTrend` | `chisei.execution` | yes | sdk | `stable` |
| `ChiseiService.ListKiokuCandidates` | `chisei.learning` | yes | none | `remove` |
| `ChiseiService.ReviewKiokuMemory` | `chisei.learning` | yes | none | `remove` |
| `ChiseiService.IssueGunshiRecommendations` | `chisei.learning, chisei.execution` | yes | none | `remove` |
| `ChiseiService.SetGunshiAllocationPolicy` | `chisei.learning` | yes | none | `remove` |
| `ChiseiService.GetGunshiAllocationStatus` | `chisei.learning` | yes | none | `remove` |
| `ChiseiService.ClaimGatewayDispatch` | `gateway.governance, chisei.execution` | yes | host | `stable` |
| `ChiseiService.PutEvaluatorDefinition` | `chisei.evaluation` | yes | none | `experimental` |
| `ChiseiService.PutEvaluationPlan` | `chisei.evaluation` | yes | cli | `stable` |
| `ChiseiService.ResolveEvaluationPlan` | `chisei.evaluation` | yes | cli | `stable` |
| `ChiseiService.GetEvaluationGateEvidence` | `chisei.evaluation` | yes | none | `experimental` |
| `ChiseiService.RunLookupFirstPromotionGate` | `chisei.evaluation` | yes | none | `remove` |
| `ChiseiService.GetSampleObservation` | `chisei.observations` | yes | none | `remove` |

<!-- /rpc-maturity-rows -->

## Deprecation notes (`remove`)

These RPCs stay on the wire until a later major-version change set. Removal of
any RPC that later gains an external consumer requires a Design Discussion.

| RPC | Why classified `remove` |
| --- | --- |
| `ChiseiService.ListKiokuCandidates` | Learning-memory research path; no SDK, host, or example consumer. |
| `ChiseiService.ReviewKiokuMemory` | Same Kioku review path; no first-class consumer. |
| `ChiseiService.IssueGunshiRecommendations` | Allocation research path; no first-class consumer. |
| `ChiseiService.SetGunshiAllocationPolicy` | Same Gunshi policy write; no first-class consumer. |
| `ChiseiService.GetGunshiAllocationStatus` | Same Gunshi status read; no first-class consumer. |
| `ChiseiService.GetSampleObservation` | Redacted sample-observation readback; no SDK, host, or example consumer. |
| `ChiseiService.RunLookupFirstPromotionGate` | Lookup-first promotion research gate; no first-class consumer. |
