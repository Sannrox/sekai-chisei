export declare const HTTP_PROJECTION_CONTRACT = "sekai.http-projection/v1";
export declare const HTTP_UNARY_METHODS: readonly [{
    readonly service: "sekai.SekaiService";
    readonly rpc: "ApplySourceBatch";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "GetSourceSyncState";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "GetPublishedDefinitionRevision";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "CreateObject";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "GetObject";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "UpdateObject";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "DeleteObject";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ListObjects";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "EvaluateObjectSet";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ReadObjectChangeSubscription";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "PutObjectSecurityPolicyRevision";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ActivateObjectSecurityPolicies";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "GetObjectSecurityActivation";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "FindByExternalId";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "FindByProperty";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "CreateLink";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "DeleteLink";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "GetLinks";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "Traverse";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "RetrieveContext";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ExpandRelations";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ExplainDerivation";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "DiscoverCapabilities";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ListSchemaTypes";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "CreateSchemaType";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "CreateOntologyClass";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "CreateOntologyRelation";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "CreateDataset";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "UpdateDataset";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "AppendRows";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "QueryRows";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "CreateGrant";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "DeleteGrant";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ListGrants";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "CheckAccess";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "PutGovernedActionType";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "SubmitActionInstance";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "DecideActionInstance";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "DescribeObjectAction";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "PreviewObjectAction";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "GetActionInstance";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ListActionInstances";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "GetActionEffect";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ListActionEffects";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "CreateCredential";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "RotateCredential";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "RevokeCredential";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "ListCredentials";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "RegisterEvidenceSchema";
}, {
    readonly service: "sekai.SekaiService";
    readonly rpc: "SubmitEvidence";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "ExecuteEvaluationManifest";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "AuthorizeExternalAction";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "TransitionExternalAction";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "RedeemExternalActionPermit";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "RecordUsage";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "SetBudgetLimit";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "DecideGatewayExecution";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "SetNamespacePolicy";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "PlanExecution";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "PlanContentExecution";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "ReportOperationEvent";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "GetOperationReceipt";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "GetQualityTrend";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "ClaimGatewayDispatch";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "PutEvaluationPlan";
}, {
    readonly service: "chisei.ChiseiService";
    readonly rpc: "ResolveEvaluationPlan";
}];
export declare function invokeHttpJson<T>(baseUrl: string, service: string, rpc: string, body: unknown, authorization: string, headers?: Record<string, string>): Promise<T>;
