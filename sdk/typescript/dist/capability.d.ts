export declare const PROJECTION_VERSION = "sekai.capability-projection/v1";
export interface ProjectionContext {
    namespace: string;
    principal: string;
    contract_version: string;
    catalog_version: string;
}
export interface ProjectedCapability {
    projection_version: string;
    context: ProjectionContext;
    name: string;
    contract_version: string;
    minimum_compatible_version: string;
    maximum_compatible_version: string;
    input_type: string;
    output_type: string;
    [key: string]: unknown;
}
export interface SdkInvocation {
    projection_version: string;
    contract_version: string;
    catalog_version: string;
    namespace: string;
    principal: string;
    capability: string;
    operation_id: string;
    input_type: string;
    output_type: string;
    input: Record<string, unknown>;
}
export declare function invocation(capability: ProjectedCapability, operationId: string, input: Record<string, unknown>): SdkInvocation;
export declare function nativeMetadata(call: SdkInvocation): Record<string, string>;
export declare function normalizeError(call: SdkInvocation, code: string, message: string): {
    code: string;
    message: string;
    capability: string;
    operation_id: string;
    retryable: boolean;
};
