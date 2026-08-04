export const PROJECTION_VERSION = "sekai.capability-projection/v1";
function required(name, value) {
    if (!value.trim())
        throw new Error(`projection requires ${name}`);
}
export function invocation(capability, operationId, input) {
    required("namespace", capability.context.namespace);
    required("principal", capability.context.principal);
    required("catalog_version", capability.context.catalog_version);
    required("operation_id", operationId);
    if (capability.projection_version !== PROJECTION_VERSION ||
        capability.contract_version !== capability.context.contract_version ||
        capability.minimum_compatible_version !== capability.context.contract_version ||
        capability.maximum_compatible_version !== capability.context.contract_version)
        throw new Error("capability contract version drift");
    return {
        projection_version: PROJECTION_VERSION,
        contract_version: capability.contract_version,
        catalog_version: capability.context.catalog_version,
        namespace: capability.context.namespace,
        principal: capability.context.principal,
        capability: capability.name,
        operation_id: operationId,
        input_type: capability.input_type,
        output_type: capability.output_type,
        input,
    };
}
export function nativeMetadata(call) {
    return {
        "x-principal": call.principal,
        "x-sekai-namespace": call.namespace,
        "x-sekai-capability": call.capability,
        "x-sekai-operation-id": call.operation_id,
        "x-chisei-work-unit": call.operation_id,
        "x-sekai-catalog-version": call.catalog_version,
    };
}
export function normalizeError(call, code, message) {
    return {
        code,
        message,
        capability: call.capability,
        operation_id: call.operation_id,
        retryable: ["aborted", "unavailable", "deadline_exceeded"].includes(code),
    };
}
