export const PROJECTION_VERSION = "sekai.capability-projection/v1";

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

function required(name: string, value: string): void {
  if (!value.trim()) throw new Error(`projection requires ${name}`);
}

export function invocation(
  capability: ProjectedCapability,
  operationId: string,
  input: Record<string, unknown>,
): SdkInvocation {
  required("namespace", capability.context.namespace);
  required("principal", capability.context.principal);
  required("catalog_version", capability.context.catalog_version);
  required("operation_id", operationId);
  if (
    capability.projection_version !== PROJECTION_VERSION ||
    capability.contract_version !== capability.context.contract_version ||
    capability.minimum_compatible_version !== capability.context.contract_version ||
    capability.maximum_compatible_version !== capability.context.contract_version
  ) throw new Error("capability contract version drift");
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

export function nativeMetadata(call: SdkInvocation): Record<string, string> {
  return {
    "x-principal": call.principal,
    "x-sekai-namespace": call.namespace,
    "x-sekai-capability": call.capability,
    "x-sekai-operation-id": call.operation_id,
  };
}

export function normalizeError(call: SdkInvocation, code: string, message: string) {
  return {
    code,
    message,
    capability: call.capability,
    operation_id: call.operation_id,
    retryable: ["aborted", "unavailable", "deadline_exceeded"].includes(code),
  };
}
