export declare const SDK_CONTRACT_VERSION = "sekai.sdk-core-loop/v1";
export type ServiceName = "sekai" | "chisei";
export type SdkErrorCode = "cancelled" | "invalid_argument" | "deadline_exceeded" | "not_found" | "already_exists" | "permission_denied" | "resource_exhausted" | "failed_precondition" | "aborted" | "unavailable" | "unimplemented" | "internal" | "unauthenticated" | "unknown";
export interface RetryPolicy {
    maxAttempts: number;
    initialBackoffMs: number;
    maxBackoffMs: number;
    retryableCodes: readonly SdkErrorCode[];
}
export declare const DEFAULT_RETRY_POLICY: RetryPolicy;
export interface RpcCallOptions {
    metadata: Readonly<Record<string, string>>;
    deadline: Date;
    signal?: AbortSignal;
}
export interface RpcTransport {
    unary(service: ServiceName, method: string, request: Record<string, unknown>, options: RpcCallOptions): Promise<unknown>;
    stream(service: ServiceName, method: string, request: Record<string, unknown>, options: RpcCallOptions): AsyncIterable<unknown>;
    close?(): void;
}
export interface ClientConfig {
    target?: string;
    token?: string;
    principal: string;
    namespace?: string;
    catalogVersion?: string;
    defaultTimeoutMs?: number;
    retry?: Partial<RetryPolicy>;
    allowInsecureRemote?: boolean;
    tlsRootCertificates?: Uint8Array;
    transport?: RpcTransport;
    protoRoot?: string;
}
export interface CallContext {
    namespace?: string;
    capability?: string;
    operationId?: string;
    catalogVersion?: string;
    metadata?: Readonly<Record<string, string>>;
}
export interface CallOptions extends CallContext {
    timeoutMs?: number;
    retryable?: boolean;
    requestId?: string;
    signal?: AbortSignal;
}
export interface SchemaType {
    kind: string;
    description?: string;
    properties?: readonly Record<string, unknown>[];
    is_builtin?: boolean;
    implements?: readonly string[];
    [key: string]: unknown;
}
export interface FactObject {
    id: string;
    kind: string;
    name: string;
    namespace?: string;
    external_id?: string;
    properties?: Readonly<Record<string, string>>;
    created?: number;
    updated?: number;
    [key: string]: unknown;
}
export interface FactLink {
    id: string;
    from_id: string;
    to_id: string;
    relation: string;
    created?: number;
    [key: string]: unknown;
}
export interface ExecutionInput {
    request_id?: string;
    namespace: string;
    spec?: string;
    preferred_model?: string;
    preferred_runtime?: string;
    task_type?: string;
    priority?: number;
    user_id?: string;
    estimated_tokens?: number;
    messages?: readonly Record<string, unknown>[];
    tools?: readonly Record<string, unknown>[];
    system?: string;
    max_tokens?: number;
    task_class?: string;
    logical_operation_id?: string;
    attempt_id?: string;
    route_override?: string;
    [key: string]: unknown;
}
export interface ExecutionPlan {
    plan_id: string;
    input?: ExecutionInput;
    resolved_runtime?: string;
    resolved_model?: string;
    executable?: boolean;
    [key: string]: unknown;
}
export interface ExecutePlanStreamEvent {
    content_delta?: string;
    response?: Record<string, unknown>;
    done?: boolean;
    executed_at?: number;
    [key: string]: unknown;
}
export interface OperationReceipt {
    receipt_json: string;
    complete: boolean;
    missing_surfaces: readonly string[];
    [key: string]: unknown;
}
export interface SeedFactsInput {
    namespace: string;
    objects: readonly FactObject[];
    links?: readonly FactLink[];
    operationId?: string;
    options?: Omit<CallOptions, "namespace" | "operationId">;
}
export interface CoreLoopInput {
    namespace: string;
    schema?: SchemaType;
    objects: readonly FactObject[];
    links?: readonly FactLink[];
    execution: ExecutionInput;
    operationId?: string;
    callerScope?: string;
    stream?: boolean;
    options?: Omit<CallOptions, "namespace" | "operationId">;
}
export interface CoreLoopResult {
    operationId: string;
    requestId: string;
    schema?: SchemaType;
    objects: readonly FactObject[];
    links: readonly FactLink[];
    plan: ExecutionPlan;
    events: readonly ExecutePlanStreamEvent[];
    receipt: OperationReceipt;
}
export interface RawRpcOptions extends CallOptions {
}
export declare class SdkError extends Error {
    readonly code: SdkErrorCode;
    readonly retryable: boolean;
    readonly service?: ServiceName;
    readonly method?: string;
    readonly operationId?: string;
    readonly requestId?: string;
    readonly cause?: unknown;
    constructor(code: SdkErrorCode, message: string, details?: {
        service?: ServiceName;
        method?: string;
        operationId?: string;
        requestId?: string;
        retryable?: boolean;
        cause?: unknown;
    });
    static from(error: unknown, details?: {
        service?: ServiceName;
        method?: string;
        operationId?: string;
        requestId?: string;
    }): SdkError;
}
export declare class RawRpcFacade {
    private readonly client;
    constructor(client: SekaiChiseiClient);
    unary<T = unknown>(service: ServiceName, method: string, request?: Record<string, unknown>, options?: RawRpcOptions): Promise<T>;
    stream<T = unknown>(service: ServiceName, method: string, request?: Record<string, unknown>, options?: RawRpcOptions): AsyncIterable<T>;
}
export declare class SekaiChiseiClient {
    #private;
    readonly raw: RawRpcFacade;
    constructor(config: ClientConfig);
    static connect(config: Omit<ClientConfig, "transport"> & {
        target: string;
    }): Promise<SekaiChiseiClient>;
    close(): void;
    metadata(context?: CallContext): Readonly<Record<string, string>>;
    callUnary<T>(service: ServiceName, method: string, request?: Record<string, unknown>, options?: CallOptions): Promise<T>;
    callStream<T>(service: ServiceName, method: string, request?: Record<string, unknown>, options?: CallOptions): AsyncIterable<T>;
    createSchemaType(type: SchemaType, options?: CallOptions): Promise<SchemaType>;
    createObject(object: FactObject, options?: CallOptions): Promise<FactObject>;
    createLink(link: FactLink, options?: CallOptions): Promise<FactLink>;
    seedFacts(input: SeedFactsInput): Promise<{
        objects: readonly FactObject[];
        links: readonly FactLink[];
    }>;
    planExecution(input: ExecutionInput, options?: CallOptions): Promise<ExecutionPlan>;
    executePlan(plan: ExecutionPlan, options?: CallOptions): Promise<Record<string, unknown>>;
    executePlanStream(plan: ExecutionPlan, options?: CallOptions): AsyncIterable<ExecutePlanStreamEvent>;
    getOperationReceipt(request: string | {
        operation_id?: string;
        request_id?: string;
        caller_scope?: string;
        attempt?: number;
    }, options?: CallOptions): Promise<OperationReceipt>;
    runCoreLoop(input: CoreLoopInput): Promise<CoreLoopResult>;
}
