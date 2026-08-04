import { randomUUID } from "node:crypto";
import { connectGrpc } from "./grpc.js";
export const SDK_CONTRACT_VERSION = "sekai.sdk-core-loop/v1";
export const DEFAULT_RETRY_POLICY = {
    maxAttempts: 3,
    initialBackoffMs: 50,
    maxBackoffMs: 1_000,
    retryableCodes: ["aborted", "deadline_exceeded", "resource_exhausted", "unavailable"],
};
function asRecord(value, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new SdkError("internal", `${label} returned an invalid response`);
    }
    return value;
}
function requiredText(name, value, max = 512) {
    if (typeof value !== "string" || !value.trim() || value.length > max || /[\r\n\0]/.test(value)) {
        throw new SdkError("invalid_argument", `${name} must be a bounded non-empty string`);
    }
    return value;
}
function optionalText(name, value, max = 512) {
    if (value === undefined || value === "")
        return undefined;
    return requiredText(name, value, max);
}
function normalizeRpcCode(value) {
    const numeric = {
        1: "cancelled",
        2: "unknown",
        3: "invalid_argument",
        4: "deadline_exceeded",
        5: "not_found",
        6: "already_exists",
        7: "permission_denied",
        8: "resource_exhausted",
        9: "failed_precondition",
        10: "aborted",
        11: "unknown",
        12: "unimplemented",
        13: "internal",
        14: "unavailable",
        16: "unauthenticated",
    };
    if (typeof value === "number")
        return numeric[value] ?? "unknown";
    if (typeof value !== "string")
        return "unknown";
    const normalized = value.toLowerCase().replaceAll("-", "_");
    const aliases = {
        canceled: "cancelled",
        cancelled: "cancelled",
        deadlineexceeded: "deadline_exceeded",
        deadline_exceeded: "deadline_exceeded",
        invalidargument: "invalid_argument",
        invalid_argument: "invalid_argument",
        notfound: "not_found",
        not_found: "not_found",
        alreadyexists: "already_exists",
        already_exists: "already_exists",
        permissiondenied: "permission_denied",
        permission_denied: "permission_denied",
        resourceexhausted: "resource_exhausted",
        resource_exhausted: "resource_exhausted",
        failedprecondition: "failed_precondition",
        failed_precondition: "failed_precondition",
        unauthenticated: "unauthenticated",
        unavailable: "unavailable",
        unimplemented: "unimplemented",
        internal: "internal",
        aborted: "aborted",
        unknown: "unknown",
    };
    return aliases[normalized] ?? "unknown";
}
function safeErrorMessage(code) {
    return {
        cancelled: "RPC cancelled",
        invalid_argument: "RPC request was invalid",
        deadline_exceeded: "RPC deadline exceeded",
        not_found: "RPC resource was not found",
        already_exists: "RPC resource already exists",
        permission_denied: "RPC permission denied",
        resource_exhausted: "RPC resource exhausted",
        failed_precondition: "RPC precondition failed",
        aborted: "RPC was aborted",
        unavailable: "Sekai/Chisei is unavailable",
        unimplemented: "RPC is not implemented",
        internal: "Sekai/Chisei returned an internal error",
        unauthenticated: "Sekai/Chisei authentication failed",
        unknown: "Sekai/Chisei RPC failed",
    }[code];
}
export class SdkError extends Error {
    code;
    retryable;
    service;
    method;
    operationId;
    requestId;
    cause;
    constructor(code, message, details = {}) {
        super(message);
        this.name = "SekaiChiseiSdkError";
        this.code = code;
        this.retryable = details.retryable ?? [
            "aborted",
            "deadline_exceeded",
            "resource_exhausted",
            "unavailable",
        ].includes(code);
        this.service = details.service;
        this.method = details.method;
        this.operationId = details.operationId;
        this.requestId = details.requestId;
        this.cause = details.cause;
    }
    static from(error, details = {}) {
        if (error instanceof SdkError) {
            return new SdkError(error.code, error.message, {
                ...details,
                operationId: details.operationId ?? error.operationId,
                requestId: details.requestId ?? error.requestId,
                retryable: error.retryable,
                cause: error,
            });
        }
        const candidate = error;
        const code = normalizeRpcCode(candidate?.code);
        return new SdkError(code, safeErrorMessage(code), { ...details, cause: error });
    }
}
function retryPolicy(value) {
    const merged = { ...DEFAULT_RETRY_POLICY, ...(value ?? {}) };
    if (!Number.isInteger(merged.maxAttempts) || merged.maxAttempts < 1 || merged.maxAttempts > 8) {
        throw new SdkError("invalid_argument", "retry.maxAttempts must be between 1 and 8");
    }
    if (!Number.isFinite(merged.initialBackoffMs) || merged.initialBackoffMs < 0) {
        throw new SdkError("invalid_argument", "retry.initialBackoffMs must be non-negative");
    }
    if (!Number.isFinite(merged.maxBackoffMs) || merged.maxBackoffMs < merged.initialBackoffMs) {
        throw new SdkError("invalid_argument", "retry.maxBackoffMs must cover initialBackoffMs");
    }
    return {
        maxAttempts: merged.maxAttempts,
        initialBackoffMs: merged.initialBackoffMs,
        maxBackoffMs: merged.maxBackoffMs,
        retryableCodes: [...merged.retryableCodes],
    };
}
function delay(ms, signal) {
    if (signal?.aborted)
        return Promise.reject(new SdkError("cancelled", "RPC cancelled"));
    return new Promise((resolve, reject) => {
        let settled = false;
        let timer;
        let abort = () => { };
        const cleanup = () => signal?.removeEventListener("abort", abort);
        const finish = (handler) => {
            if (settled)
                return;
            settled = true;
            cleanup();
            handler();
        };
        abort = () => {
            if (timer !== undefined)
                clearTimeout(timer);
            finish(() => reject(new SdkError("cancelled", "RPC cancelled")));
        };
        timer = setTimeout(() => finish(() => resolve()), ms);
        signal?.addEventListener("abort", abort, { once: true });
    });
}
function responseField(response, field, label = field) {
    const record = asRecord(response, label);
    if (!(field in record))
        throw new SdkError("internal", `${label} omitted ${field}`);
    return record[field];
}
function operationId(value) {
    return value?.trim() || randomUUID();
}
export class RawRpcFacade {
    client;
    constructor(client) {
        this.client = client;
    }
    unary(service, method, request = {}, options = {}) {
        return this.client.callUnary(service, method, request, options);
    }
    stream(service, method, request = {}, options = {}) {
        return this.client.callStream(service, method, request, options);
    }
}
export class SekaiChiseiClient {
    raw;
    #transport;
    #config;
    #retry;
    #timeoutMs;
    constructor(config) {
        if (!config.transport) {
            throw new SdkError("invalid_argument", "transport is required; use SekaiChiseiClient.connect for gRPC");
        }
        this.#config = { ...config };
        this.#transport = config.transport;
        this.#retry = retryPolicy(config.retry);
        this.#timeoutMs = config.defaultTimeoutMs ?? 30_000;
        if (!Number.isFinite(this.#timeoutMs) || this.#timeoutMs <= 0 || this.#timeoutMs > 600_000) {
            throw new SdkError("invalid_argument", "defaultTimeoutMs must be between 1 and 600000");
        }
        requiredText("principal", config.principal, 200);
        optionalText("namespace", config.namespace, 200);
        optionalText("catalogVersion", config.catalogVersion, 200);
        if (config.token !== undefined)
            requiredText("token", config.token, 4096);
        this.raw = new RawRpcFacade(this);
    }
    static async connect(config) {
        const transport = await connectGrpc({
            target: config.target,
            allowInsecureRemote: config.allowInsecureRemote,
            tlsRootCertificates: config.tlsRootCertificates,
            protoRoot: config.protoRoot,
        });
        return new SekaiChiseiClient({ ...config, transport });
    }
    close() {
        this.#transport.close?.();
    }
    metadata(context = {}) {
        const namespace = optionalText("namespace", context.namespace ?? this.#config.namespace, 200);
        const capability = optionalText("capability", context.capability, 200);
        const operation = optionalText("operationId", context.operationId, 200);
        const catalog = optionalText("catalogVersion", context.catalogVersion ?? this.#config.catalogVersion, 200);
        const metadata = { "x-principal": requiredText("principal", this.#config.principal, 200) };
        if (this.#config.token)
            metadata.authorization = `Bearer ${this.#config.token}`;
        if (namespace)
            metadata["x-sekai-namespace"] = namespace;
        if (capability)
            metadata["x-sekai-capability"] = capability;
        if (operation) {
            metadata["x-sekai-operation-id"] = operation;
            metadata["x-chisei-work-unit"] = operation;
        }
        if (catalog)
            metadata["x-sekai-catalog-version"] = catalog;
        const reserved = new Set([
            "authorization",
            "x-principal",
            "x-sekai-namespace",
            "x-sekai-capability",
            "x-sekai-operation-id",
            "x-chisei-work-unit",
            "x-sekai-catalog-version",
        ]);
        for (const [key, value] of Object.entries(context.metadata ?? {})) {
            const normalized = key.toLowerCase();
            if (reserved.has(normalized)) {
                throw new SdkError("invalid_argument", `reserved metadata must be set through SDK context: ${key}`);
            }
            if (!/^[a-z0-9-]+$/.test(normalized) || normalized.endsWith("-bin")) {
                throw new SdkError("invalid_argument", `invalid metadata key: ${key}`);
            }
            metadata[normalized] = requiredText(`metadata ${key}`, value, 4096);
        }
        return Object.freeze(metadata);
    }
    async callUnary(service, method, request = {}, options = {}) {
        const requestId = options.requestId ?? randomUUID();
        const operation = options.operationId;
        const metadata = this.metadata(options);
        const timeoutMs = options.timeoutMs ?? this.#timeoutMs;
        if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 600_000) {
            throw new SdkError("invalid_argument", "timeoutMs must be between 1 and 600000", {
                service,
                method,
                operationId: operation,
                requestId,
            });
        }
        const deadline = new Date(Date.now() + timeoutMs);
        const attempts = options.retryable ? this.#retry.maxAttempts : 1;
        let attempt = 0;
        while (attempt < attempts) {
            attempt += 1;
            if (options.signal?.aborted) {
                throw new SdkError("cancelled", "RPC cancelled", {
                    service,
                    method,
                    operationId: operation,
                    requestId,
                });
            }
            if (deadline.getTime() <= Date.now()) {
                throw new SdkError("deadline_exceeded", "RPC deadline exceeded", {
                    service,
                    method,
                    operationId: operation,
                    requestId,
                });
            }
            try {
                return await this.#transport.unary(service, method, request, {
                    metadata,
                    deadline,
                    signal: options.signal,
                });
            }
            catch (error) {
                const sdkError = SdkError.from(error, {
                    service,
                    method,
                    operationId: operation,
                    requestId,
                });
                if (attempt >= attempts
                    || !sdkError.retryable
                    || !this.#retry.retryableCodes.includes(sdkError.code))
                    throw sdkError;
                const backoff = Math.min(this.#retry.maxBackoffMs, this.#retry.initialBackoffMs * (2 ** (attempt - 1)));
                await delay(backoff, options.signal);
            }
        }
        throw new SdkError("unknown", "RPC retry loop terminated unexpectedly", {
            service,
            method,
            operationId: operation,
            requestId,
        });
    }
    callStream(service, method, request = {}, options = {}) {
        const requestId = options.requestId ?? randomUUID();
        const metadata = this.metadata(options);
        const timeoutMs = options.timeoutMs ?? this.#timeoutMs;
        if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 600_000) {
            throw new SdkError("invalid_argument", "timeoutMs must be between 1 and 600000", {
                service,
                method,
                operationId: options.operationId,
                requestId,
            });
        }
        const deadline = new Date(Date.now() + timeoutMs);
        const transport = this.#transport;
        return (async function* () {
            try {
                for await (const item of transport.stream(service, method, request, {
                    metadata,
                    deadline,
                    signal: options.signal,
                })) {
                    yield item;
                }
            }
            catch (error) {
                throw SdkError.from(error, {
                    service,
                    method,
                    operationId: options.operationId,
                    requestId,
                });
            }
        })();
    }
    async createSchemaType(type, options = {}) {
        const response = await this.callUnary("sekai", "CreateSchemaType", { type }, {
            ...options,
            capability: options.capability ?? "sekai.schema.create",
        });
        return responseField(response, "type", "CreateSchemaType");
    }
    async createObject(object, options = {}) {
        requiredText("object.id", object.id, 200);
        requiredText("object.kind", object.kind, 200);
        const response = await this.callUnary("sekai", "CreateObject", { object }, {
            ...options,
            capability: options.capability ?? "sekai.fact.seed",
        });
        return responseField(response, "object", "CreateObject");
    }
    async createLink(link, options = {}) {
        requiredText("link.id", link.id, 200);
        requiredText("link.from_id", link.from_id, 200);
        requiredText("link.to_id", link.to_id, 200);
        requiredText("link.relation", link.relation, 200);
        const response = await this.callUnary("sekai", "CreateLink", {
            link,
            fail_if_exists: false,
        }, {
            ...options,
            capability: options.capability ?? "sekai.fact.seed",
        });
        return responseField(response, "link", "CreateLink");
    }
    async seedFacts(input) {
        requiredText("namespace", input.namespace, 200);
        const base = {
            ...(input.options ?? {}),
            namespace: input.namespace,
            operationId: input.operationId,
        };
        const objects = [];
        for (const object of input.objects) {
            if (object.namespace !== undefined && object.namespace !== input.namespace) {
                throw new SdkError("invalid_argument", "object namespace must match seed namespace");
            }
            objects.push(await this.createObject({ ...object, namespace: input.namespace }, base));
        }
        const links = [];
        for (const link of input.links ?? [])
            links.push(await this.createLink(link, base));
        return { objects, links };
    }
    async planExecution(input, options = {}) {
        const namespace = requiredText("execution.namespace", input.namespace ?? options.namespace, 200);
        const requestId = input.request_id ?? options.requestId ?? randomUUID();
        const logicalOperationId = input.logical_operation_id ?? options.operationId;
        const normalized = {
            ...input,
            namespace,
            request_id: requestId,
            ...(logicalOperationId ? { logical_operation_id: logicalOperationId } : {}),
        };
        const response = await this.callUnary("chisei", "PlanExecution", { input: normalized }, {
            ...options,
            namespace,
            capability: options.capability ?? "chisei.plan.execute",
            requestId,
        });
        return responseField(response, "plan", "PlanExecution");
    }
    async executePlan(plan, options = {}) {
        return this.callUnary("chisei", "ExecutePlan", { plan }, {
            ...options,
            capability: options.capability ?? "chisei.plan.execute",
        });
    }
    executePlanStream(plan, options = {}) {
        return this.callStream("chisei", "ExecutePlanStream", { plan }, {
            ...options,
            capability: options.capability ?? "chisei.plan.execute",
        });
    }
    async getOperationReceipt(request, options = {}) {
        const value = typeof request === "string" ? { operation_id: request } : request;
        if (!value.operation_id && !value.request_id) {
            throw new SdkError("invalid_argument", "receipt requires operation_id or request_id");
        }
        if (value.operation_id && value.request_id) {
            throw new SdkError("invalid_argument", "receipt accepts exactly one of operation_id or request_id");
        }
        const requestId = value.request_id ?? (value.operation_id ? "" : options.requestId ?? randomUUID());
        const response = await this.callUnary("chisei", "GetOperationReceipt", {
            operation_id: value.operation_id ?? "",
            request_id: requestId,
            caller_scope: value.caller_scope ?? "",
            attempt: value.attempt ?? 0,
        }, {
            ...options,
            capability: options.capability ?? "chisei.receipt.read",
            requestId,
            retryable: options.retryable ?? true,
        });
        return response;
    }
    async runCoreLoop(input) {
        const namespace = requiredText("namespace", input.namespace, 200);
        const op = operationId(input.operationId);
        const baseOptions = { ...(input.options ?? {}), namespace, operationId: op };
        let schema;
        if (input.schema)
            schema = await this.createSchemaType(input.schema, baseOptions);
        const seeded = await this.seedFacts({
            namespace,
            objects: input.objects,
            links: input.links,
            operationId: op,
            options: input.options,
        });
        const requestId = input.execution.request_id ?? randomUUID();
        const plan = await this.planExecution({
            ...input.execution,
            namespace,
            request_id: requestId,
            logical_operation_id: input.execution.logical_operation_id ?? op,
        }, baseOptions);
        const events = [];
        if (plan.executable !== false) {
            if (input.stream !== false) {
                for await (const event of this.executePlanStream(plan, { ...baseOptions, requestId })) {
                    events.push(event);
                }
            }
            else {
                const response = await this.executePlan(plan, { ...baseOptions, requestId });
                events.push({ response });
            }
        }
        const receipt = await this.getOperationReceipt({
            operation_id: requiredText("plan.plan_id", plan.plan_id, 200),
            caller_scope: input.callerScope ?? "",
            attempt: 0,
        }, { ...baseOptions, requestId });
        return {
            operationId: op,
            requestId,
            schema,
            objects: seeded.objects,
            links: seeded.links,
            plan,
            events,
            receipt,
        };
    }
}
