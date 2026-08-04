function lowerCamel(method) {
    return method.length ? `${method[0].toLowerCase()}${method.slice(1)}` : method;
}
function loopback(hostname) {
    const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1";
}
function targetDetails(config) {
    const raw = config.target.trim();
    if (!raw)
        throw new Error("gRPC target is required");
    if (raw.startsWith("unix://"))
        return { target: raw, secure: false };
    let url;
    try {
        url = new URL(raw);
    }
    catch {
        throw new Error("gRPC target must be an http(s) URL or unix:// path");
    }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
        throw new Error("gRPC target URL is invalid");
    }
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    if (url.protocol === "http:" && !config.allowInsecureRemote && !loopback(hostname)) {
        throw new Error("insecure gRPC is restricted to loopback; use HTTPS for remote targets");
    }
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    return { target: `${hostname.includes(":") ? `[${hostname}]` : hostname}:${port}`, secure: url.protocol === "https:" };
}
function metadataFrom(options, Metadata) {
    const metadata = new Metadata();
    for (const [key, value] of Object.entries(options.metadata))
        metadata.set(key, value);
    return metadata;
}
async function* consumeStream(call, signal) {
    const highWaterMark = 64;
    const lowWaterMark = 16;
    const maxBuffered = 128;
    if (signal?.aborted) {
        call.cancel?.();
        throw Object.assign(new Error("RPC cancelled"), { code: 1 });
    }
    const queue = [];
    let ended = false;
    let failure;
    let wake;
    const notify = () => {
        wake?.();
        wake = undefined;
    };
    const abort = () => {
        call.cancel?.();
        failure = Object.assign(new Error("RPC cancelled"), { code: 1 });
        ended = true;
        notify();
    };
    call.on("data", (value) => {
        if (ended)
            return;
        queue.push(value);
        if (queue.length > maxBuffered) {
            call.cancel?.();
            failure = Object.assign(new Error("RPC stream buffer exhausted"), { code: 8 });
            ended = true;
        }
        else if (queue.length >= highWaterMark) {
            call.pause?.();
        }
        notify();
    });
    call.on("end", () => {
        ended = true;
        notify();
    });
    call.on("error", (error) => {
        failure = error;
        ended = true;
        notify();
    });
    signal?.addEventListener("abort", abort, { once: true });
    try {
        while (!ended || queue.length) {
            if (!queue.length)
                await new Promise((resolve) => { wake = resolve; });
            if (failure)
                throw failure;
            while (queue.length) {
                const item = queue.shift();
                if (queue.length <= lowWaterMark)
                    call.resume?.();
                yield item;
            }
        }
        if (failure)
            throw failure;
    }
    finally {
        signal?.removeEventListener("abort", abort);
        if (!ended)
            call.cancel?.();
    }
}
export class GrpcTransport {
    clients;
    Metadata;
    constructor(clients, Metadata) {
        this.clients = clients;
        this.Metadata = Metadata;
    }
    static async connect(config) {
        const grpc = await import("@grpc/grpc-js");
        const loader = await import("@grpc/proto-loader");
        const path = await import("node:path");
        const fs = await import("node:fs");
        const { fileURLToPath } = await import("node:url");
        const moduleDir = path.dirname(fileURLToPath(import.meta.url));
        const root = config.protoRoot
            ? path.resolve(config.protoRoot)
            : ["../../proto", "../../../proto"]
                .map((relative) => path.resolve(moduleDir, relative))
                .find((candidate) => fs.existsSync(path.join(candidate, "sekai.proto")))
                ?? path.resolve(moduleDir, "../../proto");
        const definition = loader.loadSync([
            path.join(root, "sekai.proto"),
            path.join(root, "chisei.proto"),
        ], {
            keepCase: true,
            longs: String,
            enums: String,
            defaults: true,
            oneofs: true,
            includeDirs: [root],
        });
        const packages = grpc.loadPackageDefinition(definition);
        const target = targetDetails(config);
        const credentials = target.secure
            ? grpc.credentials.createSsl(config.tlsRootCertificates)
            : grpc.credentials.createInsecure();
        const sekaiConstructor = packages.sekai?.SekaiService;
        const chiseiConstructor = packages.chisei?.ChiseiService;
        if (!sekaiConstructor || !chiseiConstructor)
            throw new Error("Sekai/Chisei service definitions are unavailable");
        return new GrpcTransport({
            sekai: new sekaiConstructor(target.target, credentials),
            chisei: new chiseiConstructor(target.target, credentials),
        }, grpc.Metadata);
    }
    unary(service, method, request, options) {
        const client = this.clients[service];
        const call = client[lowerCamel(method)];
        if (typeof call !== "function")
            return Promise.reject(new Error(`${service}.${method} is unavailable`));
        return new Promise((resolve, reject) => {
            let rpcCall;
            let settled = false;
            let abort = () => { };
            const cleanup = () => options.signal?.removeEventListener("abort", abort);
            const finish = (handler) => {
                if (settled)
                    return;
                settled = true;
                cleanup();
                handler();
            };
            abort = () => {
                rpcCall?.cancel?.();
                finish(() => reject(Object.assign(new Error("RPC cancelled"), { code: 1 })));
            };
            if (options.signal?.aborted) {
                abort();
                return;
            }
            options.signal?.addEventListener("abort", abort, { once: true });
            try {
                rpcCall = Reflect.apply(call, client, [
                    request,
                    metadataFrom(options, this.Metadata),
                    { deadline: options.deadline },
                    (error, response) => finish(() => error ? reject(error) : resolve(response)),
                ]);
                if (options.signal?.aborted)
                    abort();
            }
            catch (error) {
                finish(() => reject(error));
            }
        });
    }
    stream(service, method, request, options) {
        const client = this.clients[service];
        const call = client[lowerCamel(method)];
        if (typeof call !== "function") {
            return (async function* () {
                throw new Error(`${service}.${method} is unavailable`);
            })();
        }
        const stream = Reflect.apply(call, client, [
            request,
            metadataFrom(options, this.Metadata),
            { deadline: options.deadline },
        ]);
        return consumeStream(stream, options.signal);
    }
    close() {
        this.clients.sekai.close?.();
        this.clients.chisei.close?.();
    }
}
export async function connectGrpc(config) {
    return GrpcTransport.connect(config);
}
