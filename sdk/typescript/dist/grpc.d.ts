import type { RpcCallOptions, RpcTransport, ServiceName } from "./client.js";
export interface GrpcConnectionConfig {
    target: string;
    protoRoot?: string;
    allowInsecureRemote?: boolean;
    tlsRootCertificates?: Uint8Array;
}
export declare class GrpcTransport implements RpcTransport {
    private readonly clients;
    private readonly Metadata;
    private constructor();
    static connect(config: GrpcConnectionConfig): Promise<GrpcTransport>;
    unary(service: ServiceName, method: string, request: Record<string, unknown>, options: RpcCallOptions): Promise<unknown>;
    stream(service: ServiceName, method: string, request: Record<string, unknown>, options: RpcCallOptions): AsyncIterable<unknown>;
    close(): void;
}
export declare function connectGrpc(config: GrpcConnectionConfig): Promise<RpcTransport>;
