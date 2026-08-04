import assert from "node:assert/strict";
import test from "node:test";
import { GrpcTransport } from "./grpc.ts";
import type { RpcCallOptions } from "./client.ts";

class FixtureMetadata {
  readonly values: Record<string, string> = {};

  set(key: string, value: string): void {
    this.values[key] = value;
  }
}

test("native unary transport cancels an in-flight RPC on abort", async () => {
  let cancelCount = 0;
  let callback: ((error: unknown, response?: unknown) => void) | undefined;
  const clients = {
    sekai: {
      demoRpc: (_request: unknown, _metadata: unknown, _options: unknown, done: typeof callback) => {
        callback = done;
        return { cancel: () => { cancelCount += 1; } };
      },
    },
    chisei: {},
  };
  const transport = new (GrpcTransport as unknown as new (...args: unknown[]) => GrpcTransport)(
    clients,
    FixtureMetadata,
  );
  const controller = new AbortController();
  const options: RpcCallOptions = {
    metadata: {},
    deadline: new Date(Date.now() + 10_000),
    signal: controller.signal,
  };
  const pending = transport.unary("sekai", "DemoRpc", {}, options);
  controller.abort();
  await assert.rejects(
    pending,
    (error: unknown) => (error as { code?: number }).code === 1,
  );
  assert.equal(cancelCount, 1);
  callback?.(null, { ignored: true });
});
