import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  SDK_CONTRACT_VERSION,
  SdkError,
  SekaiChiseiClient,
  type RpcCallOptions,
  type RpcTransport,
  type ServiceName,
} from "./client.ts";

const fixture = JSON.parse(readFileSync(
  new URL("../../tests/fixtures/sdk_core_loop/v1.json", import.meta.url),
  "utf8",
));

class FixtureTransport implements RpcTransport {
  readonly calls: Array<{ service: ServiceName; method: string; request: Record<string, unknown>; options: RpcCallOptions }> = [];
  failNext = false;

  async unary(service: ServiceName, method: string, request: Record<string, unknown>, options: RpcCallOptions): Promise<unknown> {
    this.calls.push({ service, method, request, options });
    if (this.failNext) {
      this.failNext = false;
      throw { code: "UNAVAILABLE", message: "fixture unavailable" };
    }
    if (service === "sekai" && method === "CreateSchemaType") return { type: request.type };
    if (service === "sekai" && method === "CreateObject") return { object: request.object };
    if (service === "sekai" && method === "CreateLink") return { link: request.link };
    if (service === "chisei" && method === "PlanExecution") return { plan: fixture.plan };
    if (service === "chisei" && method === "GetOperationReceipt") return fixture.receipt;
    throw new Error(`unexpected fixture unary ${service}.${method}`);
  }

  stream(service: ServiceName, method: string, request: Record<string, unknown>, options: RpcCallOptions): AsyncIterable<unknown> {
    this.calls.push({ service, method, request, options });
    if (service !== "chisei" || method !== "ExecutePlanStream") throw new Error(`unexpected fixture stream ${service}.${method}`);
    return (async function* () {
      yield* fixture.stream_events;
    })();
  }
}

function client(transport: RpcTransport): SekaiChiseiClient {
  return new SekaiChiseiClient({
    principal: fixture.principal,
    token: fixture.token,
    namespace: fixture.namespace,
    catalogVersion: fixture.catalog_version,
    transport,
  });
}

test("TypeScript completes the ontology → facts → plan/stream → receipt loop", async () => {
  assert.equal(SDK_CONTRACT_VERSION, fixture.version);
  const transport = new FixtureTransport();
  const result = await client(transport).runCoreLoop({
    namespace: fixture.namespace,
    schema: fixture.schema,
    objects: fixture.objects,
    links: fixture.links,
    execution: fixture.execution,
    operationId: fixture.operation_id,
  });

  assert.equal(result.operationId, fixture.operation_id);
  assert.equal(result.requestId, fixture.request_id);
  assert.equal(result.plan.plan_id, fixture.plan.plan_id);
  assert.deepEqual(result.events, fixture.stream_events);
  assert.deepEqual(result.receipt, fixture.receipt);
  assert.deepEqual(transport.calls.map((call) => `${call.service}.${call.method}`), [
    "sekai.CreateSchemaType",
    "sekai.CreateObject",
    "sekai.CreateObject",
    "sekai.CreateLink",
    "chisei.PlanExecution",
    "chisei.ExecutePlanStream",
    "chisei.GetOperationReceipt",
  ]);
  const capabilities = transport.calls.map((call) => call.options.metadata["x-sekai-capability"]);
  assert.deepEqual(capabilities, [
    "sekai.schema.create",
    "sekai.fact.seed",
    "sekai.fact.seed",
    "sekai.fact.seed",
    "chisei.plan.execute",
    "chisei.plan.execute",
    "chisei.receipt.read",
  ]);
  for (const call of transport.calls) {
    for (const [key, value] of Object.entries(fixture.expected_base_metadata)) {
      assert.equal(call.options.metadata[key], value, `${call.service}.${call.method} metadata ${key}`);
    }
    assert.ok(call.options.deadline.getTime() > Date.now());
  }
  const receiptCall = transport.calls.at(-1)!;
  assert.equal(receiptCall.request.operation_id, fixture.plan.plan_id);
  assert.equal(receiptCall.request.request_id, "");
});

test("TypeScript retries only when the caller opts into retryable unary work", async () => {
  const transport = new FixtureTransport();
  transport.failNext = true;
  const sdk = client(transport);
  const result = await sdk.raw.unary("sekai", "CreateObject", { object: fixture.objects[0] }, {
    operationId: fixture.operation_id,
    retryable: true,
  });
  assert.deepEqual(result, { object: fixture.objects[0] });
  assert.equal(transport.calls.length, 2);
});

test("TypeScript preserves an explicit non-retryable transport error", async () => {
  let calls = 0;
  const transport: RpcTransport = {
    async unary() {
      calls += 1;
      throw new SdkError("unavailable", "unsafe to replay", { retryable: false });
    },
    stream() {
      return (async function* () {})();
    },
  };
  await assert.rejects(
    client(transport).raw.unary("sekai", "CreateObject", {}, {
      operationId: fixture.operation_id,
      retryable: true,
    }),
    (error: unknown) => error instanceof SdkError && !error.retryable,
  );
  assert.equal(calls, 1);
});

test("TypeScript binds seeded facts to the requested namespace", async () => {
  const transport = new FixtureTransport();
  await client(transport).seedFacts({
    namespace: fixture.namespace,
    objects: [{ id: "unscoped", kind: "service", name: "unscoped" }],
  });
  assert.equal(transport.calls[0]?.request.object.namespace, fixture.namespace);
  await assert.rejects(
    client(new FixtureTransport()).seedFacts({
      namespace: fixture.namespace,
      objects: [{ id: "foreign", kind: "service", name: "foreign", namespace: "other" }],
    }),
    (error: unknown) => error instanceof SdkError && error.code === "invalid_argument",
  );
});

test("TypeScript maps authorization failures and protects reserved metadata", async () => {
  const transport: RpcTransport = {
    async unary() {
      throw { code: 7, message: "denied" };
    },
    stream() {
      return (async function* () {})();
    },
  };
  const sdk = client(transport);
  await assert.rejects(
    sdk.raw.unary("sekai", "GetObject", {}, { operationId: fixture.operation_id }),
    (error: unknown) => error instanceof SdkError
      && error.code === "permission_denied"
      && error.message === "RPC permission denied"
      && !error.retryable,
  );
  assert.throws(
    () => sdk.metadata({ metadata: { authorization: "Bearer attacker" } }),
    /reserved metadata/,
  );
});

test("TypeScript passes cancellation through the streaming transport", async () => {
  const controller = new AbortController();
  const transport: RpcTransport = {
    async unary() {
      return {};
    },
    stream(_service, _method, _request, options) {
      return (async function* () {
        await new Promise<void>((resolve) => options.signal?.addEventListener("abort", resolve, { once: true }));
        throw { code: 1, message: "cancelled" };
      })();
    },
  };
  const iterator = client(transport).executePlanStream(fixture.plan, { signal: controller.signal })[Symbol.asyncIterator]();
  const pending = iterator.next();
  controller.abort();
  await assert.rejects(pending, (error: unknown) => error instanceof SdkError && error.code === "cancelled");
});
