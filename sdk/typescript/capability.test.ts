import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { invocation, nativeMetadata, normalizeError } from "./capability.ts";

const fixture = JSON.parse(readFileSync(
  new URL("../../tests/fixtures/capability_projection/v1.json", import.meta.url),
  "utf8",
));

test("TypeScript preserves authority, correlation, and errors", () => {
  const call = invocation(
    {...fixture.capability, projection_version: fixture.projection_version, context: fixture.context},
    fixture.invocation.operation_id,
    fixture.invocation.input,
  );
  assert.deepEqual(nativeMetadata(call), fixture.expected_metadata);
  assert.deepEqual(normalizeError(call, "permission_denied", "write denied"), fixture.expected_error);
});

test("TypeScript fails closed on contract drift", () => {
  const capability = {...fixture.capability, projection_version: fixture.projection_version, context: fixture.context, maximum_compatible_version: "2.0"};
  assert.throws(() => invocation(capability, "operation-1", {}), /version drift/);
});
