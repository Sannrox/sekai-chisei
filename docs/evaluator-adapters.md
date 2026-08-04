# External evaluator adapters

`external_adapter/v1` lets an operator add a domain evaluator without
changing or loading code into the Chisei process. The evaluator definition is
still created through the namespace-authorized `PutEvaluatorDefinition` RPC;
its `adapter_endpoint` names an already-deployed HTTPS service. Loopback HTTP
is accepted only when `SEKAI_INSECURE=1` is explicitly set for local
development.

The RPC is metadata publication, not an installation command. The returned
`EvaluatorDefinitionRecord` separates `implementation_executable` from the
definition and reports `implementation_status` as `executable`, `unavailable`,
or `unsupported`. A missing shared secret, unreachable adapter, invalid
response, disabled definition, or absent exact digest never falls back to a
different implementation.

## Request contract

Chisei sends one `POST` request to the exact endpoint for each deterministic
node. The body is canonical JSON under
`chisei.external-evaluator-request/v1`:

```json
{
  "contract_version": "chisei.external-evaluator-request/v1",
  "namespace": "stock-picker",
  "implementation_digest": "sha256:<64 lowercase hex characters>",
  "input": {
    "contract_version": "chisei.deterministic-evaluator-input/v1",
    "manifest_digest": "sha256:<...>",
    "node_id": "policy-check",
    "subject_profile": "...",
    "subject_identity": "...",
    "subject_content_digest": "sha256:<...>",
    "parameters": {},
    "invariants": [],
    "evidence": [],
    "dependency_results": []
  }
}
```

The request includes these headers:

- `x-sekai-adapter-contract: chisei.external-evaluator-request/v1`;
- `x-sekai-adapter-request-digest: sha256:<canonical body digest>`; and
- `x-sekai-adapter-signature: <base64url HMAC-SHA256>` over that digest.

The HMAC key is the operator-only `CHISEI_EVALUATOR_ADAPTER_SHARED_SECRET`.
It is never stored in evaluator definitions, receipts, or API responses. Use a
secret manager in deployed environments and rotate the key by coordinating
the Chisei and adapter deployments.

The adapter must not treat the request as permission to call Chisei, mutate
the graph, perform actions, access credentials, or retain evidence. The
namespace and exact implementation digest are binding identity fields, not
caller-selected routing hints.

## Response contract

The adapter returns HTTP 2xx with a bounded JSON
`chisei.deterministic-evaluator-result/v1` response:

```json
{
  "contract_version": "chisei.deterministic-evaluator-result/v1",
  "status": "pass",
  "reason_code": "criteria_met",
  "result": {"matched": true}
}
```

The response must include these authentication headers:

- `x-sekai-adapter-response-digest: sha256:<response body digest>`; and
- `x-sekai-adapter-response-signature: <base64url HMAC-SHA256>`.

The response signature covers the contract version, request digest, response
digest, and implementation digest, separated by newlines, using the same
operator secret as the request signature. Chisei verifies the digest and
signature before deserializing or accepting the result.

`status` is only `pass`, `fail`, or `unknown`; reason codes are lowercase
bounded tokens. Chisei applies the definition's input/output limits and
revalidates the result before producing the normal step receipt. Raw adapter
input and output are not persisted. Non-2xx responses, transport failure,
missing authentication configuration, invalid response authentication,
timeout, or an unregistered digest produce `unavailable`; malformed or
oversized authenticated responses produce a closed execution error.

## Namespace and lifecycle rules

- Only an evaluation administrator with namespace write access may publish the
  definition or change its availability.
- The definition's exact digest and endpoint are immutable for that version;
  publish a new version to change either one.
- `PutEvaluatorDefinition` lifecycle transitions remain the resolution policy authority. Disabling
  or superseding a definition blocks new plans and manifests but preserves
  historical references and receipts.
- Adapter registrations are keyed by the immutable `(namespace,
  definition_digest)` binding and retain the implementation digest and exact
  endpoint. The same implementation digest may be deployed for multiple
  definitions or namespaces without sharing endpoint mappings.
- Capability discovery must be treated as advisory. Execution rechecks the
  live definition, availability, digest, limits, and adapter registry before
  invocation and fails closed on any mismatch.

The adapter boundary therefore adds domain variability without making Chisei a
tenant code loader, generic workflow engine, or second receipt authority.
