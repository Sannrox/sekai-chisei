# Available models

Sekai Chisei exposes one compact view of the models that the current governed
availability snapshot permits routing to. Lifecycle-disabled and otherwise
unroutable models are absent. The view contains provider and model identifiers,
lifecycle state, and capability or pricing metadata when the provider registry
supplies it; it never contains provider credentials or discovery authentication
material.

The CLI renders a table by default:

```bash
sekaictl models list
sekaictl models list --provider openai
sekaictl models list --json
```

`CHISEI_NAMESPACE` selects the namespace and defaults to `default`.
`CHISEI_GRPC_URL` or `SEKAI_SOCKET` selects the control-plane endpoint. The
equivalent explicit options are `--namespace` and `--target`.

Native clients call `ChiseiService.GetEffectivePolicySummary` with a namespace and an
optional provider. The RPC requires an authenticated principal with read access
to the namespace.

Gateway clients use `GET /v1/chisei/models`; an optional `provider` query
parameter filters the result. This route uses the gateway's existing
authentication and caller scope. It is distinct from the upstream-compatible
`GET /v1/models` passthrough and from the larger
`GET /v1/chisei/capabilities` matrix.

All three surfaces use the versioned `chisei.available-models/v1` projection and
sort records by provider and canonical model identifier.
