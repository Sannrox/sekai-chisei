# Namespace-scoped capability codegen (#299)

## Purpose

Generate a **typed client** for a **selected** subset of a namespace capability
catalog, pin the catalog revision, and pair the output with a scope manifest
that credentials must not exceed.

## Generate → authenticate → invoke

1. **Discover** the live **native** catalog with `DiscoverCapabilities` for the
   authenticated principal and namespace (see `docs/capability-catalog.md`).
   Do not use `GET /v1/chisei/capabilities`; that HTTP document is the
   provider-profile matrix `chisei.provider-capabilities/v1`.
2. **Project** entries with `capability_projection` (or export the same JSON
   contract).
3. **Select** capability names the client is allowed to call.
4. **Generate** TypeScript via `sekai_chisei::capability_codegen::generate_typescript_client`.
5. **Authenticate** with a principal credential; do not embed secrets in the
   generated client.
6. **Invoke** through native gRPC using `nativeMetadata` headers. The server
   re-checks catalog visibility, ACLs, and policy on every call.

## Fail-closed rules

- Empty selection is rejected.
- Optional `catalog_version_pin` must equal the selection context version.
- Selected names missing from the catalog fail generation.
- Generated `scopeAllows` / `ALLOWED_CAPABILITIES` refuse non-selected names
  client-side; server still re-authorizes.

## Golden test

`tests/fixtures/capability_codegen/scoped_client.v1.ts` is the CI golden for
API stability on a fixed fixture catalog.

## Non-goals (v1)

- Full multi-language OSDK surface (Python can wrap the same scope JSON later)
- Replacing gRPC as system of record
- Treating catalog visibility as a runtime grant

Schema-typed object, link, action, and function clients pinned to a published
definition revision are generated separately; see
[ontology-codegen.md](ontology-codegen.md).
