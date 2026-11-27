# Revision-pinned TypeScript and Python ontology clients

Generate a **typed TypeScript or Python package** from a **selected** subset
of one published definition revision. The package pins that digest and the
selected object, link, action, and function identities. It never embeds
credentials.

Capability codegen ([capability-codegen.md](capability-codegen.md)) still
covers selected native catalog methods. This generator covers schema-typed
ontology members from `sekai.definition-revision/v1`.

## Generate → authenticate → invoke

1. Read the published revision with `GetPublishedDefinitionRevision` and the
   authorized bodies for the selected members. Unselected or hidden member
   bodies are not required and must not be requested as a catalog dump.
2. Select object, link, action, and function member identities the client may
   name. Empty selection is rejected.
3. Generate TypeScript via
   `sekai_chisei::ontology_codegen::generate_ontology_typescript_client` or
   Python via
   `sekai_chisei::ontology_codegen::generate_ontology_python_client`. For an
   application that reaches the plane over HTTP, generate the HTTP target with
   `generate_ontology_typescript_http_client` or
   `generate_ontology_python_http_client`. All four share the same selection,
   scope, typed surface, and fail-closed errors.
4. Authenticate with a principal credential held by the host. Do not copy
   secrets into the generated package.
5. Invoke through native gRPC and attach `nativeMetadata` /
   `native_metadata`. When `x-sekai-definition-revision` is present, object
   query and mutation RPCs and `SubmitActionInstance` compare it to the live
   published digest and fail closed on mismatch. Requests that omit the header
   keep current behavior. `bindLiveRevision` / `bind_live_revision` is the
   matching client-side check.

### HTTP target

The HTTP target ([ADR 0160](decisions/0160-generated-ontology-clients-target-the-http-projection.md))
calls the plane's `sekai.http-projection/v1` listener (`SEKAI_HTTP_PORT`,
[ADR 0075](decisions/0075-http-ontology-projection.md)); there is no separate
route contract. It exports `GENERATED_TRANSPORT` and replaces the native
metadata helper with `httpHeaders` / `http_headers`, which returns the
namespace, revision pin, and operation id headers for a
`POST /{service}/{method}` request. The projection forwards the pin, so the
same stale-pin failure applies on HTTP as on gRPC.

- The application adds `authorization: Bearer <token>` at call time. The
  generated HTTP package depends on the published runtime
  (`@sannrox/sekai-chisei-sdk` / `sekai-chisei-sdk`, today's HTTP helper) and
  makes `EvaluateObjectSet` and `SubmitActionInstance` itself. Object-set
  descriptors type filters on declared properties and selected link
  traversals; Action parameters use the generated Action type.
- `EvaluateObjectSet` pins in the request body: the generated client sets the
  descriptor's `definitionDigest` to `GENERATED_REVISION_DIGEST`.
- Only stable calls are hosted on HTTP; experimental calls are refused.

## Fail-closed rules

- Generation requires a published revision whose digest equals the pin.
- Unknown or hidden members fail as unavailable and do not disclose the rest
  of the catalog.
- Selections outside an optional envelope fail as excessive scope.
- Unsupported member kinds (`control`, unpublished catalogs), unknown
  schema dialects, and non-ASCII identities that cannot appear in native
  gRPC metadata fail without treating discovery as a grant.
- Selected members use the same `properties` and `required` fields as other
  definition documents. Generated types keep the published property keys so
  invocation payloads match the pinned revision. Type or method name
  collisions fail as an invalid definition. Python emits a class `TypedDict`
  when every key is a safe identifier; otherwise it uses the functional
  `TypedDict("Name", { ... })` form so hyphenated or reserved keys stay on
  the wire.
- `verify_ontology_client_package` and
  `verify_ontology_python_client_package` each require a trusted expected
  digest and reject a tampered source or scope payload. Digests are
  language-specific.
- Releases are superseded. A new digest is a new package.

## Golden tests

`tests/fixtures/ontology_codegen/scoped_client.v1.ts` and
`tests/fixtures/ontology_codegen/scoped_client.v1.py` are the CI goldens for
the same published revision and explicit four-kind selection.
`scoped_http_client.v1.ts` and `scoped_http_client.v1.py` are the HTTP-target
goldens for that selection. Those packages declare a versioned dependency on
the HTTP runtime (`ontology_http_package_json` / `ontology_http_pyproject`).
`compile_check.ts` is an application built on the earlier native output;
`compile_check_http.ts` is an application that depends only on the generated
HTTP package.

## Non-goals

- Embedding credentials or treating generation as a runtime grant
- Mixing the HTTP provider-profile matrix into the native client
- Replacing gRPC as the system of record
- Silently replacing a published package at the same digest
- Replacing the hand-written `sdk/python` facade
