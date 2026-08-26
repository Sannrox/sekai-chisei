# Revision-pinned TypeScript ontology clients

Generate a **typed TypeScript package** from a **selected** subset of one
published definition revision. The package pins that digest and the selected
object, link, action, and function identities. It never embeds credentials.

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
   `sekai_chisei::ontology_codegen::generate_ontology_typescript_client`.
4. Authenticate with a principal credential held by the host. Do not copy
   secrets into the generated package.
5. Invoke through native gRPC and attach `nativeMetadata`. When
   `x-sekai-definition-revision` is present, object query and mutation RPCs
   compare it to the live published digest and fail closed on mismatch.
   Requests that omit the header keep current behavior. `bindLiveRevision`
   is the matching client-side check.

## Fail-closed rules

- Generation requires a published revision whose digest equals the pin.
- Unknown or hidden members fail as unavailable and do not disclose the rest
  of the catalog.
- Selections outside an optional envelope fail as excessive scope.
- Unsupported member kinds (`control`, unpublished catalogs), unknown
  schema dialects, and non-ASCII identities that cannot appear in native
  gRPC metadata fail without treating discovery as a grant.
- Selected members use the same `properties` and `required` fields as other
  definition documents. Generated interfaces keep the published property
  keys so invocation payloads match the pinned revision. Type or method name
  collisions fail as an invalid definition.
- `verify_ontology_client_package` requires a trusted expected digest and
  rejects a tampered TypeScript or scope payload.
- Releases are superseded. A new digest is a new package.

## Golden test

`tests/fixtures/ontology_codegen/scoped_client.v1.ts` is the CI golden for a
fixed published revision and explicit four-kind selection.

## Non-goals

- Embedding credentials or treating generation as a runtime grant
- Mixing the HTTP provider-profile matrix into the native client
- Replacing gRPC as the system of record
- Silently replacing a published package at the same digest
