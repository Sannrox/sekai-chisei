# ADR 0116: Discover governed Action types through the native capability catalog

- Status: accepted
- Date: 2026-10-18
- Owners: @Sannrox
- Discussion: none; decided in the implementation pull request for #1459
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1459
- Supersedes: none
- Superseded by: none
- Related: [ADR 0019](0019-dual-capability-catalogs.md)

## Context

`DiscoverCapabilities` already returns namespace-visible object queries and
fixed retrieval surfaces, with a content digest and `ABORTED` on a stale
snapshot. Agent runners still hard-code Action tool lists. A new governed
Action type is invisible until someone wires it; a revoked permission can
leave a stale tool behind. A second discovery RPC, a stream, or an MCP tool
per Action type would duplicate the catalog contract.

## Decision

1. **Extend the existing catalog.** Enabled governed Action types appear as
   `sekai.actions.{type_id}` on the **core** pack. Each entry copies the
   type's `parameter_schema_json`, description, and selected `action_version`
   (last enabled row in type_id/version order). It lists visible markings from
   the bound object kind after restricted-property redaction, and sets
   `approval_behavior` from the same `submit_action_instance` decision submit
   admission uses.
2. **Filter by live permissions.** Discovery omits a type when it is disabled,
   binds a reserved or ACL-hidden object kind, submit admission is Deny, or a
   per-type action-policy override is Deny. A per-type Allow does not restore
   a submit-denied type. Callers who cannot query restricted properties also
   omit a type whose parameter schema names those properties. In a
   team-managed namespace, Action entries require the same Editor or Admin
   membership submit uses. A service principal only sees types in its
   registered `action_types` scope. Discover-only enterprise sessions keep
   object queries and omit Action entries. Visibility is not a grant. Direct submit without
   catalog headers keeps the existing `submit_action_instance` policy path.
3. **Recheck catalog-bound submit.** `SubmitActionInstance` with
   `x-sekai-capability` equal to `sekai.actions.{type_id}` rebuilds the live
   catalog and fails closed when the named entry is absent or the request
   version is not the advertised `action_version`. Direct submit without
   that header, and MCP v1 `sekai.actions.submit` when that name is not the
   native type entry, keep the existing submit path.
4. **Carry the published ontology digest.** `ontology_revision` is the
   published definition revision digest the caller may read. Empty means none
   published or the caller cannot see it. `catalog_version` includes that
   digest so a revision or permission change ABORTs a pinned snapshot.
5. **Leave MCP v1 as an allowlist.** The native catalog is the Action-type
   source. MCP v1 keeps its fixed ten tools.

## Alternatives considered

- A new Action-discovery RPC or stream: would fork pagination, snapshot, and
  cache-scope rules already on `DiscoverCapabilities`.
- One MCP tool per Action type: MCP v1 is a hard-coded allowlist; growing it
  per type would reintroduce the drift this issue removes.
- Treating a cached catalog entry as a grant: contradicts the existing catalog
  contract and would fail open after revoke.

## Consequences

Agent runners can build a tool list from `DiscoverCapabilities` at session
start and on `ABORTED`. Invoke still rechecks. Hidden types, properties, and
markings stay off the catalog. Direct Action RPCs keep their existing policy
path.

## Validation

Focused tests: a published type is listed only for a permitted principal with
schema, description, and markings; a type-level deny omits it and
catalog-bound submit fails closed; schema ACL and restricted classifications
are not revealed to unprivileged callers.
