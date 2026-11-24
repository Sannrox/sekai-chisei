# ADR 0160: Generated ontology clients target the HTTP projection with a forwarded revision pin

- Status: accepted
- Date: 2026-11-24
- Owners: @Sannrox
- Discussion: none — resolved in https://github.com/Sannrox/sekai-chisei/issues/3269
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3269 (#3269)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0033](0033-revision-pinned-typescript-ontology-clients.md),
  [ADR 0040](0040-revision-pinned-python-ontology-clients.md),
  [ADR 0066](0066-object-set-evaluate.md),
  [ADR 0075](0075-http-ontology-projection.md)

## Context

Revision-pinned ontology clients (#3228) need an HTTP target on the plane
itself, with a bearer token supplied at runtime and the revision pin of
ADR 0033 and ADR 0040.

ADR 0075 already makes HTTP/JSON a generated projection of `stable` gRPC and
requires revision binding to be the same on every transport. The plane serves
that projection as `sekai.http-projection/v1` (`POST /{service}/{method}`,
proto3 JSON bodies), and every call a generated ontology client needs is
`stable`: `GetObject`, `ListObjects`, `CreateObject`, `UpdateObject`,
`DeleteObject`, `FindByProperty`, `Traverse`, `EvaluateObjectSet`,
`SubmitActionInstance`, and `GetPublishedDefinitionRevision`.

Two gaps break ADR 0075's revision rule:

- The projection forwards a fixed header list that omits
  `x-sekai-definition-revision`, so object reads and mutations over HTTP never
  see the pin they check on gRPC.
- `SubmitActionInstance` does not read the pin header on any transport. Its
  `ontology_digest` body field is a receipt binding, not a check.

## Decision

1. The HTTP object API for generated ontology clients is the existing
   `sekai.http-projection/v1` projection. No new routes, path parameters, or
   resource model.
2. The projection forwards `x-sekai-definition-revision`, so a pinned call
   checks its pin the same way on HTTP and gRPC. A request without the header
   behaves as today.
3. `SubmitActionInstance` honors `x-sekai-definition-revision` as object
   mutations do: when the header is present and differs from the namespace's
   live published revision, the call fails closed with the same stale-pin
   `FAILED_PRECONDITION`. Without the header, behavior is unchanged.
4. `EvaluateObjectSet` keeps its in-body pin (`ObjectSetDescriptor`
   `definition_digest`, ADR 0066); a generated client sets it to the pinned
   digest.
5. Authentication is the bearer `authorization` header the projection already
   forwards, supplied by the application at runtime. Nothing is embedded in the
   generated package.

## Alternatives considered

- A resource-style REST contract (for example per-namespace object paths).
  Rejected: a second resource model, which ADR 0075 rejected.
- A caller-supplied route shape per gateway. Rejected: the pin's meaning would
  depend on each gateway.
- Pinning `SubmitActionInstance` through its `ontology_digest` body field.
  Rejected: it is a receipt binding today, and failing closed on it would
  change behavior for existing callers that set it.

## Consequences

The changes are additive: one more forwarded header on
`sekai.http-projection/v1` and an opt-in pin check on one stable call. No
proto change. Revision pins fail closed on every transport.

Generated ontology clients work only against planes that serve the HTTP
projection (`SEKAI_HTTP_PORT`), and only for stable calls, because experimental
calls are refused on HTTP by default. TLS terminates in front of the listener,
as today. A gateway in front of the plane forwards these paths and headers
unchanged; it does not own a route shape.

#3228 implements the forwarding, the `SubmitActionInstance` check, and the
generator target.

## Validation

A pinned `GetObject` and `SubmitActionInstance` with a stale
`x-sekai-definition-revision` fail with the same stale-pin error over gRPC and
HTTP, and succeed with the live digest. The same calls without the header keep
their current outcome. A generated client package contains no credential.
