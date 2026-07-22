# Enterprise identity extension contract

The public crate defines `sekai.identity-extension/v1` as a backend-neutral
composition boundary. It is an interface for a separately distributed identity
implementation, not an OAuth or OpenID Connect server in the community binary.

## Authority model

An extension validates a human session or access credential and returns one
`AuthenticatedContext`. The context binds the principal, credential kind,
optional tenant, scopes, issuer, protected resource, and expiry. HTTP and gRPC
normalize authenticated callers to this type. Caller-provided principal or
tenant headers are removed or ignored and cannot select authority.

Human credentials use the session, authorization-code, PKCE, exchange, expiry,
and revocation lifecycle. Static community credentials and gateway keys use the
machine credential kind and keep their existing rotation and revocation
lifecycle. Both produce the same internal context without making their issuance
semantics interchangeable. `SEKAI_AUTH_TOKEN` remains the local compatibility
credential and does not activate enterprise identity behavior.

Implementations must validate state, nonce, exact redirect URI, issuer,
audience/resource, PKCE, expiry, single-use authorization codes, credential
revocation, current membership, and current tenant status on the relevant
operation. A missing, unsupported, or invalid contract version fails closed;
there is no negotiation fallback to an older authority model.

## Discovery metadata

The contract can describe RFC 8414 authorization-server metadata and RFC 9728
protected-resource metadata. It deliberately does not register corresponding
HTTP routes. An enterprise distribution owns endpoint routing, TLS, persistence,
client registration, and concrete protocol compliance.

## Secret handling

Credential-bearing values use `SecretValue`, whose debug representation is
redacted and which is not serializable. Implementations must not place bearer
tokens, authorization codes, verifiers, session secrets, cookies, or raw
credential-bearing metadata in logs, graph facts, audit payloads, metrics,
traces, errors, or diagnostics. Stable opaque credential identifiers may be
used for attribution and revocation checks.

## Compatibility

Adopting `v1` requires an implementation to provide `authenticate_context`;
there is no compatibility adapter that guesses scopes or expiry from the older
principal-only hook. Adding optional methods within `v1` is allowed when their
default is fail-closed/unavailable. Changing field meaning, validation
requirements, or authority derivation requires a new contract version. The community SQLite
runtime installs no extension, stores no enterprise sessions or OAuth state,
exposes no identity discovery/session/authorization/token/revocation endpoint,
and accepts no configuration that enables one.
