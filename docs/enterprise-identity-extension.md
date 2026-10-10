# Enterprise identity extension contract

The public crate defines `sekai.identity-extension/v2` as a backend-neutral
composition boundary. It is an interface for a separately distributed identity
implementation, not an OAuth or OpenID Connect server in the community binary.

## Authority model

An extension validates a human session or access credential and returns one
`AuthenticatedContext`. The context binds the principal, credential kind,
optional tenant, space, space role, delegating actor (`act`), scopes, issuer, protected resource, and expiry. HTTP and gRPC
normalize authenticated callers to this type. Caller-provided principal or
tenant headers are removed or ignored and cannot select authority.

Human credentials use the session, authorization-code, PKCE, exchange, expiry,
and revocation lifecycle. Static community credentials and gateway keys use the
machine credential kind and keep their existing rotation and revocation
lifecycle. Both produce the same internal context without making their issuance
semantics interchangeable. Community principal credentials do not activate
enterprise identity behavior.

When an enterprise extension is installed, every authenticated context must
include a tenant. Static community or gateway credentials are rejected until
they are replaced or explicitly bound to a tenant by the extension.
Single-tenant community installations without an extension retain their
existing credential behavior.

Implementations must validate state, nonce, exact redirect URI, issuer,
audience/resource, PKCE, expiry, single-use authorization codes, credential
revocation, current membership, and current tenant status on the relevant
operation. A missing, unsupported, or invalid contract version fails closed;
there is no negotiation fallback to an older authority model.

The native model-loop methods `PlanExecution` and `ExecutePlanStream` accept
enterprise machine contexts. They authorize the
complete context for namespace write access, use its principal as the planning
and receipt actor, and ignore caller-supplied principal or tenant metadata.
Invalid context authority is checked before a plan is consumed or an LLM
provider is contacted. Machine contexts require the `chisei.execute` scope at
the Chisei boundary even when an extension uses the default namespace
authorization implementation; human sessions require `sekai.write`. Cached
enterprise plans remain bound to the authenticated tenant (or to the
credential for an unscoped enterprise context), in addition to the principal
subject.

## Space roles and delegation

A signed assertion may carry `space`, `space_role`, and `act`. Absent space
keeps the existing tenant and namespace authorization path. A role requires a
non-empty space; a space requires a role. Roles constrain existing grants:
viewer permits reads, editor permits writes, approver permits approval, and
administrator permits all three. A role does not grant object or namespace
access on its own. Unknown roles and incomplete space authority fail closed.

`act` names one originating actor, distinct from the authenticated subject.
It is attribution, never an additional policy principal or a replacement for
the credential subject. Action admission receipts and audit evidence retain
`act`; model planning receipts retain `act`, space, and role. No bearer secret
is retained. Revalidating delegation at apply and claim remains #1402.

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

GATE:mig: before adopting tenant-required authentication, bind each service
credential to a tenant in extension-owned storage and update clients to use
that credential. Tenant-less assertions must likewise be reissued with a
validated tenant. Community credential storage is not a fallback when the
extension cannot authenticate a token. No graph or protocol migration is
required.

GATE:break: `v2` changes the Rust context shape. Extension implementations must
populate the optional fields and advertise `sekai.identity-extension/v2`.
Older extension versions fail closed. The existing assertion wire version
accepts optional fields additively; assertions without them keep their prior
behavior. No protocol field numbers change.

Adopting the context contract requires an implementation to provide `authenticate_context`;
there is no compatibility adapter that guesses scopes or expiry from the older
principal-only hook. Adding optional methods within `v2` is allowed when their
default is fail-closed/unavailable. Changing field meaning, validation
requirements, or authority derivation requires a new contract version. The community SQLite
runtime installs no extension, stores no enterprise sessions or OAuth state,
exposes no identity discovery/session/authorization/token/revocation endpoint,
and accepts no configuration that enables one.
