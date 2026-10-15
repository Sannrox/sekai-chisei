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
is retained. Claim of `runtime_dispatch` work, apply of claimed action work, and
planned execution re-validate the `act` retained on the admitted instance or
planning receipt against current enablement, tenant membership, and the grant
the work needs. Claim fails closed with `delegator_disabled`,
`delegator_not_member`, or `delegator_grant_missing` before the worker receives
a fence. Apply records those reasons, or `delegator_record_missing`, on the
receipt. A missing planning receipt, action effect, or action instance fails
closed at apply. The runtime-claim client surfaces the `delegator_*` tokens
instead of collapsing them to contention or fence loss.

## Service-principal issuance

`issue_service_principal_token` is an optional `v2` method. The default is
unavailable. Core looks up a tenant-bound service-principal registration
(#1508) first, then asks the extension to verify client credentials it owns.
A successful grant is a service identity, never a user identity. Core signs
and verifies the resulting token with the plane assertion key (#1507 / #1510).
Implementations must not log or persist `client_secret`.

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

## Guests: home and acting tenant

`tenant` is the acting tenant: the tenant whose namespaces a context
addresses. `home_tenant` names the principal's own tenant when it differs; a
context with a non-empty `home_tenant` other than the acting tenant is a
guest. A home tenant without a non-empty acting tenant, or an empty home
tenant, fails closed. Same-tenant contexts leave `home_tenant` unset and keep
today's behavior.

Guests are denied by default (#1432). Core admits a guest only on the
namespace object RPCs that make a per-namespace decision (get, list, create,
update, delete object), and there only when the installed extension's
`authorize_guest_namespace` returns a host grant for that namespace. Its
default is `PermissionDenied`, and core calls it directly, so an overridden
`authorize_authenticated_context` cannot admit a guest by accident. Guests
never approve.

The extension owns guest membership: who the host tenant admitted, by which
host administrator, and when it was revoked (#1433). It returns a
`GuestGrant` with the host-chosen `role` and `marking_ceiling`; core enforces
both. Discover needs any role, read a viewer role or above, write an editor
or administrator. An object whose `access_marking` the ceiling does not
cover, or whose token is unknown, is missing to the guest on get, excluded
from list results and totals, and refused on create, update, and delete, even
when the guest's own profile allows more. Coverage uses the namespace's
activated classification lattice when one exists, otherwise the default
evidence ordinal. Core asks for the grant on every request and caches
nothing, so a revoked or narrowed grant applies to the next request. An RPC
added to the guest allowlist must apply the same ceiling check. Without an
extension a guest is always denied. Every guest decision, allowed or denied,
is audited as `tenant.guest_access` with the principal, home tenant, acting
tenant, space, the namespace (or the RPC, when the interceptor rejects it
first), and the operation. Ceiling denials use operation `ceiling` and the
object id. A denied guest read looks like a missing object.

## Discovery

An administrator-approved discovery rule names which tenants, principals,
spaces, and namespaces another tenant may find (#1435). Finding a name is
not a read. Without a rule, cross-tenant list and lookup look the same as a
missing target. The extension returns `authorize_discovery`: `Ok(None)` is
no rule, `Ok(Some(rule))` names the exposed targets at discover level only,
and `Err` is a withdrawn or one-sided rule. Core asks on every discover
request and caches nothing, so a withdrawn or narrowed rule applies to the
next request.

A rule never grants read or write. Guests still need a host `GuestGrant` for
those actions. `DiscoverCapabilities` is a discover RPC: a denied guest
lookup is `not found`. Every discovery decision is audited as
`tenant.discovery` with the principal, home tenant, owner tenant, space, the
namespace, and the operation.

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

GATE:break: `home_tenant` (#1432) is a new Rust field on the `v2` context.
Extensions that build `AuthenticatedContext` must set it (`None` keeps
same-tenant behavior). No existing field changes meaning, the default guest
hook fails closed, and no protocol field numbers change, so the contract
version stays `v2`.

GATE:break: `authorize_discovery` (#1435) is a new optional `v2` method.
The default is no rule (`Ok(None)`). Extensions that implement it return
the current `DiscoveryRule` or `Err` when the rule is withdrawn. No
existing field changes meaning and no protocol field numbers change, so
the contract version stays `v2`.

Adopting the context contract requires an implementation to provide `authenticate_context`;
there is no compatibility adapter that guesses scopes or expiry from the older
principal-only hook. Adding optional methods within `v2` is allowed when their
default is fail-closed/unavailable. Changing field meaning, validation
requirements, or authority derivation requires a new contract version. The community SQLite
runtime installs no extension, stores no enterprise sessions or OAuth state,
exposes no identity discovery/session/authorization/token/revocation endpoint,
and accepts no configuration that enables one.
