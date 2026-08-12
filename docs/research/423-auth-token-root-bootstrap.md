# `SEKAI_AUTH_TOKEN` root-bootstrap retirement

> Historical pre-1.0 research. Version 1.0 removed the server bootstrap and
> uses client-side `SEKAI_CREDENTIAL` with durable principal credentials.

Issue: [#423](https://github.com/Sannrox/sekai-chisei/issues/423)

## Decision

Retain the server-side `SEKAI_AUTH_TOKEN` root-principal bootstrap through
0.2.0. Move its earliest removal deadline to 0.3.0 and do not delete it until
TCP-only deployments have a reviewed administrator bootstrap and recovery
path.

The current guidance to “issue principal credentials via `sekaictl credential
create`” is necessary but not sufficient. That command calls the authenticated
`CreateCredential` gRPC method. Credential administration accepts only the
fixed `root` principal or the local-socket `local` principal, while durable
credential creation rejects the reserved principals `root`, `local`, and
`anonymous`. A TCP-only operator that removes the legacy root token cannot
create, rotate, revoke, or recover credentials with an ordinary durable
principal.

This is a retain-and-stage recommendation, not approval of a new trust model.
Replacing fixed-root administration with roles, an offline bootstrap command,
a one-time credential, or another mechanism requires a Design Discussion.

Before removal, client bearer transport must also stop overloading the same
environment key. Introduce a distinct client-only bearer-token input, migrate
the gateway, CLI helpers, examples, and adapters to it, and retain a bounded
fallback to `SEKAI_AUTH_TOKEN` during the compatibility window. Do not rename
the server bootstrap until a replacement administrator path is accepted;
renaming the same fixed-root authority would only hide the risk.

## Evidence and ownership

| Surface | Current use | Retirement implication |
| --- | --- | --- |
| `Config::from_env` and server startup | Reads `SEKAI_AUTH_TOKEN`, enables authenticated TCP, and warns that the value maps to `root` | This is the server-side compatibility authority that cannot yet be removed |
| `TokenAuthInterceptor` | Resolves durable credential hashes first-class and separately accepts the configured legacy token as `root` | Removal is mechanically small but changes control-plane administration and recovery |
| Credential RPCs and `sekaictl credential` | Create, rotate, revoke, and list over gRPC; only `root` or local-socket `local` is a credential administrator | Ordinary durable principals cannot complete first-run or recovery administration |
| Default local server and `sekaictl launch` | Use UDS local authority; launch provisions `local-onboarding` directly in the selected local database and clears the server legacy token | Local-first onboarding already works without server-side root bootstrap |
| Docker default | Shares the UDS volume between server and gateway and publishes no gRPC TCP port | Default compose does not depend on the root bootstrap |
| Docker TCP example | Configures the same `SEKAI_AUTH_TOKEN` on server and gateway | The value simultaneously grants server authority and transports a client bearer token |
| gRPC connection helpers | Read `SEKAI_AUTH_TOKEN` for HTTP(S) clients and as a UDS gateway fallback | Client transport must gain an explicit replacement before the old key is server-only |
| Launch helper | Clears the key in the server child but passes a durable local token under the same key to the gateway child | The key name is already client-only in this process, proving the overload |
| Examples and adapters | Use the key as bearer-token input; examples also send `x-principal`, which token auth overwrites with the authenticated credential principal | Migration must name the credential token independently and must not imply caller metadata grants identity |
| Operator console | Accepts durable credentials and the legacy root token through the shared token interceptor | Removing the bootstrap also removes fixed-root console recovery |
| Documentation and configuration | Describe both deprecated root bootstrap and ordinary client bearer use | A staged migration must update configuration, Docker, operations, security, examples, and adapters together |

Repository history shows principal-scoped durable credentials, local onboarding,
UDS gateway credentials, and authenticated operator-console support were added
after the original static token. Those additions reduced dependence on the
legacy path but did not replace its TCP administrator authority.

The portable ontology validated successfully but contains no authentication,
credential, principal-administration, or gateway-auth definition. It supplied
no structural claim for this decision.

## Supported deployment flows

### Local UDS

The default server creates a local Unix socket (mode `0600`). Requests without a
bearer token receive forced local transport authority (`x-principal` is
overwritten to `local`), and `sekaictl credential create` defaults to that
socket. This is the supported first-run path for issuing durable
principal-scoped credentials.

The socket and database therefore remain sensitive local operator boundaries.
Removing the legacy TCP root token does not require accepting caller-supplied
principal authority on UDS or over TCP.

### Managed local launch

`sekaictl launch` creates or rotates a `local-onboarding` credential directly
in its selected local database, stores the token in a private local file, starts
the server without a legacy token, and passes the durable credential to the
gateway. The flow is process- and database-local and is not a remote bootstrap
contract.

### Default Docker topology

The checked-in compose topology shares `/data/sekai.sock` and the data volume
between server and gateway. It needs no TCP credential bootstrap. Operators can
issue service credentials over the protected shared socket before switching
clients to authenticated TCP.

### TCP-only deployment

Current documentation places `SEKAI_AUTH_TOKEN` on both server and gateway.
That starts the server with fixed-root authority and lets the gateway send the
same value as a bearer token. Existing durable credentials activate
authenticated TCP, but they cannot administer credential lifecycle unless the
operator retains local-socket access.

Consequently, a safe TCP-only migration must define both first-run issuance and
lost/revoked-administrator recovery. “Create a credential before restart” is
not enough because the created principal lacks credential-admin authority.

## Migration sequence

1. **0.2.0 — retain and clarify.** Keep the server-side compatibility token and
   its runtime warning. Document UDS as the preferred bootstrap and recovery
   boundary. Treat the fixed-root token as break-glass compatibility, not the
   normal client credential.
2. **Add a client-only token input.** After a focused implementation Issue,
   make gRPC clients, gateway setup/reporting, launch, examples, and adapters
   prefer a distinctly named bearer-token variable. During one compatibility
   window, fall back to `SEKAI_AUTH_TOKEN` with a bounded warning. Never log
   either value.
3. **Resolve administrator authority.** Use a Design Discussion to choose and
   threat-model a durable administrator role, offline local bootstrap, one-time
   enrollment, or another explicit mechanism. Cover SQLite, PostgreSQL,
   TCP-only containers, rotation, revocation, backup restore, and loss of all
   administrator credentials.
4. **Prove migration and rollback.** Add deterministic tests that start with
   only the replacement bootstrap, issue and rotate principal credentials,
   restart, revoke administrator access, and exercise the documented recovery
   path. Confirm missing or invalid authority fails closed and contacts no
   protected RPC.
5. **0.3.0 earliest removal.** Remove server parsing, fixed-root token
   resolution, console fallback, Docker/server examples, warning text, and the
   compatibility record only after the replacement is shipped and the
   client-variable fallback window has completed.

Rollback before step 5 is to restore the prior server version and the existing
legacy token from the deployment secret store. Rollback must not reuse a
revoked durable credential or place token material in command history, logs,
fixtures, or research artifacts.

## Required follow-up scope

No follow-up Issue is created by this research delivery because Issue creation
requires separate maintainer authority. The smallest future work items are:

1. a Design Discussion for administrator bootstrap, recovery, and least-
   privilege credential lifecycle authority; and
2. after that direction is accepted, one focused compatibility Issue for the
   client-only bearer-token input and one removal Issue for the server root
   bootstrap, documentation, configuration, and migration checks.

The removal Issue must assert that caller metadata never constructs authority,
authenticated network startup fails closed, local insecure mode remains
loopback-only, token values stay out of observability and fixtures, and both
SQLite and implemented PostgreSQL credential paths preserve rotation and
revocation behavior.

## Revisit criteria

Reconsider removal when all of the following are true:

- the administrator bootstrap and recovery design is accepted;
- at least one supported TCP-only deployment can initialize and recover without
  the fixed-root token;
- every maintained client surface has a distinct bearer-token input;
- migration and rollback tests cover fresh and existing deployments;
- the compatibility register and maintained docs agree on the release window;
  and
- security review finds no path where caller metadata or an ordinary service
  credential acquires implicit control-plane administration.
