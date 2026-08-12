# Security Policy

## Supported versions

Security fixes target the current 1.x release line and `main`. Pre-1.0 releases
and older snapshots do not receive separate security support.

| Version | Supported |
| --- | --- |
| Current 1.x | Yes |
| Current `main` | Yes |
| Pre-1.0 and older snapshots | No |

## Reporting a vulnerability

Please report security vulnerabilities **privately** via GitHub's private
vulnerability reporting: open the
[Security tab](https://github.com/Sannrox/sekai-chisei/security/advisories/new)
and click **"Report a vulnerability"**. This keeps the report confidential
until a fix is available.

Do not open public issues or pull requests for exploitable vulnerabilities.

When reporting a vulnerability, include:

- affected commit or version
- steps to reproduce
- expected impact
- whether credentials, local data, or network exposure are involved

Maintainers will use the private advisory to coordinate reproduction, impact
assessment, remediation, and disclosure. Do not include real credentials or
unredacted sensitive user data in a report.

## Deployment notes

`SEKAI_INSECURE=1` is for local development only. It disables authentication
and defaults the server bind to `127.0.0.1`, but an explicit `SEKAI_BIND`
overrides that default. Never expose insecure mode on a non-loopback address.

For network-accessible deployments, issue principal-scoped credentials with
`cargo run --bin sekaictl -- admin access credential create <principal>` and send gRPC metadata using
`authorization: Bearer <token>`. Client processes may read that value from
`SEKAI_CREDENTIAL`; the server does not accept an environment bootstrap token.
`0.0.0.0` requires TLS (`SEKAI_TLS_CERT` + `SEKAI_TLS_KEY`) unless
`SEKAI_ALLOW_PLAINTEXT=1` is explicitly set.
`SEKAI_INSECURE=1` TCP trusts local transport and forces the caller principal to
`local` (client `x-principal` is ignored). The default Unix socket
(`SEKAI_SOCKET`) uses the same forced-`local` identity when no bearer token is
present; bearer credentials still overwrite the principal from the credential
store. Protect the socket path and its directory (the server sets socket mode
`0600`) and never treat client-supplied `x-principal` as authentication.

Do not commit:

- `data/*.db`
- `.env` files
- API keys
- bearer tokens
- local logs
- private keys
