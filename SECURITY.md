# Security Policy

## Supported versions

`sekai-chisei` is pre-1.0. Security fixes target the current `main` line; older
commits and prerelease snapshots do not receive separate security support.

| Version | Supported |
| --- | --- |
| Current `main` | Yes |
| Older commits and snapshots | No |

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
`authorization: Bearer <token>`. Keep `SEKAI_AUTH_TOKEN` as a deprecated fallback that maps to principal `root`.
`0.0.0.0` requires TLS (`SEKAI_TLS_CERT` + `SEKAI_TLS_KEY`) unless
`SEKAI_ALLOW_PLAINTEXT=1` is explicitly set.
On localhost socket paths and `SEKAI_INSECURE=1`, callers rely on local
transport trust and may assert `x-principal` headers for compatibility. Protect
the socket directory and do not treat this header as a network authentication
mechanism.

Do not commit:

- `data/*.db`
- `.env` files
- API keys
- bearer tokens
- local logs
- private keys
