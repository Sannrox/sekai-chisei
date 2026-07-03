# Security Policy

## Supported Versions

`sekai-chisei` is pre-1.0. Security fixes are expected to target the current `main` line.

## Reporting A Vulnerability

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

## Deployment Notes

`SEKAI_INSECURE=1` is for local development only. It disables authentication and binds the server to `127.0.0.1`.

For network-accessible deployments, issue principal-scoped credentials with
`cargo run --bin sekaictl -- credential create <principal>` and send gRPC metadata using
`authorization: Bearer <token>`. Keep `SEKAI_AUTH_TOKEN` as a deprecated fallback that maps to principal `root`.
`0.0.0.0` requires TLS (`SEKAI_TLS_CERT` + `SEKAI_TLS_KEY`) unless
`SEKAI_ALLOW_PLAINTEXT=1` is explicitly set.
On localhost socket paths and `SEKAI_INSECURE=1`, callers are authenticated by local transport and may
assert `x-principal` headers for compatibility.

Do not commit:

- `data/*.db`
- `.env` files
- API keys
- bearer tokens
- local logs
- private keys
