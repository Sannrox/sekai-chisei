# Security Policy

## Supported Versions

`sekai-chisei` is pre-1.0. Security fixes are expected to target the current `main` branch.

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

For network-accessible deployments, set `SEKAI_AUTH_TOKEN` and send gRPC metadata using `authorization: Bearer <token>`.

Do not commit:

- `data/*.db`
- `.env` files
- API keys
- bearer tokens
- local logs
- private keys
