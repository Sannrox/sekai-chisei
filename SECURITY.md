# Security Policy

## Supported Versions

`sekai-chisei` is pre-1.0. Security fixes are expected to target the current `main` branch.

## Reporting A Vulnerability

This repository does not yet have a public security contact configured. Until one is added, do not disclose exploitable issues publicly.

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
