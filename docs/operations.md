# Operations and security

This guide covers the deployment decisions that matter before moving beyond a
trusted local development environment. Read [SECURITY.md](../SECURITY.md) for
private vulnerability reporting.

## Transport modes

### Local Unix socket

The default `SEKAI_SOCKET=./data/sekai.sock` is the preferred local transport.
The socket and database should live in a directory accessible only to the
operator and intended local clients.

### Local insecure TCP

`SEKAI_INSECURE=1` disables token authentication, allows the compatibility
`x-principal` identity header, and defaults TCP to `127.0.0.1`. An explicit
`SEKAI_BIND` overrides that loopback default. Never combine insecure mode with
a non-loopback bind; use it only for trusted local development.

### Authenticated TCP

Create a principal-scoped credential:

```bash
cargo run --bin sekaictl -- credential create <principal>
```

Clients send the returned value as `authorization: Bearer <token>`. Rotate or
revoke it with:

```bash
cargo run --bin sekaictl -- credential rotate <principal>
cargo run --bin sekaictl -- credential revoke <principal>
```

Authenticated TCP infers a `0.0.0.0` bind when `SEKAI_BIND` is unset. Public
binds require `SEKAI_TLS_CERT` and `SEKAI_TLS_KEY` unless the operator explicitly
sets `SEKAI_ALLOW_PLAINTEXT=1`. Set `SEKAI_BIND` when the inferred address is not
appropriate.

`SEKAI_AUTH_TOKEN` is a deprecated compatibility path that maps all callers to
the fixed `root` principal. Do not use it as the long-term credential model.

The community runtime issues only unbound control-plane credentials. Legacy
credential `tenant_id` fields remain wire-compatible but are ignored; caller
metadata and principal naming never activate tenant authority. Enterprise
tenant credentials are created and enforced by the PostgreSQL enterprise
composition through the public extension contracts.

## Observability

The loopback ops listener exposes unauthenticated process endpoints and the
authenticated [operator console](operator-console.md):

```bash
curl --fail http://127.0.0.1:9464/healthz
curl --fail http://127.0.0.1:9464/readyz
curl --fail http://127.0.0.1:9464/metrics
# browser: http://127.0.0.1:9464/console/
```

- `/healthz` reports process health.
- `/readyz` verifies that the service is ready to handle governed work.
- `/metrics` exports Prometheus metrics.
- `/console/*` is the authenticated operator shell (principal Bearer login,
  HttpOnly session cookie, namespace context). It always fails closed without a
  valid session. See [operator-console.md](operator-console.md) for local and
  TLS run paths.

The standard gRPC health service is available without the application auth
interceptor so native gRPC probes can call `grpc.health.v1.Health/Check`.

For Kubernetes HTTP probes, set `OPS_BIND=0.0.0.0` only when the kubelet must
reach the pod IP:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9464
readinessProbe:
  httpGet:
    path: /readyz
    port: 9464
```

The gateway has separate `/healthz`, `/readyz`, and `/statusz` endpoints.
`/statusz` exposes live/degraded posture and aggregate cache, circuit,
reconciliation, and spool counts.

## Persistence and backups

SQLite file databases use WAL mode. A filesystem copy is not safe unless it
includes the database plus its `-wal` and `-shm` sidecars from one consistent
snapshot. Prefer SQLite's `VACUUM INTO` for an online logical backup.

Also preserve state files configured for provider registry lifecycle, gateway
budget reconciliation, and degraded audit spooling. Test restore procedures,
not only backup creation.

Audit history is not purged automatically. High-churn deployments should define
a retention policy and invoke `purge_old_records` with an explicit cutoff.

## Gateway safeguards

- Use virtual keys or authenticated passthrough only on a trusted gateway.
- Seed durable virtual keys with `sekaictl gateway setup` /
  `sekaictl gateway key create`. Control-plane `sekaictl credential create`
  tokens are for gRPC principals, not gateway HTTP keys.
- Any non-loopback `GATEWAY_BIND` **requires** at least one authenticated
  `GATEWAY_KEYS` entry, `GATEWAY_GOVERNANCE_FAILURE=closed`, and must not enable
  `CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH`.
  Startup fails closed if those gates are missing.
- Set `CHISEI_GRPC_URL` or `SEKAI_SOCKET`; gateway startup fails without a
  control-plane target and every provider request requires live admission.
- Set `GATEWAY_GOVERNANCE_FAILURE=closed` on loopback when availability must
  never override governance.
- Protect the admin refresh endpoint with a random
  `CHISEI_GATEWAY_ADMIN_TOKEN` of at least 32 bytes; it is disabled when unset.
- Keep the durable audit spool writable (default
  `data/chisei-gateway-audit.jsonl` relative to process CWD). A fail-open
  decision is refused when it cannot be recorded.
- Treat cross-provider routing as opt-in because request/response translation
  can be lossy. Tool-call streams remain denied where semantics cannot be
  preserved.

## Deployment checklist

- [ ] Insecure mode is disabled.
- [ ] Every service has a distinct principal-scoped credential.
- [ ] Network-accessible control-plane traffic uses TLS.
- [ ] The ops listener is reachable only by intended monitoring systems.
- [ ] Provider secrets come from the process environment or a secrets adapter.
- [ ] Gateway request, rate, context, and spool limits are explicit.
- [ ] The governance failure posture matches the deployment risk model.
- [ ] Database and sidecar/state backup restoration has been tested.
- [ ] Logs, receipts, audit records, and metrics have an operator-owned
  retention policy.
- [ ] The ignored provider smoke tests have been run against the intended
  provider profile before release.

See [configuration](configuration.md) for exact environment variables and
[Docker](docker.md) for the container topology.
