# Operations and security

This guide covers the deployment decisions that matter before moving beyond a
trusted local development environment. Read [SECURITY.md](../SECURITY.md) for
private vulnerability reporting.

## Transport modes

### Local Unix socket

The default `SEKAI_SOCKET=./data/sekai.sock` is the preferred local transport.
The server binds the socket with mode `0600`. Keep the socket and database in a
directory accessible only to the operator and intended local clients: socket
filesystem permissions are the trust boundary for unauthenticated local access.

Unauthenticated UDS callers receive the forced transport principal `local`
(client `x-principal` is ignored), matching insecure TCP. Present
`authorization: Bearer <token>` to act as a durable principal. `local` remains
the reserved local-socket administrative principal used for first-run credential
issuance; do not share the socket with untrusted local processes.

### Local insecure TCP

`SEKAI_INSECURE=1` disables token authentication, allows the compatibility
`x-principal` identity header, and defaults TCP to `127.0.0.1`. An explicit
`SEKAI_BIND` overrides that loopback default. Never combine insecure mode with
a non-loopback bind; use it only for trusted local development.

### Authenticated TCP

Create a principal-scoped credential:

```bash
cargo run --bin sekaictl -- admin access credential create <principal>
```

Clients send the returned value as `authorization: Bearer <token>`. Rotate or
revoke it with:

```bash
cargo run --bin sekaictl -- admin access credential rotate <principal>
cargo run --bin sekaictl -- admin access credential revoke <principal>
```

Authenticated TCP infers a `0.0.0.0` bind when `SEKAI_BIND` is unset. Public
binds require `SEKAI_TLS_CERT` and `SEKAI_TLS_KEY` unless the operator explicitly
sets `SEKAI_ALLOW_PLAINTEXT=1`. Set `SEKAI_BIND` when the inferred address is not
appropriate.

The server has no environment-token bootstrap. `SEKAI_CREDENTIAL` is read only
by clients such as `sekaictl` and the gateway after a durable principal-scoped
credential has been created.

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
- `/metrics` exports Prometheus metrics. On a process serving Sekai, each
  scrape also reads the transform work queue gauges from the store; see
  [governed-transforms.md](governed-transforms.md).
- `/console/*` is the authenticated operator shell (principal Bearer login,
  HttpOnly session cookie, namespace context). It always fails closed without a
  valid session. See [operator-console.md](operator-console.md) for local and
  TLS run paths.

Trace export is optional and disabled unless an OTLP endpoint is configured:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

The control plane and gateway export tracing spans through the standard
`tracing` subscriber. The `/metrics` endpoint remains the Prometheus metrics
surface; OpenTelemetry does not replace it. W3C `traceparent`/`tracestate`
context is accepted at trusted HTTP and gRPC boundaries and propagated to the
control plane, but is stripped before requests reach model providers.
Caller-supplied `x-sekai-operation-id` is the cross-plane operation identity
stamped on `sekai.operation_id`, the receipt, and the object-change event;
see [operation-correlation.md](operation-correlation.md). OTLP
headers, provider credentials, request content, and other credential-bearing
values must not be placed in spans or logs. The durable operation receipt and
its digest remain the authoritative operation record; exported traces are
diagnostic only.

The standard gRPC health service is available without the application auth
interceptor so native gRPC probes can call `grpc.health.v1.Health/Check`.

For Kubernetes HTTP probes, set `OPS_BIND=0.0.0.0` only when the kubelet must
reach the pod IP. The Tenkai packaging in `deploy/kubernetes/` does this and
mounts TLS from Secret `sekai-chisei-tls`; see
[kubernetes-minikube.md](kubernetes-minikube.md).

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
`/statusz` exposes live/degraded posture and aggregate circuit and usage
recovery state.

## Persistence and backups

Combined SQLite dest-pair is two WAL databases (`SEKAI_DB_PATH` and
`CHISEI_DB_PATH`). A filesystem copy is not safe unless it includes each
database plus its `-wal` and `-shm` sidecars from one consistent snapshot.
Prefer SQLite's `VACUUM INTO` for an online logical backup of each dest. The
retired single `DB_PATH` refuses boot; relocate an old single file first.

Also preserve state files configured for provider registry lifecycle, gateway
usage recovery, and durable receipt, usage, and refusal recovery. Test
restore procedures, not only backup creation.

Audit history is not purged automatically. Retention archives into tables in
the operational database ([ADR 0141](decisions/0141-retention-archives-in-database.md)),
so the archive is backed up and replicated with it; size storage for it.
`archive_retained_records` moves bounded batches (500 records per dataset per
transaction) until nothing is left, so an interrupted run resumes; its dry run
reports the counts without writing. Archived records are keyed by a SHA-256 of
their dataset and natural key, not by the key itself. Known limit: the hash is
not keyed, so someone holding the archive can confirm a guessed identifier,
even after erasure redacted the payload; the store has no erasure secret to
key it with. Subject erasure reaches archived records by each dataset's
hot-table rule, related objects and content references included: archived
LLM calls and task observations the hot rule would delete are removed,
object changes and content events are rewritten as in the hot tables, and
attestations of an erased decision are removed. Content events are archived only once a `content_events`
policy is set. Archive files written by earlier releases are kept as they
are and verify with `SekaiDb::verify_archive`; nothing is imported from them.
No operator command runs retention yet (#1987). On PostgreSQL LLM calls,
task observations and content events are covered so far (migration 0135
adds the observation `data_class` and `retention_tombstone` columns); audit
records and object changes follow. See
[postgres-sekai-parity.md](postgres-sekai-parity.md).

## Gateway safeguards

- Use virtual keys or authenticated passthrough only on a trusted gateway.
- Seed durable virtual keys with `sekaictl admin gateway setup` /
  `sekaictl admin gateway key create`. Control-plane
  `sekaictl admin access credential create`
  tokens are for gRPC principals, not gateway HTTP keys.
- Any non-loopback `GATEWAY_BIND` **requires** at least one authenticated
  `GATEWAY_KEYS` entry and must not enable `CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH`.
  Startup fails closed if those gates are missing.
- Set `CHISEI_GRPC_URL` or `SEKAI_SOCKET`; gateway startup fails without a
  control-plane target and every provider request requires live admission.
- Protect the admin refresh endpoint with a random
  `CHISEI_GATEWAY_ADMIN_TOKEN` of at least 32 bytes; it is disabled when unset.
- Keep the durable recovery spool writable. Its default path is
  `data/chisei-gateway-recovery.jsonl` relative to process CWD. The configured
  byte limit is a hard capacity rather than rotation: replay or safely archive
  processed records before it fills, because new recovery records are refused
  at capacity.
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
