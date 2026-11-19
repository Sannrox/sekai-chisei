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

`SEKAI_INSECURE=1` disables token authentication, forces the caller principal to
`local` (a client `x-principal` header is ignored), and defaults TCP to `127.0.0.1`. An explicit
`SEKAI_BIND` overrides that loopback default. Never combine insecure mode with
a non-loopback bind; use it only for trusted local development.

### Authenticated TCP

Create a principal-scoped credential:

```bash
cargo run -p sekaictl -- admin access credential create <principal>
```

Clients send the returned value as `authorization: Bearer <token>`. Rotate or
revoke it with:

```bash
cargo run -p sekaictl -- admin access credential rotate <principal>
cargo run -p sekaictl -- admin access credential revoke <principal>
```

Authenticated TCP infers a `0.0.0.0` bind when `SEKAI_BIND` is unset. Public
binds require `SEKAI_TLS_CERT` and `SEKAI_TLS_KEY` unless the operator explicitly
sets `SEKAI_ALLOW_PLAINTEXT=1`. Set `SEKAI_BIND` when the inferred address is not
appropriate. Set `SEKAI_TLS_CLIENT_CA` to a client CA PEM to require a client
certificate on that TLS listener; missing or unreadable files fail closed at
startup. Unset keeps server-TLS-only. Pair the cutover so callers present a
certificate before the server requires one.

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
  `sekai_object_log_ingest_backlog` counts admitted objects whose object-log
  ingest has not completed yet; every Sekai replica drains it about every ten
  seconds. A backlog that keeps growing means the object log is unreachable
  or refusing records; the error log names each failed operation.
- `/console/*` is the authenticated operator shell (principal Bearer login,
  HttpOnly session cookie, namespace context). It always fails closed without a
  valid session. After failover onto a replica that did not mint the cookie,
  re-authenticate. See [operator-console.md](operator-console.md) for local,
  TLS, and multi-replica paths.

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

Each model call, native or through the gateway, exports one `client` span
named `chat {model}` under the inbound trace. It carries the GenAI
attributes below and `sekai.operation_id` when the caller supplied one. It
never carries prompts, completions, tool arguments, evidence, or provider
error messages; outcome values that are not short tokens are reported as
`other`.

| Attribute | Value |
| --- | --- |
| `gen_ai.operation.name` | `chat` |
| `gen_ai.provider.name` | route provider id (`x_ai` for `xai`) |
| `gen_ai.request.model` | upstream model id sent to the provider |
| `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` | provider-reported counts |
| `gen_ai.response.finish_reasons` | provider stop reason |
| `error.type` | failure class: `precondition`, `unavailable`, `upstream_error`, or the gateway refusal type |

The response model is not reported: providers' response model fields are not
parsed today.

Inside a request, each stage is one child span named after the stage, with a
`stage` attribute and an `outcome` of `ok`, `refused`, or `failed`; a stage
that did not end `ok` also sets the span status to error. Stage spans carry no
object ids, namespaces, content, or digests. A refused request shows the stage
that refused it.

| Stage | Covers |
| --- | --- |
| `authorization` | namespace access for a model call; Action submission authorization, catalog capability, tenant, and service-principal checks |
| `policy_decision` | effective model-call policy, impact routing, and context admission; Action policy resolution and decision |
| `budget` | model-call budget reservation; Action budget checks |
| `routing` | model and route selection for a model call |
| `evaluation_step` | one evaluation graph node |
| `stochastic_trial` | one stochastic evaluator trial |
| `outbound_call` | an external evaluator request |
| `persistence` | one store connection checkout inside a request; the span lasts while the connection is held, and its outcome reports the checkout only. Background work outside a request opens none. |

`authorization`, `policy_decision`, and `budget` record errors as `refused`;
the other stages record them as `failed`. A server-side fault (internal,
unavailable, deadline) is `failed` at every stage.

Each background pass that handled work, failed, or found its work held by
another instance exports one root span named after its job kind:
`embedding_catch_up`, `search_catch_up`, `admission_reconcile`, `retention`,
`export_sweep`, `consumer_violation_sweep`, `criticality_outbox`,
`object_log_ingest`, `security_reopen`, `catalog_reconcile`, or
`schedule_tick`. It carries `job.kind`, `job.outcome` (`ok`, `held`, or
`failed`), and `job.items`. A pass with nothing to do exports nothing.
Passes that report no count (`export_sweep`, `security_reopen`,
`catalog_reconcile`) export only when they fail; `schedule_tick` counts the
transform runs it admitted. A pass that worked for recorded operations, such as an
object-log ingest drain or an admission reconciliation, has one child span
per operation (at most 32) carrying `sekai.operation_id`, the key that joins
it to that operation's request trace.

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
`CHISEI_DB_PATH`) plus the object log (`SEKAI_OBJECT_LOG`, default
`<SEKAI_DATA_DIR>/objects.mikura`). A filesystem copy is not safe unless it
includes each database plus its `-wal` and `-shm` sidecars, the object log,
and the log sidecars (`{log}.joins`, `{log}.joins.delta`, `{log}.ckpt`,
`{log}.ckpt.prev`) from one consistent snapshot. Prefer SQLite's
`VACUUM INTO` for an online logical backup of each dest, and copy the object
log with that snapshot. Restore the log together with the databases; a
database without its log is a deployment that never had identity generations,
and a log without its databases cannot rebuild receipts. The retired single
`DB_PATH` refuses boot; relocate an old single file first.

A deployment that ran without a log is backfilled once at start from recorded
objects and admitted Action receipts. Killing that backfill and starting
again produces the same log as an uninterrupted run.

Also preserve state files configured for provider registry lifecycle, gateway
usage recovery, and durable receipt, usage, and refusal recovery. Test
restore procedures, not only backup creation.

Retention is opt-in. A fresh store on either backend has no policies, so the
minute tick archives nothing until an operator sets one with
`sekaictl admin retention policy set`. Existing SQLite stores
that already contain the former global defaults (`audit` 365 days, `llm_calls`
90 days, `task_observations` 90 days) keep them; delete those rows with
`sekaictl admin retention policy delete` if they were never intended. When a
policy is set, retention archives into tables in the
operational database ([ADR 0141](decisions/0141-retention-archives-in-database.md)),
so the archive is backed up and replicated with it; size storage for it.
Exporting and pruning archive rows is follow-up, not this command surface.
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
attestations of an erased decision are removed. Audit history, LLM calls, task
observations and content events are archived only once the matching policy is
set. Archive files written by earlier releases are kept as they
are and verify with `SekaiDb::verify_archive`; nothing is imported from them.
Every Sekai plane instance runs a retention tick (ADR 0129): it calls
`archive_retained_records` on a one-minute interval. With no policy it writes
nothing. Replicas do not elect a scheduler; an interrupted run resumes, and two
ticks archive each record once.
`sekaictl admin retention status` reports the effective policies and their
cutoffs, per-dataset archive counts, and the last archive time;
`policy list` prints the same policies; `policy set` and `policy delete`
write them; `dry-run` reports the counts without writing; `run` performs them.
The same commands work on SQLite and PostgreSQL. On PostgreSQL decisions,
attestations, object changes, LLM calls, task observations and content
events are covered (migration 0135 adds the observation `data_class` and
`retention_tombstone` columns). Object changes follow the dataset-wide
`audit` policy on both backends. Expired audit records are archived only after that prefix verifies, on both
backends; a failed check refuses the whole run and names the failure. Idle
ticks with nothing expired skip the walk. `RuntimeDb::verify_ledger` still
reports the full chain on either backend. See
[postgres-sekai-parity.md](postgres-sekai-parity.md).

### Audit export

`SekaiService.ExportNamespaceAudit` (experimental, #2638) pages one
namespace's audit decisions in chain order on SQLite and PostgreSQL. It is
served only when the plane runs with `SEKAI_EXPERIMENTAL_RPCS=1` or is built
with the `experimental-rpcs` Cargo feature. A record belongs to a namespace
when its hashed evidence names it (`namespace`, else `project`).

- Authorization: the caller needs the admin role on that namespace; root and
  the local operator pass. Every page read is recorded as an `audit.export`
  decision in the namespace, so the next page returns it.
- Cursor: opaque, holding the last walked chain position. Pass
  `next_cursor` back to continue. Records are never repeated or skipped,
  including while new decisions are written. The response sets `caught_up`
  once it reaches the ledger head.
- Verification: each record carries `seq`, `prev_hash`, `entry_hash` and the
  exact hashed `evidence_json`, so a reader can recompute its hash. The plane
  checks every chain entry from `verified_from_seq` through
  `verified_through_seq`, including other namespaces' entries, and refuses
  the page with `DATA_LOSS` naming the first seq that does not verify.
- Disclosure: the seq numbers between a namespace's records are other
  namespaces' decisions. A namespace admin learns how many audit decisions
  the whole plane wrote in that span, not their content.
- Archived records: when retention archived decisions past the cursor, or
  before a fresh export, the page sets `archived_through_seq` to the latest
  purge anchor and continues after it. Archived decisions are not served by
  this call.
- Page size: 100 by default, at most 1000. One page walks at most 2000 chain
  entries, so a namespace with few records can get an empty page that is not
  `caught_up`.

`sekaictl admin assurance audit export --namespace <ns> --output <file.jsonl>`
pages until caught up. For each page it appends one `record` line per decision
and then a `checkpoint` line with the cursor and the verified range, and syncs
them together. Rerunning the same command resumes after the last checkpoint
and drops any partial page written after it.

## Gateway safeguards

- Use virtual keys or authenticated passthrough only on a trusted gateway.
- Seed durable virtual keys with `sekaictl admin gateway setup` /
  `sekaictl admin gateway key create`. Control-plane
  `sekaictl admin access credential create`
  tokens are for gRPC principals, not gateway HTTP keys.
- `gateway setup` does not enable models for route admission, which denies
  any model that model review has not enabled. Run
  `sekaictl admin model-review backfill` once after setup to enable the models
  its policies allow, or enable a family with `model-review family-set`.
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
- [ ] Database, object log, and sidecar/state backup restoration has been tested.
- [ ] Logs, receipts, audit records, and metrics have an operator-owned
  retention policy.
- [ ] The ignored provider smoke tests have been run against the intended
  provider profile before release.

See [configuration](configuration.md) for exact environment variables and
[Docker](docker.md) for the container topology.
