# Operator console

Authenticated browser shell for daily governance work. Implements the hybrid
public-API model from
[research/283-operator-console-ia.md](research/283-operator-console-ia.md)
(Issue [#284](https://github.com/Sannrox/sekai-chisei/issues/284)).

The shell ships in-process on the **ops HTTP listener** (`OPS_BIND` /
`OPS_PORT`). Process health and metrics stay unauthenticated; every `/console`
route fails closed without a valid session.

The read-only shell is an operator convenience surface. Console mutations
(kill switch, dry-run audit, promote, and rollback) are experimental in 1.0;
`sekaictl` remains the canonical stable automation interface.

## Local development

1. Start the control plane with an ops port (default `9464`):

   ```bash
   SEKAI_INSECURE=1 SEKAI_DB_PATH=./data/sekai.db CHISEI_DB_PATH=./data/chisei.db cargo run
   ```

2. Create a principal credential for authenticated access:

   ```bash
   cargo run -p sekaictl -- admin access credential create alice
   # note the printed token; store it like any other API secret
   ```

3. Open the console:

   ```text
   http://127.0.0.1:9464/console/
   ```

4. Paste the principal Bearer token (same value used for gRPC /
   `authorization: Bearer …`). Sign-in sets an **HttpOnly**, **SameSite=Strict**
   session cookie (`sekai_console_sid`). The raw token is never written to
   `localStorage`. A new sign-in replaces any session the browser presented.

5. Select a namespace from the header switcher (or open
   `/console/n/{namespace}/ops` when authorized). Primary nav is keyboard
   reachable (skip link → namespace control → Operations / Transforms /
   Pressure / Policy / Evals).

Unauthenticated visits to `/console/` or any namespaced route redirect to
`/console/login`. Unauthorized namespace paths return **403** without loading
foreign data.

## Production / TLS

| Concern | Guidance |
| --- | --- |
| Bind | Keep `OPS_BIND=127.0.0.1` unless an orchestrator or reverse proxy must reach the process. |
| TLS | Prefer terminating TLS on a reverse proxy in front of the ops port, or run the control plane with `SEKAI_TLS_*` for gRPC and proxy HTTPS to loopback ops. |
| Cookie Secure | The process issues console cookies without the `Secure` flag so loopback HTTP works. When serving the console only over HTTPS, set `Secure` at the proxy (or restrict the console to HTTPS-only hosts). |
| Sign-in origin | `POST /console/login` refuses (403, no cookie) a browser form whose `Origin`, or `Referer` when `Origin` is absent, names another host than the request's `Host` header, or an opaque `null` origin. A reverse proxy must forward the original `Host` header, or browser sign-in is refused. Clients that send neither header still sign in. |
| Credentials | Use principal-scoped tokens. Sessions re-check durable credential status on every request; revocation ends the session. |
| Multi-replica | Sessions are **process-local** ([ADR 0150](decisions/0150-process-local-console-sessions.md)). Pin console traffic to one instance to avoid extra logins. If a request reaches another replica, a rolling restart, or a process that did not mint the cookie, the console fails closed: HTML data routes 303 to `/console/login`, `GET /console/login` returns the sign-in form (200), JSON returns 401, and the session cookie is cleared. Sign in again with the same principal Bearer token. The serving process never renders signed-in chrome for a session it does not hold. |
| Metrics exposure | `/metrics`, `/healthz`, and `/readyz` remain unauthenticated process endpoints. Do not expose the ops port on an untrusted network solely to serve the console. |

Example reverse-proxy sketch (nginx):

```nginx
server {
  listen 443 ssl;
  server_name console.example.com;
  # ssl_certificate …; ssl_certificate_key …;

  location /console/ {
    proxy_pass http://127.0.0.1:9464;
    proxy_set_header Host $host;
    proxy_cookie_path /console /console;
    # Optionally force Secure on the session cookie:
    # proxy_cookie_flags ~ secure httponly samesite=strict;
  }
}
```

## Routes

| Path | Auth | Purpose |
| --- | --- | --- |
| `GET /console/login` | public | Login form |
| `POST /console/login` | public | Exchange token for session cookie |
| `POST /console/logout` | session | Clear session |
| `GET /console/` | session | Shell home + namespace switcher |
| `GET /console/n/{ns}/ops` | session + ns | Recent visible operations (7-day window) |
| `GET /console/n/{ns}/transforms` | session + ns | Governed transform definitions and run receipts |
| `GET /console/n/{ns}/transforms/{run_id}` | session + ns | Single transform run receipt |
| `GET /console/n/{ns}/ops/{operation_id}` | session + ns + receipt ACL | Causal operation workspace |
| `GET /console/api/n/{ns}/ops/{operation_id}` | session + ns + receipt ACL | Authorized report + causal stages JSON |
| `GET /console/n/{ns}/pressure` | session + ns | Governance pressure tiles |
| `GET /console/api/n/{ns}/pressure` | session + ns | Pressure snapshot JSON |
| `POST /console/n/{ns}/pressure/kill-switch` | session + ns write | Experimental Gunshi kill switch with confirm |
| `GET /console/n/{ns}/policy` | session + ns | Policy workspace |
| `POST /console/n/{ns}/policy/dry-run` | session + ns | Experimental historical dry-run (audited) |
| `POST /console/n/{ns}/policy/promote` | session + ns write | Experimental eval-gated promote with confirm |
| `POST /console/n/{ns}/policy/rollback` | session + ns write | Experimental rollback with confirm + reason |
| `GET /console/n/{ns}/evals` | session + ns | Eval dataset runs: pass-rate trend per dataset, recent runs |
| `GET /console/n/{ns}/evals/{run_id}` | session + ns | One eval run against its baseline (`?baseline={run_id}` picks it), then every recorded case |
| `GET /console/api/session` | session | JSON session summary |
| `GET /console/api/namespaces` | session | JSON memberships for the principal |

### Causal operation workspace

Deep link: `/console/n/{namespace}/ops/{operation_id}`.

- Projects the same authorized `OperationReport` as `sekaictl report` (receipt →
  causal stages → event sections → missing/uncovered surfaces).
- Side panel exposes authorized JSON only; credential-like attribute keys are
  scrubbed. Omitted references from retention remain explicit.
- Visibility matches `GetOperationReceipt`: initiating actor, or bootstrap
  principals `root` / `local`.
- Cross-namespace IDs return **403** without disclosing foreign receipt content.
- Initial fixture-sized load budget: **2s** (`WORKSPACE_INITIAL_LOAD_BUDGET_MS`).
- List home caps at **50** operations over the last **7 days**.

### Governance pressure

Deep link: `/console/n/{namespace}/pressure`.

- 24-hour operation statistics tiles (logical ops, spend, outcome classes,
  waiting) from `query_operation_statistics` (authorized namespace only).
- Gunshi allocation status: revision, auto opt-in, live/advisory posture,
  kill switch reason.
- Kill switch POST requires namespace **editor/admin** (or bootstrap principal),
  explicit confirm checkbox, and a reason when enabling.
- Refresh semantics: request/response only; operators poll/reload. No SSE and
  no shadow database in v1.
- Provider circuits, cache effectiveness, multi-site federation, and approval
  queue depth remain out of scope until their APIs land.

### Policy workspace

Deep link: `/console/n/{namespace}/policy`.

- Effective summary: routing policy from durable namespace policy objects,
  budget limit count, action policy presence, Gunshi allocation status.
- Historical dry-run: same pure engine as [the policy dry-run design](policy-dry-run.md)
  [policy-dry-run.md](policy-dry-run.md); records `policy.dry_run` audit.
- Install baseline, promote/rollback, and auto-dispatch opt-in: write
  principals only; explicit confirm. Install requires snapshot + gate JSON.
  Promote requires candidate + evaluation JSON.
- Kill switch remains on the Pressure surface; status is visible here when
  auto-dispatch policy is installed.

### Evals

Deep links: `/console/n/{namespace}/evals` and
`/console/n/{namespace}/evals/{run_id}`.

- Read-only. Reads the same recorded runs and case results as
  `ListEvalDatasetRunTrend` and `CompareEvalDatasetRuns`
  ([quality trends](evaluation-quality-trends.md),
  [operator CLI](evaluation-operator-cli.md)); starting or gating a run stays
  in `sekaictl`.
- The list groups the **50** most recent runs by dataset, newest first, with a
  pass-rate line over up to 20 of each dataset's listed runs that are
  complete. Pass rate is over recorded cases. Status is
  `Complete` when every case of the dataset version has a result,
  `Incomplete` while some are missing, `Unknown` when the dataset version no
  longer resolves.
- The run page compares with the latest earlier complete run of the same
  dataset version under the same evaluator, or with `?baseline=`, through the default
  gate (alpha 0.05, policy increases fail). It shows the verdict and reasons,
  regressions, improvements, p-value, pass and spend against the baseline,
  and policy violation changes, then regressions grouped by the candidate's
  recorded reason code. No cause is inferred beyond the code.
- The full case table (verdict, reason code, policy violations, tokens, cost)
  is folded below the comparison.
- A case id links to its operation workspace
  (`/console/n/{namespace}/ops/{operation_id}`), which shows the case's
  evaluator step under the receipt rule: the principal that ran the case,
  or `root`/`local`. Results recorded before case receipts render without
  a link.
- The underlying eval dataset RPCs are experimental, so these pages share
  their gate: without `SEKAI_EXPERIMENTAL_RPCS=1` (or the `experimental-rpcs`
  build feature), and on a process that does not serve Chisei, they answer
  **503**.

Namespace URL segments must be short ASCII tokens (`[A-Za-z0-9._-]+`). Bootstrap
principals `root` and `local` (administrative principal / local socket principal) may
open any canonical namespace; other principals require an explicit namespace
membership grant.

## Non-goals (shell)

- Replacing `sekaictl` automation.
- Embedding provider API keys in the browser.
- Private SQLite or control-plane internals exposed to the browser as a second
  API surface.
- Full design-system marketing site.

## Related

- [Operations](operations.md) — ops listener, credentials, deployment checklist
- [Configuration](configuration.md) — `OPS_BIND` / `OPS_PORT`
- [Research IA](research/283-operator-console-ia.md)
