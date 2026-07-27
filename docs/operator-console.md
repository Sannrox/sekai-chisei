# Operator console

Authenticated browser shell for daily governance work. Implements the hybrid
public-API model from
[research/283-operator-console-ia.md](research/283-operator-console-ia.md)
(Issue [#284](https://github.com/Sannrox/sekai-chisei/issues/284)).

The shell ships in-process on the **ops HTTP listener** (`OPS_BIND` /
`OPS_PORT`). Process health and metrics stay unauthenticated; every `/console`
route fails closed without a valid session.

V1 console surfaces are complete: shell (#284), Operations (#285), Pressure
(#286), and Policy (#287).

## Local development

1. Start the control plane with an ops port (default `9464`):

   ```bash
   SEKAI_INSECURE=1 cargo run
   # or authenticated local:
   # SEKAI_AUTH_TOKEN=dev-token cargo run
   ```

2. Create a principal credential when not using the deprecated root token:

   ```bash
   cargo run --bin sekaictl -- credential create alice
   # note the printed token; store it like any other API secret
   ```

3. Open the console:

   ```text
   http://127.0.0.1:9464/console/
   ```

4. Paste the principal Bearer token (same value used for gRPC /
   `authorization: Bearer …`). Sign-in sets an **HttpOnly**, **SameSite=Strict**
   session cookie (`sekai_console_sid`). The raw token is never written to
   `localStorage`.

5. Select a namespace from the header switcher (or open
   `/console/n/{namespace}/ops` when authorized). Primary nav is keyboard
   reachable (skip link → namespace control → Operations / Pressure / Policy).

Unauthenticated visits to `/console/` or any namespaced route redirect to
`/console/login`. Unauthorized namespace paths return **403** without loading
foreign data.

## Production / TLS

| Concern | Guidance |
| --- | --- |
| Bind | Keep `OPS_BIND=127.0.0.1` unless an orchestrator or reverse proxy must reach the process. |
| TLS | Prefer terminating TLS on a reverse proxy in front of the ops port, or run the control plane with `SEKAI_TLS_*` for gRPC and proxy HTTPS to loopback ops. |
| Cookie Secure | The process issues console cookies without the `Secure` flag so loopback HTTP works. When serving the console only over HTTPS, set `Secure` at the proxy (or restrict the console to HTTPS-only hosts). |
| Credentials | Prefer per-principal tokens over `SEKAI_AUTH_TOKEN`. Sessions re-check durable credential status on every request; revocation ends the session. |
| Multi-replica | Sessions are **process-local**. Pin console traffic to one instance or accept re-login after failover. |
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
| `GET /console/n/{ns}/ops/{operation_id}` | session + ns + receipt ACL | Causal operation workspace |
| `GET /console/api/n/{ns}/ops/{operation_id}` | session + ns + receipt ACL | Authorized report + causal stages JSON |
| `GET /console/n/{ns}/pressure` | session + ns | Governance pressure tiles |
| `GET /console/api/n/{ns}/pressure` | session + ns | Pressure snapshot JSON |
| `POST /console/n/{ns}/pressure/kill-switch` | session + ns write | Gunshi kill switch with confirm |
| `GET /console/n/{ns}/policy` | session + ns | Policy workspace |
| `POST /console/n/{ns}/policy/dry-run` | session + ns | Historical dry-run (audited) |
| `POST /console/n/{ns}/policy/promote` | session + ns write | Eval-gated promote with confirm |
| `POST /console/n/{ns}/policy/rollback` | session + ns write | Rollback with confirm + reason |
| `GET /console/api/session` | session | JSON session summary |
| `GET /console/api/namespaces` | session | JSON memberships for the principal |

### Causal operation workspace

Deep link: `/console/n/{namespace}/ops/{operation_id}`.

- Projects the same authorized `OperationReport` as `sekaictl report` (receipt →
  causal stages → event sections → missing/uncovered surfaces).
- Side panel exposes authorized JSON only; credential-like attribute keys are
  scrubbed. Omitted references from retention remain explicit.
- Visibility matches `GetOperationReceipt`: initiating actor, or bootstrap
  principals `root` / `local` / `chisei-gateway`.
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
- Historical dry-run: same pure engine as `DryRunNamespacePolicy` / docs
  [policy-dry-run.md](policy-dry-run.md); records `policy.dry_run` audit.
- Promote/rollback: write principals only; explicit confirm; promote requires
  candidate + evaluation JSON (same contract as `sekaictl gunshi promote`).
- Kill switch remains on the Pressure surface; status is visible here when
  auto-dispatch policy is installed.

Namespace URL segments must be short ASCII tokens (`[A-Za-z0-9._-]+`). Bootstrap
principals `root` and `local` (legacy root token / local socket principal) may
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
