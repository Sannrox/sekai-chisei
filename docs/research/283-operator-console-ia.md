# Research: operator console information architecture

Issue: [#283](https://github.com/Sannrox/sekai-chisei/issues/283)
Date: 2026-07-26
Status: **recommendation complete**
Operator guide: [operator-console.md](../operator-console.md)

## Decision question

What is the minimum viable **product console** (not a static HTML dump) for
daily governance operations: primary surfaces, auth model, and read vs write
capabilities for v1 vs later?

## Evidence collected

### Existing operator surfaces (today)

| Surface | Form | Authz | Role |
| --- | --- | --- | --- |
| `sekaictl` subcommands (credential, gateway, report, receipt, gunshi, ontology, compliance, …) | CLI | Bearer token / socket; namespace membership | Primary local operator tool |
| Operation report (`sekaictl report`) | Text/JSON from authorized receipt | Receipt ACL | Causal chain summary for one operation |
| Gateway report (`src/gateway_report.rs`) | JSON + optional static HTML file | gRPC auth | Aggregate LLM-call stats, not a workspace |
| Ontology inspection (`sekaictl ontology inspect`) | Authenticated static HTML artifact | API + declared authorization context | Closed research #150 / ADR 0003 direction |
| Effective policy summary RPC | gRPC | Namespace access | Read-only policy posture |
| Policy dry-run RPC (#282) | gRPC | Namespace write / admin | Historical counterfactual samples |
| Gunshi allocation status / promote / kill (#280) | gRPC + CLI | Namespace write | Automation control, not a UI |
| Compliance / attest / weekly report | CLI + bundles | Audit projection | Export and verification |

### Closed research #150

Chose **authenticated static inspection artifacts** for ontology—not a general
admin console, not an unauthenticated parallel path. That remains the right
model for *snapshot* inspection; it is **insufficient** for daily multi-operation
governance (no navigation, no near-live pressure, no confirmed writes).

### Follow-up Issues already shaped

| Issue | Intent |
| --- | --- |
| #284 | Authenticated console shell |
| #285 | Causal operation workspace |
| #286 | Live fleet / governance pressure |
| #287 | Policy authoring + dry-run + promote |

### Personas

| Persona | Primary jobs | Risk posture |
| --- | --- | --- |
| On-call operator | Find failing ops, kill auto-dispatch, check budget denials | High urgency, limited write |
| Namespace admin | Policy dry-run, promote allocation, membership-aware scope | Privileged writes with confirm |
| Security reviewer | Causal chain, egress/privacy decisions, compliance export | Mostly read + export |
| Governance lead | Fleet scorecard, acceptance rates, revision status | Read + controlled promote |

## Options compared

| Option | Fit | Main risk |
| --- | --- | --- |
| **1. UI process served by control plane only (loopback/TLS)** | Strong local-first | Harder multi-site later if it assumes co-process state |
| **2. Separate console app, public APIs only** | Strong federation | Two deployables day-one; may lag local socket UX |
| **3. Hybrid: in-repo shell + public-API-only data plane** | Best match | Must keep UI free of private control-plane types |

### Recommendation

**Option 3 (hybrid).**

- **Shell** ships in-repo (workspace crate or static assets served by an
  authenticated control-plane HTTP listener on loopback/TLS).
- **All data and mutations** go through the same public gRPC/HTTP APIs that
  `sekaictl` uses (Bearer principal credentials, namespace ACLs).
- **No second control plane**: no browser-only decision logic, no superuser
  bypass, no private SQLite path from the UI.
- **Local-first**: default target is Unix socket / loopback; remote HTTPS
  deployments reuse the same client.
- **Federation later**: a separate site only changes the API endpoint list;
  the shell does not embed site-local tables.

Static HTML exports (gateway report, ontology inspect) remain **export
artifacts** reachable from the console, not the console itself.

## Auth model

| Rule | Detail |
| --- | --- |
| Credential | Same principal credentials as gRPC (`authorization: Bearer …`); prefer per-principal tokens over deprecated `SEKAI_AUTH_TOKEN` |
| Session | Short-lived browser session cookie **or** token held only in memory after paste/login; no long-lived secret in `localStorage` for v1 |
| Authz | Every request re-checked server-side; UI never infers cross-namespace visibility from labels alone |
| Writes | Promote, kill switch, policy apply, dry-run that mutates audit: **explicit confirmation** + reason where CLI already requires one |
| Fail closed | Unauthenticated routes return empty chrome + login; no partial foreign data |

## Screen list and API dependencies

### V1 (minimum product console)

| Screen | Purpose | Primary APIs / artifacts | Read / write |
| --- | --- | --- | --- |
| **S0 Shell** | Login, logout, namespace context switcher, nav | Credential validation; `List`/membership as available | Read |
| **S1 Operations home** | Recent operations for the active namespace; deep link to S2 | Receipt list / statistics query; report summary inputs | Read |
| **S2 Causal operation workspace** | One operation: receipt events, policy/budget/route, permits, outcome, Gunshi links | `GetOperationReceipt`, report projection, decisions/list as authorized, Gunshi scorecard by allocation id when present | Read; export write to file only |
| **S3 Governance pressure** | Budget burn, denials, approval queue depth, auto-dispatch live/kill/revision | Budget RPCs, gunshi `GetGunshiAllocationStatus` / scorecard, approval list surfaces | Read; **kill switch** write with confirm |
| **S4 Policy workspace** | Effective policy summary, dry-run candidate, promote/rollback allocation | `GetEffectivePolicySummary`, internal dry-run engine, Gunshi install/promote/rollback/opt-in | Read + confirmed write |

Delivery mapping to Issues:

| Screen | Issue |
| --- | --- |
| S0 | #284 |
| S2 (+ S1 list stub) | #285 |
| S3 | #286 |
| S4 | #287 |

Ship order recommendation: **#284 → #285 → #286 → #287** (shell first; causal
workspace is the daily path; pressure and policy build on it).

### V2 (explicitly later)

| Screen / capability | Why later |
| --- | --- |
| Multi-site federation dashboard | Depends on #288 residency/federation research |
| Full policy authoring editor (schema-driven forms for all policy kinds) | V1 reuses dry-run + JSON candidate upload / structured forms for allocation only |
| Ontology class browser as primary nav | Covered by static inspect artifact (#150/#218); embed as panel when needed |
| Real-time multi-user collaboration | Out of scope |
| Tenant / billing admin | Tenant epic deferred |
| Provider key management in browser | Forbidden; remains ops/env |

## Information architecture sketch

```text
[Login]
   │
   ▼
[Shell: namespace ▾ | Operations | Pressure | Policy | Exports]
   │
   ├─ Operations ──► list ──► Operation workspace (causal graph + JSON side panel)
   │                              └─ Export report / compliance bundle
   ├─ Pressure ──► budget / denials / auto-dispatch status
   │                    └─ Kill switch (confirm)
   └─ Policy ──► effective summary ──► dry-run ──► promote/rollback (confirm)
```

Deep links: `/n/{namespace}/ops/{operation_id}`, `/n/{namespace}/pressure`,
`/n/{namespace}/policy`. Namespace is always explicit in the URL.

## Read vs write matrix (v1)

| Action | Persona | Confirmation |
| --- | --- | --- |
| View operations / pressure / policy | All with namespace read | No |
| Export report / compliance | All with read | No |
| Kill switch on/off | Namespace admin / on-call with write | Yes + reason |
| Policy dry-run | Namespace write | Yes (creates audit decision) |
| Promote / rollback / opt-in allocation | Namespace write | Yes + expected revision shown |
| Edit raw policy objects | Not in v1 UI | Use CLI/API |

## Non-recommendations

- Do **not** make the gateway HTML report the product console.
- Do **not** put SQLite or control-plane internals behind browser-only RPC.
- Do **not** default auto-dispatch or policy apply from the UI.
- Do **not** build a free-form YAML policy editor without schema validation.
- Do **not** reverse #150 for ontology (static authenticated artifact remains valid).

## Refined acceptance for follow-up Issues

Use this research as planning truth:

1. **#284** — public-API shell, namespace context, fail-closed auth, local + TLS run docs.
2. **#285** — operation workspace driven by authorized receipt/report; missing links explicit; cross-namespace fail closed.
3. **#286** — pressure tiles from existing APIs; include Gunshi allocation status; kill switch with confirm.
4. **#287** — wire dry-run (#282) + allocation promote/rollback (#280); no silent apply.

## Conclusion

Ship a **hybrid, public-API-only operator console** with four v1 surfaces
(shell, causal operation, governance pressure, policy/promote). CLI and static
exports remain first-class; the console orchestrates them for daily work without
becoming a second control plane.

No further research is required before implementing #284 under this IA.
