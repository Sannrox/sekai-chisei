# Offline compliance export

Issue: [#297](https://github.com/Sannrox/sekai-chisei/issues/297).

## Purpose

Produce a bounded, offline-verifiable package of what ran in a namespace over a
time window — operation receipts plus related audit decisions — without giving
auditors live database credentials.

## Bundle shape (`sekai.compliance-export/v1`)

| Field | Meaning |
| --- | --- |
| `manifest` | Namespace, window, redaction mode, exporter, counts, content digest |
| `receipts` | Operation receipts overlapping the window |
| `decisions` | Portable audit decision snapshots in the window that touch the namespace |
| `signature` | Optional ed25519 signature over the canonical bundle |

Integrity uses the same canonical-JSON digest approach as Shomei attestation
bundles. Offline verification recomputes the content digest and optionally
checks the ed25519 signature.

## Export

```bash
sekaictl compliance export \
  --namespace team-a \
  --from-ms 1700000000000 \
  --to-ms 1700086400000 \
  --output ./audit-week.json \
  --redact \
  --actor auditor@example.com \
  --request-id export-2026-07-01
```

Optional signing:

```bash
sekaictl compliance export ... \
  --signing-key ./export-seed.hex \
  --identity compliance-export \
  --key-id 2026-07
```

Every successful export records a `compliance.export` audit decision with
namespace, window, redaction mode, request id, content digest, and counts.

## Verify offline

```bash
sekaictl compliance verify ./audit-week.json
sekaictl compliance verify ./audit-week.json --trusted-key ./export-public.hex
```

No control-plane database is required for verification.

## Redaction

| Mode | Behavior |
| --- | --- |
| `full` (default) | Keep admitted receipt attributes and decision evidence as stored |
| `redacted` (`--redact`) | Replace sensitive attribute/evidence values with `[redacted]` while keeping keys and decision metadata |

Sensitive keys include prompt/token/password/body/content/payload fields and
values that look like credentials or are very large.

## Limits

- At most 5,000 receipts and 10,000 decisions per export
- Window length at most 366 days
- `sekaictl compliance export` uses the configured runtime backend
  (`SEKAI_DB_BACKEND` / `DB_PATH` or `DATABASE_URL`)
- Host filesystem/DB credentials are the trust boundary for this CLI, as with
  other offline `sekaictl` report tools. A future gRPC export will enforce
  namespace authorization for networked multi-tenant access.

## Non-goals (this version)

- Console download UI
- Cross-tenant / org-wide export
- Continuous SIEM streaming
- gRPC transport (library + sekaictl; RPC can follow once consumers need it)
