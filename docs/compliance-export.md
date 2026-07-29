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
sekaictl admin assurance compliance export \
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
sekaictl admin assurance compliance export ... \
  --signing-key ./export-seed.hex \
  --identity compliance-export \
  --key-id 2026-07
```

Every successful export records a `compliance.export` audit decision with
namespace, window, redaction mode, request id, content digest, and counts.

## Verify offline

```bash
sekaictl admin assurance compliance verify ./audit-week.json
sekaictl admin assurance compliance verify ./audit-week.json --trusted-key ./export-public.hex
```

No control-plane database is required for verification.

## Redaction

| Mode | Behavior |
| --- | --- |
| `full` (default) | Keep admitted receipt attributes and decision evidence as stored |
| `redacted` (`--redact`) | Keep structural identifiers only: receipt/event ids, kinds, surfaces, versions, timestamps, and `namespace`/`project` evidence. Clear free-form attributes, principals, reasons, and references. |

Redaction is intentionally aggressive so offline auditor bundles cannot carry
prompts, PII, or free-form error text under unexpected field names.

## Limits

- At most 5,000 receipts and 10,000 decisions per export
- Window length at most 366 days
- `sekaictl admin assurance compliance export` uses the configured runtime backend
  (`SEKAI_DB_BACKEND` / `DB_PATH` or `DATABASE_URL`)
- Host filesystem/DB credentials are the trust boundary for this CLI, as with
  other offline `sekaictl` report tools. A future gRPC export will enforce
  namespace authorization for networked multi-tenant access.

## Non-goals (this version)

- Console download UI
- Cross-tenant / org-wide export
- Continuous SIEM streaming
- gRPC transport (library + sekaictl; RPC can follow once consumers need it)

## Peer import (#290)

Cross-site compliance bundles can be imported after configuring trust roots:

```text
sekaictl admin assurance compliance trust-root --namespace <ns> --site-identity <site> --key-id <id> --public-key-hex <hex>
sekaictl admin assurance compliance import-peer --namespace <ns> --bundle <export.json>
sekaictl admin assurance compliance list-trust-roots --namespace <ns>
```

Imported records are verified under enabled roots and stored with
`permit_authority=false`. They never authorize local permit redemption.

Federation membership, policy pack pins, and peer health for multi-plane
operation are documented in [federation-profile.md](federation-profile.md)
(`sekai.federation-profile/v1`, #291).
