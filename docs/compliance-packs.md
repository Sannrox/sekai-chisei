# Compliance packs

Issue: [#1468](https://github.com/Sannrox/sekai-chisei/issues/1468).
Builds on the offline [compliance export](compliance-export.md) (#297) and signed
receipts (#1449).

## Purpose

Map a control framework onto evidence already present in a compliance export.
The result is a per-control report: `met`, `partly_met`, or `no_evidence`, plus
the decision ids used and the queries that had no hits. Status is evidence
presence. It is not legal advice and it is not a certification claim.

## Packs are data

Packs live under `compliance/packs/` as JSON (`sekai.compliance-pack/v1`).
Named evidence queries live in `compliance/queries/v1.json`. A query lists the
audit `decision.action` values that count as hits. Operators can add a pack
with `--pack-file` without changing code, as long as every control names a
catalog query.

Built-in packs: `fixture`, `gdpr`, `nis2`, `iso27001`. They map listed controls
to catalog queries. `met` means those `decision.action` values were in the
export. Retention already writes `privacy.subject_erased` (`deletion_proofs`).
Other query ids (`access_reviews`, `grant_expiry`, `purpose_records`,
`incident_records`, `key_rotation`, `backup_drills`) match when the export
contains those actions; the fixture pack injects them. This command does not
invent those decisions from other tables. Packs omit framework clauses with
no catalog query. They do not enumerate an entire framework.

## Report

```bash
sekaictl admin assurance compliance report \
  --pack gdpr \
  --bundle ./audit-week.json \
  --output ./gdpr-report.json
```

Custom pack:

```bash
sekaictl admin assurance compliance report \
  --pack-file ./my-pack.json \
  --bundle ./audit-week.json \
  --output ./my-report.json
```

The report embeds the pack that was evaluated, the source export content
digest, and a content digest of its own. Optional ed25519 signing uses the
same flags as export (`--signing-key`, `--identity`, `--key-id`).

Removing an evidence source from the export (for example deleting every
`privacy.subject_erased` decision and rebuilding the bundle) turns every
control that depended only on `deletion_proofs` to `no_evidence`. A control
with two queries and one remaining source becomes `partly_met`.

## Verify offline

```bash
sekaictl admin assurance compliance report-verify ./gdpr-report.json \
  --bundle ./audit-week.json
sekaictl admin assurance compliance report-verify ./gdpr-report.json \
  --bundle ./audit-week.json \
  --trusted-key ./export-public.hex
```

Verification recomputes the report from the embedded pack and the supplied
export. It checks the content digest, the optional signature, and that the
export digest still matches. No control-plane database is required.

## Fixture namespace

The built-in `fixture` pack is the acceptance namespace
`compliance-pack-fixture`. A fixture export with one decision per catalog
query marks every mapped control `met`.

## Non-goals

- Legal advice or certification language
- A general-purpose query language over receipts
- Networked gRPC report generation (library + sekaictl, matching export)
