# Team operations

## Lookup-first substitution report

Inspect realized lookup-first and model-path evidence from the configured local
control-plane backend:

```sh
sekaictl report substitution \
  --namespace acme \
  --since-ms 1783900800000 \
  --until-ms 1784505600000 \
  --json \
  --output reports/acme-substitution.json
```

The command reads the bounded, namespace-scoped receipt window selected by
`DB_PATH` (or the configured PostgreSQL backend). With `SEKAI_CREDENTIAL`, the
command authenticates the credential against the configured backend; an
optional `--principal` or `SEKAI_PRINCIPAL` must match that authenticated
principal. Without a credential, the command runs as the local bootstrap
principal, which is the trusted local operator boundary; an arbitrary named
principal is rejected. It fails closed when the authenticated identity cannot
access the requested namespace. The report includes counts of
`lookup_hit`, `model_path`, `lookup_refusal`, and unclassified receipts;
refusal counts by reason; task-type breakdowns; and provider, input-token,
output-token, total-token, and optional priced-cost totals for model-path
receipts. It contains no prompt bodies, provider credentials, or raw receipt
event payloads.

These are realized receipt facts for one authorized namespace and time window,
not a fleet-wide ROI or spend-percentage claim. The report is read-only,
bounded to one year and 4,096 receipts, and does not change routing or promote
a provider/model.

Generate operation reports through the authenticated control plane before
building a team summary. Each input is already restricted to the caller's
authorized receipt projection:

```sh
sekaictl report op-123 --json --output reports/op-123.json
sekaictl report op-456 --json --output reports/op-456.json
```

The weekly command accepts only one explicit namespace and half-open time
window. Reports from another namespace or outside that window are not
projected into the output:

```sh
sekaictl admin access team weekly-report reports/*.json \
  --namespace acme \
  --since-ms 1783900800000 \
  --until-ms 1784505600000 \
  --output weekly/acme-2026-07-20.json
```

The artifact contains per-principal usage and evidence coverage, cost and
quality totals, receipt references, governed attestation and external-evidence
references, retention redaction counts, and unresolved policy, approval,
failure, and evidence events. It does not re-read source systems or expand the
authorized disclosures in its input reports.

For a scheduled run, place the command in a wrapper that computes the previous
seven-day window, then invoke the wrapper from cron. Keep the input and output
directories separate so the output artifact is not consumed as an operation
report on the next run.

```sh
#!/bin/sh
set -eu
until_ms="$(date +%s)000"
since_ms="$((until_ms - 604800000))"
exec sekaictl admin access team weekly-report /var/lib/sekai/reports/*.json \
  --namespace acme \
  --since-ms "$since_ms" \
  --until-ms "$until_ms" \
  --output "/var/lib/sekai/weekly/acme-$until_ms.json"
```

```cron
0 8 * * 1 /usr/local/bin/sekai-weekly-report
```
