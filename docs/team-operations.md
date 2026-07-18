# Team operations

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
sekaictl team weekly-report reports/*.json \
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
exec sekaictl team weekly-report /var/lib/sekai/reports/*.json \
  --namespace acme \
  --since-ms "$since_ms" \
  --until-ms "$until_ms" \
  --output "/var/lib/sekai/weekly/acme-$until_ms.json"
```

```cron
0 8 * * 1 /usr/local/bin/sekai-weekly-report
```
