# Team operations

## Evaluation quality trend report

Project authorized model and agent quality evidence from canonical evaluation
receipts:

```sh
sekaictl report quality \
  --namespace acme \
  --since-ms 1783900800000 \
  --until-ms 1784505600000 \
  --json \
  --output reports/acme-quality.json
```

Authenticated clients can read the same report through
`ChiseiService.GetQualityTrend`. The CLI is a single-store reader of the Sekai store (`SEKAI_DB_PATH` /
`SEKAI_DATABASE_URL`) and refuses Combined Split; dest-pair operators use the RPC. The report
keeps allow, deny, unknown, unavailable, cancelled, running,
partial-population, missing-dependency, and invalid-receipt states distinct.
Its totals reconcile to the selected receipt window. Baselines require an
earlier closed point with the same exact evaluator and canonical input digest,
including the subject revision, direct evidence, dependency results, and
population contract; otherwise the baseline is explicitly missing or
incomparable. See
[Evaluation quality trends](evaluation-quality-trends.md) for denominator,
freshness, redaction, recovery, retention, and rollback semantics.

## Governed decision trend report

Compare how governed Action decisions behave in a window and in the baseline
window of the same length just before it:

```sh
sekaictl report decisions \
  --namespace acme \
  --window 7d \
  --until-ms 1784505600000 \
  --fail-on-drift \
  --json \
  --output reports/acme-decisions.json
```

The command reads `ListActionInstances` from the plane at `CHISEI_GRPC_URL`
or `SEKAI_SOCKET`, as the caller's credential allows. `--window` takes
`ms`, `s`, `m`, `h` or `d`; `--until-ms` defaults to now. Per action type it
reports, for both windows: policy outcomes (`allow`, which includes
`auto_apply`, `deny`, `require_approval`, other), approver outcomes of parked
instances (grant, deny, pending), median and p95 time to decision, decided
instances that missed their review deadline or escalated, and decisions made
by agents. Each share is a series in basis points. A series is `drifted` when
both windows hold at least `--min-count` instances in its denominator
(default 30) and the share moved by more than `--max-share-shift-bps`
(default 1500); otherwise it is `stable` or `low_count`. `--fail-on-drift`
exits non-zero after printing a report with a drifted series, so any
scheduler can alert on it. An unknown or misspelled option fails instead of
being ignored.

Instances the caller may not read are excluded and counted as `withheld`.
A window holding more than 4,096 instances, withheld ones included, fails
with "narrow the window". A plane that predates the created window fails
with "server does not support windowed listing". The report lists the
instance ids of each window, and `digest` is a SHA-256 over the report with
the digest empty, so the same instances give the same digest and a verifier
who fetches the listed instances recomputes it.

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

The command is a single-store reader of the Sekai store: `SEKAI_DB_PATH` (default `<SEKAI_DATA_DIR>/sekai.db`) or `SEKAI_DB_BACKEND=postgres` with `SEKAI_DATABASE_URL`. Combined Split is
refused so relocated Chisei receipts cannot be omitted; use
`ChiseiService.GetOperationReceipt`. With `SEKAI_CREDENTIAL`, the
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

Path counters are evidence dimensions rather than a forced single-choice
classification: a mixed receipt can contribute to both `lookup_hit` and
`model_path`, while model usage follows its recorded `ModelCalled` events.

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
