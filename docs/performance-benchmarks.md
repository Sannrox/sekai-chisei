# Performance benchmarks

The versioned control-plane benchmark suite is defined in
`benchmarks/manifest-v1.json`. It uses only synthetic, sanitized fixtures and
local providers so upstream latency and credentials cannot affect the result.
The suite establishes measurement substrate and reviewable budgets; it does
not gate CI or optimize runtime behavior.

Run the release-profile suite from a quiet machine:

```bash
SEKAI_BENCH_HARDWARE="$(sysctl -n machdep.cpu.brand_string), $(sysctl -n hw.memsize) bytes RAM" \
SEKAI_BENCH_OS="$(sw_vers -productName) $(sw_vers -productVersion)" \
SEKAI_BENCH_RUSTC="$(rustc --version)" \
SEKAI_BENCH_RECORDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
SEKAI_BENCH_PROFILE=release \
cargo bench --bench control_plane -- benchmarks/manifest-v1.json \
  > benchmarks/baseline-apple-m2-pro.json
```

Linux operators should replace the `sysctl` and `sw_vers` expressions with
equivalent `/proc/cpuinfo`, memory, and OS-release metadata. All five metadata
variables are mandatory so reports cannot silently omit the environment.

Each workload records its fixture version, dataset size, concurrency, explicit
domain operations per iteration, sample count, nearest-rank p50/p95/p99
control-plane latency, throughput, sample standard deviation, and relative
standard deviation. The `observes` field states which
additional operational signals are meaningful to the workload. Streaming
fixtures contain no simulated network wait, so their measurements are Chisei
assembly overhead rather than provider time-to-first-token.

The checked-in baseline was captured on the hardware named in its report.
Budgets live in the manifest and are intentionally wider than the initial
variance. A later optimization may change a budget only with a documented
workload or product reason. Gating and CI wiring are described under
[Measured before/after results](#measured-beforeafter-results) below.

The concurrent persistence workload uses a temporary file-backed WAL database.
Its benchmark-local pressure recovery is capped at 20 attempts with a one
millisecond backoff; exhausting that bound fails the run instead of hiding
unbounded contention.

Gateway streaming keeps forwarding pressure bounded with a 32-slot channel and
64 KiB input and forwarding windows. Transport chunks and undeclared raw JSON
fallbacks are limited to the normal 32 MiB gateway body ceiling. SSE parsers
retain at most one 1 MiB incomplete frame, and cross-provider translation
forwards each input window before processing the next. Oversized declared SSE
input emits a wire-compatible ambiguous-retry error before termination. An
undeclared raw body cannot safely append an error after partial bytes, so it
terminates without extra client bytes while the gateway records an interrupted
receipt and accounting outcome.

SQLite tests pin the mixed persistence workload's representative
`WHERE namespace = ? ORDER BY id` query plan. A candidate secondary
`(namespace, id)` index was rejected because repeated same-machine runs showed
a material regression in the write-heavy reconciliation workload. PostgreSQL
runtime parity remains limited to the interfaces documented in the
architecture guide, so no unmeasured backend-specific index was added.

Object-list callers that do not request pagination totals execute only the
bounded page query. The `list_objects_with_total` contract still performs the
separate count needed by public paginated responses, so the optimization does
not change totals or compatibility behavior.

Do not use production databases, provider credentials, raw traces, customer
payloads, or secret-bearing environment dumps. New fixtures must remain
synthetic or demonstrably sanitized, and metric names and labels must contain
bounded identifiers rather than request content.

## Measured before/after results

Results for the consolidation sequence in Issues #94–#98.

### Evaluating a run

A single run cannot separate a regression from noise, so `perf-gate` refuses
fewer than three reports:

```bash
cargo run --release --bin perf-gate -- \
  --manifest benchmarks/manifest-v1.json \
  --baseline benchmarks/baseline-apple-m2-pro.json \
  run-1.json run-2.json run-3.json
```

### Measurement conditions

| | Before | After |
| --- | --- | --- |
| Recorded | 2026-07-18T13:03:00Z | 2026-07-19 |
| Hardware | Apple M2 Pro, 34359738368 bytes RAM | identical |
| Operating system | macOS 26.5.2 | identical |
| Compiler | rustc 1.96.1 (31fca3adb 2026-06-26) | identical |
| Build profile | release | release |
| Fixture version | `sekai.adoption-workloads/v1` | identical |
| Repetitions | 1 (checked-in baseline) | 3 per round, 2 independent rounds |

Both sides were measured on the same physical machine. The "before" side is
`benchmarks/baseline-apple-m2-pro.json`, recorded before this sequence began.
Dataset size, concurrency, and sample iterations per workload are defined in
`benchmarks/manifest-v1.json`.

### Uncertainty

This section bounds what every other number here is allowed to claim.

Repeating the matrix on identical hardware with **no code changes** produced
run-to-run spread of up to 60%:

| Dispersion | Workloads |
| --- | --- |
| ≤ 12% | most workloads |
| 26% | `startup_fresh_sqlite` (filesystem and SQLite setup) |
| 35% | `report_attestation_export` |
| 60% | `provider_failure_fallback` (0.2–0.4 µs, at timer resolution) |

Consequences:

- **Five of thirteen workloads cannot carry a gate** on this hardware. Four are
  noise-dominated; `provider_failure_fallback` measures below timer resolution
  and needs a much larger `operations_per_iteration` to become measurable.
- A delta smaller than combined dispersion is not a result. Rows marked "not
  comparable" report their observed delta without claiming it.
- Measuring on a busy machine is visibly noisier. Round 2 below has more
  noise-dominated rows than round 1 for that reason alone.

Baseline and current uncertainty combine in quadrature rather than by sum: they
are independent measurements, so their variances add while their standard
deviations do not.

### Results

p95 latency in microseconds, two independent rounds of three runs each.

| Workload | Before | Round 1 | Δ | Round 2 | Δ | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `context_egress_filtering` | 33.2 | 33.0 | −0.5% | 35.2 | +6.3% | unchanged |
| `evidence_ingest_project_retract` | 8114.0 | 9225.1 | **+13.7%** | 9249.8 | **+14.0%** | **REGRESSED** |
| `gateway_stream_cancelled_usage` | 2.5 | 2.0 | −16.9% | 2.2 | −11.8% | improved (round 1 only) |
| `gateway_stream_text_tools` | 2.0 | 2.1 | +2.0% | 2.1 | +2.1% | unchanged |
| `gunshi_advisory_planning` | 7.6 | 8.2 | +7.7% | 9.1 | +20.3% | unchanged |
| `kioku_candidate_fingerprinting` | 26.3 | 29.8 | +13.5% | 31.5 | +20.0% | unchanged |
| `mixed_persistence_reconciliation` | 12526.1 | 11552.4 | −7.8% | 12562.7 | +0.3% | not comparable |
| `policy_resolution_cold` | 6.2 | 7.4 | +20.3% | 6.4 | +3.4% | unchanged |
| `policy_resolution_warm` | 5.8 | 6.0 | +3.6% | 6.1 | +5.0% | unchanged |
| `provider_failure_fallback` | 0.4 | 0.2 | −33.3% | 0.3 | −10.9% | not comparable |
| `receipt_audit_assembly` | 19.7 | 20.6 | +4.4% | 25.6 | +30.0% | not comparable |
| `report_attestation_export` | 390.1 | 299.1 | −23.3% | 301.3 | −22.8% | not comparable |
| `startup_fresh_sqlite` | 23627.1 | 38870.3 | +64.5% | 27652.2 | +17.0% | not comparable |

#### The one confirmed regression

`evidence_ingest_project_retract` is **~14% slower** than baseline. It is the
only claim in this table that survives its own uncertainty:

- It reproduced across two independent rounds at +13.7% and +14.0%, landing
  within 0.3% of each other (9225.1 µs and 9249.8 µs).
- It is a low-noise workload, dispersion consistently under 8%, so a 14% shift
  clears the significance threshold in both rounds.

**Cause not established.** The leading suspect is the pool-saturation sample
added to `SekaiDb::conn` during this sequence, which calls `pool.state()` on
every connection acquisition and takes the pool's internal lock. Removing the
sample and re-measuring was **inconclusive**: the control run returned
noise-dominated at 26% spread because the machine was loaded. That experiment
must be repeated on an idle machine before anything is attributed.

Per Issue #98's scope, this regression feeds a follow-up rather than being
fixed here.

#### Movements that are not results

Four rows show large deltas this report explicitly does **not** claim:

- `startup_fresh_sqlite`, +64.5% then +17.0% — the rounds disagree by more than
  either delta, against 26% dispersion.
- `report_attestation_export`, −23% — consistent across rounds, but the
  workload's own dispersion is 35%.
- `provider_failure_fallback`, −33% then −11% — absolute values of 0.2–0.4 µs,
  below timer resolution.
- `receipt_audit_assembly`, +30% in round 2 against +4.4% in round 1.

### Regression gating

Two gates run over the same reports:

1. **Budget gate** — median p95 against the manifest budget. Budgets carry
   between **1.6x and 119.6x** headroom over observed values, so this fires only
   on a catastrophic slowdown. The confirmed 14% regression passes it.
2. **Baseline gate** — median p95 against the recorded baseline, threshold
   derived from combined dispersion and floored at 5%. This caught the
   regression.

The budget gate is retained because "is it fast enough" stays a real question,
but it cannot detect a regression at current headroom. The two workloads with
tight budgets, `mixed_persistence_reconciliation` (1.6x) and
`startup_fresh_sqlite` (2.2x), are both noise-dominated and not gateable, so the
gateable workloads are exactly those whose budgets are loose.

`.github/workflows/performance.yml` runs the matrix three times on a schedule
and evaluates in **reporting** mode. It does not enforce: budgets and baseline
describe Apple M2 Pro while CI runs `ubuntu-latest`, and enforcing
hardware-specific absolute latencies on different hardware fails for reasons
unrelated to any code change. Recording a baseline on the CI runner is the
prerequisite for enforcement there, and the scheduled runs collect that data.
`workflow_dispatch` accepts an `enforce` input for once it exists.

### Status against Issue #98

| Requirement | State |
| --- | --- |
| Metrics: overhead, saturation, DB waits, queue depth, cache, receipt lag, fallback, rejected work | Surface complete; wired at gRPC, persistence, gateway caches, auth, budget |
| Traces correlate stages with bounded-cardinality identifiers | Primitive complete, wired at the gRPC entry point only |
| Load tests: overload, shutdown, restart, recovery | Overload, restart, recovery covered; graceful shutdown not covered |
| CI smoke budget; scheduled full matrix with significance | Scheduled matrix and significance testing done; smoke budget needs CI-hardware calibration |
| Dedup/reconciliation reporting | Idempotent replays and key conflicts only; the wider set describes machinery this codebase does not reach |
| Compatibility-shim lifecycle reporting | Complete, with a test that fails when a shim is added without a deadline |
| Published before/after report | This section |

Known gaps: graceful-shutdown load coverage, trace correlation beyond the entry
point, CI-hardware calibration, and the unattributed 14% regression above.
