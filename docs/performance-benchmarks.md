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
workload or product reason. CI enforcement belongs to Issue #98.

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
