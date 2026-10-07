# Research: integration-test binary consolidation

Issue: [#1304](https://github.com/Sannrox/sekai-chisei/issues/1304)
Date: 2026-10-07
Status: **landed** in [#1308](https://github.com/Sannrox/sekai-chisei/issues/1308); spike discarded
Command: `cargo test --workspace --locked --no-run --timings` after a one-line edit in `src/lib.rs`, warm debug cache.

Each of the 133 files in `tests/*.rs` is its own binary linked against the root library. The question is whether merging them into one or a few binaries cuts that incremental compile.

## Palantir analog

Palantir `gradle-baseline` configures **one `Test` task per project**, not one JVM per test class. JUnit 5 runs methods in parallel by default; tests that need static or process-global state are marked non-parallel rather than forked. Plugin tests that mutate a workspace still get an isolated directory. `gradle-guide` says measure configuration work before changing it.

Cargo's closest analog is one integration-test target (one rustc/link) for the bulk source set, with a separate binary only where process isolation is load-bearing.

## Measurements

Warm cache, then one comment line in `src/lib.rs`. Debug profile.

| Layout | Wall | User | Sys | Root `tests/` binaries |
| --- | ---: | ---: | ---: | ---: |
| Current (133 autodiscovered) | 88.0 s | 254.1 s | 71.5 s | 133 |
| Spike: 117 modules in `tests/it.rs` + 16 remaining binaries | 56.3 s | 115.0 s | 38.2 s | 17 |

Wall **−36%**. CPU **−55%**. The grouped `it` target compiled in 15.4 s and listed **373** tests.

Critical path is still the root library: `sekai-chisei` lib codegen ~23–31 s, then parallel relink of test binaries, bins, and examples. After grouping, leftover cost is bins, examples, `chisei-gateway` tests, and the 16 unmerged binaries (each still 6–8 s, overlapping).

A naive `#[path]` of all 133 files into one crate does not compile. Fifteen tests pull `adapters/` or `examples/` and address those files as `crate::…` siblings. Those stay separate binaries unless the `crate::` paths are rewritten.

The `it` debug binary is ~190 MiB. The root lib-test already warns `ld: __eh_frame section too large`. Grouping more modules into one binary makes that worse, not better.

## Process isolation that must stay separate

| Test binary | Why a private process |
| --- | --- |
| `gateway_cache_signals` | Process-global Prometheus recorder plus `std::env::set_var`. The file already documents that a sibling test in the same process could satisfy cache-signal assertions without the production path. |
| `auth_signals`, `db_signals`, `dedup_signals`, `resilience_load`, `observability` | Same recorder. Empty-before, sibling-pollution, and exact-value gauge asserts fail (or flake) in the grouped binary. The spike listed 373 tests and did not run them. |

Port-binding tests use `127.0.0.1:0` or spawn a child with `Command.env`. They do not need a private rustc binary. `crate::`-coupled adapter tests need their own binary only until those paths move.

## Hypotheses

1. **Linking the integration-test binaries dominates** an incremental `--no-run` after a library edit. **Partly.** Library codegen is the long pole (~25–31 s). The 133 test binaries dominate **CPU** (user 254 s) and the wall time *after* the library is ready.
2. **One `tests/it/main.rs` cuts that time substantially** without losing isolation that matters. **Yes, for the self-contained majority:** 36% wall, 55% CPU, 373 tests still discovered. A single crate for all 133 files is blocked on `crate::` adapter paths.

## Recommendation

Land the grouped layout in [#1308](https://github.com/Sannrox/sekai-chisei/issues/1308), matching Palantir's one-task-per-source-set rule:

- `autotests = false` on the root package.
- One `tests/it.rs` that modules the self-contained files.
- Keep process-global Prometheus recorder tests as their own `[[test]]` (`gateway_cache_signals`, `observability`, and `auth_signals` / `db_signals` / `dedup_signals` / `resilience_load` which the spike did not run).
- Keep the 15 `crate::`-coupled adapter/example/ratchet binaries until those paths are rewritten; do not rewrite them in the grouping change.
- Prove `cargo test --test it` and `cargo test --workspace --locked` on the landed layout. The spike did not run the 373 tests.
- Do not merge examples or bins; they were out of scope and still show up on the incremental critical path.

Further wall-clock wins on this command come from shrinking the root library (#1302 / #1303), not from a second round of test-binary merging.

The spike is discarded. This note is the decision artifact.
