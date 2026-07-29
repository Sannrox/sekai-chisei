# Gateway administration single-source boundary

Issue: [#421](https://github.com/Sannrox/sekai-chisei/issues/421)

## Decision

Consolidate the duplicated gateway setup and reporting implementation in a new
leaf workspace crate after the façade cleanup tracked by
[#422](https://github.com/Sannrox/sekai-chisei/issues/422).

The new crate should own the provider-neutral administration client:

- setup and gateway-key configuration performed through the public gRPC
  services;
- report query, aggregation, terminal rendering, and HTML rendering;
- the setup and report argument/configuration types used by both binaries; and
- the shared deterministic tests for those behaviors.

Both `sekai-chisei` and `chisei-gateway` should depend on that crate. The crate
should depend on `sekai-proto`, `sekai-provider`, and third-party libraries, but
on neither consumer. Root-only `RuntimeDb` egress querying remains in
`sekai-chisei` and supplies protocol `Row` values to shared renderers.

Do not move this behavior into `sekai-proto` or `sekai-provider`. The former
owns generated wire contracts and the latter owns provider execution
contracts; neither owns an operator-facing control-plane client. A dedicated
leaf crate makes the existing behavior single-source without recreating the
forbidden normal dependency between the root control plane and gateway
runtime.

This is a refactor recommendation, not an implementation. Publishing the
focused follow-up Issue requires separate issue-creation authority.

## Measured duplication

The two `gateway_setup.rs` files are each 1,539 lines. Their production sections
are identical, and their tests differ only in how one test fixture is wrapped
and how test-only budget usage is reached.

The root report module is 1,415 lines and the gateway copy is 1,397 lines.
Their shared production behavior is identical. The only root production
addition is `egress_rows`, an 18-line adapter from `RuntimeDb` query types to
protocol `Row` values. Tests begin at line 950 in the root copy and line 932 in
the gateway copy.

Extraction therefore removes approximately:

- 1,907 duplicated production lines: 976 setup lines plus 931 report lines;
- 1,029 duplicated test lines; and
- 2,936 duplicated lines overall.

The resulting consumer adapters should be small: the root retains
`egress_rows`, and each binary retains only command dispatch and presentation
of returned errors.

## Function and consumer inventory

The public setup surface is identical in both copies:

| Function or type | Root consumer | Gateway consumer | Shared ownership |
| --- | --- | --- | --- |
| `GatewaySetupConfig` | `sekaictl`, launch workflow | Public crate API and tests | New administration crate |
| `run_setup` | `src/launch.rs`, `sekaictl` | Public crate API and tests | New administration crate |
| `run_gateway_key_command` | `sekaictl` | Public crate API and tests | New administration crate |
| `usage`, `key_usage` | `sekaictl` | Public crate API | New administration crate |

The report surface differs only at the persistence adapter:

| Function or type | Root consumer | Gateway consumer | Shared ownership |
| --- | --- | --- | --- |
| `GatewayReportConfig`, `ReportGroupBy`, `GatewayReportRow` | `sekaictl` | Gateway report command | New administration crate |
| `run_report`, `summarize_rows`, `render_dashboard`, `report_usage` | `sekaictl` and tests | Gateway report command and tests | New administration crate |
| `render_egress_html`, `render_egress_csv` | Root offline egress command | Tests | New administration crate |
| `egress_rows` | Root offline egress command | None | `sekai-chisei` |

All governed setup mutations already cross gRPC. The extraction does not move
persistence or policy enforcement and does not change the proto surface.
There is no in-repository gateway-binary setup consumer; preserving re-exports
from both current crates avoids making removal of the gateway library API an
unrelated compatibility decision.

## Change-history evidence

PR [#257](https://github.com/Sannrox/sekai-chisei/pull/257) deliberately copied
the setup and report clients while separating the runtime crate. Since that
merge:

- multi-region budget topology updated both setup copies;
- region-pinned leases and permit redemption updated both setup copies;
- optional lease preconditions updated both setup copies;
- `RuntimeDb` dual-wiring changed only the gateway test fixture; and
- PostgreSQL public-runtime activation changed only the root setup/report
  fixtures.

The synchronized feature changes show continuing duplicate maintenance. The
one-sided backend changes show why the persistence and integration fixtures
must not be extracted wholesale.

## Dependency direction

The normal graph after extraction should be:

```text
sekai-chisei ───────┐
                    ├──> sekai-admin-client ──> sekai-proto
chisei-gateway ─────┘                       └──> sekai-provider

sekai-chisei ──> sekai-proto
sekai-chisei ──> sekai-provider
chisei-gateway ──> sekai-proto
chisei-gateway ──> sekai-provider
```

There is no edge between `sekai-chisei` and `chisei-gateway`. The existing
gateway dev dependency on the root crate remains test-only until shared tests
and the remaining runtime fixtures can be separated independently.

The name `sekai-admin-client` is descriptive rather than normative. The
follow-up should confirm the final package name against workspace naming before
implementation.

## Why #422 comes first

The duplicated files currently import protocol services through
`crate::grpc::pb`, connection helpers through `crate::grpc::client`, provider
key helpers through `crate::gateway_keys`, and classification through
`crate::sekai::dataset`. The gateway crate recreates those root-shaped paths
with private façade modules.

Issue #422 already targets those façade modules. Completing it first will make
the true dependencies explicit and prevent the extraction from preserving a
synthetic `crate::` namespace as an accidental API. The follow-up extraction
should then move code against direct `sekai_proto` and `sekai_provider` imports
and either own or inject the connection helper.

## Focused follow-up scope

The implementation Issue should require:

1. add one leaf administration-client workspace crate with no dependency on
   either consumer;
2. move setup, key administration, gRPC reporting, aggregation, and rendering
   into it without behavior changes;
3. keep root `RuntimeDb` egress querying in `sekai-chisei`;
4. replace both copied modules with direct imports or narrow root adapters;
5. preserve CLI flags, help text, output, key hashing, policy/audit behavior,
   and gRPC contracts;
6. retain deterministic characterization tests and add a check that the
   duplicate source files no longer exist; and
7. verify the normal dependency graph with `cargo tree`.

The work should not absorb gateway runtime decomposition, protocol changes,
provider abstraction changes, persistence changes, or removal of the
gateway-to-root dev dependency beyond what naturally follows from moving these
tests.

## Risks and controls

- **New crate overhead:** one package and dependency edge pair replaces nearly
  3,000 duplicated lines and an established synchronized-edit burden.
- **Hidden circular ownership:** prohibit dependencies on either consumer and
  inspect the normal graph in CI.
- **CLI drift:** move the existing parsing and usage tests with the code rather
  than rewriting them.
- **Offline reporting leakage:** keep `RuntimeDb` and database query types out
  of the new crate.
- **Test-fixture coupling:** shared unit tests belong with the new crate;
  consumer integration tests may continue using their existing fixtures.

## Rejection of other options

- Existing shared crate extraction is rejected because administration-client
  behavior is neither a wire contract nor provider execution behavior.
- Keeping the copies with drift detection is rejected because it detects but
  does not remove an already demonstrated synchronized-edit burden.
- Making either current consumer the owner is rejected because the reverse
  consumer dependency would undo the acyclic boundary established by #154.
- Moving root offline queries is rejected because it would place
  control-plane persistence inside a client-only boundary.
