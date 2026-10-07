# ADR 0098: Keep a separate `chisei-plane` process

- Status: accepted
- Date: 2026-10-08
- Owners: @Sannrox
- Discussion: none
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1300 (#1300)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0096](0096-sekai-runs-without-chisei.md),
  [ADR 0082](0082-separate-chisei-and-sekai-durable-stores.md),
  [ADR 0083](0083-two-store-cutover-and-recovery.md)

## Context

ADR 0096 requires Chisei to have an attached Sekai and leaves open whether a
separately deployed `chisei-plane` process is still worth its cost. Combined
`sekai-chisei` is the default local binary and already opens both stores.
`chisei-plane` exists to run `ChiseiService` against only the Chisei dest, hop
to Sekai with `SEKAI_ENDPOINT` / `SEKAI_CREDENTIAL`, and refuse wrong-plane
RPCs.

Issue #1300 asked whether that process should go away now that Chisei cannot
boot without Sekai. The inventory:

- Shipped binary: `src/bin/chisei.rs` (`chisei-plane` in the root `Cargo.toml`).
- Process proof: `tests/two_plane_processes.rs` and
  `tests/data_dir_store_layout.rs`.
- Operator docs: [two-plane processes](../two-plane-processes.md),
  configuration, store relocation, architecture.
- Contributor contract: `AGENTS.md` / `CLAUDE.md` name both bin sources;
  `tests/agent_instruction_sync.rs` fails if either bin disappears.
- Deployment manifests in this repository do not start `chisei-plane`. Combined
  remains the supported local and image default.

Palantir packages each product as its own SLS distribution
([`sls-packaging`](https://github.com/palantir/sls-packaging)) and records
required `productDependency` on other products. Ontology, object storage, and
functions stay separate services with authenticated calls; they are not folded
into one process because one product requires another.

## Decision

1. **Keep `chisei-plane`.** Combined mode stays the default local binary. A
   Chisei process remains a supported second product that opens only the
   Chisei dest and reaches Sekai over an authenticated hop.
2. **`chisei-plane` requires `SEKAI_ENDPOINT`.** That boot rule is ADR 0096
   rule 4 and lands with [#1296](https://github.com/Sannrox/sekai-chisei/issues/1296).
   This ADR does not delete not-attached paths.
3. **Store separation does not depend on two processes.** ADR 0082/0083 stamps
   and wrong-plane dest checks remain the store proof. Two processes are the
   product-boundary proof: each binary can serve only its plane.
4. **No follow-up to remove the binary.** Combined-only would delete the hop
   implementation, the two-plane tests, and the process-isolation proof. That
   cost is larger than keeping a small bin and a hop.

## Alternatives considered

- **Delete `chisei-plane` and keep only combined.** Rejected: it removes the
  only in-repo proof that Chisei can run as a separate product with an
  authenticated Sekai hop, which is the Palantir product-dependency shape
  ADR 0096 already chose (Chisei requires Sekai; Sekai does not require
  Chisei).
- **Keep the hop traits but drop the bin.** Rejected: an unused hop is not a
  product; the bin is what operators and tests actually start.

## Consequences

- `src/bin/chisei.rs`, the hop, and `tests/two_plane_processes.rs` stay.
- Kubernetes or image work that wants a split deploy still has a binary; this
  repository does not add that deploy in this change.
- [#1296](https://github.com/Sannrox/sekai-chisei/issues/1296) still makes
  `chisei-plane` refuse boot without `SEKAI_ENDPOINT`.

## Validation

- `tests/agent_instruction_sync.rs` still requires `chisei-plane` at
  `src/bin/chisei.rs`.
- `tests/two_plane_processes.rs` still starts both bins.
- This ADR is listed in [the decisions index](README.md).
