# ADR 0085: Keep product frontends out of the control-plane repository

- Status: accepted
- Date: 2026-09-20
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/1080
- Supersedes: none
- Superseded by: none

## Context

[Research 283](../research/283-operator-console-ia.md) chose a hybrid operator
shell: in-process `/console/` on the ops listener, with every read and
mutation going through the same public APIs as `sekaictl`. That shell exists
for daily governance (operations, pressure, policy). It is not an Ontology
Manager, Object Explorer, evals studio, or Action-approval queue.

Product planning mixed those application surfaces with control-plane P0
(connectors, writeback, approval RPC, postgres parity). Growing them inside
`sekai-chisei` would couple a TypeScript/UI release cadence to proto,
persistence, and gRPC lanes, and would expand the in-process HTML shell past
the hybrid #283 accepted.

## Decision

`sekai-chisei` is the control plane. Product frontends are a separate
repository.

This repository owns durable facts, governed decisions, public gRPC and its
HTTP/JSON projection, `sekaictl`, the compatibility gateway, published
clients, `sekai-mcp`, and the **thin** in-process ops shell at `/console/`.

A product UI (Ontology Manager, Object Explorer, Logic/Agent Studio-like
chrome, evals UI, approval queue and forms) lives outside this repository. It
consumes only **stable** public RPCs and published packages. It uses the same
principal Bearer as `sekaictl`. It does not import server types, open the
control-plane database, or decide policy in the browser.

Control-plane work that those UIs need (approval RPC, object/link/action
postgres parity, connector and writeback adapters, retrieve/expand/explain
maturity) stays here and lands before the corresponding screens.

The existing ops shell stays here so local operators need no second process.
It does not grow into those product surfaces.

## Alternatives considered

- **Grow product UIs in this repo** (in-process pages or a `ui/` crate). One
  checkout and loopback, but UI toolchain, review, and release share collision
  surfaces with proto and migrations. Rejected.
- **Move `/console/` out with the product app.** Removes the zero-extra-process
  local ops path that #283 required. Rejected; the thin shell stays.

## Consequences

- New product screens are not added under `src/obs/` or as a workspace UI
  crate in this repository.
- Experimental RPCs stay opt-in and are not advertised as product navigation.
- Opening a frontend repository is follow-up, not this ADR. It waits until at
  least one stable vertical (for example object read plus receipt inspect) is
  enough to render.

## Validation

- Operator docs name this split: [operator-console.md](../operator-console.md).
- Review of UI-shaped Issues and PRs against this repository fails closed
  unless they are the existing ops shell or a public-API change the shell
  already uses.
