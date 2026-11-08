# ADR 0148: Sources are first-class; one connector runtime runs every integration

- Status: proposed
- Date: 2026-11-08
- Owners: @Sannrox
- Discussion: none
- Supersedes: none
- Superseded by: none
- Related: [ADR 0022](0022-source-batch-transactions.md),
  [ADR 0055](0055-connector-certification.md),
  [ADR 0060](0060-additive-source-type-descriptors.md),
  [ADR 0090](0090-object-change-action-bindings.md),
  [ADR 0129](0129-scheduling-ownership.md),
  [ADR 0130](0130-governed-export.md),
  [ADR 0149](0149-one-claimable-work-queue.md),
  [ADR 0147](0147-spatial-engine-integration-outside-the-plane.md)

## Context

Every integration is its own process, wired to the plane in its own way:

- **In.** Connectors built on `sekai-source-sdk` call `ApplySourceBatch`
  under a plane-owned cursor. Evidence adapters call `SubmitEvidence` from
  a local outbox.
- **Out.** A saved export leaves an artifact. Some process must fetch it,
  deliver it and acknowledge it.
- **Writeback.** `adapters/source_writeback.rs` redeems a permit and
  applies an `external_mutate` effect. The executor that does it is not
  named anywhere in the plane.
- **Reference programs.** The feedback publisher and investigator are
  separate programs with their own configuration.

Each of these processes picks its own configuration format, credential
handling, scheduling and health reporting. Nothing in the plane names the
external system, so an operator cannot see which integrations exist, who
owns them, which credentials they use, or whether they are running. A new
integration means a new process. The in-plane Ezu code (ADR 0147) showed
the opposite failure: putting the integration in the plane to get one place
to configure it.

The parts already exist: plane-owned cursors, saved exports with delivery
artifacts, Action bindings, writeback effects, the claim and lease client
(ADR 0129) and connector certification (ADR 0055). What is missing is the
object they all hang off.

## Decision

1. **A Source is a governed object.** A namespace administrator creates
   `sekai.source/v1` with:
   - a connector type and version;
   - configuration validated against that type's schema;
   - a credential reference;
   - an egress allowlist;
   - an owner, markings and an optional certification pin (ADR 0055).

   Source batches, saved exports and writeback effects name a Source.
   Today they name a free-form source instance, an export id, or nothing.
   Deleting or disabling a Source stops all its work.
2. **Connector types replace adapters.** A connector type implements the
   `sekai-source-sdk` operations it supports:
   - `check` and `discover`;
   - `read_page` and `read_changes` for data coming in;
   - `deliver` for export artifacts going out;
   - `apply` for writeback effects.

   A type declares its operations, its configuration schema and its
   credential slots. GitHub, the Ezu spatial engine, relational sources
   and the evidence producers become types.
3. **One connector runtime.** A single worker binary holds the connector
   types. It never links the control-plane package. It claims sync, delivery
   and effect work for the Sources it is entitled to, as the
   `source_sync`, `export_delivery` and `external_effect` kinds of the one
   work queue (ADR 0149), and adds no claim RPCs of its own. The
   deployment layer runs as many runtimes as it needs. The plane never
   pushes and holds no vendor code.
4. **Credentials stay with the runtime.** A credential reference names a
   secret that the runtime resolves locally. The plane stores the
   reference, never the value. A Source whose credential cannot be resolved
   reports `unavailable` and is not retried in a loop. Plane-held
   credentials sealed to a runtime key are a possible later extension, not
   part of this decision.
5. **Work comes from the existing schedules.**
   - **Syncs:** a schedule or a webhook delivery (ADR 0035).
   - **Delivery:** a completed export artifact (ADR 0130).
   - **Effects:** an admitted Action with an `external_mutate` effect
     (#1085).

   Automation stays with Action bindings (ADR 0090). A Source adds no
   trigger language of its own.
6. **Health is per Source.** Last success, lag, failure class and the
   runtime that holds the current claim. All of it is read from the plane's
   own records, never from a live probe (ADR 0046).

## Alternatives considered

- **Keep one process per integration.** Each new integration keeps paying
  for its own configuration, credential handling, scheduling and health
  reporting, and none of it is visible in the plane.
- **Run connectors inside the plane.** One place to configure, but vendor
  code and outbound credentials move into the governed core. ADR 0147
  removed exactly that.
- **Plane-held credentials now.** Simpler setup, but the plane becomes a
  credential store before key management for it exists.

## Consequences

- An operator lists Sources in a namespace and sees each one's type,
  owner, credential reference, last run and health.
- A new integration is a connector type in the runtime plus a Source. It
  needs no new process, configuration format or plane change.
- The free-form source instance on source batches becomes a Source id. The
  existing GitHub profile is migrated to a Source, and old batches keep
  their identity.
- The reference adapters under `adapters/` become connector types or are
  removed. `docs/ezu-adapter.md` becomes the description of the Ezu
  connector type.
- The runtime is a new deployable. It has to survive crash, takeover and
  rolling deploy as any claim worker does.
- This ADR depends on ADR 0149. Source, delivery and effect work are new
  kinds of that queue, not new claim families. They stay experimental
  until the queue's RPCs are stable.

## Validation

- One connector runtime syncs a Source, delivers a saved export and
  applies a writeback effect. A test covers crash mid-claim, takeover after
  lease expiry, and a rolling deploy with two runtime versions.
- The GitHub profile runs as a Source with unchanged object identity.
- No integration outside the runtime needs its own credential or schedule
  configuration.
