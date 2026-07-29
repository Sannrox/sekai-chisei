# Research: reduce the top-level `sekaictl` command surface

Issue: [#442](https://github.com/Sannrox/sekai-chisei/issues/442)
Date: 2026-07-29
Status: recommendation complete

> Compatibility timing was amended by
> [ADR 0010](../decisions/0010-retire-sekaictl-aliases-at-0.2.0.md): the
> deprecated aliases are removed in `0.2.0` without a separate 90-day minimum.

## Recommendation

Keep the ontology-first product loop at the root and group expert operations
under `sekaictl admin`. Do not introduce journey verbs or a second binary.

The canonical root becomes:

```text
sekaictl <ontology|launch|doctor|smoke|models|estimate|receipt|report|admin> ...
```

This reduces top-level choices from 20 to 9 without adding a step to the
ontology apply, seed, run, first-run, receipt, report, model-discovery, launch,
or diagnostic paths. Expert tasks add one explicit `admin` segment.

This is a compatibility-affecting information-architecture recommendation, not
implementation authority. Open a Design Discussion before moving commands.

## Evidence

### Current inventory

`sekaictl --help` exposes 20 top-level commands:

`credential`, `gateway`, `launch`, `doctor`, `smoke`, `action`, `attest`,
`compliance`, `federation`, `estimate`, `provenance`, `ontology`, `receipt`,
`replay`, `report`, `memory`, `models`, `team`, `gunshi`,
`governed-subject`, and `admin` is absent.

The first-run product loop already has a coherent noun:

```text
sekaictl ontology apply
sekaictl ontology seed
sekaictl ontology run
sekaictl ontology first-run
sekaictl receipt
```

The validated ontology describes the repository entry point as the
ontology-first loop and treats the gateway as a secondary compatibility path.
That supports retaining `ontology`, `receipt`, and the adjacent day-one tools
at the root rather than renaming them around generic journey verbs.

### Journey counts

| Journey | Current decisions/steps | Recommended decisions/steps |
| --- | ---: | ---: |
| First run (`ontology first-run`) | choose among 20, then 1 command | choose among 9, then 1 command |
| Define and seed | choose among 20, then 2 commands | choose among 9, then 2 commands |
| Run and inspect receipt | choose among 20, then 2 commands | choose among 9, then 2 commands |
| Diagnose local setup | choose among 20, then 1 command | choose among 9, then 1 command |
| Rotate a credential | choose among 20, then 2 command segments | choose among 9, then 3 segments |
| Federation administration | choose among 20, then 2 command segments | choose among 9, then 3 segments |

The recommendation removes 11 root choices without increasing any core-loop
task. Expert administration pays one extra, meaningful navigation segment.

### Compatibility dependencies

Repository search finds maintained invocations in:

- `scripts/chisei_gateway_smoke.sh` for `gateway`;
- Docker and Compose documentation for `gateway`;
- gateway, operations, security, attestation, compliance, federation, team,
  ontology, and receipt documentation;
- CLI-generated guidance that points from `ontology run` to `receipt`; and
- examples and tests that assert current usage strings.

The command names are therefore automation contracts, not only help labels.
Moving them without aliases would create immediate script and documentation
breakage.

## Command mapping

| Existing command | Canonical command after grouping | Audience / capability |
| --- | --- | --- |
| `ontology` | `ontology` | Core define, seed, run, and inspect |
| `launch` | `launch` | Core local bootstrap |
| `doctor` | `doctor` | Core diagnostics |
| `smoke` | `smoke` | Core first governed operation |
| `models` | `models` | Core model discovery |
| `estimate` | `estimate` | Core preflight cost estimate |
| `receipt` | `receipt` | Core operation evidence |
| `report` | `report` | Core operation reporting |
| `credential` | `admin access credential` | Principal credential administration |
| `team` | `admin access team` | Shared namespace administration |
| `gateway` | `admin gateway` | Compatibility gateway administration |
| `action` | `admin governance action` | Action policy and approvals |
| `memory` | `admin governance memory` | Governed memory review |
| `gunshi` | `admin governance gunshi` | Advanced allocation and promotion |
| `governed-subject` | `admin governance subject` | Governed external-subject evaluation |
| `attest` | `admin assurance attest` | Attestation export and verification |
| `compliance` | `admin assurance compliance` | Compliance bundle and trust roots |
| `provenance` | `admin assurance provenance` | Detailed lineage lookup |
| `replay` | `admin assurance replay` | Replay export |
| `federation` | `admin federation` | Peer and site administration |

The hierarchy does not grant authority. Every command continues to authenticate
to the server and remains subject to the same server-side authorization,
policy, audit, and persistence behavior.

## Compatibility policy

1. Add grouped canonical paths without removing existing paths.
2. Keep every old top-level path as an exact behavioral alias for all `0.1.x`
   releases.
3. After grouped paths ship, print a one-line deprecation warning only on old
   paths; never change stdout formats used by scripts.
4. Update maintained scripts, examples, Docker assets, and docs in the same
   release that adds grouped paths.
5. Remove aliases no earlier than `0.2.0`, after a repository usage audit and a
   release note naming every removed alias.
6. If `0.2.0` ships before grouped paths have been available for 90 days, keep
   the aliases until the next minor release after that 90-day window.

## Help prototypes

### Recommended

```text
Usage: sekaictl <command> ...

Core:
  ontology   Define, seed, run, and inspect a governed domain
  launch     Start the local stack and an integrated client
  doctor     Diagnose local configuration
  smoke      Run one governed model operation
  models     List available models
  estimate   Estimate operation cost
  receipt    Inspect an operation receipt
  report     Build or verify operation reports

Administration:
  admin      Access, gateway, governance, assurance, and federation operations
```

### Rejected journey hierarchy

```text
sekaictl <start|define|run|inspect|admin> ...
```

This reaches five root choices, but `run` and `inspect` obscure stable nouns,
split the existing `ontology` workflow across several roots, and require
compatibility aliases for nearly every core command. The four-choice reduction
relative to the recommended nine does not repay that migration and support
cost.

## Other rejected options

- **Keep the flat surface:** ordering and prose cannot remove 20 peer choices;
  advanced operations continue to define the product at first glance.
- **Capability-conditioned help:** discovery would depend on a live server and
  could hide recovery commands precisely when capabilities are unavailable.
- **Separate day-one binary:** duplicates packaging, authentication,
  configuration, and documentation without removing server complexity.

## Follow-up implementation slices

These are issue-ready slices, not Issues created by this research:

1. Add the `admin` dispatcher, grouped help, and exact aliases with
   characterization tests; do not change command handlers.
2. Migrate maintained scripts, Docker assets, examples, and docs to canonical
   grouped paths; add stderr-only alias warnings.
3. At the `0.2.0` boundary, audit external and repository usage and either
   remove aliases under the stated window or record the reason to extend them.

The first slice requires an accepted Design Discussion because it establishes
the public hierarchy and deprecation contract. The later slices depend on it.
