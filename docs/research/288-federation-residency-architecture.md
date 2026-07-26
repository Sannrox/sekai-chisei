# Research: max federation and model-residency architecture

Issue: [#288](https://github.com/Sannrox/sekai-chisei/issues/288)  
Date: 2026-07-26  
Status: **recommendation complete**

## Decision question

What architecture lets sekai-chisei operate as a multi-site, multi-team
governance backbone with strong model/data residency—without a single global
mutable graph or a workflow engine?

## Evidence collected (today’s plane)

| Capability | Where | Implication for federation |
| --- | --- | --- |
| Namespace ACLs + membership | Sekai graph / grants | Natural isolation boundary per plane |
| Data class + classification markings | Policy, egress, #301 markings | Residency can pin **data class / purpose**, not free tags |
| Provider / model allow-lists | Effective policy, routing | Residency pin can ride existing allow-lists first |
| External permits + kill switch | Durable permits | Double-redeem must stay **plane-local** or generation-fenced |
| Leases (object-bound) | #0005 ADR, coordination | Multi-region leases need explicit authority (see #292/#293) |
| Attestations (policy / Shomei-style) | Get/VerifyAttestation RPCs | Cross-site **verify/import** is additive, not rewrite-home |
| Capability package Ed25519 trust | ADR 0006 | Offline-capable keys fit multi-site packaging |
| Replica-safe shared state | #117 closed | Shared-read patterns exist; not a global write graph |
| PostgreSQL runtime | #238 closed | Multi-region durability may use PG per region, not one global DB |
| Gunshi auto-dispatch | #279/#280 | Auto path must **not** cross sites under lag; kill switch is local |

No multi-control-plane wire contract exists yet. Single-site SQLite remains the
complete community baseline.

## Threat model (must fail closed)

| Threat | Failure mode | Required control |
| --- | --- | --- |
| Forged remote site | Accepts fake receipts/policy packs | Site identity + attested import only |
| Stale policy pack | Auto-dispatch under obsolete gate | Pack version + not-after + gate ids on receipts |
| Split-brain budget | Double spend across regions | Single write authority per budget scope (#292/#294) |
| Double-redeem permits | Same permit spent twice | Plane-local redeem ledger or generation fence (#293) |
| Residency bypass via route | Model in wrong region | Pre-upstream residency check on provider + data class |
| Gunshi thrash under lag | Promote/rollback flip-flop | Keep auto-dispatch **intra-plane**; no cross-site promote |

## Options

| # | Topology | Local-first? | Residency | Global write graph? | Verdict |
| --- | --- | --- | --- | --- | --- |
| 1 | Federated planes, Shomei/receipt exchange, policy packs | Yes | Per plane | No | Strong base |
| 2 | Hierarchical namespaces + regional pins + optional read replicas | Yes (with discipline) | Pins on provider/data class | No if replicas read-only | Good for single multi-region org |
| 3 | Global strongly consistent control plane | **No** | Easy but wrong product | Yes | **Reject** |
| 4 | Hybrid: regional write authorities + cross-site **verify-only** federation API | Yes | Per authority + import rules | No | **Recommend** |

### Recommendation: hybrid (4) composed with (1)+(2)

**One plane = one write authority** for graph mutations, permits, leases, budgets,
and Gunshi promotion for that site’s namespaces.

Cross-site:

- Exchange **attested** receipts, compliance bundles, capability packages, and
  **versioned policy packs** (not live shared mutability).
- Federation API is **verify / import / deny**, never “apply remote mutate
  locally without attestation.”
- Optional hierarchical namespaces and delegated policy **within** a plane or
  via imported policy packs.

Global SC control plane (3) is out: it kills local-first SQLite topology and
creates a single blast radius.

## Sequenced delivery (maps to open Issues)

Ship **single-plane residency first**, then cross-site verify, then multi-plane
contract, then multi-region consistency research/features.

| Order | Issue | Outcome |
| --- | --- | --- |
| 1 | **#289** provider + data-class residency enforcement | Single plane: fail closed before upstream; policy pins on model/provider/data class |
| 2 | **#290** cross-site attestation verify/import | Import attested artifacts; no remote write |
| 3 | **#291** multi-control-plane federation contract | Wire contract for site identity, pack exchange, verify-only API |
| 4 | **#292** multi-region consistency research | Budgets/leases/permits under lag (design freeze before #293/#294) |
| 5 | **#293** region-pinned leases/permits | Explicit redeem authority |
| 6 | **#294** multi-region budget topology | Single writer per budget scope |

### Single-plane residency (#289) freeze sketch

- Policy fields (or structured overlay): `allowed_provider_regions` /
  `allowed_model_residency` / `data_class_residency` maps.
- Evaluate **after** effective policy resolve, **before** any provider contact
  (gateway and PlanExecution).
- Receipt attributes: `residency_decision`, `provider_region`, `data_class`.
- Default: if no residency policy configured → today’s behavior (no surprise
  break); once configured → fail closed.

### Cross-site (#290/#291) freeze sketch

- Site identity: long-lived key (Ed25519, ADR 0006 family) per plane.
- Importable: attestations, compliance bundles, capability packages, Gunshi
  **scorecards** as evidence only—not live auto-dispatch remote control.
- Forbidden: remote promote of allocation policy, remote kill switch of another
  plane, remote budget debit.

### Gunshi under lag

Auto-dispatch (#280) stays **intra-plane**. Cross-site may import evaluation
evidence into local suites (#300 path) only under attestation; never enable
auto on a remote revision without local promote + local opt-in.

## Non-recommendations

- No global mutable graph or workflow engine.
- No browser/console superuser path for federation (#283).
- No assuming one enterprise IdP product in the federation contract
  (identity extension posture).
- No silent residency defaults that route EU data to non-EU providers.

## Conclusion

Adopt **regional write authorities + verify-only federation** with
**single-plane residency first**. Existing Issues #289–#294 are the correct
sequence; no further research is required before implementing #289 under this
freeze. #292 remains the gate before multi-region lease/budget features.
