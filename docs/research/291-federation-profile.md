# Research freeze: multi-control-plane federation profile v1

Issue: [#291](https://github.com/Sannrox/sekai-chisei/issues/291)  
Related: [#288](https://github.com/Sannrox/sekai-chisei/issues/288) (architecture),
[#290](https://github.com/Sannrox/sekai-chisei/issues/290) (peer import/verify),
[#292](https://github.com/Sannrox/sekai-chisei/issues/292) (multi-region consistency)  
Date: 2026-07-27  
Status: **v1 profile freeze (F1)**

## Design decision (F1)

Maintainer Design Discussion on #291 is closed. Session design discussion plus
[#288 research](288-federation-residency-architecture.md) are accepted as the
public federation **v1 profile freeze**.

This document is the durable freeze. Implementation must not expand the wire
semantics beyond what is listed here without a new Design Discussion.

## Authority model

| Rule | Meaning |
| --- | --- |
| One plane = one write authority | Graph mutations, permits, leases, budgets, and Gunshi promotion stay **plane-local**. |
| Cross-site is verify / import / deny only | A peer may present attested artifacts; the importer verifies under pins and admits evidence or denies. |
| No shared write graph | Federating planes never merge tenancy or share a mutable control graph. |
| Local-first alone remains valid | A plane with no peers (or all peers down) is a complete topology. |

## v1 profile objects

| Object | Contract role | Notes |
| --- | --- | --- |
| **Site identity** | Long-lived Ed25519 verifying key per plane (`site_id` + `key_id` + 32-byte public key) | Private keys never stored in the control-plane DB. Same key family as ADR 0006 / #290 trust roots. |
| **Trust root pin** | Namespace-scoped enabled peer public key that may sign importable bundles | Reuses `#290` `PeerTrustRoot` / `sekai_peer_trust_roots`. Join requires a matching enabled root. |
| **Policy pack pin** | Visible `(pack_id, version, content_digest)` associated with a peer membership | Pin is observational for v1: importers compare digests; automatic remote pack apply is out of scope. |
| **Residency metadata** | Optional region label + data-class list on local site and peer records | Aligns with [#289](../residency-policy.md); does not replace single-plane residency enforcement. |
| **Peer health** | `up` / `down` / `unknown` on the local view of a peer link | Operator or probe-driven; fail closed for import when not `up`. |

## Membership lifecycle

- **Join**: local site registers peer under an enabled trust root; membership
  becomes `joined`; audit decision `federation.peer_join`.
- **Leave**: membership becomes `left`; audit decision `federation.peer_leave`.
- Join and leave are always audited. Re-join of a left peer is allowed as a new
  join event with updated pins/metadata.

## Fail-closed behavior

| Condition | Required behavior |
| --- | --- |
| Peer `down` or `unknown` | Local governance continues (decisions, budgets, permits, Gunshi local promote). Cross-site **import is unavailable**. |
| Untrusted peer (no enabled matching trust root, or key mismatch) | Reject join and reject import. |
| Peer claims remote promote / kill / budget debit | **Forbidden** — always deny; never execute. |

## Forbidden remote operations (hard deny)

The federation profile **must not** expose or honor remote control of:

1. **Remote promote** — Gunshi / allocation policy promotion on another plane
2. **Remote kill** — kill switch or permit revoke authority on another plane
3. **Remote budget debit** — spend or transfer against another plane’s budget ledger

Allowed cross-site verbs remain only:

- **verify** (offline signature/hash checks)
- **import** (admit verified evidence under local pins; no permit authority)
- **deny** (explicit rejection)

## Acceptance mapping (#291)

| Acceptance evidence | Profile requirement |
| --- | --- |
| Two local processes federate with pinned roots; policy pack pin visible | Each process has a local site identity; mutual trust root pins; join records expose policy pack pin. |
| Peer down → local governance continues; cross-site import marked unavailable | Health `down` keeps local write paths; import availability API/CLI returns unavailable. |
| Untrusted peer rejected | Join/import without enabled matching trust root fails closed. |

## Non-goals (v1)

- Cross-plane distributed transactions or consensus
- Workflow orchestration across sites
- Automatic policy-pack apply or remote Gunshi auto-dispatch
- Enterprise IdP product coupling
- gRPC multi-tenant authorization surface for federation admin (library +
  durable store + `sekaictl` is sufficient for v1; networked RPC may follow)
- Multi-region lease/budget write topology (see
  [292-multi-region-consistency.md](292-multi-region-consistency.md))

## Contract identifier

Durable records and CLI/library surfaces use:

```text
sekai.federation-profile/v1
```

## Implementation anchors

| Concern | Location |
| --- | --- |
| Profile domain + join/leave/health/import availability | `src/sekai/federation_profile.rs` |
| SQLite store | `src/db/federation_store.rs` + `sekai_federation_*` tables |
| Trust roots / compliance import | `src/sekai/peer_import.rs` (#290) |
| Operator guide | [docs/federation-profile.md](../federation-profile.md) |

## Revision policy

Any change to authority rules, forbidden remote ops, or profile object meaning
is a **breaking** public profile change and requires a new Design Discussion
plus a contract version bump (`/v2` or equivalent). Additive operator metadata
that does not change verify/import/deny semantics may ship under v1 with docs.
