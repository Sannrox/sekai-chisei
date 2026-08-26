# Multi-control-plane federation profile (v1)

Issue: [#291](https://github.com/Sannrox/sekai-chisei/issues/291)  
Freeze: [research/291-federation-profile.md](research/291-federation-profile.md)  
Architecture: [research/288-federation-residency-architecture.md](research/288-federation-residency-architecture.md)  
Peer import: [compliance-export.md](compliance-export.md) (#290)

## Posture

- **One plane = one write authority.** Graph mutations, permits, leases,
  budgets, and Gunshi promotion stay local to the plane.
- **Cross-site is verify / import / deny only.** Never remote promote, remote
  kill, or remote budget debit.
- **Peer down is degraded, not offline for the plane.** Local governance
  continues; cross-site import is marked unavailable.
- **Untrusted peers fail closed.** Join and import require an enabled trust
  root pin that matches the peer’s Ed25519 verifying key.

Contract id: `sekai.federation-profile/v1`.

## Operator workflow (two local processes)

Assume process A uses `DB_PATH=data/site-a.db` and process B uses
`DB_PATH=data/site-b.db`. Generate offline Ed25519 keys; only verifying keys
enter the control plane.

### 1. Register local site identity

```text
DB_PATH=data/site-a.db sekaictl admin federation register-site \
  --site-id site-a --key-id k1 --public-key-hex <a-pubkey-hex> \
  --region eu-central --data-class internal

DB_PATH=data/site-b.db sekaictl admin federation register-site \
  --site-id site-b --key-id k1 --public-key-hex <b-pubkey-hex> \
  --region us-east --data-class internal
```

### 2. Pin trust roots (reuse #290 store)

```text
DB_PATH=data/site-a.db sekaictl admin federation pin-trust-root \
  --site-identity site-b --key-id k1 --public-key-hex <b-pubkey-hex>

DB_PATH=data/site-b.db sekaictl admin federation pin-trust-root \
  --site-identity site-a --key-id k1 --public-key-hex <a-pubkey-hex>
```

Default pin namespace is `federation`. Compliance import can use the same roots
via `sekaictl admin assurance compliance trust-root --namespace federation ...` or a shared
namespace chosen by operators.

### 3. Join with policy pack pin

```text
DB_PATH=data/site-a.db sekaictl admin federation join \
  --peer-site-id site-b --peer-key-id k1 --peer-public-key-hex <b-pubkey-hex> \
  --pack-id governance-pack --pack-version 1.0.0 --pack-digest sha256:...

DB_PATH=data/site-b.db sekaictl admin federation join \
  --peer-site-id site-a --peer-key-id k1 --peer-public-key-hex <a-pubkey-hex> \
  --pack-id governance-pack --pack-version 1.0.0 --pack-digest sha256:...
```

Join is audited (`federation.peer_join`). The pack pin is visible on the peer
record:

```text
DB_PATH=data/site-a.db sekaictl admin federation list-peers
```

### 4. Peer health and import availability

```text
DB_PATH=data/site-a.db sekaictl admin federation set-health --peer-site-id site-b --health up
DB_PATH=data/site-a.db sekaictl admin federation import-availability --peer-site-id site-b
# {"available":true, ...}

DB_PATH=data/site-a.db sekaictl admin federation set-health --peer-site-id site-b --health down
DB_PATH=data/site-a.db sekaictl admin federation import-availability --peer-site-id site-b
# {"available":false,"reason":"peer is down; cross-site import unavailable ..."}
```

While the peer is down, site-a continues local policy, budgets, and permits.
Import of peer compliance bundles should only proceed when availability is
true (and still under #290 verify rules).

### 5. Leave (audited)

```text
DB_PATH=data/site-a.db sekaictl admin federation leave --peer-site-id site-b
```

## Namespace snapshots (#697)

`sekai.namespace-snapshot/v1` shares **visible typed objects** between two
independent planes. Each plane keeps local write and governance authority.

1. Join and pin trust roots as above. A trust pin proves the peer key only.
2. On the importing plane, grant the peer an explicit namespace scope:

```text
DB_PATH=data/site-b.db sekaictl admin federation grant-namespace \
  --peer-site-id site-a --namespace ops --max-classification internal
```

3. Export a signed snapshot from the exporting plane. The signing key must
   match the registered local site verifying key. Hidden or marking-denied
   objects are omitted without a hidden count.

```text
DB_PATH=data/site-a.db sekaictl admin federation export-snapshot \
  --namespace ops --output ./ops-snapshot.json \
  --signing-key ./site-a-seed.hex \
  --pack-id governance-pack --pack-version 1.0.0 --pack-digest sha256:... \
  --actor local
```

4. Import only when the peer is joined, healthy, granted, and the bundle
   verifies. Imported facts are replicas (`write_authority=false`). A local
   object with the same id is a conflict and is not overwritten.

```text
DB_PATH=data/site-b.db sekaictl admin federation set-health --peer-site-id site-a --health up
DB_PATH=data/site-b.db sekaictl admin federation import-snapshot \
  --namespace ops --bundle ./ops-snapshot.json
```

Ungranted, stale, tampered, revoked, hidden, or residency-conflicting bundles
fail closed before local use. Re-importing the same digest is idempotent.

Each accepted assertion stores an immutable
`sekai.federation-provenance/v1` chain back to signed source evidence. The
exporter signs every hop. Re-export appends signer, transform, and verification
hops and never rewrites earlier hops. Downstream import verifies each hop
against an enabled trust root, so a relay cannot forge origin history.
`show-snapshot-provenance` inspects a chain only when the caller can already
read the imported fact. Hidden, missing, and revoked assertions return the same
unavailable result. Signatures prove identity only.

## Forbidden remote control

Library guard: `federation_profile::evaluate_remote_control` and
`deny_forbidden_remote` always reject:

| Op | Result |
| --- | --- |
| `promote` | denied |
| `kill` | denied |
| `budget_debit` | denied |

Allowed: `verify`, `import`, `deny`.

## CLI surface

```text
sekaictl admin federation register-site ...
sekaictl admin federation show-site
sekaictl admin federation pin-trust-root ...
sekaictl admin federation join ...
sekaictl admin federation leave ...
sekaictl admin federation set-health ...
sekaictl admin federation set-pack-pin ...
sekaictl admin federation list-peers
sekaictl admin federation import-availability ...
sekaictl admin federation grant-namespace ...
sekaictl admin federation revoke-namespace-grant ...
sekaictl admin federation list-namespace-grants ...
sekaictl admin federation export-snapshot ...
sekaictl admin federation import-snapshot ...
sekaictl admin federation list-snapshot-imports ...
sekaictl admin federation show-snapshot-facts ...
sekaictl admin federation show-snapshot-provenance ...
```

Host filesystem / `DB_PATH` is the trust boundary for this CLI (same posture as
compliance export). A multi-tenant gRPC federation admin surface is a follow-up.

## Runtime notes

- SQLite is the reference store (`sekai_federation_local_site`,
  `sekai_federation_peers`). Community PostgreSQL fails closed as unavailable
  until parity is required.
- Trust roots live in `sekai_peer_trust_roots` (#290).
- Single-plane residency enforcement remains [residency-policy.md](residency-policy.md).

## Non-goals (v1)

- Cross-plane distributed transactions
- Automatic remote policy-pack apply
- Remote Gunshi promote / kill switch / budget debit
- Multi-region lease/budget write topology (see
  [research/292-multi-region-consistency.md](research/292-multi-region-consistency.md))
