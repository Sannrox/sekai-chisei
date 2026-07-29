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
