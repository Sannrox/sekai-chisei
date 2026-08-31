# Federation network contracts

Exchange governed requests, evidence, and outcomes through an explicit
bilateral contract. Each plane keeps local write and governance authority.
See [ADR 0053](decisions/0053-federation-network-contracts.md).

## Contract

`sekai.federation-network-contract/v1` binds:

- identity `(namespace, contract_id)`
- local and peer site identities
- allowed kinds `request`, `evidence`, and `outcome`
- residency class
- status `accepted`, `disconnected`, or `revoked`

An exchange is a digest-bound envelope under that contract. It is
observational and never a local grant.

## Operator workflow

```text
sekaictl admin network accept --contract ./contract.json --actor operator
sekaictl admin network exchange --exchange ./request.json --actor operator
sekaictl admin network get --namespace shared --contract-id net:alpha-beta --actor operator
sekaictl admin network peer-loss --namespace shared --contract-id net:alpha-beta --actor operator
sekaictl admin network reconnect --namespace shared --contract-id net:alpha-beta --actor operator
sekaictl admin network revoke --namespace shared --contract-id net:alpha-beta --actor operator
```

Exact replay of an accepted contract or exchange is idempotent. Peer loss
blocks exchange until reconnect. Revoked contracts remain inspectable and
cannot reconnect.

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, revoked, untrusted, tampered, or residency-conflicting exchange | `federation network is unavailable` |
| Peer loss while disconnected | `federation peer is disconnected` |
| Unknown contract revision | `federation network revision is unsupported` |

SQLite stores contracts and exchanges. PostgreSQL surfaces stay unavailable.
