# Connector certification

Issue a signed, revocable verification record after the catalogued
GitHub object-sync connector passes authority and failure conformance.
Certification is not a runtime grant. See
[ADR 0055](decisions/0055-connector-certification.md).

## Contract

`sekai.connector-certification/v1` binds:

- identity `(namespace, certification_id)`
- connector `adapter.github.object_sync` / `1.0.0`
- the catalogued type digest
- producer identity, signer, and test-suite/result digests
- a connector digest, certification digest, and Ed25519 signature over that digest
- optional predecessor, supersession, revocation, and revocation timestamp

## Operator workflow

```text
sekaictl admin connectors certify --certification ./cert.json --actor reviewer
sekaictl admin connectors get --namespace ops --certification-id cert:github-1 --actor reviewer
sekaictl admin connectors verify --namespace ops --certification-id cert:github-1 \
  --certification ./cert.json --actor reviewer
sekaictl admin connectors revoke --namespace ops --certification-id cert:github-1 \
  --reason "signer rotated" --actor reviewer
```

Exact replay of a live certification is idempotent. Independent
verification recomputes both digests. A type-digest, producer, signer,
or test change fails verification. Recertification uses a new
certification identity and a predecessor pin. Revoked records remain
gettable and fail verify.

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, superseded, revoked, secret-bearing, or digest-mismatched certification | `connector certification is unavailable` |
| Unknown contract revision | `connector certification revision is unsupported` |

SQLite stores certifications. PostgreSQL surfaces stay unavailable.
