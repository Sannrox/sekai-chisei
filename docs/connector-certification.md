# Connector certification

Issue a signed, revocable verification record after a connector passes
authority and failure conformance: the catalogued GitHub object-sync
connector, or a connector for a kind admitted through a registered source
type descriptor (#1698, [ADR 0060](decisions/0060-additive-source-type-descriptors.md)).
Certification is not a runtime grant. See
[ADR 0055](decisions/0055-connector-certification.md).

## Contract

`sekai.connector-certification/v1` binds:

- identity `(namespace, certification_id)`
- a connector id and version, and the source type it reads:
  - the GitHub profile: `adapter.github.object_sync` / `1.0.0` with the
    catalogued type digest;
  - or the producer's own connector id and version with the digest of a
    source type descriptor registered and live in the same namespace. The
    GitHub connector id and type digest are reserved for the GitHub profile.
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

A descriptor-bound certification re-checks its descriptor on every
verify. Once the descriptor is retired, verify answers unavailable, as for a
revoked certification, and the record itself is unchanged.

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, superseded, revoked, secret-bearing, or digest-mismatched certification | `connector certification is unavailable` |
| Unregistered, retired, or other-namespace descriptor, or a reserved GitHub id or digest outside its profile | `connector certification is unavailable` |
| Unknown contract revision | `connector certification revision is unsupported` |

SQLite and PostgreSQL store certifications with the same identities and
fail-closed rules. Normal CI runs SQLite; PostgreSQL conformance is the
ignored `connector_certification_backend_conformance` test behind
`SEKAI_TEST_POSTGRES_URL`.
