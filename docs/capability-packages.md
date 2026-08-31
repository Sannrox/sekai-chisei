# Capability-package certification

Bind signer, manifest, compatibility, tests, and revocation to one verified
package digest. Certification is not a runtime grant and does not install,
deploy, or authorize invocation. See
[ADR 0052](decisions/0052-capability-package-certification.md).

## Contract

`sekai.capability-package-certification/v1` binds:

- identity `(namespace, certification_id)` and logical `package_id`
- a package digest over members and compatibility
- signer identity and digest
- test-suite and test-result digests
- a certification digest of those pins
- optional predecessor, supersession, revocation, and revocation timestamp

Closed member kinds are `change_set`, `action_type`, `ontology`, and
`evaluation`.

## Operator workflow

```text
sekaictl admin packages certify --certification ./cert.json --actor reviewer
sekaictl admin packages get --namespace ops --certification-id cert:1 --actor reviewer
sekaictl admin packages verify --namespace ops --certification-id cert:1 \
  --certification ./cert.json --actor reviewer
sekaictl admin packages revoke --namespace ops --certification-id cert:1 \
  --reason "signer rotated" --actor reviewer
```

Exact replay of a live certification is idempotent. Independent verification
recomputes both digests from the submitted members, compatibility, signer, and
tests. A content or dependency change fails verification. Recertification
uses a new certification identity and a predecessor pin; the prior record
stays inspectable. Revoked certifications remain gettable and fail verify.

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, superseded, revoked, or digest-mismatched certification | `capability package is unavailable` |
| Unknown contract revision | `capability package revision is unsupported` |

SQLite stores certifications. PostgreSQL surfaces stay unavailable.
