# Model-platform adapter certification

Require providers to pass capability, streaming, usage, fallback, and
receipt protocol fixtures. Certification pins
`sekai.evaluation-evidence/v1` and is not a runtime grant. See
[ADR 0058](decisions/0058-model-platform-certification.md).

## Contract

`sekai.model-platform-certification/v1` binds:

- identity `(namespace, certification_id)`
- adapter `adapter.model.responses` or `adapter.model.messages`
- evaluation-evidence identity `(evidence_id, evidence_version, evidence_digest)`
- capability, streaming, usage, fallback, and receipt fixture digests

Exact digest replay is idempotent. Unsupported capability and ambiguous
usage fail closed. Interrupted streams reconstruct from the receipt
fixture and must be marked `retry_safety: ambiguous`. Revocation is
terminal.

## Operator workflow

```text
sekaictl admin providers certify --certification ./cert.json --actor integrator
sekaictl admin providers get --namespace ops --certification-id mp:responses --actor integrator
sekaictl admin providers verify --namespace ops --certification-id mp:responses \
  --certification ./cert.json --actor integrator
sekaictl admin providers revoke --namespace ops --certification-id mp:responses --actor integrator
```

## Failure

| Condition | Result |
| --- | --- |
| Unknown, foreign, revoked, secret-bearing, unsupported-capability, or ambiguous-usage certification | `model platform certification is unavailable` |
| Unknown contract revision | `model platform certification revision is unsupported` |

SQLite stores certifications. PostgreSQL surfaces stay unavailable.
Adapters never receive grants, credentials, or receipt authority.
