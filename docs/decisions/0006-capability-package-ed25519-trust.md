# ADR 0006: Capability package ed25519 trust levels

- Status: accepted
- Date: 2026-07-26
- Owners: @Sannrox
- Discussion: Issue #295 (Discussion categories unavailable)
- Supersedes: none
- Superseded by: none

## Context

Capability packages can be installed and upgraded, but namespaces needed a
governed trust model for who signed a package and whether unsigned packages are
acceptable.

## Decision

1. Packages may carry an optional ed25519 signature over the **unsigned**
   manifest digest (`sha256:` of the JSON with `signature` cleared).
2. Namespaces configure `required_trust_level`:
   - `unsigned_allowed` (default grandfather path)
   - `signed` (signature required and must verify against a trusted signer)
3. Trusted signers are stored per namespace as `(identity, key_id, public_key)`.
4. Install and upgrade fail closed when the policy is not satisfied; the trust
   decision is recorded in package lifecycle evidence.
5. Trust policy and signer mutations append audited package events.

## Alternatives considered

- Trust-on-first-use without signatures — weaker for multi-operator and
  federation scenarios.
- Cosign/Sigstore only — heavier operational dependency; local-first operators
  need offline-capable keys. Ed25519 matches existing permit/attestation crypto.

## Consequences

- Existing packages continue to install until a namespace opts into `signed`.
- Operators manage signing keys offline and register verifying keys via
  `PutCapabilityPackageSigner`.
- PostgreSQL package trust policy admin is not complete in the community
  runtime; SQLite is the reference path.

## Validation

- Unit tests: unsigned under default; signed required rejects unsigned/invalid/
  untrusted; valid signature installs; policy events audited.
