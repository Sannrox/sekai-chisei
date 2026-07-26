# Capability package trust levels

Issue: [#295](https://github.com/Sannrox/sekai-chisei/issues/295).  
Decision: [ADR 0006](decisions/0006-capability-package-ed25519-trust.md).

## Model

| Level | Meaning |
| --- | --- |
| `unsigned_allowed` | Default. Packages may omit signatures (grandfather path). |
| `signed` | Install/upgrade requires a valid ed25519 signature from a **namespace-trusted** signer. |

## Signing keys (operator)

1. Generate an offline ed25519 key pair (any tool that emits a 32-byte seed /
   verifying key is fine; the control plane stores only the **verifying** key).
2. Register the verifying key:

```text
PutCapabilityPackageSigner
  namespace, identity, key_id, public_key_b64 (standard base64 of 32 bytes)
```

3. Optionally require signatures for the namespace:

```text
SetCapabilityPackageTrustPolicy
  required_trust_level = "signed"
```

4. Sign packages by attaching `CapabilityPackageSignature` to the manifest:
   - digest = unsigned manifest `digest()` (`sha256:…` of JSON without signature)
   - `signature_b64` = base64 of ed25519 signature over the digest **string bytes**
   - `algorithm` = `ed25519`

Never embed private keys in the control plane database or package store.

## Failure modes

| Case | Result |
| --- | --- |
| Policy `signed`, no signature | denied |
| Unknown signer/key id | denied |
| Bad signature bytes | denied |
| Policy `unsigned_allowed`, no signature | allowed |

Trust decisions are recorded on the install/upgrade lifecycle event evidence.

## Compatibility

- Existing fixtures and packages without signatures continue to work under the
  default policy.
- Tightening a namespace to `signed` does not re-trust old packages; new
  installs must present valid signatures.
- SQLite is the reference runtime for trust policy and signer administration.
  On the community PostgreSQL runtime, trust admin RPCs (`Set`/`Get` policy,
  `Put`/`List` signers) fail closed as unavailable until package-trust table
  parity lands. Install/upgrade stay on the grandfather path
  (`unsigned_allowed` with an empty trusted-signer set). Omit package
  signatures there: a supplied signature still requires a registered signer and
  is denied until trust-table parity lands.
