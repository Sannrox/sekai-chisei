# ADR 0126: Device-bound identity assertions with per-request proof

- Status: accepted
- Date: 2026-10-23
- Issue: #1697
- Amends: [ADR 0078](0078-audience-bound-assertions.md)

## Context

Offline sync (#1634) needs requests bound to a device: a stolen assertion alone must not let another machine act as the device. The v1 identity assertion has no device claim. It also refuses unknown fields, so an issuer cannot add a claim until every server accepts it.

## Decision

1. The v1 assertion (`sekai.identity-assertion/v1`) gains an optional claim `device { id, ed25519_pub }`.
   - `ed25519_pub` is the device's Ed25519 public key, base64url without padding.
   - The claim refuses unknown fields.
   - Without the claim, an assertion authenticates exactly as before, and its wire form is unchanged.
   - A claim with an empty id or an unusable key refuses the assertion.
2. A verified device-bound assertion fills `AuthenticatedContext.device` with the device id, its key and the assertion's nonce.
3. **Proof.** A per-request proof is the device's Ed25519 signature over three lines:

   ```text
   sekai.device-proof/v1
   <assertion nonce>
   <request digest>
   ```

   - The request digest is `sha256:<hex>` over the length-prefixed gRPC method path and the encoded request message.
   - The proof travels as base64url without padding in `x-sekai-device-proof`.
4. **Hook.** A protected RPC calls the device-proof hook.
   - It refuses a device-bound context whose proof is missing or does not verify for this request.
   - It passes an unbound context, unless the RPC requires a device.
   - Strict Ed25519 verification is used.
5. **Fail closed elsewhere.** Every RPC that does not check device proofs refuses a device-bound assertion outright. RPCs that do check them are listed explicitly: `SubmitActionInstance` for offline Actions (ADR 0127), with sync (#1634) to follow. A copied assertion therefore authenticates nowhere a proof is not checked.
6. **No nonce store.** `sia1.` assertions are short-lived and one-use, so the proof needs no nonce store of its own. A replayed assertion is refused by the existing one-use check before any proof is looked at. A captured proof is useless without its assertion, and it only covers the request it was made for.
7. **Revocation stays with the issuer.** For a revoked device, the issuer stops minting normal assertions and mints only a wipe-only assertion. The core keeps no device registry and no revocation list.
8. **Rollout order.** Servers ship the claim first, then issuers start emitting it. An issuer that emits it before every server it talks to accepts it gets those requests refused, which fails closed.

## Alternatives considered

- Transport client certificates. Rejected: they tie clients to provisioning infrastructure.
- A v2 assertion. Rejected: an optional v1 claim is enough once servers accept it first.
- Revocation held in memory in the plane. Rejected: it is lost on restart and diverges across instances.

## Consequences

#1634 wires the hook into sync and adds wipe on revoked devices.

The proof is only as fresh as the assertion's one-use check. That check is the replay cache from ADR 0078, held per instance. An assertion accepted by one instance can still be presented once to another within its lifetime, so issuers keep device-bound assertions short-lived.

## Validation

Unit tests cover:
- an assertion without the claim, which authenticates as before;
- a valid proof, which is accepted;
- a proof over another request digest or method, or signed by another key, which is refused;
- a missing proof on a device-bound context, which is refused;
- a replayed device-bound assertion, which is refused;
- unknown fields in the claim and unusable keys, which are refused.
