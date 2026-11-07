# ADR 0145: Ed25519 identity assertions verified by key id

- Status: accepted
- Date: 2026-11-07
- Issue: #2133
- Amends: [ADR 0078](0078-audience-bound-assertions.md)

## Context

ADR 0078 identity assertions (`sia1.`) are HMAC-SHA256 under a key the authority and the plane share. The plane can therefore mint assertions it accepts, anything that reads its secret can impersonate any principal, and the key cannot rotate without both sides switching at once.

## Decision

1. **Token.** An authority may sign with an Ed25519 private key only it holds:

   ```text
   sia2.<kid>.<payload>.<signature>
   ```

   - `payload` is the unchanged `sekai.identity-assertion/v1` claims JSON, base64url without padding.
   - `signature` is the Ed25519 signature over the ASCII bytes `sia2.<kid>.<payload>`, so the kid is signed too; base64url without padding. Verification is strict.
   - `kid` is 1 to 64 ASCII letters, digits, `-` or `_`.
2. **Keys.** `SEKAI_ASSERTION_ED25519_KEYS` lists public keys as `<kid>=<key>`. A token whose kid is not listed is refused as a bad signature. Rotation: add the next kid, switch the signer, remove the old kid once its assertions have expired.
3. **Claims unchanged.** Issuer, audience, expiry and skew, one-use nonce, scopes, space, `act` and the device claim (ADR 0126) are checked exactly as for `sia1.`.
4. **HMAC window.** `sia1.` stays accepted by default. `SEKAI_ASSERTION_ACCEPT_HMAC=0` refuses it, and needs Ed25519 keys. The HMAC key keeps sealing the plane's own runtime and service tokens (ADR 0099), which the plane both issues and verifies. With Ed25519 keys and no HMAC key the plane holds no signing material and issues no runtime or service tokens.
5. **Advertisement.** `IDENTITY_ASSERTION_SIGNATURES` lists the schemes a build verifies. An authority switches to `sia2.` only against a release that lists `ed25519`, and can confirm a deployed plane with one `sia2.` read.
6. **Signer.** `Ed25519AssertionSigner` mints `sia2.` tokens for an authority built on this crate, as `AssertionAuthority::sign` does for `sia1.`.

## Consequences

- A plane configured with public keys only cannot forge assertions.
- After an authority switches and HMAC acceptance is off, the HMAC key is the plane's own; operators replace it with a value the authority never held.
- The compatibility matrix is unchanged: a new field would break readers that refuse unknown fields.
- Removing `sia1.` is a later, breaking release.
