# Epistemic profiles across federation contracts

Issue #500 asked whether the epistemic profile from the deterministic
[replication fixture](../../examples/epistemic-replication/profile-v1.json)
needed a new federation adapter. The conformance fixture in
[`tests/epistemic_federation_conformance.rs`](../../tests/epistemic_federation_conformance.rs)
answers that question with the existing contracts: no new adapter or remote
authority is required.

## Decision

Compose the domain profile with the existing signed artifacts:

1. Keep the profile package and its versioned domain vocabulary outside core.
   Put the profile digest, claim/evidence/assessment digests, bounded status
   labels, and disclosed-field declarations in the normal operation receipt.
   Do not copy raw claims, evidence payloads, or a mutable epistemic graph into
   a federation object.
2. Use a Shomei `AttestationBundle` for portable integrity and policy evidence.
   Its generic `GovernedReference` entries preserve the profile and evidence
   identities, while the policy attestation remains linked to the receipt's
   policy event and is replayable under its pinned policy snapshot.
3. Use the signed compliance export for peer exchange. A peer pins the source
   identity and key, verifies the bundle offline, records an idempotent import,
   and keeps `permit_authority=false`. Duplicate imports, tampering, disabled
   trust roots, and revoked Shomei signer keys during Shomei policy
   verification are rejected. Peer-import trust-root revocation is the
   existing explicit `enabled` control; v1 does not infer temporal key state.
4. Use the governed-subject provenance envelope when an external consumer
   needs a payload-free subject/content/receipt binding. Its expiry is checked
   at verification time; it does not grant delivery, promotion, or write
   authority.
5. Use `HandoffManifest` only for local coordination. It carries opaque,
   principal- and namespace-scoped references with expiry, supersession, and
   revocation checks through the existing local resolver, but it is not a
   signed cross-site trust envelope. The federation fixture checks only the
   manifest's bounded reference serialization; the existing gRPC handoff
   conformance tests cover the live lifecycle re-checks.
6. Keep federation remote control limited to `verify`, `import`, and `deny`.
   Residency metadata on a peer is observational; each plane must re-run its
   own provider/model/data-class residency policy before a route. Imported
   evidence cannot change that decision.

## Preservation matrix

| Contract | Preserved across the boundary | Intentionally not carried or trusted |
| --- | --- | --- |
| Operation receipt / Shomei | Profile/version digest; claim, evidence, and assessment references; evidence/lifecycle status; policy snapshot and attestation; causal event chain; signer and verification time | Raw profile package, raw evidence payloads, mutable graph state |
| Compliance export / peer import | Signed receipt and decision snapshots; namespace/window/redaction; source identity and key; content digest; idempotent import record | Permit authority; remote policy promotion; untrusted or disabled signer; temporal key state not represented by the v1 trust root |
| Governed-subject provenance | Subject identity, content digest, receipt digest, issuer key, freshness window | Delivery authority; a replacement for local policy or evidence admission |
| Handoff | Opaque reference kind/id/version; intended principal/scope; expiry; supersession and revocation state | Cross-site signer trust; remote authorization; raw omitted evidence |
| Federation profile | Peer membership/health, policy-pack pin, observational region/data-class metadata, allowed remote verbs | Global mutable graph; remote promote/kill/budget debit; local residency decision |

The test verifies the tiny fixture offline and sanity-checks its serialized
size. That size check is a fixture regression guard, not a general byte-level
verification limit: v1 bounds receipt and decision counts but does not impose
a total bundle or per-field byte cap. Backend parity remains covered by the
existing evidence backend conformance suite; the federation-specific proof is
intentionally SQLite-only because it exercises the portable artifacts rather
than a new database schema.

## Explicit residual limits

- `PeerTrustRoot` has an explicit enable/disable control, but no validity
  window, revocation timestamp, or successor-key metadata. Shomei's keyring
  can reject a revoked signed attestation; peer operators must disable a
  revoked compliance-import root. Automatic peer-root lifecycle enforcement
  would be a separate generic trust-management change, not an epistemic
  adapter.
- Compliance-export v1 has count and time-window limits but no total byte
  limit. The fixture carries only digests and bounded labels and records its
  size as evidence; a universal byte budget should be proposed separately if
  deployments need an import-side resource guard.

## Complexity dividend

The no-adapter result removes a new trust boundary, schema, migration, and
cross-site write path. A future domain can reuse the same composition if it can
express its state as bounded references and digests. A new core adapter should
only be proposed if a later profile demonstrates a semantic field that cannot
be represented by these generic contracts without changing authority or
verification rules.
