# ADR 0115: Compliance packs map controls to export evidence as data

- Status: accepted
- Date: 2026-10-18
- Owners: @Sannrox
- Discussion: none; decided in the implementation pull request for #1468
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1468
- Supersedes: none
- Superseded by: none
- Related: [ADR 0114](0114-signed-receipt-chain.md)

## Context

The auditor export (#297) packages receipts and decisions for a namespace and
time window, with a content digest and optional ed25519 signature. Auditors
still work from control frameworks (GDPR, NIS2, ISO/IEC 27001). Mapping each
control onto the right evidence by hand is the remaining gap. The mapping must
be versioned, operator-extensible, and honest about missing sources. It must
not claim legal compliance or certification.

## Decision

1. **Packs are JSON data, not code.** A pack (`sekai.compliance-pack/v1`) lists
   controls and the named evidence queries each control requires. The query
   catalog (`sekai.compliance-evidence-query/v1`) maps those names to audit
   decision actions already present in a #297 export. New frameworks are new
   pack files. New evidence kinds are catalog entries, not a query language.
2. **Evaluate the export, not the live store.** `sekaictl admin assurance
   compliance report` reads a compliance export and a pack and writes a report
   bundle (`sekai.compliance-pack-report/v1`). Removing a source from the
   export is how a control becomes `no_evidence` or `partly_met`.
3. **Status is evidence presence.** `met` means every named query for that
   control had at least one hit. `partly_met` means some but not all.
   `no_evidence` means none. The report lists hits (decision ids) and missing
   query ids. It does not assert that a control is satisfied in law.
4. **The report verifies offline.** The bundle embeds the pack that was used,
   the source export content digest, and its own digest. Optional ed25519
   signing reuses the export signature shape. `report-verify` recomputes the
   control results from the embedded pack and the supplied export without a
   database.
5. **Built-in packs are the mapping, not a coverage claim.** `fixture`,
   `gdpr`, `nis2`, and `iso27001` name the queries each listed control needs.
   `met` means those decision actions were in the export. Retention already
   persists `privacy.subject_erased` for `deletion_proofs`. Other catalog
   queries stay unevidenced until the corresponding actions appear; this
   slice does not add those writers. Clauses with no catalog query are
   omitted rather than listed as perpetual gaps.

## Alternatives considered

- Query the control-plane database directly: would require store credentials
  and would not be offline-verifiable.
- Encode match logic in Rust per framework: packs would not be data; operators
  could not add a control without a release.
- Treat report status as certification: contradicts the issue non-goal and
  would over-claim.

## Consequences

Operators generate a report from an existing export. Custom packs are JSON.
Trust follows the export digest and optional signature. Future evidence kinds
extend the catalog; they do not grow a general query engine.

## Validation

Focused tests on the fixture pack: all sources present mark mapped controls
`met`; removing a source turns affected controls to `no_evidence`; a two-query
control with one source is `partly_met`; a signed report verifies and tampering
fails digest checks.
