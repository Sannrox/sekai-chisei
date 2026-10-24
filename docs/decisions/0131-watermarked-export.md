# ADR 0131: Watermarked exports carry an export-keyed fingerprint

- Status: accepted
- Date: 2026-10-24
- Issue: #1466
- Related: #1627, ADR 0130

## Context

A governed export records that data left the plane. Once a file is copied,
that receipt cannot tell which export a fragment came from. Marked
measurements can carry a per-export fingerprint without changing exact-value
properties.

## Decision

1. **Off until a marking says otherwise.** Fingerprinting is a
   `(namespace, marking)` policy (`PutExportFingerprintPolicy` /
   `GetExportFingerprintPolicy`) of an explicit `fingerprint_properties`
   allowlist. An empty list is off. Unmarked rows are never fingerprinted.
   The policy is not a classification-lattice field.
2. **Measurements only.** The allowlist may name only float or decimal
   measurement properties. Integers, identifiers, timestamps, strings,
   booleans, enums, `id`, and `access_marking` cannot be listed. A listed
   property present as one of those kinds refuses the export. A withheld
   cell is skipped.
3. **At most one last decimal place.** A listed decimal moves by at most
   one unit in its last decimal place, keyed by HMAC-SHA256 of the export
   id, row id, and property. The last digit's parity is that HMAC bit, so
   a fragment can be scored against a candidate export without stored
   originals.
4. **Receipt and permutation.** A fingerprinted export records the
   properties and group size on its receipt, stores a compact fingerprint
   record keyed by the export id, and permutes rows in groups of 16 under
   the same key. No default perturbation, no inferred numeric set, no
   canary rows.
5. **Trace is a governed read.** `TraceExport` takes a sample and format,
   scores fingerprint records in the namespace, and returns matches with a
   confidence. It is allowed to a namespace administrator, or to a caller
   for exports they initiated. Every call is an audit decision.

## Alternatives considered

- Perturb by default, or infer numeric columns: exact identifiers and
  counts would move, and unmarked data would be marked without a decision.
- Embed the fingerprint only in format metadata: CSV and JSON Lines have
  none that survives a partial copy.
- Recover originals from the watermarked value: given V' and the HMAC bit,
  unapplying is tautological; the identifiable signal is extracted parity
  versus HMAC.

## Consequences

- Two exports of the same marked measurements are distinguishable. A 10%
  sample of decimal cells identifies the export when enough unique
  fingerprinted cells remain. The HMAC is keyed by a version string and
  the export id, which the recipient already holds; this identifies a
  copy, it does not stop a holder from rewriting last digits. Unmarked
  decimals in the same column are not stored as originals, so a sample
  that is mostly unmarked cannot reach a perfect last-digit match.
- Exact-value properties stay byte-identical to the source projection.
  Put and export classify cells by spelling because there is no decimal
  property type; a listed name present as a non-decimal spelling refuses
  the export.
- Dataset rows without an object id key HMAC by the exported columns that
  are not in the fingerprint union, including a dataset column named `id`.

## Validation

Tests: two users exporting the same marked set get different files; each
file's 10% sample traces to that export; exact-value columns match the
source; a caller without an export or namespace administration is refused
and the refusal is audited.
