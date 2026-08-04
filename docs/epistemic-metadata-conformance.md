# Epistemic metadata conformance

Issue #497 defines a non-disclosure boundary for the additive
`chisei.epistemic-descriptor/v1` projection. Metadata is useful only after the
underlying source has passed namespace, object-ACL, classification, and
lifecycle checks; it must never become an existence oracle for withheld facts.

The default-CI black-box suite is
`tests/epistemic_metadata_conformance.rs`:

- an authorized graph snapshot is compared with the same snapshot containing
  an ACL-denied object in another namespace;
- denied neighbors do not change candidates, links, descriptors, source refs,
  counts, ordering, truncation, or errors;
- a denied root and a missing root have the same public retrieval shape;
- receipt attributes remain bounded structural summaries and contain neither
  hidden identities nor descriptor payload; and
- deterministic malformed-descriptor cases cover source-list limits, row
  limits, control characters, observation bounds, confidence bounds, and the
  mixed-authorization rule that Kioku projections do not disclose linked
  evidence digests.

The service keeps internal denied-root accounting separate from retrieval
diagnostics. Public graph projections map a denied root to the same generic
unresolved-root shape as an absent root and always omit denied-object counts;
denied traversal neighbors do not contribute to public counts. The retrieval
engine's own unit tests continue to exercise detailed internal accounting.

## Existing cross-boundary evidence

The conformance suite is intentionally small and composes existing focused
tests rather than recreating every source fixture:

- `src/chisei/epistemic_descriptor.rs` covers asserted, derived, hypothesis,
  Kioku supported/contested/insufficient, stale/retracted/superseded lifecycle,
  external evidence, aggregate byte bounds, and source-digest omission.
- `src/chisei/pipeline.rs` covers local versus external egress, classification
  ceilings, object-property redaction, Kioku applicability, and bounded
  egress records.
- `src/grpc/sekai_service.rs` covers evidence submission lifecycle and
  content authorization, ontology ACL filtering, and semantic catalog binding.
- `src/grpc/chisei_service.rs` covers native pipeline planning/execution,
  gateway sampling through the canonical decision preflight, receipt descriptor
  aggregates, and egress-audit projections.

Asserted graph retrieval is reusable on SQLite and PostgreSQL. Query-time
ontology entailment remains SQLite-only; PostgreSQL returns an explicit
`FAILED_PRECONDITION` instead of a partial inference projection. The suite is
credential- and service-free; backend-specific PostgreSQL conformance remains
covered by the existing ignored inventory tests when
`SEKAI_TEST_POSTGRES_URL` is supplied.
