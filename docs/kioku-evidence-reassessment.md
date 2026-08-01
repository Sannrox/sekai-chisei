# Kioku evidence reassessment

Kioku memory admission is outcome-driven, while later governed evidence can
change the support basis of an active memory. The ReassessKiokuMemory RPC
records that change as a candidate successor; it never changes the active
version.

Callers identify the active memory version, an idempotency key, and one or more
KiokuEvidenceBasis JSON records. A basis record contains the exact evidence
reference and digest, its supporting or contradicting stance, the admitted
evidence lifecycle state, and (for newly attached governed evidence) the
authoritative source_submission_id.

The control plane rechecks namespace and classification grants, source
submission digest and lifecycle, evidence retention, and projected-evidence
read authorization before creating a candidate. A source submission must be in
an admitted lifecycle state; quarantined, expired, or unreadable evidence is
rejected. A basis entry without a source submission is allowed only when it
matches the active memory's existing exact evidence identity and digest.

The successor ID is deterministic for (active memory id, version,
reassessment_key). Replaying the same key and evidence returns the existing
candidate with idempotent=true; a different basis under the same key is a
conflict. The candidate stores the sorted evidence basis digest, copied
operation links, sample size, confidence, uncertainty, derivation method, and
an explicit supersedes reference to the prior version. Lifecycle events use
evidence_reassessed; outcome-regression retirement continues to use its
existing outcome lifecycle and is not interpreted as source contradiction.

Promotion remains a human review operation. Until promotion, the active memory
and its original evidence remain unchanged. Concurrent reassessment attempts
share the deterministic candidate key, and normal review transaction fencing
allows at most one successor to supersede an active version.

Candidate listing is namespace- and operation-class-filtered, applies the
requesting actor's classification and evidence-read authorization, and uses a
stable keyset page token. Each request scans at most four 100-record backend
pages; callers continue with `next_page_token` when more candidates remain.
