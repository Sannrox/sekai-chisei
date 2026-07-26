# Classification markings and purpose (#301)

## Purpose

Namespace ACLs alone do not express classification of artifacts or
purpose-based constraints on actions. v1 adds optional markings and purpose
gates on top of existing grants.

## Provisional vocabulary

Classification lattice (reuses evidence classification order):

`public` < `internal` < `confidential` < `restricted`

This vocabulary is **provisional**. A later design discussion may refine or
replace it; the storage keys and fail-open/fail-closed posture below are the
stable contract for v1.

## Object markings

Objects may set property **`access_marking`** to one of the lattice tokens.
(This is intentionally not named `classification`, which is already used for
schema property redaction classes and free-form domain fields.)

- **Unmarked objects** (missing, empty, or non-lattice value): no extra check
  (migration fail-open for existing data).
- **Marked objects** (valid lattice token): principal must present a sufficient
  `classification_ceiling` or be a trusted service principal
  (`root`, `local`, `chisei-gateway`). Otherwise read and action targeting
  fail closed with generic `access denied`.

## Principal profiles

Principal attributes live on a graph object with:

- kind `principal_profile`
- external id `principal:<actor>` (must match `name`)

| Property | Meaning |
| --- | --- |
| `classification_ceiling` | Highest marking the principal may access |
| `allowed_purposes` | Comma-separated or JSON array of purpose tokens |

**Trust rules:**

- Create/update of `principal_profile` requires credential admin (`root` /
  `local`).
- Create sets `sealed_by_credential_admin=true` and seals with an Admin grant.
- Authority is **ignored** unless the profile is sealed and has an Admin grant.
  World-open or self-asserted profiles cannot confer clearance or purpose.

## Object read surfaces

Marking checks apply to `GetObject`, `FindByExternalId`, `FindByProperty`,
`ListObjects`, `Traverse`, `UpdateObject`, `DeleteObject`, context retrieval,
action execution, and approval resume. `ListObjects` walks principal-visible
SQL pages, counts only marking-visible rows for `total`, and returns the
requested offset/limit window over that filtered set.

## Action purpose

`ActionTypeDef.required_purpose` (proto field 7) gates invocation:

- Empty / unset: no purpose check.
- Set: principal’s `allowed_purposes` must include the token, unless the actor
  is a trusted service principal. Fail closed otherwise with
  `purpose not allow-listed`.

## Audit / receipts

When a marking or purpose gate is **applicable** (not `not_applicable`):

- **GetObject** successful marking reads record decision action `marking.read`
  (per-object; includes decision id).
- Bulk surfaces (`ListObjects`, `Traverse`, find, retrieval) **enforce** marking
  without per-row allow audits to avoid ledger spam.
- purpose allows/denies record `purpose.execute`

Evidence includes decision id (`marking:…` / `purpose:…`), classification
tokens, and a short detail string. Denied marking checks intentionally avoid
leaking classification details in the RPC error.

## Migration

1. Existing unmarked data continues to work without principal profiles.
2. Operators mark sensitive objects with `access_marking`.
3. Create `principal:<actor>` profiles with ceilings and purpose allow-lists
   before marking objects or purpose-gating actions that those principals use.
4. Purpose-gated action types only block callers once `required_purpose` is set
   on the action type definition.

## Residual risks (v1)

- **Deleted-object history**: `ListObjectChanges` for a missing object cannot
  reconstruct `access_marking` and falls back to ACL-only until tombstones
  retain markings.
- **List scan cost**: marking-aware list walks the ACL-visible set in pages to
  compute exact visible totals (fine for typical namespaces).

## Non-goals (v1)

- Full MLS / compartment lattice
- Replacing namespace isolation
- Enterprise IdP attribute sync (extension contracts remain)
- Egress/residency policy beyond existing data-class paths
