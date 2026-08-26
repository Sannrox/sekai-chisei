# Classification markings and purpose (#301)

## Purpose

Namespace ACLs alone do not express classification of artifacts or
purpose-based constraints on actions. v1 adds optional markings and purpose
gates on top of existing grants.

## Default vocabulary

Namespaces that never publish a lattice keep the evidence ordinal:

`public` < `internal` < `confidential` < `restricted`

That default is the stable contract for unmarked data. An activated namespace
may replace it with `sekai.classification-lattice/v1`. See
[ADR 0032](decisions/0032-hierarchical-classifications.md).

## Namespace lattices

Credential admins publish a lattice through `PutClassificationLattice` and
inspect it through `GetClassificationLattice`. The document names tokens,
parent edges (child → more-dominant parents), and explicit incomparable pairs.
Dominance is reachability from the marking to the caller’s sealed ceiling.

- **Unmarked objects** (missing or empty `access_marking`): no extra check.
- **Unactivated namespaces**: unknown tokens stay unmarked; only the evidence
  ordinal enforces clearance.
- **Activated lattices**: unknown tokens, stale digest or namespace identity,
  and incomparable joins fail closed. Hidden rows stay observationally
  identical to absent rows.
- Graph hops take the least upper bound of the path marking and the candidate.
  If that join does not exist, the hop is denied.
- Trusted service principals (`root`, `local`, `chisei-gateway`) remain an
  explicit exception.
- The sealed `classification_ceiling` is one global principal-profile token,
  interpreted in the object’s namespace lattice. Do not reuse a custom token
  name across lattices unless the same clearance is intended.

SQLite stores the lattice. PostgreSQL get returns no lattice so the default
ceiling stays in force; put is unavailable.

## Object markings

Objects may set property **`access_marking`** to a lattice token.
(This is intentionally not named `classification`, which is already used for
schema property redaction classes and free-form domain fields.)

- **Unmarked objects** (missing or empty value): no extra check
  (migration fail-open for existing data).
- **Marked objects**: principal must present a ceiling that dominates the
  marking, or be a trusted service principal. Otherwise read and action
  targeting fail closed with generic `access denied`.

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
governed mutation and admission boundaries. `ListObjects` walks principal-visible
SQL pages, counts only marking-visible rows for `total`, and returns the
requested offset/limit window over that filtered set.

## Audit / receipts

When a marking or purpose gate is **applicable** (not `not_applicable`):

- **GetObject** successful marking reads record decision action `marking.read`
  (per-object; includes decision id).
- Bulk surfaces (`ListObjects`, `Traverse`, find, retrieval) **enforce** marking
  without per-row allow audits to avoid ledger spam.

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
5. Purpose-bound reads require an activated object-security policy that names
   `required_purpose` plus a live `sekai.purpose-authorization/v1`. Principal
   `allowed_purposes` alone are not read authority.
6. Operators who need compartments or extra tokens publish
   `sekai.classification-lattice/v1` before marking objects with those tokens.

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
