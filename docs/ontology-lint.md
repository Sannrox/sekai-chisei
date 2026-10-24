# Ontology lint

`GetOntologyLintReport` (#1454) reports structural problems in one
namespace's published definition and the data the caller may see. It is
`experimental`, so it is rejected unless `SEKAI_EXPERIMENTAL_RPCS=1` or the
`experimental-rpcs` Cargo feature is enabled. It reports and does not block.
Gating a definition proposal on findings is a separate layer.

```sh
sekaictl ontology lint --namespace <ns> [--target <url-or-socket>]
```

## Rules

| `rule` | Subject | Severity | Finds |
| --- | --- | --- | --- |
| `orphan_object_type` | object type | warning | no visible object of the type has a link to another visible object, and no visible consumer binding references it |
| `orphan_object` | object | info | an object of a published type with no link to another visible object of the namespace |
| `unowned_object_type` | object type | warning | the definition has no `owner`, and no catalog entry of the type lists an owner |
| `unowned_link_type` | link type | warning | the definition has no `owner` |
| `broad_marking_applied` | marking | warning | one `access_marking` token is on at least 90% of the visible objects |
| `broad_marking_granted` | marking | warning | at least 90% of the visible principal profiles have a classification ceiling at or above the level |
| `action_type_never_run` | Action type | info | an enabled Action type the caller administers, with no instance the caller may see among its latest 50 |
| `unreferenced_property` | property (`subject_id` is the type, `property` the property) | warning | a property in an object type's `properties` that no visible consumer binding (#837) references by name |

"Referenced" means declared by a registered consumer binding. The lint does not
count reads, and a binding to the whole type does not reference its
properties.

The broad-marking rules need a population of at least ten. `owner` is an
optional string on any definition member. Naming or changing it is a
compatible change.

## Suppressions

A definition member can suppress findings about itself, with a reason, in
`lint_suppressions` (#1684):

```json
{"name": "Ticket", "properties": ["title", "legacy"],
 "lint_suppressions": [
   {"rule": "unreferenced_property", "property": "legacy",
    "reason": "read by the nightly export"}]}
```

| Member kind | Rules it can suppress |
| --- | --- |
| object type | `orphan_object_type`, `unowned_object_type`, `unreferenced_property` (with `property`) |
| link type | `unowned_link_type` |

A definition edit is refused when an entry has no reason, names a rule its
member kind cannot raise, or sets `property` for any rule other than
`unreferenced_property` (or leaves it out for that rule). A suppressed finding
is still reported, with `suppressed` and its `suppression_reason`.
Suppressions are part of the definition, so a proposal diff shows a change to
them as `changed_lint_suppressions`, a compatible change. There is no
separate table. Findings about objects, markings and Action types cannot be
suppressed.

## Visibility

The caller needs read on the namespace and on every published member, as for
reading the published revision. Everything else the lint reads is limited to
what the caller may see: objects, links, consumer bindings, catalog entries
and principal profiles pass the object read policy. A link counts only when
the caller can see both of its ends, objects of the namespace of any kind.
Action types count only for a caller who administers them, and their
instances only as `GetActionInstance` would show them. A finding never names a hidden object,
consumer or principal. A hidden link or owner can at most cause an extra
finding.

## Bounds

At most 2,000 objects are scanned. A population larger than that (all
objects of a type, consumer bindings, catalog entries or principal profiles)
is not scanned at all, so the work stays bounded. Properties are read as a
read of the object would show them, after property grants and redaction.
Links are read up to 64 per object and direction, and at most 2,000 neighbor
objects are authorized. Past any of these bounds, the object rules
(`orphan_object_type`, `orphan_object`, `broad_marking_applied`) are skipped
and `complete` is false. `complete` is also false when a consumer, catalog or
profile scan is capped, or when findings past 500 are dropped. Findings are
sorted by rule and then by subject.
