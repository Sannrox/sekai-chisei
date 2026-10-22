# Neighborhood and path queries

`ExpandNeighborhood` and `FindPaths` are experimental RPCs for exploring how
objects are linked. They are classified `experimental`
([rpc-maturity.md](rpc-maturity.md)) and are rejected unless
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is
enabled. Capability discovery lists them as `sekai.relations.neighborhood` and
`sekai.relations.paths` with their limits; discovery is not a grant.

## Read policy at every hop

Both RPCs follow links in both directions. Every object reached is checked the
way `Traverse` checks it:

- row policy in the store query;
- namespace, collaboration, ACL, marking and object security policy;
- purpose;
- the delegated actor's markings;
- the marking join along the path ([classification-markings.md](classification-markings.md)).

An object that fails any check is omitted, and so is every link to it. Hidden
objects are never returned as placeholders, never counted, and never used as a
step in a path, so a response is the same as if they did not exist. A start
object the caller cannot read is reported as not found, with the same status
and message as a missing one. Returned objects pass through the same property grants and
redaction as every other read.

## ExpandNeighborhood

The request takes the following fields:

| Field | Meaning |
| --- | --- |
| `seed_ids` | Starting objects, 1 to 100. |
| `relations` | Link relations to follow. Empty follows every relation. |
| `object_kinds` | Kinds to include and expand beyond the seeds. Empty includes all kinds. |
| `depth` | Hops to walk, 1 to 4. Defaults to 1. |
| `fan_out_cap` | Neighbors per node that are returned and expanded. Defaults to 100, at most 1,000. |
| `limit` | Objects returned. Defaults to 100, at most 1,000. |

Objects come back with the seeds first, then in breadth-first order. Within one
node, neighbors are ordered by relation and id. `links` holds the links whose
two ends are both returned.

`total_count` counts every visible object within `depth`. That includes the
seeds, and it includes neighbors past a fan-out cap: they are counted but not
returned or expanded. When a cap or the examination budget leaves nodes
unexpanded, `total_is_lower_bound` is true. When fewer objects are returned
than counted, `truncated` is true. A seed with 10,000 visible neighbors
therefore returns one capped page together with a count of all 10,000.

## FindPaths

`FindPaths` returns the shortest paths between `from_id` and `to_id`:

| Field | Meaning |
| --- | --- |
| `max_depth` | Longest path searched, 1 to 4 links. Defaults to 4. |
| `relations` | Link relations to follow. Empty follows every relation. |
| `limit` | Paths returned. Defaults to 10, at most 100. |

Each path lists object ids from start to end, plus the link joining each
consecutive pair, in either direction. All paths have the shortest visible
length and come back in a stable order. `objects` holds every object on a
returned path, once. `truncated` is true when more shortest paths exist than
`limit`, or when the examination budget ran out before the search finished.
If no visible path of at most `max_depth` links exists, `paths` is empty.

## Limits

Each request examines at most 50,000 visible neighbor links. Past that budget,
the walk stops and the response reports a lower bound or truncation. Hidden
links never count against it. To protect the server, a request may also scan
at most 200,000 raw link rows, visible or not. Past that it fails with
`RESOURCE_EXHAUSTED` before any authorization work on those rows; narrow
`relations`, the seeds or the depth. A fan-out cap that skips a node before the
last level always marks the count as a lower bound, even if another parent
admits that node later.
