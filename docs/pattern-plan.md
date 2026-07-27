# Multi-hop pattern plan IR (`pattern_plan/v1`)

Issue: [#375](https://github.com/Sannrox/sekai-chisei/issues/375).  
Research freeze: [145-semantic-pattern-query.md](research/145-semantic-pattern-query.md) ([#145](https://github.com/Sannrox/sekai-chisei/issues/145)).

## Purpose

Provide a **versioned, structured, read-only** multi-hop pattern plan so callers
can express named intermediate variable bindings with hop-by-hop authorization
re-check, hard bounds, and a deterministic plan EXPLAIN — without introducing a
textual query dialect.

Example shape (domain-neutral kinds/relations in fixtures):

```text
A —rel_works_for→ B —rel_owns→ C —rel_uses→ D
```

## Plan version

| Id | Notes |
| --- | --- |
| `pattern_plan/v1` | Asserted graph only. Ephemeral plans (not stored). |

Unknown version ids are rejected with `INVALID_ARGUMENT`.

## Steps

| Op | Role |
| --- | --- |
| `match_node` | Bind a variable from `object_id` or `external_id` (exactly one). Optional `kind` constraint. |
| `expand_edge` | Expand one relation hop `from_var → to_var`. Direction: `outgoing` (default) or `incoming`. Optional `kind_filter` on the target. |
| `bind` | Project variables into result rows. Empty `vars` projects all bound vars in definition order. At most one bind step; an implicit bind is added when omitted. |

Plans require at least one `match_node`. Re-binding an already bound variable is
invalid. Expanding from an unbound variable is invalid.

## Bounds

Defaults and absolute caps reuse retrieval ceilings (`src/sekai/retrieval.rs`):

| Bound | Default | Cap |
| --- | --- | --- |
| `max_depth` (expand_edge count) | 3 | 3 |
| `max_rows` | 20 | 100 |
| `max_time_ms` | 100 | 1000 |
| `max_memory_bytes` | 1 MiB | 16 MiB |
| `max_source_rows` | 200 | 1000 |

Exceeding `max_depth` at plan validation time is `INVALID_ARGUMENT`. Runtime
caps set `truncated=true` with non-sensitive reasons only:
`max_rows`, `max_time_ms`, `max_source_rows`, `max_memory_bytes`.

## Authorization

1. **Plan-time name visibility.** Ontology-defined relation/class names the
   principal cannot read yield a non-disclosing `PERMISSION_DENIED` (`access
   denied`) on execute and EXPLAIN. Free-form asserted names not present in the
   ontology remain usable; hop-time object ACL is the data gate.
2. **Hop-time ACL re-check.** Each matched or expanded object is checked for
   object ACL, team namespace, markings, and reserved governance kinds.
   **Denied intermediate hops fail closed as absence**: no permission error, no
   secret names in errors, counts, truncation reasons, or EXPLAIN.

## gRPC

```text
ExecutePatternPlan
  plan: PatternPlan           # version + bounds + steps
  include_objects             # optional full Object payloads on projected vars

ExplainPatternPlan
  plan: PatternPlan           # same IR; no graph side effects
```

`ExplainPatternPlan` returns normalized bounds, step summaries, expand-edge
count, and projected variables. It never reports path existence, edge counts
from the store, or hidden names beyond what the caller already supplied (subject
to plan-time name visibility).

## Determinism

Under fixed bounds and a stable graph snapshot:

- links are examined in deterministic order (`target_id`, then `link.id`);
- result rows are sorted by projected variable object ids;
- truncation reasons and row order are stable across repeated executes.

## Capability catalog

`DiscoverCapabilities` advertises:

- `sekai.pattern.execute` → `ExecutePatternPlan`
- `sekai.pattern.explain` → `ExplainPatternPlan`

Scopes: `namespace:read`, `object:read`. Limits advertise `max_depth`,
`max_rows`, `plan_version_pattern_plan_v1=1`, and `asserted_graph_only=1`.

## Non-goals

- Core Ontology SQL, SPARQL, Cypher, or free-form NL planning
- Write / mutate plans
- Catalog projection of *named* pattern capabilities (follow-up on #151)
- Hybrid late-fusion (#360 / #361) — separate multi-representation path
- PostgreSQL parity as a gate (SQLite complete baseline)
- Entailment mode (asserted graph only in v1)

## Related

- Research freeze: [145-semantic-pattern-query.md](research/145-semantic-pattern-query.md)
- Single-frontier traversal: `Traverse` / `src/sekai/query.rs` (unchanged)
- Context retrieval: `RetrieveContext` / `src/sekai/retrieval.rs` (unchanged)
- Hybrid fusion: [hybrid-retrieval.md](hybrid-retrieval.md)
- Implementation: `src/sekai/pattern_plan.rs`
