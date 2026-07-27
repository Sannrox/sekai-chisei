# Research: semantic pattern-query surface

Issue: [#145](https://github.com/Sannrox/sekai-chisei/issues/145)  
Related: #141 (closed), #144 (closed), #151 (open), #152 (open),
implementation [#375](https://github.com/Sannrox/sekai-chisei/issues/375)
([pattern-plan.md](../pattern-plan.md), plan version `pattern_plan/v1`)  
Date: 2026-07-27  
Status: **recommendation complete** (IR vertical: #375)

## Decision question

Should Sekai add a textual semantic query language, extend structured gRPC
queries, or adapt SPARQL/Cypher for ontology-aware multi-hop patterns?

## Evidence

### Existing surfaces

| Surface | Location | Strengths | Gaps for Alice-pattern |
| --- | --- | --- | --- |
| `GraphQuery` / `traverse` | `src/sekai/query.rs`, `Traverse` RPC | Bounded BFS, kind/property filters | Single relation frontier per step; no multi-hop *pattern* variables |
| Entailment retrieval | `src/sekai/retrieval.rs` (#144) | Asserted/entailment modes, hard bounds, authz-aware | Path is expansion/derivation, not named join patterns |
| Capability catalog | #106/#107, `docs/capability-catalog.md` | Discovery + governed invocation | Not a query language; composes fixed capabilities |

### Pattern evaluation (qualitative)

Example: `Alice —works_for→ Company —owns→ Project —uses→ Dataset`

| Option | Alice pattern | Authz during planning | Versioning | Local-first ops cost |
| --- | --- | --- | --- | --- |
| **Structured pattern/join protobuf** | Natural: steps as messages with variable bindings | Can re-check ACL at each hop; deny non-disclosing | Explicit plan schema version | Low; no parser surface |
| Small core DSL | Same after compile | Same if compile→same plan | Grammar + plan version | Medium; parser/security bugs |
| SPARQL/Cypher adapter | High expressiveness | Risk of planner leaks; must sandbox | External dialect drift | High; dependency + partial semantics |
| **No new syntax; compose #151** | Encode pattern as sequenced catalog capabilities | Best fit for governance | Capability package version | Lowest core cost |

### Why not SPARQL/Cypher in core

- Durable syntax must not be a SPARQL∪Cypher hybrid (issue constraint).
- Core would own dialect versioning forever while local-first deployments pay
  the cost whether they need graph SQL or not.
- Adapter boundary remains valid later if a product domain needs SPARQL *outside*
  the control plane.

### Why not a core DSL now

- Parser/version/EXPLAIN surface is a multi-issue product; benefits only appear
  after multi-hop join primitives exist.
- Spike parser only after structured joins prove insufficient ergonomics.

## Recommendation

**Prefer structured pattern/join protobufs as the durable core plan**, with
**capability composition (#151) as the primary product-facing surface** for
agent runtimes.

### Direction

1. **Core plan IR (v1):** versioned, read-only pattern steps:
   - `match_node` / `expand_edge` / `bind` with explicit variable names
   - bounds: depth, rows, time, memory (reuse retrieval constants)
   - deterministic `EXPLAIN` over the same IR
   - authorization at plan time (visibility of relation names) and hop time
2. **No core textual language** in this phase.
3. **#151** projects high-value patterns as named capabilities
   (`resolve` → `expand` → `retrieve` → `explain`) so runtimes do not invent
   RPC sequences.
4. **Optional later:** external SPARQL/Cypher *adapter* compiling to the same IR
   behind an adapter crate — not a core dialect.

### Implementation issue (single vertical)

When #151 is shaped or immediately if maintainer prioritizes IR first:

> **feat(sekai): structured multi-hop pattern plan IR and bounded executor**  
> Deliver protobuf/plan types + SQLite executor for the Alice path with ACL
> re-check, EXPLAIN, and fixture suite. No textual syntax.

### Explicit non-actions

- Do not adopt SPARQL or Cypher as a core public dialect.
- Do not invent a free-form NL pattern language.
- Do not treat #151 as blocked on a textual syntax choice.

## Conclusion

**Extend structured contracts, not text.** Compose for agents via #151; keep
any future textual language at an adapter boundary over a private core plan.
Close research #145 with this recommendation; open the IR vertical when ready
to implement.
