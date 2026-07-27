# Research: when can a governed ontology lookup replace a model call?

Issue: [#175](https://github.com/Sannrox/sekai-chisei/issues/175)
Related: #144 (closed), #151 (catalog), #152 (recommendation complete; #360/#361
shipped), #281 (feature; S1 shipped)
Date: 2026-07-26
Status: **recommendation complete — S1 shipped (#281)**

## Decision question

For which request classes can a bounded, authorized ontology/capability lookup
fully answer a request that today dispatches to a model — and is the cost
reduction large enough to justify the correctness machinery?

## Evidence collected

### Pipeline placement (code)

| Step | Location | Behavior |
| --- | --- | --- |
| Object context enrich | `ObjectContextEnrichStep` / `run_object_context_enrich` | Injects authorized object context into the **spec**; does not short-circuit dispatch |
| Kioku / learnings enrich | adjacent enrich steps | Same pattern: enrich then continue |
| `template_only` | early return in enrich paths | Sanitization contract; not an answer surface |
| Plan / execute | later pipeline | Model path remains the answer producer |

Substitution would sit **after** enrichment and authz/egress checks, **before**
provider routing, returning a normal operation receipt with **zero provider
tokens** when fully satisfied (as #281 sketches). That placement is coherent
with existing step order; the gap is substrate and measurement, not topology.

### Retrieval / catalog substrate

| Work | State | Relevance |
| --- | --- | --- |
| #144 bounded entailment-aware retrieval | **Closed** | Graph can answer some structured traversals with provenance |
| #151 semantic retrieval through capability catalog | **Open** | Deliberately scopes natural-language work to a **governed model call** |
| #152 hybrid retrieval contract | Blocked | Would define combined lookup surfaces |

Any substitution that answers free-form or catalog NL questions without a model
would reverse #151’s boundary unless #151 is reopened. Structured capability
contracts (fixed inputs → fixed graph query → fixed output schema) are the only
safe v1 class that does not reverse that boundary.

### Request-record reconstructability

Today’s durable artifacts for post-hoc analysis:

- Operation receipts (events, attributes, models, outcomes)
- Budget / route decisions
- Enrichment is reflected as pipeline actions, not as a full “inputs that
  determined the answer” dependency graph

**Finding:** current records are **insufficient** to measure, from production
history alone, “would a lookup have fully determined this answer?” at scale.
They support fixture design and manual case review, not a reliable volume/spend
fraction without new instrumentation (structured task class + dependency tags +
optional golden structured answer).

### Sampling / fractions

No checked-in production request corpus or anonymized fleet export is available
in this repository. Therefore **no numeric addressable fraction** can be
honestly claimed. Estimates without that corpus would be fiction.

What *can* be ranked qualitatively:

| Opportunity class | Likelihood | Notes |
| --- | --- | --- |
| Catalog capability with pure graph facts (id → properties/links) | Highest | Fits fixed contract; authz re-check required |
| Ontology class/relation inspection | Medium | Already partially served by inspect artifacts; not dispatch-shaped |
| Enrichment-redundant NL (“summarize these objects”) | Low–medium | Enrichment already loads objects; model still does language work |
| Open-ended NL planning / coding / free-form Q&A | Lowest | Out of scope; wrong-but-confident risk high |

### Equivalence-checking sketch (for when reopened)

1. **Contract mode:** capability declares `answer_mode=structured_lookup` and a
   query template; output must validate against a schema.
2. **Dual-run eval (shadow):** for allow-listed fixtures, run lookup and model;
   require structural equality or bounded semantic judge under eval suite
   (feeds #280/#300 gates).
3. **Fail closed:** any incomplete graph, ACL miss, or schema miss → model path
   with `lookup_refusal` on the receipt.
4. **Never silent:** receipts always mark `lookup_hit` vs `model_path`.

Wrong lookup is worse than cost regression because it does not show up as
spend. Shadow dual-run + promotion gate is the minimum correctness machinery.

## Options evaluated

| Option | Verdict |
| --- | --- |
| No addressable set | Too strong; structured catalog lookups clearly exist in principle |
| Narrow deterministic set | **Likely true**, but **not implementable safely** until #151 surfaces exist |
| Enrichment-adjacent set | Partial; enrichment reduces *prompt* work, not *answer* authority |
| Deferred | **Recommended now** |

## Recommendation

**Defer** implementation of #281 (and this research’s “proceed” path) until:

1. **#151 lands** (or is explicitly reshaped) so there is a governed capability
   contract for retrieval-shaped answers without reversing the NL→model boundary
   by accident; and
2. **Minimum instrumentation** exists to tag operations with task class and
   optional structured dependency refs (object ids / query profile) so a later
   study can measure volume and spend; and
3. At least one **eval suite** of dual-run fixtures exists (can use #300 feedback
   promotion for operator-accepted structured cases).

### Re-open condition

Re-open #175 (or spawn a short follow-up research) when #151 is closed **or**
maintainer explicitly authorizes a fixed allow-list of non-NL capability ids for
lookup-first answers. Then re-measure with fixtures + dual-run eval before
shipping #281.

### Explicit non-actions

- Do **not** implement free-form NL lookup substitution in core.
- Do **not** treat enrichment success as proof the model call was redundant.
- Do **not** claim a spend % without a measured corpus.

## Impact on #281

Maintainer decision **S1** (issue #281 comment) unblocked a narrow
implementation after #151 landed:

- Allow-listed structured capabilities only (`sekai.semantic.*` / `sekai.context.retrieve`).
- Fixture suite + dual-run structural equality (no production corpus / no fleet spend %).
- Fail closed to model path with `lookup_refusal`; receipts mark `lookup_hit` vs `model_path`.

See `docs/capability-catalog.md` (Lookup-first answers) and
`src/chisei/lookup_first.rs`.

## Conclusion

There is a **plausible narrow deterministic set** of lookup-shaped capabilities.
Research initially deferred broad fleet measurement; maintainer **S1** then
shipped a bounded allow-list short-circuit via #281 (see Impact section above).
Close this research as **recommendation complete with S1 shipped**; further
spend % claims still require measured corpora beyond the structural dual-run
fixture suite.
