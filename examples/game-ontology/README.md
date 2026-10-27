# game-ontology/v1 reference package

The ontology package of the game reference workload: players own planets,
fleets are stationed at planets, and players ally.

`crates/sekai-ontology/tests/reference_packages.rs` validates it with the same
offline import and `validate` checks as any ontology package. The synthetic
`GameWorkload` builds its tenant from it, and `tests/game_reference_actions.rs`
runs governed Action scenarios against its Fleet and Planet classes through the
public gRPC API.

## Policy pack and routing config

`policy-pack-v1.json` (`game-ontology.policy-pack/v1`) and `routing-v1.json`
(`game-ontology.routing/v1`) are versioned with the package. Both use only
shipped formats: Action types are `sekaictl admin governance action type put`
files, policies are `action policy set` scopes, budgets are `SetBudgetLimit`
fields, the lattice is `sekai.classification-lattice/v1`, and routes are
`SetNamespacePolicy` and model family enablement fields.
`reference_packages.rs` checks both against the package, and
`tests/game_governance_pack.rs` applies them to the server and shows one
allowed and one refused case per rule.
`tests/game_ai_players.rs` plays two AI players on one seed, one governed by
the pack and one in a namespace without its rules, through scripted alliance
betrayal, treasury drain and unapproved invasion scenarios. Model replies are
recorded in `tests/fixtures/game_players/` and replayed, so runs make no live
model calls.

`report/` holds the side-by-side report of those scenarios, as `report.json`
(`game-ontology.demo-report/v1`) and `report.md`: outcomes for both players,
policy blocks with the pack rule behind each, an audit and lineage excerpt,
and tokens per move, cost per win and routing savings. `tests/game_demo_report.rs`
builds it twice from the seed and recordings, checks both runs give the same
bytes, and compares them with the committed copy. Costs use the illustrative
price table in `tests/fixtures/game_players/prices-v1.json`; the report lists
how each field is computed, its normalization, and what it cannot fill yet.
Regenerate it with `GAME_REPORT_UPDATE=1 cargo test --test it game_demo_report`.

| Rule | Expressed as |
| --- | --- |
| Spending caps | `game.treasury.spend` caps `spend` at 500 in its parameter schema. Treasuries live in `game-treasury`, whose namespace Action budget admits 2 spends a day. |
| No attacks on allies | Attack and invasion types require `diplomacy` = `hostile` on the target planet. |
| Invasion approval | Invasions resolve to a `require_approval` policy scope with `admiral` as approver. |
| Spy-only visibility | Reports are marked `spy-only`, a lattice token only a `spy-only` ceiling dominates. |
| Turn budgets | A turn is a budget work unit. Opening a turn sets each route's token and call limits on `project:<route namespace>/agent:<player>/work_unit:<turn>`. |
| Day budgets | Token and call limits on the player's flat `agent:<player>` scope, which every route's chain includes. |
| Cheap local route | The `game` namespace allows only the local `native` runtime and enables only that family. |
| Expensive route | Only `game-high-impact` allows and enables `openai`. Callers send high-impact decisions there. |
| Hard stop | An exhausted turn or day budget denies the decision as `budget_denied`. The local route is `native`, so local-free fallback never applies. |

Known gaps, where the pack approximates or leaves a rule out:

- Spending caps are per day only. A governed Action budget subject has no
  work-unit segment, so there is no per-turn Action cap, and an admission is
  one unit whatever its `spend` amount (#1859).
- Alliances live in the identity extension's shared-space approvals, which
  submission criteria cannot read. The pack mirrors them as a `diplomacy`
  property the game keeps current (#1860).
- Routing cannot pick a model by an operation's impact class, so the caller
  chooses the high-impact namespace (#1861).
- A turn's limits must be set when the turn opens; there is no default limit
  for every work unit (#1862).
- With split stores, admission ignores an action type's `budget_scope`
  (#1863), so treasuries keep their own namespace; a submit refused for
  invalid parameters still charges a unit there (#1864).
