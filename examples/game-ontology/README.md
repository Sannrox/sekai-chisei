# game-ontology/v1 reference package

The ontology package of the game reference workload: players own planets,
fleets are stationed at planets, and players ally.

`crates/sekai-ontology/tests/reference_packages.rs` validates it with the same
offline import and `validate` checks as any ontology package. The synthetic
`GameWorkload` builds its tenant from it, and `tests/game_reference_actions.rs`
runs governed Action scenarios against its Fleet and Planet classes through the
public gRPC API.

## Policy pack and routing config

`policy-pack-v1.json` (`game-ontology.policy-pack/v1`) and `routing-v2.json`
(`game-ontology.routing/v2`) are versioned with the package. Both use only
shipped formats: Action types are `sekaictl admin governance action type put`
files, policies are `action policy set` scopes, budgets are `SetBudgetLimit`
fields, the lattice is `sekai.classification-lattice/v1`, and routing is
`SetNamespacePolicy` fields, including its `chisei.impact-route/v1` rule, and
model family enablement fields.
`reference_packages.rs` checks both against the package, and
`tests/game_governance_pack.rs` applies them to the server and shows one
allowed and one refused case per rule.
`tests/game_ai_players.rs` plays two AI players on one seed, one governed by
the pack and one in a namespace without its rules, through scripted alliance
betrayal, treasury drain and unapproved invasion scenarios. Model replies and
their token usage are recorded in `tests/fixtures/game_players/` and replayed,
so runs make no live model calls.

`report/` holds the side-by-side report of those scenarios, as `report.json`
(`game-ontology.demo-report/v1`) and `report.md`: outcomes for both players,
policy blocks with the pack rule behind each, an audit and lineage excerpt,
and tokens per move, cost per win and routing savings. `tests/game_demo_report.rs`
builds it twice from the seed and recordings, checks both runs give the same
bytes, and compares them with the committed copy. Costs are the ones each
model call's receipt records; the server prices them from the illustrative
table in `tests/fixtures/game_players/prices-v2.json`, passed as its
`CHISEI_GATEWAY_PRICING`. The report lists how each field is computed, its
normalization, and what it cannot fill yet.
Regenerate it with `GAME_REPORT_UPDATE=1 cargo test --test it game_demo_report`.

| Rule | Expressed as |
| --- | --- |
| Spending caps | `game.treasury.spend` caps `spend` at 500 in its parameter schema. Treasuries live in `game-treasury`, whose namespace Action budget admits 2 spends a day. |
| No attacks on allies | Attack and invasion types require `diplomacy` = `hostile` on the target planet. |
| Invasion approval | Invasions resolve to a `require_approval` policy scope with `admiral` as approver. |
| Spy-only visibility | Reports are marked `spy-only`, a lattice token only a `spy-only` ceiling dominates. |
| Turn budgets | A turn is a budget work unit. The token and call limits are the work-unit default (`SetBudgetWorkUnitDefault`) of `project:game/agent:<player>`, so every `work_unit:<turn>` under it gets its own budget without being set up. |
| Day budgets | Token and call limits on the player's flat `agent:<player>` scope, which every turn's chain includes. |
| Cheap local route | The `game` namespace's impact route rule gives `unclassified` and `routine` calls only the local `native-default` model. Decision steps cite no Action claim, so they route there; a request for the expensive model is substituted. |
| Expensive route | Only a `high_impact` call may use `gpt-5.5`: one citing a live claim, held by the caller, of the granted invasion's `runtime_dispatch` work. `game.planet.invade` is `high_impact`; attacks and spends are `routine`. A route override cannot pin it. |
| Hard stop | An exhausted turn or day budget denies the decision as `budget_denied`. The local route is `native`, so local-free fallback never applies. |

Known gaps, where the pack approximates or leaves a rule out:

- Spending caps are per day only. A governed Action budget subject has no
  work-unit segment, so there is no per-turn Action cap, and an admission is
  one unit whatever its `spend` amount (#1859).
- Alliances live in the identity extension's shared-space approvals, which
  submission criteria cannot read. The pack mirrors them as a `diplomacy`
  property the game keeps current (#1860).
- Both routes share the `game` namespace, so turn budgets cap the turn's
  model use as a whole, not per route.
- With split stores, admission ignores an action type's `budget_scope`
  (#1863), so treasuries keep their own namespace; a submit refused for
  invalid parameters still charges a unit there (#1864).
