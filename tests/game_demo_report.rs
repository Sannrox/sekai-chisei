//! Side-by-side governance and cost report for the game demo scenarios
//! (#1856).
//!
//! Plays every scripted scenario of `game_ai_players` on its seed and
//! recorded replies, then reads what the server recorded through public RPCs
//! and renders one report, as `report.json` (schema
//! `game-ontology.demo-report/v1`) and `report.md`:
//!
//! - outcomes for both players, turn by turn, and the effect on the target;
//! - each policy block with the server's reason and the pack rule behind it;
//! - an audit excerpt (`GetActionInstance`, `ListDecisions`,
//!   `GetOperationReceipt`) and a lineage excerpt (`ExplainValue`);
//! - tokens per move, cost per win and savings from routing, priced with
//!   `fixtures/game_players/prices-v1.json`.
//!
//! The report keeps only fields that are the same on every run: no
//! timestamps, durations, change or decision ids, paths or hosts. Action
//! instance ids are replaced by `instance:<turn key>`. The test renders the
//! report twice, on two servers, and compares the bytes with each other and
//! with the golden copy in `examples/game-ontology/report/`. To regenerate
//! the golden copy:
//!
//! ```sh
//! GAME_REPORT_UPDATE=1 cargo test --test it game_demo_report
//! ```
#![cfg(unix)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use sekai_chisei::grpc::pb::chisei::GetOperationReceiptRequest;
use sekai_chisei::grpc::pb::sekai::{
    ExplainValueRequest, GetActionInstanceRequest, ListDecisionsRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::game_ai_players::{Outcome, Replay, SCENARIOS, SEED, Turn, Verdict, play, start};
use crate::game_governance_pack::{GovernedGame, pack};

const SCHEMA: &str = "game-ontology.demo-report/v1";
const ROUTING: &str = include_str!("../examples/game-ontology/routing-v1.json");
const RESPONSES: &str = include_str!("fixtures/game_players/responses-v1.json");
const PRICES: &str = include_str!("fixtures/game_players/prices-v1.json");
const PRICES_VERSION: &str = "game-players.prices/v1";
const REPORT_DIR: &str = "examples/game-ontology/report";
const UPDATE_ENV: &str = "GAME_REPORT_UPDATE";

/// The pack rule behind each block trigger: a submission criterion id, an
/// Action policy scope, or an Action budget subject.
const RULES: [(&str, &str); 3] = [
    ("target_is_hostile", "no_attacks_on_allies"),
    ("project:game-invasions", "invasion_approval"),
    ("action:governed/project:game-treasury", "spending_caps"),
];

/// How each derived field is computed. Rendered into both forms.
const METHODS: [(&str, &str); 6] = [
    (
        "tokens",
        "Input and output tokens of each move's model_called event in its GetOperationReceipt. The replay endpoint reports the same usage for every reply, because the recordings store none.",
    ),
    (
        "cost",
        "Each move's tokens priced at the route whose runtime the receipt's route_selected event names, using the fixture price table, in millicredits.",
    ),
    (
        "routing_savings",
        "Counterfactual: the same tokens priced at the high_impact route, minus the cost. It is not charged spend; no public RPC reads model spend per route.",
    ),
    (
        "win",
        "A move whose Action applied. The harness scores no game result.",
    ),
    (
        "cost_per_win",
        "Cost divided by wins, rounded to 3 decimals; null without a win.",
    ),
    (
        "rule",
        "The pack rule a block's trigger belongs to. A parked Action's trigger is the policy scope its instance names.",
    ),
];

const NORMALIZATION: [&str; 4] = [
    "Timestamps, durations, change ids, decision ids and model operation ids are left out.",
    "Action instance ids are replaced by instance:<turn key>; Action operation ids are the harness's deterministic operation-<turn key>.",
    "Receipts and decision records are excerpted to named fields; maps are sorted by key.",
    "Rows follow scenario order, then player (governed first), then turn.",
];

/// Report fields the existing public data does not fill, or fills only
/// approximately.
const GAPS: [(&str, &str); 4] = [
    (
        "#1866",
        "Plan execution charges model use only to the flat user budget scope, so per-route and per-turn model spend is neither charged nor readable; routing savings are counterfactual prices.",
    ),
    (
        "#1870",
        "No public RPC reads budget usage or remaining limit for a scope; tokens come from operation receipts.",
    ),
    (
        "#1871",
        "An Action submission refused by its Action budget leaves no instance, decision record or operation receipt; its audit row is empty.",
    ),
    (
        "#1872",
        "Chisei has no model price table; cost uses the fixture's illustrative prices. Recorded replies carry no token usage, so tokens per move reflect the replay endpoint.",
    ),
];

#[derive(Deserialize, Serialize, Clone)]
struct RoutePrice {
    route: String,
    runtime: String,
    input_per_1k: i64,
    output_per_1k: i64,
}

#[derive(Deserialize)]
struct Prices {
    version: String,
    unit: String,
    routes: Vec<RoutePrice>,
}

impl Prices {
    fn load() -> Self {
        let prices: Self = serde_json::from_str(PRICES).expect("prices json");
        assert_eq!(prices.version, PRICES_VERSION);
        prices
    }

    fn by(&self, field: impl Fn(&RoutePrice) -> &str, value: &str) -> &RoutePrice {
        self.routes
            .iter()
            .find(|price| field(price) == value)
            .unwrap_or_else(|| panic!("no price for {value}"))
    }
}

fn sha256(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    seed: u64,
    inputs: BTreeMap<&'static str, String>,
    prices: Vec<RoutePrice>,
    methods: BTreeMap<&'static str, &'static str>,
    normalization: Vec<&'static str>,
    scenarios: Vec<ScenarioReport>,
    totals: Sides<Cost>,
    gaps: Vec<Gap>,
}

#[derive(Serialize)]
struct Gap {
    issue: &'static str,
    gap: &'static str,
}

#[derive(Serialize)]
struct Sides<T> {
    governed: T,
    ungoverned: T,
}

#[derive(Serialize)]
struct ScenarioReport {
    scenario: String,
    players: Sides<PlayerReport>,
    blocks: Vec<Block>,
    audit: Vec<Audit>,
    lineage: Vec<Lineage>,
}

#[derive(Serialize)]
struct PlayerReport {
    turns: Vec<TurnReport>,
    effect: Effect,
    cost: Cost,
}

#[derive(Serialize)]
struct TurnReport {
    turn: usize,
    decision: Value,
    #[serde(flatten)]
    verdict: Verdict,
    route: String,
    input_tokens: i64,
    output_tokens: i64,
}

#[derive(Serialize)]
struct Effect {
    object: String,
    property: &'static str,
    value: String,
}

#[derive(Serialize)]
struct Block {
    player: &'static str,
    turn: usize,
    type_id: &'static str,
    verdict: &'static str,
    /// submission_criterion, action_policy or action_budget.
    mechanism: &'static str,
    trigger: String,
    /// What the server returned: deny reason, policy decision or status
    /// message.
    server_reason: String,
    rule: &'static str,
    rule_description: String,
}

#[derive(Serialize)]
struct Audit {
    player: &'static str,
    turn: usize,
    model: ModelReceipt,
    action: Option<ActionAudit>,
}

/// Excerpt of a model call's operation receipt.
#[derive(Serialize)]
struct ModelReceipt {
    complete: bool,
    namespace: String,
    route_policy_decision: String,
    runtime: String,
    model: String,
    routing_mode: String,
    budget_allowed: String,
    estimated_tokens: String,
    status: String,
}

#[derive(Serialize)]
struct ActionAudit {
    type_id: &'static str,
    operation_id: String,
    instance: Option<InstanceExcerpt>,
    decision_record: Option<DecisionExcerpt>,
    receipt: Option<ActionReceipt>,
}

#[derive(Serialize)]
struct InstanceExcerpt {
    instance: String,
    status: String,
    deny_reason: String,
    policy_decision: String,
    budget_decision: String,
}

#[derive(Serialize)]
struct DecisionExcerpt {
    actor: String,
    action: String,
    reason: String,
    outcome: String,
}

/// Excerpt of an Action's admission receipt.
#[derive(Serialize)]
struct ActionReceipt {
    complete: bool,
    missing_surfaces: Vec<String>,
    schema_version: String,
    /// Event kind to its attributes, with instance ids normalized.
    events: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Serialize)]
struct Lineage {
    player: &'static str,
    object: String,
    property: &'static str,
    value: String,
    complete: bool,
    writes: Vec<Write>,
}

#[derive(Serialize)]
struct Write {
    field: String,
    value: String,
    writer_kind: String,
    writer: String,
    receipt_id: String,
    changed_by: String,
}

/// Token and cost totals for one player.
#[derive(Default, Clone, Copy)]
struct Tally {
    moves: i64,
    model_calls: i64,
    input_tokens: i64,
    output_tokens: i64,
    cost: i64,
    high_impact_cost: i64,
    wins: i64,
}

impl Tally {
    fn add(&mut self, other: Tally) {
        self.moves += other.moves;
        self.model_calls += other.model_calls;
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cost += other.cost;
        self.high_impact_cost += other.high_impact_cost;
        self.wins += other.wins;
    }

    fn summary(self) -> Cost {
        let round = |value: f64| (value * 1000.0).round() / 1000.0;
        let tokens = self.input_tokens + self.output_tokens;
        Cost {
            moves: self.moves,
            model_calls: self.model_calls,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            tokens_per_move: round(tokens as f64 / self.moves as f64),
            cost_millicredits: self.cost,
            wins: self.wins,
            cost_per_win_millicredits: (self.wins > 0)
                .then(|| round(self.cost as f64 / self.wins as f64)),
            high_impact_cost_millicredits: self.high_impact_cost,
            routing_savings_millicredits: self.high_impact_cost - self.cost,
            tally: self,
        }
    }
}

#[derive(Serialize)]
struct Cost {
    moves: i64,
    model_calls: i64,
    input_tokens: i64,
    output_tokens: i64,
    tokens_per_move: f64,
    cost_millicredits: i64,
    wins: i64,
    cost_per_win_millicredits: Option<f64>,
    high_impact_cost_millicredits: i64,
    routing_savings_millicredits: i64,
    #[serde(skip)]
    tally: Tally,
}

impl Cost {
    /// The markdown rows of the cost table.
    fn rows(&self) -> [(&'static str, String); 9] {
        [
            ("Moves", self.moves.to_string()),
            ("Model calls", self.model_calls.to_string()),
            (
                "Tokens (in / out)",
                format!("{} / {}", self.input_tokens, self.output_tokens),
            ),
            ("Tokens per move", self.tokens_per_move.to_string()),
            ("Cost", self.cost_millicredits.to_string()),
            ("Wins", self.wins.to_string()),
            (
                "Cost per win",
                self.cost_per_win_millicredits
                    .map_or("n/a".into(), |cost| cost.to_string()),
            ),
            (
                "Cost at high_impact",
                self.high_impact_cost_millicredits.to_string(),
            ),
            (
                "Savings from routing",
                self.routing_savings_millicredits.to_string(),
            ),
        ]
    }
}

/// Reads the server's records for the played scenarios.
struct Reader<'a> {
    game: &'a GovernedGame,
    prices: Prices,
    /// Generated instance id to its stable label.
    labels: BTreeMap<String, String>,
}

impl Reader<'_> {
    fn label(&self, text: &str) -> String {
        self.labels
            .iter()
            .fold(text.to_string(), |text, (id, label)| {
                text.replace(id, label)
            })
    }

    async fn receipt(
        &self,
        request: GetOperationReceiptRequest,
    ) -> Option<(Value, bool, Vec<String>)> {
        let response = self
            .game
            .server
            .chisei()
            .await
            .get_operation_receipt(request)
            .await
            .ok()?
            .into_inner();
        let receipt = serde_json::from_str(&response.receipt_json).expect("receipt json");
        Some((receipt, response.complete, response.missing_surfaces))
    }

    async fn model(&self, turn: &Turn) -> (ModelReceipt, Tally) {
        let (receipt, complete, _) = self
            .receipt(GetOperationReceiptRequest {
                request_id: turn.request_id.clone(),
                ..Default::default()
            })
            .await
            .unwrap_or_else(|| panic!("{}: no model receipt", turn.request_id));
        let attribute = |kind: &str, name: &str| -> String {
            receipt["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| event["kind"] == kind)
                .and_then(|event| event["attributes"][name].as_str())
                .unwrap_or_default()
                .to_string()
        };
        let tokens = |name: &str| -> i64 { attribute("model_called", name).parse().unwrap_or(0) };
        let runtime = attribute("route_selected", "runtime");
        let price = self.prices.by(|price| &price.runtime, &runtime);
        let high_impact = self.prices.by(|price| &price.route, "high_impact");
        let (input, output) = (tokens("input_tokens"), tokens("output_tokens"));
        let tally = Tally {
            moves: 1,
            model_calls: i64::from(!attribute("model_called", "provider").is_empty()),
            input_tokens: input,
            output_tokens: output,
            cost: input * price.input_per_1k + output * price.output_per_1k,
            high_impact_cost: input * high_impact.input_per_1k + output * high_impact.output_per_1k,
            wins: i64::from(turn.verdict == Verdict::Applied),
        };
        let model = ModelReceipt {
            complete,
            namespace: receipt["namespace"].as_str().unwrap_or_default().into(),
            route_policy_decision: attribute("policy_decided", "route_policy_decision"),
            runtime,
            model: attribute("route_selected", "model"),
            routing_mode: attribute("route_selected", "routing_mode"),
            budget_allowed: attribute("budget_decided", "allowed"),
            estimated_tokens: attribute("budget_decided", "estimated_tokens"),
            status: attribute("outcome_recorded", "status"),
        };
        (model, tally)
    }

    async fn action(&self, turn: &Turn) -> Option<ActionAudit> {
        let submission = turn.submission.as_ref()?;
        let mut sekai = self.game.sekai.clone();
        let mut instance = None;
        let mut decision_record = None;
        if let Some(id) = &submission.instance_id {
            let found = sekai
                .get_action_instance(GetActionInstanceRequest {
                    instance_id: id.clone(),
                    ..Default::default()
                })
                .await
                .expect("action instance")
                .into_inner()
                .instance
                .expect("instance");
            instance = Some(InstanceExcerpt {
                instance: self.label(&found.instance_id),
                status: found.status,
                deny_reason: found.deny_reason,
                policy_decision: found.policy_decision,
                budget_decision: found.budget_decision,
            });
            let records: Vec<_> = sekai
                .list_decisions(ListDecisionsRequest {
                    target_id: id.clone(),
                    action: "submit_action_instance".into(),
                    limit: 10,
                    ..Default::default()
                })
                .await
                .expect("decisions")
                .into_inner()
                .decisions;
            assert_eq!(records.len(), 1, "{}: {records:?}", turn.request_id);
            let record = &records[0];
            decision_record = Some(DecisionExcerpt {
                actor: record.actor.clone(),
                action: record.action.clone(),
                reason: record.reason.clone(),
                outcome: record.outcome.clone(),
            });
        }
        let receipt = self
            .receipt(GetOperationReceiptRequest {
                operation_id: submission.operation_id.clone(),
                ..Default::default()
            })
            .await
            .map(|(receipt, complete, mut missing_surfaces)| {
                missing_surfaces.sort();
                let events = receipt["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|event| {
                        let attributes = event["attributes"]
                            .as_object()
                            .unwrap()
                            .iter()
                            .map(|(key, value)| {
                                (key.clone(), self.label(value.as_str().unwrap_or_default()))
                            })
                            .collect();
                        (event["kind"].as_str().unwrap().to_string(), attributes)
                    })
                    .collect();
                ActionReceipt {
                    complete,
                    missing_surfaces,
                    schema_version: receipt["schema_version"].as_str().unwrap().into(),
                    events,
                }
            });
        Some(ActionAudit {
            type_id: submission.type_id,
            operation_id: submission.operation_id.clone(),
            instance,
            decision_record,
            receipt,
        })
    }

    async fn lineage(&self, player: &'static str, object: &str, property: &'static str) -> Lineage {
        let explained = self
            .game
            .sekai
            .clone()
            .explain_value(ExplainValueRequest {
                object_id: object.into(),
                property: property.into(),
                as_of_ms: 0,
            })
            .await
            .expect("explain value")
            .into_inner();
        Lineage {
            player,
            object: object.into(),
            property,
            value: explained.value,
            complete: explained.complete,
            writes: explained
                .steps
                .into_iter()
                .map(|step| Write {
                    field: step.field,
                    value: step.value,
                    writer_kind: step.writer_kind,
                    writer: self.label(&step.writer_ref),
                    receipt_id: step.receipt_id,
                    changed_by: step.changed_by,
                })
                .collect(),
        }
    }

    async fn scenario(&self, outcome: &Outcome) -> ScenarioReport {
        let pack = pack();
        let mut players = Vec::new();
        let mut blocks = Vec::new();
        let mut audit = Vec::new();
        let mut lineage = Vec::new();
        let sides = [
            ("governed", &outcome.governed, &outcome.governed_effect),
            (
                "ungoverned",
                &outcome.ungoverned,
                &outcome.ungoverned_effect,
            ),
        ];
        for ((player, turns, effect), object) in sides.into_iter().zip(&outcome.targets) {
            let mut tally = Tally::default();
            let mut rows = Vec::new();
            for (index, turn) in turns.iter().enumerate() {
                let (model, turn_tally) = self.model(turn).await;
                tally.add(turn_tally);
                let action = self.action(turn).await;
                if let Some(block) = block(&pack, player, index, turn) {
                    blocks.push(block);
                }
                rows.push(TurnReport {
                    turn: index,
                    decision: turn.decision.clone(),
                    verdict: turn.verdict.clone(),
                    route: self
                        .prices
                        .by(|price| &price.runtime, &model.runtime)
                        .route
                        .clone(),
                    input_tokens: turn_tally.input_tokens,
                    output_tokens: turn_tally.output_tokens,
                });
                audit.push(Audit {
                    player,
                    turn: index,
                    model,
                    action,
                });
            }
            lineage.push(self.lineage(player, object, outcome.property).await);
            players.push(PlayerReport {
                turns: rows,
                effect: Effect {
                    object: object.clone(),
                    property: outcome.property,
                    value: effect.clone(),
                },
                cost: tally.summary(),
            });
        }
        let [governed, ungoverned]: [PlayerReport; 2] = players.try_into().ok().unwrap();
        ScenarioReport {
            scenario: outcome.scenario.clone(),
            players: Sides {
                governed,
                ungoverned,
            },
            blocks,
            audit,
            lineage,
        }
    }
}

/// The block a verdict records, with the pack rule behind its trigger.
fn block(pack: &Value, player: &'static str, turn: usize, played: &Turn) -> Option<Block> {
    let type_id = played.submission.as_ref()?.type_id;
    let (verdict, mechanism, trigger, server_reason) = match &played.verdict {
        Verdict::Applied | Verdict::Held => return None,
        Verdict::Denied { rule } => ("denied", "submission_criterion", rule.clone(), rule.clone()),
        Verdict::Parked { policy, scope, .. } => {
            ("parked", "action_policy", scope.clone(), policy.clone())
        }
        Verdict::Refused { message, .. } => {
            let subject = pack["action_budgets"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|budget| budget["subject"].as_str())
                .find(|subject| message.contains(subject))
                .unwrap_or_else(|| panic!("refusal names no pack budget: {message}"));
            (
                "refused",
                "action_budget",
                subject.to_string(),
                message.clone(),
            )
        }
    };
    let rule = RULES
        .iter()
        .find(|(known, _)| *known == trigger)
        .unwrap_or_else(|| panic!("no pack rule for trigger {trigger}"))
        .1;
    let rule_description = pack["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["rule"] == rule)
        .unwrap_or_else(|| panic!("pack has no rule {rule}"))["description"]
        .as_str()
        .unwrap()
        .into();
    Some(Block {
        player,
        turn,
        type_id,
        verdict,
        mechanism,
        trigger,
        server_reason,
        rule,
        rule_description,
    })
}

/// Plays every scenario on a fresh server and reads the report from it.
async fn build_report() -> Report {
    let replay = Replay::spawn(None).await;
    let game = start(&replay).await;
    let mut outcomes = Vec::new();
    for scenario in SCENARIOS {
        outcomes.push(play(&game, SEED, scenario).await);
    }
    let labels = outcomes
        .iter()
        .flat_map(|outcome| outcome.governed.iter().chain(&outcome.ungoverned))
        .filter_map(|turn| {
            let id = turn.submission.as_ref()?.instance_id.clone()?;
            Some((id, format!("instance:{}", turn.request_id)))
        })
        .collect();
    let reader = Reader {
        game: &game,
        prices: Prices::load(),
        labels,
    };
    let mut scenarios = Vec::new();
    let mut totals = [Tally::default(); 2];
    for outcome in &outcomes {
        let scenario = reader.scenario(outcome).await;
        totals[0].add(scenario.players.governed.cost.tally);
        totals[1].add(scenario.players.ungoverned.cost.tally);
        scenarios.push(scenario);
    }
    let version = |document: &str| -> String {
        serde_json::from_str::<Value>(document).unwrap()["version"]
            .as_str()
            .unwrap()
            .into()
    };
    let pack_version = pack()["version"].as_str().unwrap().to_string();
    Report {
        schema: SCHEMA,
        seed: SEED,
        inputs: BTreeMap::from([
            ("policy_pack", pack_version),
            ("routing", version(ROUTING)),
            ("responses", version(RESPONSES)),
            ("responses_sha256", sha256(RESPONSES)),
            ("prices", version(PRICES)),
            ("prices_sha256", sha256(PRICES)),
            ("price_unit", reader.prices.unit.clone()),
        ]),
        prices: reader.prices.routes.clone(),
        methods: METHODS.into_iter().collect(),
        normalization: NORMALIZATION.to_vec(),
        scenarios,
        totals: Sides {
            governed: totals[0].summary(),
            ungoverned: totals[1].summary(),
        },
        gaps: GAPS
            .iter()
            .map(|&(issue, gap)| Gap { issue, gap })
            .collect(),
    }
}

impl Report {
    fn json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap() + "\n"
    }

    fn markdown(&self) -> String {
        let mut out = String::new();
        let cell = |text: &str| text.replace('|', "\\|");
        let unset = |value: &str| {
            if value.is_empty() {
                "(unset)".to_string()
            } else {
                value.to_string()
            }
        };
        let verdict = |verdict: &Verdict| match verdict {
            Verdict::Applied => "applied".to_string(),
            Verdict::Held => "held".to_string(),
            Verdict::Denied { rule } => format!("denied: `{rule}`"),
            Verdict::Parked {
                policy,
                scope,
                rule,
                approvers,
            } => format!(
                "parked: `{policy}` by `{scope}` `{rule}`, approvers `{}`",
                approvers.join(",")
            ),
            Verdict::Refused { code, message } => format!("refused ({code}): {message}"),
        };
        let cost_table = |out: &mut String, governed: &Cost, ungoverned: &Cost| {
            out.push_str("| | Governed | Ungoverned |\n| --- | --- | --- |\n");
            for ((name, governed), (_, ungoverned)) in
                governed.rows().into_iter().zip(ungoverned.rows())
            {
                let _ = writeln!(out, "| {name} | {governed} | {ungoverned} |");
            }
        };

        let _ = write!(
            out,
            "# Game demo report\n\n\
             Generated by `tests/game_demo_report.rs` ({schema}); do not edit by hand.\n\
             Regenerate with `{UPDATE_ENV}=1 cargo test --test it game_demo_report`.\n\n\
             | Input | |\n| --- | --- |\n| Seed | {seed} |\n",
            schema = self.schema,
            seed = self.seed,
        );
        for (name, value) in &self.inputs {
            let _ = writeln!(out, "| {name} | `{value}` |");
        }
        out.push_str("\nCosts are in millicredits at these illustrative route prices (credits per 1000 tokens):\n\n");
        out.push_str("| Route | Runtime | Input | Output |\n| --- | --- | --- | --- |\n");
        for price in &self.prices {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                price.route, price.runtime, price.input_per_1k, price.output_per_1k
            );
        }

        for scenario in &self.scenarios {
            let players = &scenario.players;
            let _ = write!(
                out,
                "\n## {}\n\n### Outcomes\n\n\
                 | Turn | Decision | Governed | Ungoverned |\n| --- | --- | --- | --- |\n",
                scenario.scenario
            );
            for (governed, ungoverned) in
                players.governed.turns.iter().zip(&players.ungoverned.turns)
            {
                let decision = if governed.decision == ungoverned.decision {
                    format!("`{}`", governed.decision)
                } else {
                    format!("`{}` / `{}`", governed.decision, ungoverned.decision)
                };
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} |",
                    governed.turn,
                    cell(&decision),
                    cell(&verdict(&governed.verdict)),
                    cell(&verdict(&ungoverned.verdict)),
                );
            }
            for player in [&players.governed, &players.ungoverned] {
                let effect = &player.effect;
                let _ = writeln!(
                    out,
                    "\n`{}.{}` afterwards: `{}`",
                    effect.object,
                    effect.property,
                    unset(&effect.value)
                );
            }

            out.push_str("\n### Policy blocks\n\n");
            if scenario.blocks.is_empty() {
                out.push_str("None.\n");
            } else {
                out.push_str(
                    "| Player | Turn | Action | Verdict | Mechanism | Trigger | Rule |\n\
                     | --- | --- | --- | --- | --- | --- | --- |\n",
                );
                for block in &scenario.blocks {
                    let _ = writeln!(
                        out,
                        "| {} | {} | `{}` | {} | {} | `{}` | `{}`: {} |",
                        block.player,
                        block.turn,
                        block.type_id,
                        block.verdict,
                        block.mechanism,
                        block.trigger,
                        block.rule,
                        cell(&block.rule_description),
                    );
                }
            }

            out.push_str(
                "\n### Audit\n\n\
                 | Player | Turn | Model route | Action | Instance | Decision record | Admission receipt |\n\
                 | --- | --- | --- | --- | --- | --- | --- |\n",
            );
            for entry in &scenario.audit {
                let model = &entry.model;
                let route = format!(
                    "{} `{}` in `{}`, policy {}, budget allowed {}",
                    model.routing_mode,
                    model.model,
                    model.namespace,
                    model.route_policy_decision,
                    model.budget_allowed
                );
                let (action, instance, record, receipt) = match &entry.action {
                    None => ("held".to_string(), "".into(), "".into(), "".into()),
                    Some(action) => (
                        format!("`{}` `{}`", action.type_id, action.operation_id),
                        action.instance.as_ref().map_or("none".to_string(), |i| {
                            format!(
                                "{}: policy {}, budget {}",
                                i.status, i.policy_decision, i.budget_decision
                            )
                        }),
                        action
                            .decision_record
                            .as_ref()
                            .map_or("none".to_string(), |r| {
                                format!("{} by {}: {}", r.action, r.actor, r.reason)
                            }),
                        action.receipt.as_ref().map_or("none".to_string(), |r| {
                            let events: Vec<String> = r
                                .events
                                .iter()
                                .map(|(kind, attributes)| {
                                    let shown: Vec<String> = attributes
                                        .iter()
                                        .filter(|(key, _)| key.as_str() != "request_digest")
                                        .map(|(key, value)| format!("{key}={value}"))
                                        .collect();
                                    format!("{kind} ({})", shown.join(", "))
                                })
                                .collect();
                            format!("`{}`: {}", r.schema_version, events.join("; "))
                        }),
                    ),
                };
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} | {} | {} |",
                    entry.player,
                    entry.turn,
                    cell(&route),
                    cell(&action),
                    cell(&instance),
                    cell(&record),
                    cell(&receipt),
                );
            }

            out.push_str(
                "\n### Lineage\n\n\
                 | Player | Value | Writes, oldest first |\n| --- | --- | --- |\n",
            );
            for entry in &scenario.lineage {
                let writes: Vec<String> = entry
                    .writes
                    .iter()
                    .map(|write| {
                        let writer = if write.writer.is_empty() {
                            write.writer_kind.clone()
                        } else {
                            format!("{} `{}`", write.writer_kind, write.writer)
                        };
                        format!(
                            "`{}` = `{}` by {} ({writer})",
                            write.field, write.value, write.changed_by
                        )
                    })
                    .collect();
                let _ = writeln!(
                    out,
                    "| {} | `{}.{}` = `{}` | {} |",
                    entry.player,
                    entry.object,
                    entry.property,
                    unset(&entry.value),
                    if writes.is_empty() {
                        "none".to_string()
                    } else {
                        cell(&writes.join("; "))
                    },
                );
            }

            out.push_str("\n### Cost\n\n");
            cost_table(&mut out, &players.governed.cost, &players.ungoverned.cost);
        }

        out.push_str("\n## Totals\n\n");
        cost_table(&mut out, &self.totals.governed, &self.totals.ungoverned);

        out.push_str("\n## Methods\n\n");
        for (name, method) in &self.methods {
            let _ = writeln!(out, "- `{name}`: {method}");
        }
        out.push_str("\n## Normalization\n\n");
        for rule in &self.normalization {
            let _ = writeln!(out, "- {rule}");
        }
        out.push_str("\n## Gaps\n\n");
        for gap in &self.gaps {
            let _ = writeln!(out, "- {}: {}", gap.issue, gap.gap);
        }
        out
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_report_is_byte_identical_and_matches_the_golden_copy() {
    let first = build_report().await;
    let second = build_report().await;
    let rendered = [first.json(), first.markdown()];
    assert_eq!(rendered, [second.json(), second.markdown()]);

    // Each governed block names its pack rule, and no ungoverned move is
    // blocked.
    let rules: Vec<(&str, &str)> = first
        .scenarios
        .iter()
        .flat_map(|scenario| &scenario.blocks)
        .map(|block| (block.player, block.rule))
        .collect();
    assert_eq!(
        rules,
        [
            ("governed", "no_attacks_on_allies"),
            ("governed", "spending_caps"),
            ("governed", "invasion_approval"),
        ]
    );
    assert!(first.totals.governed.routing_savings_millicredits > 0);

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(REPORT_DIR);
    let files = ["report.json", "report.md"];
    if std::env::var_os(UPDATE_ENV).is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        for (file, content) in files.iter().zip(&rendered) {
            std::fs::write(dir.join(file), content).unwrap();
        }
        return;
    }
    for (file, content) in files.iter().zip(&rendered) {
        let golden = std::fs::read_to_string(dir.join(file)).unwrap_or_default();
        assert!(
            golden == *content,
            "{REPORT_DIR}/{file} is stale; regenerate with {UPDATE_ENV}=1 cargo test --test it game_demo_report\n{content}"
        );
    }
}
