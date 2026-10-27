//! The game reference workload's policy pack and budget and routing config
//! (#1854).
//!
//! `examples/game-ontology/policy-pack-v1.json` and `routing-v1.json` are
//! versioned with the `game-ontology/v1` package. Each test applies them to
//! the shipped binary through its public surfaces, the operator CLI and gRPC,
//! and shows one allowed and one refused case for one rule. Routing decisions
//! go through `DecideGatewayExecution`, which never calls a provider.
#![cfg(unix)]

use sekai_chisei::grpc::client::GatewayClient;
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::chisei::{
    DecideGatewayExecutionRequest, DecideGatewayExecutionResponse, RecordUsageRequest,
    SetBudgetLimitRequest, SetModelFamilyEnablementRequest, SetNamespacePolicyRequest,
};
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{
    ActionInstance, ClassificationIncomparablePair, ClassificationLattice,
    ClassificationParentEdge, CreateObjectRequest, DecideActionInstanceRequest,
    EnsureTeamNamespaceRequest, GetObjectRequest, Object, PutClassificationLatticeRequest,
    SubmitActionInstanceRequest,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use tonic::Code;

use crate::product_loop_backend_conformance::{Backend, LoopServer, bearer};

const PACKAGE: &str = include_str!("../examples/game-ontology/game-v1.json");
const PACK: &str = include_str!("../examples/game-ontology/policy-pack-v1.json");
const ROUTING: &str = include_str!("../examples/game-ontology/routing-v1.json");

pub(crate) fn pack() -> Value {
    serde_json::from_str(PACK).expect("policy pack json")
}

pub(crate) fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn write_json(dir: &std::path::Path, name: &str, value: &Value) -> String {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

/// The package classes the pack governs, as the operator CLI's ontology
/// document.
fn ontology() -> Value {
    let package: Value = serde_json::from_str(PACKAGE).expect("package json");
    let classes: Vec<Value> = ["Planet", "Treasury", "Report"]
        .into_iter()
        .map(|name| {
            let found = package["classes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|class| class["name"] == name)
                .unwrap_or_else(|| panic!("package has no {name} class"));
            json!({
                "name": name,
                "description": found["description"],
                "mapped_kind": name.to_lowercase(),
                "ensure_kind": true,
                "kind_description": format!("{name} (game-ontology/v1)"),
            })
        })
        .collect();
    json!({"version": "sekai.ontology-product/v1", "classes": classes, "relations": []})
}

/// The namespace the pack registers `type_id` in.
pub(crate) fn type_namespace(type_id: &str) -> String {
    pack()["action_types"]
        .as_array()
        .unwrap()
        .iter()
        .find(|type_def| type_def["type_id"] == type_id)
        .unwrap_or_else(|| panic!("pack has no {type_id}"))["namespace"]
        .as_str()
        .unwrap()
        .into()
}

/// One player's world, and its treasury in the namespace the pack puts
/// spends in. Reports take the marking the pack assigns their class.
fn seeds() -> [Value; 2] {
    let report_marking = pack()["markings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|marking| marking["class"] == "Report")
        .expect("Report marking")["access_marking"]
        .clone();
    let planet = |id: &str, diplomacy: &str| json!({"id": id, "kind": "planet", "name": id, "properties": {"diplomacy": diplomacy}});
    [
        json!({
            "version": "sekai.seed/v1",
            "namespace": type_namespace("game.planet.attack"),
            "objects": [
                planet("p-rival", "hostile"),
                planet("p-ally", "allied"),
                {"id": "r-spy", "kind": "report", "name": "r-spy", "properties": {"access_marking": report_marking}},
                {"id": "r-brief", "kind": "report", "name": "r-brief", "properties": {"access_marking": "internal"}},
            ],
        }),
        json!({
            "version": "sekai.seed/v1",
            "namespace": type_namespace("game.treasury.spend"),
            "objects": [
                {"id": "t-main", "kind": "treasury", "name": "t-main", "properties": {"spend": "0"}},
            ],
        }),
    ]
}

/// A server with the policy pack applied, and a token per workload role.
pub(crate) struct GovernedGame {
    pub(crate) server: LoopServer,
    pub(crate) sekai: SekaiServiceClient<GatewayClient>,
    pub(crate) tokens: HashMap<&'static str, String>,
}

impl GovernedGame {
    async fn start() -> Self {
        Self::start_with_env(&[]).await
    }

    /// Like [`Self::start`], with extra server environment such as a model
    /// endpoint.
    pub(crate) async fn start_with_env(env: &[(&str, &str)]) -> Self {
        let server = LoopServer::spawn_with_env(&Backend::Sqlite, env);
        let logs = || server.logs();
        let pack = pack();
        let files = tempfile::tempdir().unwrap();
        let socket = server.socket_str();
        let mut sekai = server.sekai().await;

        // Markings first, so the seeded reports carry an activated token.
        let lattice = &pack["classification_lattice"];
        sekai
            .put_classification_lattice(PutClassificationLatticeRequest {
                lattice: Some(ClassificationLattice {
                    contract_version: lattice["contract_version"].as_str().unwrap().into(),
                    namespace: lattice["namespace"].as_str().unwrap().into(),
                    tokens: strings(&lattice["tokens"]),
                    parents: lattice["parents"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|edge| ClassificationParentEdge {
                            child: edge["child"].as_str().unwrap().into(),
                            parent: edge["parent"].as_str().unwrap().into(),
                        })
                        .collect(),
                    incomparable: lattice["incomparable"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|pair| ClassificationIncomparablePair {
                            left: pair["left"].as_str().unwrap().into(),
                            right: pair["right"].as_str().unwrap().into(),
                        })
                        .collect(),
                    digest: String::new(),
                }),
            })
            .await
            .unwrap_or_else(|error| panic!("lattice: {error}\n{}", logs()));
        let [world, treasury] = seeds();
        for (command, file, document) in [
            ("apply", "ontology.json", ontology()),
            ("seed", "world.json", world),
            ("seed", "treasury.json", treasury),
        ] {
            server.sekaictl_ok(&[
                "ontology",
                command,
                "--file",
                &write_json(files.path(), file, &document),
                "--target",
                &socket,
            ]);
        }

        let mut tokens = HashMap::new();
        for (principal, role) in [
            ("commander", "editor"),
            ("admiral", "viewer"),
            ("spy", "viewer"),
        ] {
            for namespace in ["game.planet.attack", "game.treasury.spend"].map(type_namespace) {
                sekai
                    .ensure_team_namespace(EnsureTeamNamespaceRequest {
                        namespace,
                        principal: principal.into(),
                        role: role.into(),
                    })
                    .await
                    .unwrap_or_else(|error| panic!("grant {principal}: {error}\n{}", logs()));
            }
            tokens.insert(principal, server.token(principal));
        }
        for clearance in pack["clearances"].as_array().unwrap() {
            let principal = clearance["principal"].as_str().unwrap();
            sekai
                .create_object(CreateObjectRequest {
                    object: Some(Object {
                        id: format!("profile-{principal}"),
                        kind: "principal_profile".into(),
                        name: principal.into(),
                        namespace: "game-ops".into(),
                        external_id: format!("principal:{principal}"),
                        properties: HashMap::from([(
                            "classification_ceiling".into(),
                            clearance["classification_ceiling"].as_str().unwrap().into(),
                        )]),
                        ..Default::default()
                    }),
                    lease_precondition: None,
                })
                .await
                .unwrap_or_else(|error| panic!("profile {principal}: {error}\n{}", logs()));
        }

        for policy in pack["action_policies"].as_array().unwrap() {
            server.sekaictl_ok(&[
                "admin",
                "governance",
                "action",
                "policy",
                "set",
                "--scope",
                policy["scope"].as_str().unwrap(),
                "--default",
                policy["default"].as_str().unwrap(),
            ]);
        }
        for (index, type_def) in pack["action_types"].as_array().unwrap().iter().enumerate() {
            server.sekaictl_ok(&[
                "admin",
                "governance",
                "action",
                "type",
                "put",
                "--file",
                &write_json(files.path(), &format!("type-{index}.json"), type_def),
            ]);
        }
        let mut chisei = server.chisei().await;
        for budget in pack["action_budgets"].as_array().unwrap() {
            chisei
                .set_budget_limit(SetBudgetLimitRequest {
                    subject: budget["subject"].as_str().unwrap().into(),
                    metric: budget["metric"].as_str().unwrap().into(),
                    period_type: budget["period_type"].as_str().unwrap().into(),
                    max_tokens: budget["max"].as_i64().unwrap() as i32,
                    ..Default::default()
                })
                .await
                .unwrap_or_else(|error| panic!("action budget: {error}\n{}", logs()));
        }
        Self {
            server,
            sekai,
            tokens,
        }
    }

    /// Submits as the commander, the player's acting agent.
    async fn try_submit(
        &self,
        type_id: &str,
        key: &str,
        parameters: Value,
    ) -> Result<ActionInstance, tonic::Status> {
        self.sekai
            .clone()
            .submit_action_instance(bearer(
                &self.tokens["commander"],
                SubmitActionInstanceRequest {
                    namespace: type_namespace(type_id),
                    type_id: type_id.into(),
                    version: "1".into(),
                    parameters_json: parameters.to_string(),
                    idempotency_key: key.into(),
                    request_id: format!("operation-{key}"),
                    ..Default::default()
                },
            ))
            .await
            .map(|response| response.into_inner().instance.unwrap())
    }

    async fn submit(&self, type_id: &str, key: &str, parameters: Value) -> ActionInstance {
        self.try_submit(type_id, key, parameters)
            .await
            .unwrap_or_else(|error| panic!("submit {key}: {error}\n{}", self.server.logs()))
    }

    pub(crate) async fn property(&self, id: &str, property: &str) -> String {
        self.sekai
            .clone()
            .get_object(GetObjectRequest { id: id.into() })
            .await
            .expect("read object")
            .into_inner()
            .object
            .expect("object")
            .properties
            .get(property)
            .cloned()
            .unwrap_or_default()
    }

    async fn decide(&self, role: &str, instance_id: &str) -> Result<ActionInstance, tonic::Status> {
        self.sekai
            .clone()
            .decide_action_instance(bearer(
                &self.tokens[role],
                DecideActionInstanceRequest {
                    instance_id: instance_id.into(),
                    decision: "grant".into(),
                    reason: "approved".into(),
                },
            ))
            .await
            .map(|response| response.into_inner().instance.unwrap())
    }

    async fn reads(&self, role: &str, id: &str) -> Result<(), tonic::Status> {
        self.sekai
            .clone()
            .get_object(bearer(
                &self.tokens[role],
                GetObjectRequest { id: id.into() },
            ))
            .await
            .map(|_| ())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn each_spend_is_capped() {
    let game = GovernedGame::start().await;
    let spend = |amount: i64| json!({"object_id": "t-main", "spend": amount});

    let allowed = game
        .submit("game.treasury.spend", "spend-cap", spend(500))
        .await;
    assert_eq!(allowed.status, "admitted", "{allowed:?}");
    let refused = game
        .try_submit("game.treasury.spend", "spend-over-cap", spend(501))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument, "{refused:?}");
    assert_eq!(game.property("t-main", "spend").await, "500");
}

#[tokio::test(flavor = "multi_thread")]
async fn spends_stop_at_the_daily_cap() {
    let game = GovernedGame::start().await;
    let spend = |amount: i64| json!({"object_id": "t-main", "spend": amount});

    // Allowed: spends up to the daily count.
    for (key, amount) in [("spend-1", 100), ("spend-2", 200)] {
        let admitted = game.submit("game.treasury.spend", key, spend(amount)).await;
        assert_eq!(admitted.status, "admitted", "{admitted:?}");
    }
    assert_eq!(game.property("t-main", "spend").await, "200");

    // Refused: a third spend in the day names the exhausted treasury budget.
    let third = game
        .try_submit("game.treasury.spend", "spend-3", spend(50))
        .await
        .unwrap_err();
    assert_eq!(third.code(), Code::FailedPrecondition, "{third:?}");
    assert!(
        third
            .message()
            .contains("action:governed/project:game-treasury"),
        "{third:?}"
    );
    assert_eq!(game.property("t-main", "spend").await, "200");
}

#[tokio::test(flavor = "multi_thread")]
async fn attacks_never_target_allied_planets() {
    let game = GovernedGame::start().await;
    let attack = |planet: &str| json!({"object_id": planet, "attacked_by": "commander"});

    let allowed = game
        .submit("game.planet.attack", "attack-rival", attack("p-rival"))
        .await;
    assert_eq!(allowed.status, "admitted", "{allowed:?}");
    assert_eq!(game.property("p-rival", "attacked_by").await, "commander");

    // The refusal names the failing criterion and writes nothing.
    let refused = game
        .submit("game.planet.attack", "attack-ally", attack("p-ally"))
        .await;
    assert_eq!(refused.status, "denied", "{refused:?}");
    assert_eq!(refused.deny_reason, "target_is_hostile", "{refused:?}");
    assert_eq!(game.property("p-ally", "attacked_by").await, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn invasions_apply_only_after_the_admiral_grants() {
    let game = GovernedGame::start().await;
    let parked = game
        .submit(
            "game.planet.invade",
            "invade-rival",
            json!({"object_id": "p-rival", "occupied_by": "commander"}),
        )
        .await;
    assert_eq!(parked.status, "parked", "{parked:?}");

    // Refused: the submitting agent cannot approve its own invasion.
    let self_approval = game
        .decide("commander", &parked.instance_id)
        .await
        .unwrap_err();
    assert_eq!(self_approval.code(), Code::PermissionDenied);
    assert_eq!(game.property("p-rival", "occupied_by").await, "");

    // Allowed: the admiral's grant applies it.
    let granted = game
        .decide("admiral", &parked.instance_id)
        .await
        .unwrap_or_else(|error| panic!("grant: {error}\n{}", game.server.logs()));
    assert_eq!(granted.status, "admitted", "{granted:?}");
    assert_eq!(game.property("p-rival", "occupied_by").await, "commander");
}

#[tokio::test(flavor = "multi_thread")]
async fn spy_reports_are_visible_only_to_spies() {
    let game = GovernedGame::start().await;

    game.reads("spy", "r-spy")
        .await
        .unwrap_or_else(|error| panic!("spy read: {error}\n{}", game.server.logs()));
    // The commander holds the highest ordinary clearance and is still
    // refused the spy report, without its marking, but reads the briefing.
    let hidden = game.reads("commander", "r-spy").await.unwrap_err();
    assert_eq!(
        (hidden.code(), hidden.message()),
        (Code::PermissionDenied, "access denied")
    );
    game.reads("commander", "r-brief")
        .await
        .unwrap_or_else(|error| panic!("commander read: {error}\n{}", game.server.logs()));
}

/// A server with the routing config applied for one player.
struct RoutedGame {
    server: LoopServer,
    chisei: ChiseiServiceClient<GatewayClient>,
    routing: Value,
}

const PLAYER: &str = "red";

impl RoutedGame {
    async fn start() -> Self {
        // `native` is the local model runtime and `openai` the expensive one.
        // Neither endpoint is contacted: a decision never calls a provider.
        let server = LoopServer::spawn_with_env(
            &Backend::Sqlite,
            &[
                ("NATIVE_LLM_URL", "http://127.0.0.1:9"),
                ("OLLAMA_URL", "http://127.0.0.1:9"),
                ("CHISEI_GATEWAY_PROVIDED_PROVIDERS", "openai"),
            ],
        );
        let routing: Value = serde_json::from_str(ROUTING).expect("routing json");
        let mut chisei = server.chisei().await;
        let allow_context = json!({
            "contract_version": "chisei.context-admission/v1",
            "default_action": "include",
            "unknown_action": "hold_out",
            "rules": [],
        });
        for route in routing["routes"].as_array().unwrap() {
            chisei
                .set_namespace_policy(SetNamespacePolicyRequest {
                    namespace: route["namespace"].as_str().unwrap().into(),
                    allowed_runtimes: strings(&route["allowed_runtimes"]),
                    allowed_models: strings(&route["allowed_models"]),
                    default_runtime: route["default_runtime"].as_str().unwrap().into(),
                    default_model: route["default_model"].as_str().unwrap().into(),
                    data_class: String::new(),
                    context_admission_policy_json: allow_context.to_string(),
                })
                .await
                .unwrap_or_else(|error| panic!("route policy: {error}\n{}", server.logs()));
            // Route admission refuses any model family not enabled for the
            // namespace, so the expensive family exists only on its route.
            for family in strings(&route["enabled_families"]) {
                chisei
                    .set_model_family_enablement(SetModelFamilyEnablementRequest {
                        namespace: route["namespace"].as_str().unwrap().into(),
                        region_label: String::new(),
                        family_id: family,
                        status: "enabled".into(),
                        reason: "game-ontology/v1 routing".into(),
                    })
                    .await
                    .unwrap_or_else(|error| panic!("family: {error}\n{}", server.logs()));
            }
        }
        let game = Self {
            server,
            chisei,
            routing,
        };
        for budget in game.budgets("day") {
            game.set_limit(&budget, "", "").await;
        }
        game
    }

    fn budgets(&self, window: &str) -> Vec<Value> {
        self.routing["budgets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|budget| budget["window"] == window)
            .cloned()
            .collect()
    }

    fn namespace(&self, route: &str) -> String {
        self.routing["routes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["route"] == route)
            .unwrap_or_else(|| panic!("no {route} route"))["namespace"]
            .as_str()
            .unwrap()
            .into()
    }

    /// A day limit lands on the player's flat agent scope, which every
    /// route's chain includes. A turn limit lands on the turn's work unit
    /// under one route's namespace.
    async fn set_limit(&self, budget: &Value, project: &str, turn: &str) {
        self.chisei
            .clone()
            .set_budget_limit(SetBudgetLimitRequest {
                project: project.into(),
                agent: PLAYER.into(),
                work_unit: turn.into(),
                metric: budget["metric"].as_str().unwrap().into(),
                period_type: budget["period_type"].as_str().unwrap().into(),
                max_tokens: budget["max"].as_i64().unwrap() as i32,
                ..Default::default()
            })
            .await
            .unwrap_or_else(|error| panic!("budget: {error}\n{}", self.server.logs()));
    }

    /// Opens a turn: each route's turn limits apply to its work unit.
    async fn open_turn(&self, turn: &str) {
        for budget in self.budgets("turn") {
            let namespace = self.namespace(budget["route"].as_str().unwrap());
            self.set_limit(&budget, &namespace, turn).await;
        }
    }

    async fn decide(&self, route: &str, turn: &str, tokens: i32) -> DecideGatewayExecutionResponse {
        let namespace = self.namespace(route);
        self.chisei
            .clone()
            .decide_gateway_execution(DecideGatewayExecutionRequest {
                contract_version: "gateway.decide/v2".into(),
                namespace: namespace.clone(),
                requested_model: "gpt-5.5".into(),
                operation_class: "chat".into(),
                correlation_operation_id: format!("{route}-{turn}-{tokens}"),
                correlation_attempt: 1,
                estimated_tokens: tokens,
                // A cheap-eligible class with local fallback offered: a hard
                // stop must still refuse instead of degrading.
                task_class: "bulk".into(),
                preferred_runtime: "openai".into(),
                project: namespace,
                agent: PLAYER.into(),
                work_unit: turn.into(),
                local_free_available: true,
                user_id: PLAYER.into(),
                expected_calls: 1,
                ..Default::default()
            })
            .await
            .unwrap_or_else(|error| panic!("decide: {error}\n{}", self.server.logs()))
            .into_inner()
    }

    async fn spend(&self, route: &str, turn: &str, metric: &str, amount: i32) {
        self.chisei
            .clone()
            .record_usage(RecordUsageRequest {
                tokens_used: amount,
                project: self.namespace(route),
                agent: PLAYER.into(),
                work_unit: turn.into(),
                metric: metric.into(),
                idempotency_key: format!("{route}-{turn}-{metric}-{amount}"),
                ..Default::default()
            })
            .await
            .unwrap_or_else(|error| panic!("record usage: {error}\n{}", self.server.logs()));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn routine_actions_route_local_and_only_high_impact_ones_route_expensive() {
    let game = RoutedGame::start().await;
    game.open_turn("turn-1").await;

    // Allowed: a high-impact decision gets the expensive model it asks for.
    let high_impact = game.decide("high_impact", "turn-1", 100).await;
    assert!(high_impact.admitted, "{high_impact:?}");
    assert_eq!(
        (
            high_impact.resolved_runtime.as_str(),
            high_impact.resolved_model.as_str()
        ),
        ("openai", "gpt-5.5")
    );
    // Refused: a routine decision asking for the same model gets the local one.
    let routine = game.decide("routine", "turn-1", 100).await;
    assert!(routine.admitted, "{routine:?}");
    assert_eq!(routine.resolved_runtime, "native", "{routine:?}");
    assert!(
        routine.resolved_model.ends_with("native-default"),
        "{routine:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn turn_budgets_cap_tokens_and_model_calls() {
    let game = RoutedGame::start().await;
    game.open_turn("turn-1").await;

    // Refused: the routine token budget and the high-impact call budget of
    // turn 1 are spent.
    game.spend("routine", "turn-1", "tokens", 4000).await;
    let tokens_out = game.decide("routine", "turn-1", 100).await;
    assert!(!tokens_out.admitted, "{tokens_out:?}");
    assert_eq!(tokens_out.deny_reason, "budget_denied");
    assert!(
        tokens_out.budget_scope.ends_with("work_unit:turn-1"),
        "{tokens_out:?}"
    );
    game.spend("high_impact", "turn-1", "requests", 2).await;
    let calls_out = game.decide("high_impact", "turn-1", 100).await;
    assert!(!calls_out.admitted, "{calls_out:?}");
    assert_eq!(calls_out.deny_reason, "budget_denied");

    // Allowed: the next turn opens with fresh turn budgets.
    game.open_turn("turn-2").await;
    for route in ["routine", "high_impact"] {
        let next = game.decide(route, "turn-2", 100).await;
        assert!(next.admitted, "{route}: {next:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exhausted_day_budget_is_a_hard_stop() {
    let game = RoutedGame::start().await;
    game.open_turn("turn-1").await;
    let allowed = game.decide("routine", "turn-1", 100).await;
    assert!(allowed.admitted, "{allowed:?}");

    // Refused: once the day's tokens are spent, a fresh turn on either route
    // stops, with no fallback to a local-free model.
    game.spend("high_impact", "turn-1", "tokens", 40_000).await;
    game.open_turn("turn-2").await;
    for route in ["routine", "high_impact"] {
        let stopped = game.decide(route, "turn-2", 100).await;
        assert!(!stopped.admitted, "{route}: {stopped:?}");
        assert_eq!(stopped.deny_reason, "budget_denied", "{route}");
        assert_eq!(stopped.budget_scope, format!("agent:{PLAYER}"), "{route}");
    }
}
