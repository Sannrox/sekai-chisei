//! Governed Action scenarios against the game reference workload (#1624).
//!
//! The Fleet and Planet classes come from the `game-ontology/v1` package
//! under `examples/game-ontology/`. Everything else goes through
//! the shipped binary's public surfaces: the operator CLI for ontology,
//! seed, credentials and policies, and gRPC for Actions. Four scenarios: an
//! allowed proposal, a proposal refused by its policy, a move applied only
//! after an approver grants it, and two concurrent conflicting moves of one
//! fleet where exactly one applies.
#![cfg(unix)]

use sekai_chisei::grpc::pb::sekai::{
    DecideActionInstanceRequest, EnsureTeamNamespaceRequest, GetObjectRequest, GovernedActionType,
    PutGovernedActionTypeRequest, SubmitActionInstanceRequest,
};
use serde_json::{Value, json};

use crate::product_loop_backend_conformance::{Backend, LoopServer, bearer};

const PACKAGE: &str = include_str!("../examples/game-ontology/game-v1.json");
const NAMESPACE: &str = "game";

/// The pinned package's Fleet and Planet classes and their `stationed-at`
/// relation, as the operator CLI's ontology document.
fn fleet_ontology() -> Value {
    let package: Value = serde_json::from_str(PACKAGE).expect("package json");
    let class = |name: &str| {
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
    };
    let relation = package["relations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|relation| relation["name"] == "stationed-at")
        .expect("stationed-at relation")
        .clone();
    json!({
        "version": "sekai.ontology-product/v1",
        "classes": [class("Fleet"), class("Planet")],
        "relations": [relation],
    })
}

fn seed() -> Value {
    let planet = |id: &str| json!({"id": id, "kind": "planet", "name": id});
    let fleet = |id: &str| json!({"id": id, "kind": "fleet", "name": id, "properties": {"planet": "p-home", "orders": "hold"}});
    json!({
        "version": "sekai.seed/v1",
        "namespace": NAMESPACE,
        "objects": [
            planet("p-home"), planet("p-ally"), planet("p-rim"),
            fleet("f-scout"), fleet("f-strike"), fleet("f-main"), fleet("f-contested"),
        ],
        "links": [
            {"from": "f-scout", "to": "p-home", "relation": "stationed-at"},
            {"from": "f-main", "to": "p-home", "relation": "stationed-at"},
            {"from": "f-contested", "to": "p-home", "relation": "stationed-at"},
        ],
    })
}

fn write_json(dir: &std::path::Path, name: &str, value: &Value) -> String {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

/// A fleet Action type under its own policy scope, so each scenario's
/// policy is independent.
fn fleet_action(
    type_id: &str,
    scope: &str,
    property: &str,
    approvers: &[&str],
) -> GovernedActionType {
    GovernedActionType {
        namespace: NAMESPACE.into(),
        type_id: type_id.into(),
        version: "1".into(),
        description: format!("{type_id} (game reference workload)"),
        parameter_schema_json: json!({
            "type": "object",
            "properties": {"object_id": {"type": "string"}, property: {"type": "string"}},
            "required": ["object_id", property],
            "additionalProperties": false,
        })
        .to_string(),
        allowed_effect_kinds: vec!["notify".into()],
        policy_scope: scope.into(),
        object_kind: "fleet".into(),
        object_mutation: "update".into(),
        approvers: approvers.iter().map(ToString::to_string).collect(),
        enabled: true,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn game_fleet_actions_follow_their_policies() {
    let server = LoopServer::spawn(&Backend::Sqlite);
    let logs = || server.logs();
    let files = tempfile::tempdir().unwrap();
    let socket = server.socket_str();
    server.sekaictl_ok(&[
        "ontology",
        "apply",
        "--file",
        &write_json(files.path(), "ontology.json", &fleet_ontology()),
        "--target",
        &socket,
    ]);
    server.sekaictl_ok(&[
        "ontology",
        "seed",
        "--file",
        &write_json(files.path(), "seed.json", &seed()),
        "--target",
        &socket,
    ]);
    let mut sekai = server.sekai().await;
    for (principal, role) in [("commander", "editor"), ("admiral", "viewer")] {
        sekai
            .ensure_team_namespace(EnsureTeamNamespaceRequest {
                namespace: NAMESPACE.into(),
                principal: principal.into(),
                role: role.into(),
            })
            .await
            .unwrap_or_else(|error| panic!("grant {principal}: {error}\n{}", logs()));
    }
    let commander = server.token("commander");
    let admiral = server.token("admiral");
    // An Action type's `policy_scope` resolves as the `project:` scope.
    for (scope, default) in [
        ("project:game-orders", "allow"),
        ("project:game-raids", "deny"),
        ("project:game-moves", "require_approval"),
    ] {
        server.sekaictl_ok(&[
            "admin",
            "governance",
            "action",
            "policy",
            "set",
            "--scope",
            scope,
            "--default",
            default,
        ]);
    }
    for type_def in [
        fleet_action("game.fleet.orders", "game-orders", "orders", &[]),
        fleet_action("game.fleet.raid", "game-raids", "orders", &[]),
        fleet_action("game.fleet.move", "game-moves", "planet", &["admiral"]),
    ] {
        sekai
            .put_governed_action_type(PutGovernedActionTypeRequest {
                r#type: Some(type_def),
                request_id: String::new(),
            })
            .await
            .unwrap_or_else(|error| panic!("put action type: {error}\n{}", logs()));
    }
    let submit = |type_id: &str, key: &str, parameters: Value| {
        bearer(
            &commander,
            SubmitActionInstanceRequest {
                namespace: NAMESPACE.into(),
                type_id: type_id.into(),
                version: "1".into(),
                parameters_json: parameters.to_string(),
                idempotency_key: key.into(),
                request_id: format!("operation-{key}"),
                ..Default::default()
            },
        )
    };
    let reader = sekai.clone();
    let fleet_property = |id: &'static str, property: &'static str| {
        let mut client = reader.clone();
        async move {
            client
                .get_object(GetObjectRequest { id: id.into() })
                .await
                .expect("read fleet")
                .into_inner()
                .object
                .expect("fleet")
                .properties
                .get(property)
                .cloned()
                .unwrap_or_default()
        }
    };

    // 1. An allowed proposal is admitted and applied.
    let allowed = sekai
        .submit_action_instance(submit(
            "game.fleet.orders",
            "scout-patrol",
            json!({"object_id": "f-scout", "orders": "patrol"}),
        ))
        .await
        .unwrap_or_else(|error| panic!("allowed proposal: {error}\n{}", logs()))
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(allowed.status, "admitted");
    assert_eq!(fleet_property("f-scout", "orders").await, "patrol");

    // 2. A proposal its policy refuses is denied, names the refusal, and
    //    writes nothing.
    let refused = sekai
        .submit_action_instance(submit(
            "game.fleet.raid",
            "strike-raid",
            json!({"object_id": "f-strike", "orders": "raid"}),
        ))
        .await
        .unwrap_or_else(|error| panic!("refused proposal: {error}\n{}", logs()))
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(refused.status, "denied");
    assert!(
        refused.policy_decision.contains("deny") || refused.deny_reason.contains("deny"),
        "{refused:?}"
    );
    assert_eq!(fleet_property("f-strike", "orders").await, "hold");

    // 3. A move parks on proposal and applies only once the approver grants.
    let parked = sekai
        .submit_action_instance(submit(
            "game.fleet.move",
            "main-to-ally",
            json!({"object_id": "f-main", "planet": "p-ally"}),
        ))
        .await
        .unwrap_or_else(|error| panic!("move proposal: {error}\n{}", logs()))
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(parked.status, "parked");
    assert_eq!(fleet_property("f-main", "planet").await, "p-home");
    let decide = |instance_id: &str| {
        bearer(
            &admiral,
            DecideActionInstanceRequest {
                instance_id: instance_id.into(),
                decision: "grant".into(),
                reason: "approved".into(),
            },
        )
    };
    let applied = sekai
        .decide_action_instance(decide(&parked.instance_id))
        .await
        .unwrap_or_else(|error| panic!("grant move: {error}\n{}", logs()))
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(applied.status, "admitted");
    assert_eq!(fleet_property("f-main", "planet").await, "p-ally");

    // 4. Two conflicting moves of one fleet park against the same state;
    //    granted concurrently, exactly one applies and the other is stale.
    let mut moves = Vec::new();
    for (key, planet) in [("contested-ally", "p-ally"), ("contested-rim", "p-rim")] {
        let instance = sekai
            .submit_action_instance(submit(
                "game.fleet.move",
                key,
                json!({"object_id": "f-contested", "planet": planet}),
            ))
            .await
            .unwrap_or_else(|error| panic!("conflicting proposal: {error}\n{}", logs()))
            .into_inner()
            .instance
            .unwrap();
        assert_eq!(instance.status, "parked");
        moves.push((instance.instance_id, planet));
    }
    let (mut first, mut second) = (sekai.clone(), sekai.clone());
    let (a, b) = tokio::join!(
        first.decide_action_instance(decide(&moves[0].0)),
        second.decide_action_instance(decide(&moves[1].0)),
    );
    let outcomes: Vec<_> = [a, b]
        .into_iter()
        .map(|outcome| {
            let instance = outcome
                .unwrap_or_else(|error| panic!("concurrent grant: {error}\n{}", logs()))
                .into_inner()
                .instance
                .unwrap();
            (instance.status, instance.deny_reason)
        })
        .collect();
    let admitted: Vec<usize> = outcomes
        .iter()
        .enumerate()
        .filter(|(_, (status, _))| status == "admitted")
        .map(|(index, _)| index)
        .collect();
    assert_eq!(admitted.len(), 1, "exactly one move applies: {outcomes:?}");
    let loser = &outcomes[1 - admitted[0]];
    assert_eq!(loser.0, "denied", "{outcomes:?}");
    assert!(loser.1.contains("stale"), "{outcomes:?}");
    assert_eq!(
        fleet_property("f-contested", "planet").await,
        moves[admitted[0]].1
    );
    assert_eq!(server.panics(), 0, "{}", logs());
}
