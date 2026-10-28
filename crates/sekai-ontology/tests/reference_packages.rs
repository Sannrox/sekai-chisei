//! Reference ontology packages under `examples/` (#1624).
//!
//! The game reference workload's `game-ontology/v1` package is validated with
//! the same offline import and `validate` checks as the product vocabulary
//! pack. Its policy pack and its budget and routing config (#1854) are
//! versioned with it and checked here against the package and against the
//! closed vocabularies the control plane accepts, so a malformed edit fails.
//! `tests/game_governance_pack.rs` applies both to the server.

use sekai_ontology::ImportDocument;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;

const GAME_PACKAGE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/game-ontology/game-v1.json"
);

const POLICY_PACK: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/game-ontology/policy-pack-v1.json"
);

const ROUTING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/game-ontology/routing-v2.json"
);

fn sekai(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sekai"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn game_package_imports_and_validates_offline() {
    let document: ImportDocument =
        serde_json::from_str(&fs::read_to_string(GAME_PACKAGE).unwrap()).unwrap();
    assert_eq!(document.schema_version, 1);
    assert!(
        document
            .provenance
            .iter()
            .any(|record| record.source == "game-ontology/v1"),
        "the package names its source"
    );

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("knowledge.db");
    let database = database.to_str().unwrap();
    assert!(sekai(&["--db", database, "init"]).status.success());
    let imported = sekai(&["--db", database, "import", GAME_PACKAGE]);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let validated = sekai(&["--db", database, "--json", "validate"]);
    assert!(validated.status.success());
    let validated: Value = serde_json::from_slice(&validated.stdout).unwrap();
    assert_eq!(validated["data"]["valid"], true, "{validated}");
    let exported = sekai(&["--db", database, "--json", "export"]);
    let exported: Value = serde_json::from_slice(&exported.stdout).unwrap();
    let classes = exported["data"]["classes"].as_array().unwrap();
    assert_eq!(classes.len(), document.classes.len());
}

fn json(path: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn items<'a>(value: &'a Value, field: &str) -> &'a Vec<Value> {
    value[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} must be a list"))
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| panic!("{field} must be a non-empty string in {value}"))
}

fn texts(value: &Value, field: &str) -> BTreeSet<String> {
    items(value, field)
        .iter()
        .map(|item| item.as_str().expect("string item").to_string())
        .collect()
}

/// A budget the Chisei tracker accepts: a known metric and period, and a
/// positive cap.
fn assert_budget(budget: &Value) {
    assert!(
        ["tokens", "requests"].contains(&text(budget, "metric")),
        "{budget}"
    );
    assert!(
        ["daily", "weekly", "monthly"].contains(&text(budget, "period_type")),
        "{budget}"
    );
    assert!(
        budget["max"]
            .as_i64()
            .is_some_and(|max| max > 0 && max <= i64::from(i32::MAX)),
        "{budget}"
    );
}

fn game_package_classes() -> BTreeSet<String> {
    let package = json(GAME_PACKAGE);
    items(&package, "classes")
        .iter()
        .map(|class| text(class, "name").to_string())
        .collect()
}

#[test]
fn game_policy_pack_matches_its_package() {
    let pack = json(POLICY_PACK);
    assert_eq!(pack["version"], "game-ontology.policy-pack/v1");
    assert_eq!(pack["package"], "game-ontology/v1");
    let classes = game_package_classes();
    let kinds: BTreeSet<String> = classes.iter().map(|class| class.to_lowercase()).collect();

    let rules: BTreeSet<&str> = items(&pack, "rules")
        .iter()
        .map(|rule| text(rule, "rule"))
        .collect();
    assert_eq!(
        rules,
        BTreeSet::from([
            "spending_caps",
            "no_attacks_on_allies",
            "invasion_approval",
            "spy_only_visibility",
        ])
    );

    let mut scopes = BTreeSet::new();
    for policy in items(&pack, "action_policies") {
        assert!(
            ["allow", "deny", "require_approval"].contains(&text(policy, "default")),
            "{policy}"
        );
        assert!(scopes.insert(text(policy, "scope")), "duplicate {policy}");
    }

    let mut type_ids = BTreeSet::new();
    for type_def in items(&pack, "action_types") {
        let type_id = text(type_def, "type_id");
        assert!(type_ids.insert(type_id), "duplicate {type_id}");
        text(type_def, "namespace");
        text(type_def, "version");
        assert!(
            scopes.contains(format!("project:{}", text(type_def, "policy_scope")).as_str()),
            "{type_id} has no action policy for its scope"
        );
        assert!(kinds.contains(text(type_def, "object_kind")), "{type_id}");
        assert!(
            ["create", "update"].contains(&text(type_def, "object_mutation")),
            "{type_id}"
        );
        // The closed parameter schema an Action type must declare.
        let schema = &type_def["parameter_schema_json"];
        assert_eq!(schema["type"], "object", "{type_id}");
        assert_eq!(schema["additionalProperties"], false, "{type_id}");
        let properties = schema["properties"].as_object().expect("properties");
        let required = texts(schema, "required");
        assert!(required.contains("object_id"), "{type_id}");
        assert!(
            required.iter().all(|name| properties.contains_key(name)),
            "{type_id}"
        );
        for property in properties.values() {
            assert!(
                ["string", "number", "integer", "boolean"].contains(&text(property, "type")),
                "{type_id}"
            );
        }
        for criterion in type_def["submission_criteria"]
            .as_array()
            .into_iter()
            .flatten()
        {
            text(criterion, "criterion_id");
            assert!(
                [
                    "allow_all",
                    "subject_equals_property",
                    "required_scope_equals",
                    "property_equals",
                ]
                .contains(&text(criterion, "kind")),
                "{type_id}"
            );
        }
        for approver in type_def["approvers"].as_array().into_iter().flatten() {
            assert!(approver.as_str().is_some_and(|name| !name.is_empty()));
        }
    }
    for budget in items(&pack, "action_budgets") {
        assert!(
            text(budget, "subject").starts_with("action:governed"),
            "{budget}"
        );
        assert_budget(budget);
    }

    let lattice = &pack["classification_lattice"];
    assert_eq!(
        lattice["contract_version"],
        "sekai.classification-lattice/v1"
    );
    text(lattice, "namespace");
    let tokens = texts(lattice, "tokens");
    assert_eq!(
        tokens.len(),
        items(lattice, "tokens").len(),
        "duplicate token"
    );
    for edge in items(lattice, "parents") {
        assert!(tokens.contains(text(edge, "child")), "{edge}");
        assert!(tokens.contains(text(edge, "parent")), "{edge}");
        assert_ne!(edge["child"], edge["parent"], "{edge}");
    }
    for pair in items(lattice, "incomparable") {
        assert!(tokens.contains(text(pair, "left")), "{pair}");
        assert!(tokens.contains(text(pair, "right")), "{pair}");
    }
    for clearance in items(&pack, "clearances") {
        text(clearance, "principal");
        assert!(
            tokens.contains(text(clearance, "classification_ceiling")),
            "{clearance}"
        );
    }
    for marking in items(&pack, "markings") {
        assert!(classes.contains(text(marking, "class")), "{marking}");
        assert!(
            tokens.contains(text(marking, "access_marking")),
            "{marking}"
        );
    }
}

#[test]
fn game_routing_config_uses_only_known_routes_and_budgets() {
    let routing = json(ROUTING);
    assert_eq!(routing["version"], "game-ontology.routing/v2");
    assert_eq!(routing["package"], "game-ontology/v1");

    // One namespace route policy; its impact route rule picks the models
    // each impact class may use.
    text(&routing, "namespace");
    let runtimes = texts(&routing, "allowed_runtimes");
    let models = texts(&routing, "allowed_models");
    assert!(runtimes.contains(text(&routing, "default_runtime")));
    assert!(models.contains(text(&routing, "default_model")));
    // A model family is its provider runtime.
    assert!(texts(&routing, "enabled_families").is_subset(&runtimes));
    let rule = &routing["impact_routes"];
    assert_eq!(rule["contract_version"], "chisei.impact-route/v1");
    let classes = rule["routes"].as_object().expect("impact routes");
    assert_eq!(
        classes.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["unclassified", "routine", "high_impact"])
    );
    for (class, route) in classes {
        let allowed = texts(route, "allowed_models");
        assert!(allowed.is_subset(&models), "{class}");
        assert!(allowed.contains(text(&routing, "default_model")), "{class}");
    }
    // Only high-impact calls may use a model beyond the default.
    for class in ["unclassified", "routine"] {
        assert_eq!(texts(&classes[class], "allowed_models").len(), 1, "{class}");
    }
    for type_def in items(&json(POLICY_PACK), "action_types") {
        if let Some(class) = type_def.get("impact_class") {
            assert!(
                classes.contains_key(class.as_str().expect("impact class")),
                "{type_def}"
            );
        }
    }

    let mut windows = BTreeSet::new();
    for budget in items(&routing, "budgets") {
        assert_budget(budget);
        let window = text(budget, "window");
        match window {
            "turn" | "day" => assert!(budget.get("route").is_none(), "{budget}"),
            other => panic!("unknown budget window {other}"),
        }
        windows.insert((window, text(budget, "metric")));
    }
    for window in ["turn", "day"] {
        for metric in ["tokens", "requests"] {
            assert!(
                windows.contains(&(window, metric)),
                "no {window} {metric} budget"
            );
        }
    }
}
