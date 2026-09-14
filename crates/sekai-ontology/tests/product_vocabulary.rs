use sekai_ontology::{EMBEDDED_SKILL, ImportDocument};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const PACK: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/ontologies/sekai-chisei-product-v1.json"
);
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const AGENT_SKILL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../.agents/skills/sekai-ontology/SKILL.md"
);
const ALLOWED_SOURCES: &[&str] = &[
    "VISION.md",
    "AGENTS.md",
    "docs/architecture.md",
    "docs/ontology.md",
    "docs/rpc-maturity.md",
];
const PRODUCT_CLASS_NAMES: &[&str] = &[
    "Sekai",
    "Chisei",
    "Portable Ontology Database",
    "Control Plane Database",
    "Receipt",
    "Governed Action",
    "Directory Fact",
    "Ontology Class",
];

fn sekai(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sekai"))
        .args(arguments)
        .output()
        .unwrap()
}

fn repo_root() -> PathBuf {
    PathBuf::from(REPO_ROOT)
        .canonicalize()
        .expect("repository root")
}

fn imported_database() -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("knowledge.db");
    let database = database.to_str().unwrap().to_string();
    let initialized = sekai(&["--db", &database, "init"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let imported = sekai(&["--db", &database, "import", PACK]);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    (directory, database)
}

fn json_command(database: &str, arguments: &[&str]) -> Value {
    let mut command = vec!["--db", database, "--json"];
    command.extend(arguments);
    let output = sekai(&command);
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn provenance_sources(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|record| record["source"].as_str().map(str::to_string))
        .collect()
}

fn assert_provenance_into_shipped_docs(provenance: &Value) {
    let sources = provenance_sources(provenance);
    assert!(
        !sources.is_empty(),
        "expected provenance sources, got {provenance}"
    );
    let root = repo_root();
    for source in &sources {
        assert!(
            ALLOWED_SOURCES.contains(&source.as_str()),
            "provenance source {source} is outside the shipped product-doc set"
        );
        let path = root.join(source);
        assert!(
            path.is_file(),
            "provenance source {source} does not exist at {}",
            path.display()
        );
    }
}

fn assert_class_description_contains(class: &Value, name: &str, needle: &str) {
    assert_eq!(class["name"], name);
    let description = class["description"].as_str().unwrap_or_default();
    assert!(
        description.contains(needle),
        "class {name} description missing {needle:?}: {description}"
    );
}

fn class_names(classes: &Value) -> Vec<&str> {
    classes
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|class| class["name"].as_str())
        .collect()
}

#[test]
fn product_pack_imports_and_validates_offline() {
    let (_guard, database) = imported_database();
    let validated = json_command(&database, &["validate"]);
    assert_eq!(validated["command"], "validate");
    assert_eq!(validated["data"]["valid"], true);
    let issues = validated["data"]["issues"].as_array().unwrap();
    assert!(issues.is_empty(), "validate reported issues: {issues:?}");

    let document: ImportDocument =
        serde_json::from_str(&fs::read_to_string(PACK).unwrap()).unwrap();
    assert_eq!(document.schema_version, 1);
    assert!(
        PACK.ends_with("/ontologies/sekai-chisei-product-v1.json"),
        "pack must live outside proto/: {PACK}"
    );
}

#[test]
fn product_classes_are_absent_from_default_init_and_directory_vocabulary() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("knowledge.db");
    let database = database.to_str().unwrap();
    assert!(sekai(&["--db", database, "init"]).status.success());
    assert!(
        sekai(&["--db", database, "directory", "init"])
            .status
            .success()
    );
    let exported = json_command(database, &["export"]);
    let names = class_names(&exported["data"]["classes"]);
    for name in PRODUCT_CLASS_NAMES {
        assert!(
            !names.contains(name),
            "{name} leaked into default init / directory vocabulary: {names:?}"
        );
    }
}

#[test]
fn question_sekai_and_chisei() {
    let (_guard, database) = imported_database();

    let sekai_explain = json_command(&database, &["explain", "Sekai"]);
    assert_eq!(sekai_explain["command"], "explain");
    assert_class_description_contains(
        &sekai_explain["data"]["class"],
        "Sekai",
        "operational memory",
    );
    assert_provenance_into_shipped_docs(&sekai_explain["data"]["provenance"]);

    let chisei_explain = json_command(&database, &["explain", "Chisei"]);
    assert_class_description_contains(
        &chisei_explain["data"]["class"],
        "Chisei",
        "Governed decision",
    );
    assert_provenance_into_shipped_docs(&chisei_explain["data"]["provenance"]);

    let asked = json_command(&database, &["ask", "what is Sekai"]);
    assert_eq!(asked["command"], "ask");
    assert_eq!(
        asked["data"]["interpretation"]["plan"]["operation"],
        "explain"
    );
    assert_eq!(asked["data"]["interpretation"]["plan"]["name"], "Sekai");
    assert_eq!(asked["data"]["answer"]["kind"], "explain");
    assert_class_description_contains(
        &asked["data"]["answer"]["data"]["class"],
        "Sekai",
        "operational memory",
    );
    assert_provenance_into_shipped_docs(&asked["data"]["answer"]["data"]["provenance"]);

    let related = json_command(
        &database,
        &["query", "Chisei", "--direction", "outbound", "--depth", "1"],
    );
    assert_eq!(related["command"], "query");
    let reached = class_names(&related["data"]["classes"]);
    assert!(reached.contains(&"Sekai"), "{reached:?}");
    let relation = related["data"]["relations"][0]["name"].as_str().unwrap();
    assert_eq!(relation, "governs_through");
}

#[test]
fn question_portable_ontology_database_vs_control_plane() {
    let (_guard, database) = imported_database();

    let portable = json_command(&database, &["explain", "Portable Ontology Database"]);
    assert_class_description_contains(
        &portable["data"]["class"],
        "Portable Ontology Database",
        "--db",
    );
    assert_provenance_into_shipped_docs(&portable["data"]["provenance"]);

    let control = json_command(&database, &["explain", "Control Plane Database"]);
    assert_class_description_contains(
        &control["data"]["class"],
        "Control Plane Database",
        "data/sekai.db",
    );
    assert_provenance_into_shipped_docs(&control["data"]["provenance"]);

    let distinct = json_command(
        &database,
        &[
            "query",
            "Portable Ontology Database",
            "--relation",
            "distinct_from",
            "--direction",
            "outbound",
        ],
    );
    let reached = class_names(&distinct["data"]["classes"]);
    assert!(reached.contains(&"Control Plane Database"), "{reached:?}");

    let asked = json_command(&database, &["ask", "what is Portable Ontology Database"]);
    assert_eq!(
        asked["data"]["interpretation"]["plan"]["operation"],
        "explain"
    );
    assert_eq!(asked["data"]["answer"]["kind"], "explain");
    assert_provenance_into_shipped_docs(&asked["data"]["answer"]["data"]["provenance"]);
}

#[test]
fn question_receipt_and_what_it_records() {
    let (_guard, database) = imported_database();

    let receipt = json_command(&database, &["explain", "Receipt"]);
    assert_class_description_contains(&receipt["data"]["class"], "Receipt", "GetOperationReceipt");
    assert_provenance_into_shipped_docs(&receipt["data"]["provenance"]);

    let asked = json_command(&database, &["ask", "what does Receipt record"]);
    assert_eq!(
        asked["data"]["interpretation"]["plan"]["operation"],
        "query"
    );
    assert_eq!(asked["data"]["interpretation"]["plan"]["name"], "Receipt");
    assert_eq!(asked["data"]["answer"]["kind"], "query");
    let reached = class_names(&asked["data"]["answer"]["data"]["classes"]);
    assert!(reached.contains(&"Operation"), "{reached:?}");
}

#[test]
fn question_governed_action_and_relations() {
    let (_guard, database) = imported_database();

    let action = json_command(&database, &["explain", "Governed Action"]);
    assert_class_description_contains(
        &action["data"]["class"],
        "Governed Action",
        "SubmitActionInstance",
    );
    assert_provenance_into_shipped_docs(&action["data"]["provenance"]);

    let asked = json_command(&database, &["ask", "what is related to Governed Action"]);
    assert_eq!(
        asked["data"]["interpretation"]["plan"]["operation"],
        "query"
    );
    assert_eq!(asked["data"]["answer"]["kind"], "query");
    let reached = class_names(&asked["data"]["answer"]["data"]["classes"]);
    assert!(reached.contains(&"Receipt"), "{reached:?}");
    assert!(reached.contains(&"Operation"), "{reached:?}");
}

#[test]
fn question_directory_fact_vs_ontology_class() {
    let (_guard, database) = imported_database();

    let fact = json_command(&database, &["explain", "Directory Fact"]);
    assert_class_description_contains(&fact["data"]["class"], "Directory Fact", "directory");
    assert_provenance_into_shipped_docs(&fact["data"]["provenance"]);

    let class = json_command(&database, &["explain", "Ontology Class"]);
    assert_class_description_contains(&class["data"]["class"], "Ontology Class", "meaning");
    assert_provenance_into_shipped_docs(&class["data"]["provenance"]);

    let asked = json_command(&database, &["ask", "what is Directory Fact"]);
    assert_eq!(
        asked["data"]["interpretation"]["plan"]["operation"],
        "explain"
    );
    assert_eq!(asked["data"]["answer"]["kind"], "explain");
    assert_provenance_into_shipped_docs(&asked["data"]["answer"]["data"]["provenance"]);

    let contrast = json_command(
        &database,
        &[
            "query",
            "Directory Fact",
            "--relation",
            "is_not",
            "--direction",
            "outbound",
        ],
    );
    let reached = class_names(&contrast["data"]["classes"]);
    assert!(reached.contains(&"Ontology Class"), "{reached:?}");
}

#[test]
fn product_skill_documents_the_five_questions_and_stays_in_sync() {
    let agent_skill = fs::read_to_string(AGENT_SKILL).unwrap();
    assert_eq!(agent_skill, EMBEDDED_SKILL);
    for needle in [
        "sekai-chisei-product-v1.json",
        "What is Sekai, and what is Chisei?",
        "What is the portable ontology database",
        "What is a Receipt, and what does it record?",
        "What is a governed Action",
        "What is a directory fact vs an ontology class?",
        "do not answer from memory",
        "data/sekai.db",
    ] {
        assert!(
            EMBEDDED_SKILL.contains(needle),
            "embedded skill missing {needle:?}"
        );
    }
    for forbidden in ["summarize", "sekaictl ontology apply", "HTTP/JSON"] {
        assert!(
            !EMBEDDED_SKILL.contains(forbidden),
            "skill documents a non-shipping command or surface: {forbidden}"
        );
    }
}
